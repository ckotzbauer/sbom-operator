package job

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"time"

	"golang.org/x/exp/maps"
	batchv1 "k8s.io/api/batch/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/sirupsen/logrus"
)

type imagePod struct {
	Pod       string `json:"pod"`
	Namespace string `json:"namespace"`
	Cluster   string `json:"cluster"`
}

type imageConfig struct {
	Host     string     `json:"registry-host"`
	User     string     `json:"registry-user"`
	Password string     `json:"registry-password"`
	Image    string     `json:"image"`
	Pods     []imagePod `json:"pods"`
}

type JobClient struct {
	k8s             *kubernetes.KubeClient
	image           string
	imagePullSecret string
	timeout         int64
	clusterId       string
}

func New(k8s *kubernetes.KubeClient, image, imagePullSecret, clusterId string, timeout int64) JobClient {
	return JobClient{
		k8s:             k8s,
		image:           image,
		imagePullSecret: imagePullSecret,
		timeout:         timeout,
		clusterId:       clusterId,
	}
}

func (j JobClient) StartJob(pods []libk8s.PodInfo) (*batchv1.Job, error) {
	podNamespace := os.Getenv("POD_NAMESPACE")
	images := make(map[string]imageConfig, 0)

	for _, pod := range pods {
		for _, container := range pod.Containers {
			cfg, err := oci.ResolveAuthConfig(*container.Image)
			if err != nil {
				logrus.WithError(err).Error("Error occurred during auth-resolve")
				return nil, err
			}

			img, ok := images[container.Image.ImageID]
			if !ok {
				img = imageConfig{
					Host:     cfg.ServerAddress,
					User:     cfg.Username,
					Password: cfg.Password,
					Image:    container.Image.ImageID,
					Pods:     []imagePod{},
				}
			}

			img.Pods = append(img.Pods, j.convertPod(pod))
			images[container.Image.ImageID] = img
		}
	}

	bytes, err := json.Marshal(maps.Values(images))
	if err != nil {
		logrus.WithError(err).Error("Error occurred during config-marshal")
		return nil, err
	}

	suffix := generateObjectSuffix()
	err = j.k8s.CreateJobSecret(podNamespace, suffix, bytes)
	if err != nil {
		logrus.WithError(err).Error("Error occurred during job-secret creation/update")
		return nil, err
	}

	job, err := j.k8s.CreateJob(podNamespace, suffix, j.image, j.imagePullSecret, j.timeout, getJobEnvs())
	if err != nil {
		logrus.WithError(err).Error("Error occurred during job creation/update")
		return nil, err
	}

	logrus.Infof("Created job %s-%s", kubernetes.JobName, suffix)
	return job, nil
}

func (j JobClient) WaitForJob(job *batchv1.Job) bool {
	for {
		job, err := j.k8s.Client.Client.BatchV1().Jobs(job.Namespace).Get(context.Background(), job.Name, meta.GetOptions{})
		if err != nil {
			logrus.WithError(err).Warnf("Error while waiting for job %s.", job.Name)
			return false
		}

		pending := job.Status.Active == 0 && job.Status.Succeeded == 0 && job.Status.Failed == 0
		succeeded := job.Status.Active == 0 && job.Status.Succeeded > 0
		failed := job.Status.Active == 0 && job.Status.Failed > 0

		if !pending && succeeded {
			logrus.Infof("Job succeeded %s", job.Name)
			return true
		} else if !pending && failed {
			logrus.Infof("Job failed %s", job.Name)
			return false
		}

		time.Sleep(10 * time.Second)
	}
}

func generateObjectSuffix() string {
	t := time.Now()
	return t.Format("20060102-150405")
}

func getJobEnvs() map[string]string {
	m := make(map[string]string)
	re := regexp.MustCompile(`SBOM_JOB_(?P<Key>[A-Za-z0-9-_\.]*)=(?P<Value>[A-Za-z0-9-_\.=]*)`)

	for _, v := range os.Environ() {
		matches := re.FindStringSubmatch(v)
		if len(matches) > 1 {
			index := re.SubexpIndex("Key")
			key := matches[index]
			index = re.SubexpIndex("Value")
			m[key] = matches[index]
		}
	}

	return m
}

func (j JobClient) convertPod(pod libk8s.PodInfo) imagePod {
	return imagePod{
		Pod:       pod.PodName,
		Namespace: pod.PodNamespace,
		Cluster:   j.clusterId,
	}
}
