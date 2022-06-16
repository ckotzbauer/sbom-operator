package kubernetes

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
)

type KubeClient struct {
	Client                *libk8s.KubeClient
	ignoreAnnotations     bool
	SbomOperatorNamespace string
}

var (
	annotationTemplate = "ckotzbauer.sbom-operator.io/%s"
	jobSecretName      = "sbom-operator-job-config"
	JobName            = "sbom-operator-job"
)

func NewClient(ignoreAnnotations bool) *KubeClient {
	client := libk8s.NewClient()

	sbomOperatorNamespace := os.Getenv("POD_NAMESPACE")
	return &KubeClient{Client: client, ignoreAnnotations: ignoreAnnotations, SbomOperatorNamespace: sbomOperatorNamespace}
}

func (client *KubeClient) LoadImageInfos(namespaces []corev1.Namespace, podLabelSelector string) ([]libk8s.KubeImage, map[string]libk8s.KubeImage) {
	fallbackPullSecretName := viper.GetString(internal.ConfigKeyFallbackPullSecret)
	var fallbackPullSecret []oci.KubeCreds

	if fallbackPullSecretName != "" {
		if client.SbomOperatorNamespace == "" {
			logrus.Debugf("please specify the environment variable 'POD_NAMESPACE' in order to use the fallbackPullSecret")
		} else {
			fallbackPullSecret = client.Client.LoadSecrets(client.SbomOperatorNamespace, []corev1.LocalObjectReference{{Name: fallbackPullSecretName}})
		}
	}

	allImages := client.Client.LoadImageInfos(namespaces, podLabelSelector)
	imagesToProcess := make([]libk8s.KubeImage, 0)

	for _, img := range allImages {
		if fallbackPullSecret != nil {
			img.Image.PullSecrets = append(img.Image.PullSecrets, fallbackPullSecret...)
		}

		annotationFound := false
		for _, pod := range img.Pods {
			containers := getContainerStatuses(pod, img.Image.ImageID)
			for _, c := range containers {
				x := client.hasAnnotation(pod.Annotations, c)
				if x {
					annotationFound = true
					break
				}
			}

			if annotationFound {
				break
			}
		}

		if !annotationFound {
			imagesToProcess = append(imagesToProcess, img)
		} else {
			logrus.Debugf("Skip image %s", img.Image.ImageID)
		}
	}

	return imagesToProcess, allImages
}

func getContainerStatuses(pod corev1.Pod, imageID string) []corev1.ContainerStatus {
	found := make([]corev1.ContainerStatus, 0)

	statuses := []corev1.ContainerStatus{}
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	statuses = append(statuses, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)

	for _, s := range statuses {
		if s.ImageID == imageID {
			found = append(found, s)
		}
	}

	return found
}

func (client *KubeClient) UpdatePodAnnotation(pod corev1.Pod) {
	newPod, err := client.Client.Client.CoreV1().Pods(pod.Namespace).Get(context.Background(), pod.Name, meta.GetOptions{})

	if err != nil {
		if !errors.IsNotFound(err) {
			logrus.WithError(err).Errorf("Pod %s/%s could not be fetched!", pod.Namespace, pod.Name)
		}

		return
	}

	ann := newPod.Annotations
	if ann == nil {
		ann = make(map[string]string)
	}

	for _, c := range pod.Status.ContainerStatuses {
		ann[fmt.Sprintf(annotationTemplate, c.Name)] = c.ImageID
	}

	for _, c := range pod.Status.InitContainerStatuses {
		ann[fmt.Sprintf(annotationTemplate, c.Name)] = c.ImageID
	}

	for _, c := range pod.Status.EphemeralContainerStatuses {
		ann[fmt.Sprintf(annotationTemplate, c.Name)] = c.ImageID
	}

	newPod.Annotations = ann

	_, err = client.Client.Client.CoreV1().Pods(newPod.Namespace).Update(context.Background(), newPod, meta.UpdateOptions{})
	if err != nil {
		logrus.WithError(err).Errorf("Pod %s/%s could not be updated!", pod.Namespace, pod.Name)
	}
}

func (client *KubeClient) hasAnnotation(annotations map[string]string, status corev1.ContainerStatus) bool {
	if annotations == nil || client.ignoreAnnotations {
		return false
	}

	if val, ok := annotations[fmt.Sprintf(annotationTemplate, status.Name)]; ok {
		return val == status.ImageID
	}

	return false
}

func (client *KubeClient) CreateJobSecret(namespace, suffix string, data []byte) error {
	m := make(map[string][]byte)
	m["image-config.json"] = data
	vTrue := true
	vFalse := false

	s := &corev1.Secret{
		ObjectMeta: meta.ObjectMeta{
			Namespace: namespace,
			Name:      fmt.Sprintf("%s-%s", jobSecretName, suffix),
			OwnerReferences: []meta.OwnerReference{
				{
					APIVersion:         "v1",
					Kind:               "Pod",
					Name:               os.Getenv("POD_NAME"),
					UID:                types.UID(os.Getenv("POD_UID")),
					BlockOwnerDeletion: &vTrue,
					Controller:         &vFalse,
				},
			},
		},
		Data: m,
	}

	_, err := client.Client.Client.CoreV1().Secrets(namespace).Create(context.Background(), s, meta.CreateOptions{})
	return err
}

func (client *KubeClient) CreateJob(namespace, suffix, image, pullSecrets string, timeout int64, envs map[string]string) (*batchv1.Job, error) {
	backoffLimit := int32(0)
	vTrue := true
	vFalse := false

	j := &batchv1.Job{
		ObjectMeta: meta.ObjectMeta{
			Namespace: namespace,
			Name:      fmt.Sprintf("%s-%s", JobName, suffix),
			OwnerReferences: []meta.OwnerReference{
				{
					APIVersion:         "v1",
					Kind:               "Pod",
					Name:               os.Getenv("POD_NAME"),
					UID:                types.UID(os.Getenv("POD_UID")),
					BlockOwnerDeletion: &vTrue,
					Controller:         &vFalse,
				},
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          &backoffLimit,
			ActiveDeadlineSeconds: &timeout,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Name: JobName,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "sbom",
							Image: image,
							Env:   mapToEnvVars(envs),
							SecurityContext: &corev1.SecurityContext{
								Privileged: &vTrue,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "config",
									MountPath: "/sbom",
								},
							},
						},
					},
					RestartPolicy:    corev1.RestartPolicyNever,
					ImagePullSecrets: createPullSecrets(pullSecrets),
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: fmt.Sprintf("%s-%s", jobSecretName, suffix),
								},
							},
						},
					},
				},
			},
		},
	}

	return client.Client.Client.BatchV1().Jobs(namespace).Create(context.Background(), j, meta.CreateOptions{})
}

func createPullSecrets(name string) []corev1.LocalObjectReference {
	refs := make([]corev1.LocalObjectReference, 0)

	if name != "" {
		refs = append(refs, corev1.LocalObjectReference{Name: name})
	}

	return refs
}

func mapToEnvVars(m map[string]string) []corev1.EnvVar {
	vars := make([]corev1.EnvVar, 0)
	for k, v := range m {
		vars = append(vars, corev1.EnvVar{Name: k, Value: v})
	}

	return vars
}
