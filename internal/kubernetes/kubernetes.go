package kubernetes

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
)

type KubeClient struct {
	Client                *libk8s.KubeClient
	ignoreAnnotations     bool
	fallbackPullSecret    string
	SbomOperatorNamespace string
}

var (
	annotationTemplate = "ckotzbauer.sbom-operator.io/%s"
	/* #nosec */
	jobSecretName = "sbom-operator-job-config"
	JobName       = "sbom-operator-job"
)

func NewClient(ignoreAnnotations bool, fallbackPullSecret string) *KubeClient {
	client := libk8s.NewClient()

	sbomOperatorNamespace := os.Getenv("POD_NAMESPACE")
	return &KubeClient{Client: client, ignoreAnnotations: ignoreAnnotations, fallbackPullSecret: fallbackPullSecret, SbomOperatorNamespace: sbomOperatorNamespace}
}

func (client *KubeClient) StartPodInformer(podLabelSelector string, handler cache.ResourceEventHandlerFuncs) cache.SharedIndexInformer {
	fallbackPullSecret := client.loadFallbackPullSecret()
	informer := client.Client.CreatePodInformer(podLabelSelector)
	informer.AddEventHandler(handler)
	informer.SetTransform(func(x interface{}) (interface{}, error) {
		pod := x.(corev1.Pod)
		containers := client.Client.ExtractContainerInfos(pod)
		if fallbackPullSecret != nil {
			for _, c := range containers {
				c.Image.PullSecrets = append(c.Image.PullSecrets, fallbackPullSecret...)
			}
		}

		return libk8s.PodInfo{Containers: containers, PodName: pod.Name, PodNamespace: pod.Namespace, Annotations: pod.Annotations}, nil
	})

	return informer
}

func (client *KubeClient) loadFallbackPullSecret() []oci.KubeCreds {
	var fallbackPullSecret []oci.KubeCreds

	if client.fallbackPullSecret != "" {
		if client.SbomOperatorNamespace == "" {
			logrus.Debugf("please specify the environment variable 'POD_NAMESPACE' in order to use the fallbackPullSecret")
		} else {
			fallbackPullSecret = client.Client.LoadSecrets(client.SbomOperatorNamespace, []corev1.LocalObjectReference{{Name: client.fallbackPullSecret}})
		}
	}

	return fallbackPullSecret
}

func (client *KubeClient) LoadImageInfos(namespaces []corev1.Namespace, podLabelSelector string) ([]libk8s.PodInfo, []oci.RegistryImage) {
	fallbackPullSecret := client.loadFallbackPullSecret()
	podInfos := client.Client.LoadPodInfos(namespaces, podLabelSelector)
	filteredPodInfos := make([]libk8s.PodInfo, 0)
	allImages := make([]oci.RegistryImage, 0)

	for _, pod := range podInfos {
		imageMap := make(map[string]bool, 0)
		filteredContainers := make([]libk8s.ContainerInfo, 0)

		for _, container := range pod.Containers {
			allImages = append(allImages, container.Image)

			if fallbackPullSecret != nil {
				container.Image.PullSecrets = append(container.Image.PullSecrets, fallbackPullSecret...)
			}

			if client.hasAnnotation(pod.Annotations, container) {
				logrus.Debugf("Skip image %s", container.Image.ImageID)
			} else {
				_, ok := imageMap[container.Image.ImageID]
				if !ok {
					filteredContainers = append(filteredContainers, container)
					imageMap[container.Image.ImageID] = true
				}
			}
		}

		if len(filteredContainers) > 0 {
			filteredPodInfos = append(filteredPodInfos, libk8s.PodInfo{
				Containers:   filteredContainers,
				PodName:      pod.PodName,
				PodNamespace: pod.PodNamespace,
				Annotations:  pod.Annotations,
			})
		}
	}

	return filteredPodInfos, allImages
}

func (client *KubeClient) UpdatePodAnnotation(pod libk8s.PodInfo) {
	newPod, err := client.Client.Client.CoreV1().Pods(pod.PodNamespace).Get(context.Background(), pod.PodName, meta.GetOptions{})

	if err != nil {
		if !errors.IsNotFound(err) {
			logrus.WithError(err).Errorf("Pod %s/%s could not be fetched!", pod.PodNamespace, pod.PodName)
		}

		return
	}

	ann := newPod.Annotations
	if ann == nil {
		ann = make(map[string]string)
	}

	for _, c := range newPod.Status.ContainerStatuses {
		ann[fmt.Sprintf(annotationTemplate, c.Name)] = c.ImageID
	}

	for _, c := range newPod.Status.InitContainerStatuses {
		ann[fmt.Sprintf(annotationTemplate, c.Name)] = c.ImageID
	}

	for _, c := range newPod.Status.EphemeralContainerStatuses {
		ann[fmt.Sprintf(annotationTemplate, c.Name)] = c.ImageID
	}

	newPod.Annotations = ann

	_, err = client.Client.Client.CoreV1().Pods(newPod.Namespace).Update(context.Background(), newPod, meta.UpdateOptions{})
	if err != nil {
		logrus.WithError(err).Errorf("Pod %s/%s could not be updated!", newPod.Namespace, newPod.Name)
	}
}

func (client *KubeClient) hasAnnotation(annotations map[string]string, container libk8s.ContainerInfo) bool {
	if annotations == nil || client.ignoreAnnotations {
		return false
	}

	if val, ok := annotations[fmt.Sprintf(annotationTemplate, container.Name)]; ok {
		return val == container.Image.ImageID
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
