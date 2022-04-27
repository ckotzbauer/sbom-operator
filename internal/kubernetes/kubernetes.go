package kubernetes

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ckotzbauer/sbom-operator/internal"
)

type ContainerImage struct {
	Image      string
	ImageID    string
	Auth       []byte
	LegacyAuth bool
	Pods       []corev1.Pod
}

type KubeClient struct {
	Client            *kubernetes.Clientset
	ignoreAnnotations bool
}

var (
	annotationTemplate = "ckotzbauer.sbom-operator.io/%s"
	jobSecretName      = "sbom-operator-job-config"
	JobName            = "sbom-operator-job"
)

func NewClient() *KubeClient {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		logrus.WithError(err).Fatal("kubeconfig file could not be found!")
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		logrus.WithError(err).Fatal("Could not create Kubernetes client from config!")
	}

	return &KubeClient{Client: client, ignoreAnnotations: viper.GetBool(internal.ConfigKeyIgnoreAnnotations)}
}

func prepareLabelSelector(selector string) meta.ListOptions {
	listOptions := meta.ListOptions{}

	if len(selector) > 0 {
		listOptions.LabelSelector = internal.Unescape(selector)
		logrus.Tracef("Applied labelSelector %v", listOptions.LabelSelector)
	}

	return listOptions
}

func (client *KubeClient) ListNamespaces(labelSelector string) []corev1.Namespace {
	list, err := client.Client.CoreV1().Namespaces().List(context.Background(), prepareLabelSelector(labelSelector))

	if err != nil {
		logrus.WithError(err).Error("ListNamespaces errored!")
		return []corev1.Namespace{}
	}

	return list.Items
}

func (client *KubeClient) listPods(namespace, labelSelector string) []corev1.Pod {
	list, err := client.Client.CoreV1().Pods(namespace).List(context.Background(), prepareLabelSelector(labelSelector))

	if err != nil {
		logrus.WithError(err).Error("ListPods errored!")
		return []corev1.Pod{}
	}

	return list.Items
}

func (client *KubeClient) LoadImageInfos(namespaces []corev1.Namespace, podLabelSelector string) (map[string]ContainerImage, []ContainerImage) {
	images := map[string]ContainerImage{}
	allImages := []ContainerImage{}

	for _, ns := range namespaces {
		pods := client.listPods(ns.Name, podLabelSelector)

		for _, pod := range pods {
			annotations := pod.Annotations
			statuses := []corev1.ContainerStatus{}
			statuses = append(statuses, pod.Status.ContainerStatuses...)
			statuses = append(statuses, pod.Status.InitContainerStatuses...)
			statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)

			pullSecrets, legacy, err := client.loadSecrets(pod.Namespace, pod.Spec.ImagePullSecrets)

			if err != nil {
				logrus.WithError(err).Errorf("PullSecrets could not be retrieved for pod %s/%s", ns.Name, pod.Name)
				continue
			}

			for _, c := range statuses {
				if c.ImageID != "" {
					imageIDSlice := strings.Split(c.ImageID, "://")
					trimmedImageID := imageIDSlice[len(imageIDSlice)-1]

					if !client.hasAnnotation(annotations, c) {
						img, ok := images[trimmedImageID]
						if !ok {
							img = ContainerImage{
								Image:      c.Image,
								ImageID:    trimmedImageID,
								Auth:       pullSecrets,
								LegacyAuth: legacy,
								Pods:       []corev1.Pod{},
							}
						}

						img.Pods = append(img.Pods, pod)
						images[trimmedImageID] = img
						allImages = append(allImages, img)
					} else {
						logrus.Debugf("Skip image %s", trimmedImageID)
						allImages = append(allImages, ContainerImage{
							Image:      c.Image,
							ImageID:    trimmedImageID,
							Auth:       pullSecrets,
							LegacyAuth: legacy,
							Pods:       []corev1.Pod{},
						})
					}
				}
			}
		}
	}

	return images, allImages
}

func (client *KubeClient) UpdatePodAnnotation(pod corev1.Pod) {
	newPod, err := client.Client.CoreV1().Pods(pod.Namespace).Get(context.Background(), pod.Name, meta.GetOptions{})

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

	_, err = client.Client.CoreV1().Pods(newPod.Namespace).Update(context.Background(), newPod, meta.UpdateOptions{})
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

func (client *KubeClient) loadSecrets(namespace string, secrets []corev1.LocalObjectReference) ([]byte, bool, error) {
	// TODO: Support all secrets which are referenced as imagePullSecrets instead of only the first one.
	for _, s := range secrets {
		secret, err := client.Client.CoreV1().Secrets(namespace).Get(context.Background(), s.Name, meta.GetOptions{})
		if err != nil {
			return nil, false, err
		}

		var creds []byte
		legacy := false

		if secret.Type == corev1.SecretTypeDockerConfigJson {
			creds = secret.Data[corev1.DockerConfigJsonKey]
		} else if secret.Type == corev1.SecretTypeDockercfg {
			creds = secret.Data[corev1.DockerConfigKey]
			legacy = true
		} else {
			return nil, false, fmt.Errorf("invalid secret-type %s for pullSecret %s/%s", secret.Type, secret.Namespace, secret.Name)
		}

		if len(creds) > 0 {
			return creds, legacy, nil
		}
	}

	return nil, false, nil
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

	_, err := client.Client.CoreV1().Secrets(namespace).Create(context.Background(), s, meta.CreateOptions{})
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

	return client.Client.BatchV1().Jobs(namespace).Create(context.Background(), j, meta.CreateOptions{})
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
