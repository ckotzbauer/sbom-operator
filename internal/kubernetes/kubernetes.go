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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ckotzbauer/sbom-operator/internal"
)

type KubeCreds struct {
	SecretName      string
	SecretCredsData []byte
	IsLegacySecret  bool
}

type ContainerImage struct {
	Image       string
	ImageID     string
	Pods        []corev1.Pod
	PullSecrets []KubeCreds
}

type KubeClient struct {
	Client                *kubernetes.Clientset
	ignoreAnnotations     bool
	SbomOperatorNamespace string
}

var (
	annotationTemplate = "ckotzbauer.sbom-operator.io/%s"
	jobSecretName      = "sbom-operator-job-config"
	JobName            = "sbom-operator-job"
)

func NewClient(ignoreAnnotations bool) *KubeClient {
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

	sbomOperatorNamespace := os.Getenv("POD_NAMESPACE")
	return &KubeClient{Client: client, ignoreAnnotations: ignoreAnnotations, SbomOperatorNamespace: sbomOperatorNamespace}
}

func prepareLabelSelector(selector string) meta.ListOptions {
	listOptions := meta.ListOptions{}

	if len(selector) > 0 {
		listOptions.LabelSelector = internal.Unescape(selector)
		logrus.Tracef("Applied labelSelector %v", listOptions.LabelSelector)
	}

	return listOptions
}

func (client *KubeClient) ListNamespaces(labelSelector string) ([]corev1.Namespace, error) {
	list, err := client.Client.CoreV1().Namespaces().List(context.Background(), prepareLabelSelector(labelSelector))

	if err != nil {
		return []corev1.Namespace{}, fmt.Errorf("failed to list namespaces: %w", err)
	}

	return list.Items, nil
}

func (client *KubeClient) listPods(namespace, labelSelector string) ([]corev1.Pod, error) {
	list, err := client.Client.CoreV1().Pods(namespace).List(context.Background(), prepareLabelSelector(labelSelector))

	if err != nil {
		return []corev1.Pod{}, fmt.Errorf("failed to list pods: %w", err)
	}

	return list.Items, nil
}

func (client *KubeClient) LoadImageInfos(namespaces []corev1.Namespace, podLabelSelector string) (map[string]ContainerImage, []ContainerImage) {
	images := map[string]ContainerImage{}
	allImages := []ContainerImage{}

	for _, ns := range namespaces {
		pods, err := client.listPods(ns.Name, podLabelSelector)
		if err != nil {
			logrus.WithError(err).Errorf("failed to list pods for namespace: %s", ns.Name)
			continue
		}

		for _, pod := range pods {
			allImageCreds := []KubeCreds{}

			annotations := pod.Annotations
			statuses := []corev1.ContainerStatus{}
			statuses = append(statuses, pod.Status.ContainerStatuses...)
			statuses = append(statuses, pod.Status.InitContainerStatuses...)
			statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)

			allImageCreds = client.loadSecrets(pod.Namespace, pod.Spec.ImagePullSecrets)

			fallbackPullSecretName := viper.GetString(internal.ConfigKeyFallbackPullSecret)
			if fallbackPullSecretName != "" {
				if client.SbomOperatorNamespace == "" {
					logrus.Debugf("please specify the environment variable 'POD_NAMESPACE' in order to use the fallbackPullSecret")
				} else {
					fallbackPullSecret := client.loadSecrets(client.SbomOperatorNamespace, []corev1.LocalObjectReference{{Name: fallbackPullSecretName}})
					allImageCreds = append(allImageCreds, fallbackPullSecret...)
				}
			}

			for _, c := range statuses {
				if c.ImageID != "" {
					imageIDSlice := strings.Split(c.ImageID, "://")
					trimmedImageID := imageIDSlice[len(imageIDSlice)-1]

					if !client.hasAnnotation(annotations, c) {
						img, ok := images[trimmedImageID]
						if !ok {
							img = ContainerImage{
								Image:       c.Image,
								ImageID:     trimmedImageID,
								Pods:        []corev1.Pod{},
								PullSecrets: allImageCreds,
							}
						}

						img.Pods = append(img.Pods, pod)
						images[trimmedImageID] = img
						allImages = append(allImages, img)
					} else {
						logrus.Debugf("Skip image %s", trimmedImageID)
						allImages = append(allImages, ContainerImage{
							Image:       c.Image,
							ImageID:     trimmedImageID,
							Pods:        []corev1.Pod{},
							PullSecrets: allImageCreds,
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

func (client *KubeClient) loadSecrets(namespace string, secrets []corev1.LocalObjectReference) []KubeCreds {
	allImageCreds := []KubeCreds{}

	for _, s := range secrets {
		secret, err := client.Client.CoreV1().Secrets(namespace).Get(context.Background(), s.Name, meta.GetOptions{})
		if err != nil {
			logrus.WithError(err).Errorf("Could not load secret: %s/%s", namespace, s.Name)
			continue
		}

		var creds []byte
		legacy := false
		name := secret.Name

		if secret.Type == corev1.SecretTypeDockerConfigJson {
			creds = secret.Data[corev1.DockerConfigJsonKey]
		} else if secret.Type == corev1.SecretTypeDockercfg {
			creds = secret.Data[corev1.DockerConfigKey]
			legacy = true
		} else {
			logrus.WithError(err).Errorf("invalid secret-type %s for pullSecret %s/%s", secret.Type, secret.Namespace, secret.Name)
		}

		if len(creds) > 0 {
			allImageCreds = append(allImageCreds, KubeCreds{SecretName: name, SecretCredsData: creds, IsLegacySecret: legacy})
		}
	}

	return allImageCreds
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
