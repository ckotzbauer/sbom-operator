package kubernetes

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ckotzbauer/sbom-operator/internal"
)

type ContainerImage struct {
	Image   string
	ImageID string
	Auth    []byte
	Pods    []corev1.Pod
}

type KubeClient struct {
	Client            *kubernetes.Clientset
	ignoreAnnotations bool
}

var (
	annotationTemplate = "ckotzbauer.sbom-operator.io/%s"
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

func (client *KubeClient) LoadImageInfos(namespaces []corev1.Namespace, podLabelSelector string) (map[string]ContainerImage, []string) {
	images := map[string]ContainerImage{}
	allImages := []string{}

	for _, ns := range namespaces {
		pods := client.listPods(ns.Name, podLabelSelector)

		for _, pod := range pods {
			annotations := pod.Annotations
			statuses := []corev1.ContainerStatus{}
			statuses = append(statuses, pod.Status.ContainerStatuses...)
			statuses = append(statuses, pod.Status.InitContainerStatuses...)
			statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)

			pullSecrets, err := client.loadSecrets(pod.Namespace, pod.Spec.ImagePullSecrets)

			if err != nil {
				logrus.WithError(err).Errorf("PullSecrets could not be retrieved for pod %s/%s", ns.Name, pod.Name)
				continue
			}

			for _, c := range statuses {
				if c.ImageID != "" {
					if !client.hasAnnotation(annotations, c) {
						img, ok := images[c.ImageID]
						if !ok {
							img = ContainerImage{Image: c.Image, ImageID: c.ImageID, Auth: pullSecrets, Pods: []corev1.Pod{}}
						}

						img.Pods = append(img.Pods, pod)
						images[c.ImageID] = img
					} else {
						logrus.Debugf("Skip image %s", c.ImageID)
					}

					allImages = append(allImages, c.ImageID)
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

func (client *KubeClient) loadSecrets(namespace string, secrets []corev1.LocalObjectReference) ([]byte, error) {
	// TODO: Support all secrets which are referenced as imagePullSecrets instead of only the first one.
	for _, s := range secrets {
		secret, err := client.Client.CoreV1().Secrets(namespace).Get(context.Background(), s.Name, meta.GetOptions{})
		if err != nil {
			return nil, err
		}

		creds := secret.Data[corev1.DockerConfigJsonKey]

		if len(creds) > 0 {
			return creds, nil
		}
	}

	return nil, nil
}
