package kubernetes

import (
	"context"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ckotzbauer/sbom-git-operator/internal"
)

type ImageDigest struct {
	Digest string
	Auth   []byte
}

type KubeClient struct {
	Client *kubernetes.Clientset
}

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

	return &KubeClient{Client: client}
}

func prepareLabelSelector(selector string) meta.ListOptions {
	listOptions := meta.ListOptions{}

	if len(selector) > 0 {
		listOptions.LabelSelector = internal.Unescape(selector)
		logrus.Debugf("Applied labelSelector %v", listOptions.LabelSelector)
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

func (client *KubeClient) ListPods(namespace, labelSelector string) []corev1.Pod {
	list, err := client.Client.CoreV1().Pods(namespace).List(context.Background(), prepareLabelSelector(labelSelector))

	if err != nil {
		logrus.WithError(err).Error("ListPods errored!")
		return []corev1.Pod{}
	}

	return list.Items
}

func (client *KubeClient) GetContainerDigests(pods []corev1.Pod) []ImageDigest {
	digests := []ImageDigest{}

	for _, p := range pods {
		pullSecrets, err := client.loadSecrets(p.Namespace, p.Spec.ImagePullSecrets)

		if err != nil {
			logrus.WithError(err).Error("PullSecrets could not be retrieved!")
			return []ImageDigest{}
		}

		for _, c := range p.Status.ContainerStatuses {
			digests = append(digests, ImageDigest{Digest: c.ImageID, Auth: pullSecrets})
		}

		for _, c := range p.Status.InitContainerStatuses {
			digests = append(digests, ImageDigest{Digest: c.ImageID, Auth: pullSecrets})
		}

		for _, c := range p.Status.EphemeralContainerStatuses {
			digests = append(digests, ImageDigest{Digest: c.ImageID, Auth: pullSecrets})
		}
	}

	return removeDuplicateValues(digests)
}

func removeDuplicateValues(slice []ImageDigest) []ImageDigest {
	keys := make(map[string]bool)
	list := []ImageDigest{}

	for _, entry := range slice {
		if _, value := keys[entry.Digest]; !value {
			keys[entry.Digest] = true
			list = append(list, entry)
		}
	}
	return list
}

func (client *KubeClient) loadSecrets(namespace string, secrets []corev1.LocalObjectReference) ([]byte, error) {
	// TODO: Support all secrets which are referenced as imagePullSecrets instead of only the first one.
	for _, s := range secrets {
		secret, err := client.Client.CoreV1().Secrets(namespace).Get(context.Background(), s.Name, meta.GetOptions{})
		if err != nil {
			return nil, err
		}

		creds := secret.Data[".dockerconfigjson"]

		if len(creds) > 0 {
			return creds, nil
		}
	}

	return nil, nil
}
