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
	Client             *libk8s.KubeClient
	ignoreAnnotations  bool
	fallbackPullSecret []*oci.KubeCreds
}

var (
	AnnotationTemplate = "ckotzbauer.sbom-operator.io/%s"
	/* #nosec */
	jobSecretName = "sbom-operator-job-config"
	JobName       = "sbom-operator-job"
)

func NewClient(ignoreAnnotations bool, fallbackPullSecretName string) *KubeClient {
	client := libk8s.NewClient()

	sbomOperatorNamespace := os.Getenv("POD_NAMESPACE")
	fallbackPullSecret := loadFallbackPullSecret(client, sbomOperatorNamespace, fallbackPullSecretName)
	return &KubeClient{Client: client, ignoreAnnotations: ignoreAnnotations, fallbackPullSecret: fallbackPullSecret}
}

func (client *KubeClient) StartPodInformer(podLabelSelector string, handler cache.ResourceEventHandlerFuncs) (cache.SharedIndexInformer, error) {
	informer := client.Client.CreatePodInformer(podLabelSelector)
	informer.AddEventHandler(handler)
	err := informer.SetTransform(func(x interface{}) (interface{}, error) {
		pod := x.(*corev1.Pod).DeepCopy()
		logrus.Tracef("Transform %s/%s", pod.Namespace, pod.Name)

		return &corev1.Pod{
				ObjectMeta: meta.ObjectMeta{
					Name:        pod.Name,
					Namespace:   pod.Namespace,
					Annotations: pod.Annotations,
					Labels:      pod.Labels,
				},
				Status: corev1.PodStatus{
					InitContainerStatuses:      pod.Status.InitContainerStatuses,
					EphemeralContainerStatuses: pod.Status.EphemeralContainerStatuses,
					ContainerStatuses:          pod.Status.ContainerStatuses,
				},
				Spec: corev1.PodSpec{
					ImagePullSecrets: pod.Spec.ImagePullSecrets,
				},
			},
			nil
	})

	return informer, err
}

func loadFallbackPullSecret(client *libk8s.KubeClient, namespace, name string) []*oci.KubeCreds {
	var fallbackPullSecret []*oci.KubeCreds

	if name != "" {
		if namespace == "" {
			logrus.Debugf("please specify the environment variable 'POD_NAMESPACE' in order to use the fallbackPullSecret")
		} else {
			fallbackPullSecret = client.LoadSecrets(namespace, []corev1.LocalObjectReference{{Name: name}})
		}
	}

	return fallbackPullSecret
}

func (client *KubeClient) InjectPullSecrets(pod libk8s.PodInfo) {
	for _, container := range pod.Containers {
		container.Image.PullSecrets = client.Client.LoadSecrets(pod.PodNamespace, pod.PullSecretNames)

		if client.fallbackPullSecret != nil {
			container.Image.PullSecrets = append(container.Image.PullSecrets, client.fallbackPullSecret...)
		}
	}
}

func (client *KubeClient) LoadImageInfos(namespaces []corev1.Namespace, podLabelSelector string) ([]libk8s.PodInfo, []*oci.RegistryImage) {
	podInfos := client.Client.LoadPodInfos(namespaces, podLabelSelector)
	allImages := make([]*oci.RegistryImage, 0)

	for _, pod := range podInfos {
		for _, container := range pod.Containers {
			allImages = append(allImages, container.Image)
		}
	}

	return podInfos, allImages
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
		ann[fmt.Sprintf(AnnotationTemplate, c.Name)] = c.ImageID
	}

	for _, c := range newPod.Status.InitContainerStatuses {
		ann[fmt.Sprintf(AnnotationTemplate, c.Name)] = c.ImageID
	}

	for _, c := range newPod.Status.EphemeralContainerStatuses {
		ann[fmt.Sprintf(AnnotationTemplate, c.Name)] = c.ImageID
	}

	newPod.Annotations = ann

	_, err = client.Client.Client.CoreV1().Pods(newPod.Namespace).Update(context.Background(), newPod, meta.UpdateOptions{})
	if err != nil {
		logrus.WithError(err).Warnf("Pod %s/%s could not be updated!", newPod.Namespace, newPod.Name)
	}
}

func (client *KubeClient) HasAnnotation(annotations map[string]string, container *libk8s.ContainerInfo) bool {
	if annotations == nil || client.ignoreAnnotations {
		return false
	}

	if val, ok := annotations[fmt.Sprintf(AnnotationTemplate, container.Name)]; ok {
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

func (client *KubeClient) CreateConfigMap(namespace, name, imageId string, data []byte) error {
	cm := corev1.ConfigMap{
		ObjectMeta: meta.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"ckotzbauer.sbom-operator.io": "true",
			},
			Annotations: map[string]string{
				fmt.Sprintf(AnnotationTemplate, "image-id"): imageId,
			},
		},
		BinaryData: map[string][]byte{"sbom": data},
	}

	_, err := client.Client.Client.CoreV1().ConfigMaps(namespace).Create(context.Background(), &cm, meta.CreateOptions{})
	return err
}

func (client *KubeClient) ListConfigMaps() ([]corev1.ConfigMap, error) {
	list, err := client.Client.Client.CoreV1().ConfigMaps("").List(context.Background(), meta.ListOptions{LabelSelector: "ckotzbauer.sbom-operator.io=true"})
	return list.Items, err
}

func (client *KubeClient) DeleteConfigMap(cm corev1.ConfigMap) error {
	return client.Client.Client.CoreV1().ConfigMaps(cm.Namespace).Delete(context.Background(), cm.Name, meta.DeleteOptions{})
}
