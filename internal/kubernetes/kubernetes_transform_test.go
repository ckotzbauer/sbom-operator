package kubernetes

import (
	"testing"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTransformPodKeepsContainerImages(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "redis", Namespace: "ns",
			Annotations: map[string]string{"a": "b"}, Labels: map[string]string{"app": "redis"},
		},
		Spec: corev1.PodSpec{
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pull"}},
			NodeName:         "node-1",
			Containers: []corev1.Container{{
				Name:  "redis",
				Image: "docker.io/library/redis:7.4.2-alpine@sha256:02419de7eddf55aa5bcf49efb74e88fa8d931b4d77c07eff8a6b2144472b6952",
				Env:   []corev1.EnvVar{{Name: "X", Value: "y"}},
				Args:  []string{"--big"},
			}},
			InitContainers: []corev1.Container{{Name: "init", Image: "busybox:1.37.0", Command: []string{"sh"}}},
			EphemeralContainers: []corev1.EphemeralContainer{{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "alpine:3.22"},
			}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{Name: "redis", Image: "sha256:dc11e3cc", ImageID: "docker.io/library/redis@sha256:02419de7"}},
			Phase:             corev1.PodRunning,
		},
	}

	out, err := transformPod(pod)
	require.NoError(t, err)
	got := out.(*corev1.Pod)

	assert.Equal(t, []corev1.Container{{Name: "redis", Image: pod.Spec.Containers[0].Image}}, got.Spec.Containers)
	assert.Equal(t, []corev1.Container{{Name: "init", Image: "busybox:1.37.0"}}, got.Spec.InitContainers)
	assert.Equal(t, []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "alpine:3.22"}}},
		got.Spec.EphemeralContainers)

	// Kept as before.
	assert.Equal(t, pod.Spec.ImagePullSecrets, got.Spec.ImagePullSecrets)
	assert.Equal(t, pod.Status.ContainerStatuses, got.Status.ContainerStatuses)
	assert.Equal(t, "redis", got.Name)
	assert.Equal(t, pod.Labels, got.Labels)
	assert.Equal(t, pod.Annotations, got.Annotations)

	// Still trimmed.
	assert.Empty(t, got.Spec.NodeName)
	assert.Empty(t, got.Status.Phase)

	// The informer's object is not modified.
	assert.Equal(t, []string{"--big"}, pod.Spec.Containers[0].Args)
}

// On containerd, the status of an image pulled by digest holds the local image ID, so the tag of
// a tag@digest reference only reaches libk8soci through the spec the transform keeps.
func TestTransformPodThenExtractPodInfosKeepsSpecImage(t *testing.T) {
	specImage := "docker.io/library/redis:7.4.2-alpine@sha256:02419de7eddf55aa5bcf49efb74e88fa8d931b4d77c07eff8a6b2144472b6952"
	imageID := "docker.io/library/redis@sha256:02419de7eddf55aa5bcf49efb74e88fa8d931b4d77c07eff8a6b2144472b6952"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "redis", Namespace: "ns"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "redis", Image: specImage}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name:    "redis",
			Image:   "sha256:dc11e3cc3a9fa8e1b6dd7e1b06a3d3d8ae4b5f1c1c9b1a0d2c0e2f2b2a9c8d7e",
			ImageID: imageID,
		}}},
	}

	out, err := transformPod(pod)
	require.NoError(t, err)
	info := (&libk8s.KubeClient{}).ExtractPodInfos(*out.(*corev1.Pod))

	require.Len(t, info.Containers, 1)
	assert.Equal(t, specImage, info.Containers[0].Image.Image)
	assert.Equal(t, imageID, info.Containers[0].Image.ImageID)
}
