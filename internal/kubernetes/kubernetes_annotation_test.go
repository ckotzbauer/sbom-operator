package kubernetes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestNormalizeImageID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{input: "docker-pullable://repo@sha256:abc", expected: "repo@sha256:abc"},
		{input: "sha256:abc", expected: "sha256:abc"},
		{input: "docker://sha256:abc", expected: "sha256:abc"},
		{input: "", expected: ""},
	}

	for _, v := range tests {
		assert.Equal(t, v.expected, normalizeImageID(v.input), "input %q", v.input)
	}
}

func TestHasAnnotation(t *testing.T) {
	k := &KubeClient{}
	container := &libk8s.ContainerInfo{Name: "c1", Image: &oci.RegistryImage{ImageID: "repo@sha256:abc"}}

	t.Run("raw docker-pullable annotation matches", func(t *testing.T) {
		ann := map[string]string{"ckotzbauer.sbom-operator.io/c1": "docker-pullable://repo@sha256:abc"}
		assert.True(t, k.HasAnnotation(ann, container))
	})

	t.Run("normalized annotation matches", func(t *testing.T) {
		ann := map[string]string{"ckotzbauer.sbom-operator.io/c1": "repo@sha256:abc"}
		assert.True(t, k.HasAnnotation(ann, container))
	})

	t.Run("different image does not match", func(t *testing.T) {
		ann := map[string]string{"ckotzbauer.sbom-operator.io/c1": "sha256:other"}
		assert.False(t, k.HasAnnotation(ann, container))
	})

	t.Run("missing annotation does not match", func(t *testing.T) {
		assert.False(t, k.HasAnnotation(nil, container))
	})
}

func TestUpdatePodAnnotationNormalizesImageID(t *testing.T) {
	var updated corev1.Pod
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "app-pod-1", Namespace: "prod"},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{Name: "c1", ImageID: "docker-pullable://repo@sha256:abc"},
						{Name: "c2", ImageID: "docker-pullable://repo@sha256:def"},
					},
				},
			})
		case http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&updated)
			_ = json.NewEncoder(w).Encode(&updated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	clientset, err := k8s.NewForConfig(&rest.Config{
		Host:          ts.URL,
		ContentConfig: rest.ContentConfig{ContentType: "application/json"},
	})
	require.NoError(t, err)
	k := &KubeClient{Client: &libk8s.KubeClient{Client: clientset}}

	t.Run("only the named containers are annotated", func(t *testing.T) {
		updated = corev1.Pod{}
		err = k.updatePodAnnotation(libk8s.PodInfo{PodName: "app-pod-1", PodNamespace: "prod"}, []string{"c1"})
		require.NoError(t, err)
		assert.Equal(t, "repo@sha256:abc", updated.Annotations["ckotzbauer.sbom-operator.io/c1"])
		_, ok := updated.Annotations["ckotzbauer.sbom-operator.io/c2"]
		assert.False(t, ok, "c2 must not be annotated when not listed")
	})

	t.Run("all containers are annotated when all are named", func(t *testing.T) {
		updated = corev1.Pod{}
		err = k.updatePodAnnotation(libk8s.PodInfo{PodName: "app-pod-1", PodNamespace: "prod"}, []string{"c1", "c2"})
		require.NoError(t, err)
		assert.Equal(t, "repo@sha256:abc", updated.Annotations["ckotzbauer.sbom-operator.io/c1"])
		assert.Equal(t, "repo@sha256:def", updated.Annotations["ckotzbauer.sbom-operator.io/c2"])
	})
}
