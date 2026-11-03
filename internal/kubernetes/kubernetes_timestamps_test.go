package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func newTestKubeClient(t *testing.T, handler http.HandlerFunc) (*KubeClient, func()) {
	t.Helper()
	ts := httptest.NewServer(handler)
	clientset, err := k8s.NewForConfig(&rest.Config{Host: ts.URL})
	require.NoError(t, err)

	return &KubeClient{
		Client: &libk8s.KubeClient{
			Client: clientset,
		},
	}, ts.Close
}

func TestResolvePodTimestamps(t *testing.T) {
	ctx := context.Background()
	rsCreationTime := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	podCreationTime := time.Date(2026, 10, 15, 12, 30, 0, 0, time.UTC)

	t.Run("1. Nil KubeClient falls back to current time", func(t *testing.T) {
		var k *KubeClient
		before := time.Now().UTC().Add(-time.Second)
		rsTime, podTime := k.ResolvePodTimestamps(ctx, libk8s.PodInfo{PodName: "p", PodNamespace: "ns"})
		assert.True(t, rsTime.After(before))
		assert.Equal(t, rsTime, podTime)
	})

	t.Run("2. Empty PodName or PodNamespace falls back to current time", func(t *testing.T) {
		k, closeServer := newTestKubeClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		defer closeServer()

		before := time.Now().UTC().Add(-time.Second)
		rsTime, podTime := k.ResolvePodTimestamps(ctx, libk8s.PodInfo{PodName: "", PodNamespace: "default"})
		assert.True(t, rsTime.After(before))
		assert.Equal(t, rsTime, podTime)
	})

	t.Run("3. Pod not found in API falls back to current time", func(t *testing.T) {
		k, closeServer := newTestKubeClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		defer closeServer()

		before := time.Now().UTC().Add(-time.Second)
		rsTime, podTime := k.ResolvePodTimestamps(ctx, libk8s.PodInfo{PodName: "missing", PodNamespace: "default"})
		assert.True(t, rsTime.After(before))
		assert.Equal(t, rsTime, podTime)
	})

	t.Run("4. Pod with owning ReplicaSet returns ReplicaSet and Pod timestamps", func(t *testing.T) {
		k, closeServer := newTestKubeClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/api/v1/namespaces/prod/pods/app-pod-1":
				_ = json.NewEncoder(w).Encode(&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "app-pod-1",
						Namespace:         "prod",
						CreationTimestamp: metav1.NewTime(podCreationTime),
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "ReplicaSet", Name: "app-rs"},
						},
					},
				})
			case "/apis/apps/v1/namespaces/prod/replicasets/app-rs":
				_ = json.NewEncoder(w).Encode(&appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "app-rs",
						Namespace:         "prod",
						CreationTimestamp: metav1.NewTime(rsCreationTime),
					},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})
		defer closeServer()

		rsTime, podTime := k.ResolvePodTimestamps(ctx, libk8s.PodInfo{PodName: "app-pod-1", PodNamespace: "prod"})
		assert.Equal(t, rsCreationTime, rsTime)
		assert.Equal(t, podCreationTime, podTime)
	})

	t.Run("5. Pod with missing ReplicaSet falls back to Pod CreationTimestamp", func(t *testing.T) {
		k, closeServer := newTestKubeClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/v1/namespaces/prod/pods/app-pod-2" {
				_ = json.NewEncoder(w).Encode(&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "app-pod-2",
						Namespace:         "prod",
						CreationTimestamp: metav1.NewTime(podCreationTime),
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "ReplicaSet", Name: "deleted-rs"},
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
		defer closeServer()

		rsTime, podTime := k.ResolvePodTimestamps(ctx, libk8s.PodInfo{PodName: "app-pod-2", PodNamespace: "prod"})
		assert.Equal(t, podCreationTime, rsTime)
		assert.Equal(t, podCreationTime, podTime)
	})

	t.Run("6. Pod without CreationTimestamp uses Status.StartTime", func(t *testing.T) {
		startTime := metav1.NewTime(podCreationTime)
		k, closeServer := newTestKubeClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-pod-3",
					Namespace: "prod",
				},
				Status: corev1.PodStatus{
					StartTime: &startTime,
				},
			})
		})
		defer closeServer()

		rsTime, podTime := k.ResolvePodTimestamps(ctx, libk8s.PodInfo{PodName: "app-pod-3", PodNamespace: "prod"})
		assert.Equal(t, podCreationTime, rsTime)
		assert.Equal(t, podCreationTime, podTime)
	})
}
