package dtrack

import (
	"net/http"
	"net/http/httptest"
	"testing"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadImages_NamespaceMode verifies that in isNamespaceMode()
// the namespace is parsed correctly form kubernetes-cluster tag (<clusterId>/<namespace>).
func TestLoadImages_NamespaceMode(t *testing.T) {
	projectUUID := uuid.New()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if r.URL.Path == "/api/v1/project" {
			// Project contains the cluster tag incl. namespace "production"
			_, _ = w.Write([]byte(`[{
				"uuid": "` + projectUUID.String() + `",
				"name": "alpine",
				"version": "3.14",
				"active": true,
				"tags": [
					{"name": "kubernetes-cluster=my-cluster/production"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine@sha256:111"}
				]}]`))
			return
		}
		if r.URL.Path == "/api/v1/version" {
			_, _ = w.Write([]byte(`{"version": "4.8.0"}`))
			return
		}
		_, _ = w.Write([]byte(`{"totalCount": "1"}`))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag-namespace", "", "", "", true, false, "")
	err := g.Initialize()
	require.NoError(t, err)

	images, err := g.LoadImages()
	require.NoError(t, err)

	// Check if image was loaded with correct namespace
	require.Len(t, images, 1)
	assert.Equal(t, "alpine@sha256:111", images[0].ImageID)
	assert.Equal(t, "production", images[0].Namespace)

	// Check if cache for this namespace was filled (imageProjectMap)
	nsMap, exists := g.imageProjectMap["alpine@sha256:111"]
	require.True(t, exists)
	assert.Contains(t, nsMap["production"], projectUUID)
}

// TestHandleProjectDeactivation_NamespaceMode verifies that in isNamespaceMode()
// the deletion of one images in a namespace only deletes the specific clusterId/namespace tag
// while other namespaces or clusters remains untouched.
func TestHandleProjectDeactivation_NamespaceMode(t *testing.T) {
	projectUUID := uuid.New()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut && r.URL.Path == "/api/v1/project/"+projectUUID.String() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"uuid": "` + projectUUID.String() + `"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"totalCount": "1"}`))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "cluster-A", "tag-namespace", "", "", "", true, false, "")
	err := g.Initialize()
	require.NoError(t, err)

	// Simulated DT-project with Tags for two different namespaces (in same cluster)
	project := &dtrack.Project{
		UUID:    projectUUID,
		Name:    "shared-app",
		Version: "1.0",
		Active:  true,
		Tags: []dtrack.Tag{
			{Name: "kubernetes-cluster=cluster-A/ns-staging"},
			{Name: "kubernetes-cluster=cluster-A/ns-production"},
			{Name: "sbom-operator"},
			{Name: "raw-image-id=shared@sha256:999"},
		},
	}

	targetImage := &target.TargetImage{
		RegistryImage: &oci.RegistryImage{ImageID: "shared@sha256:999"},
		Namespace:     "ns-staging", // Only staging is cleand-up
	}

	client, err := dtrack.NewClient(ts.URL)
	require.NoError(t, err)
	err = g.handleProjectDeactivation(client, project, targetImage, false)
	assert.NoError(t, err)

	// Only tag "cluster-A/ns-staging" should be removed.
	// "cluster-A/ns-production" must remain in project.
	tagNames := make([]string, len(project.Tags))
	for i, tag := range project.Tags {
		tagNames[i] = tag.Name
	}

	assert.NotContains(t, tagNames, "kubernetes-cluster=cluster-A/ns-staging")
	assert.Contains(t, tagNames, "kubernetes-cluster=cluster-A/ns-production")
	assert.Contains(t, tagNames, "sbom-operator")
}
