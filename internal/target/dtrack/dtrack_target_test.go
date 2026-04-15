package dtrack

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dtrack "github.com/DependencyTrack/client-go"
	libk8s_real "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGetRepoWithVersion(t *testing.T) {
	tests := []struct {
		name             string
		image            *liboci.RegistryImage
		useShortName     bool
		k8sClusterId     string
		k8sClusterIdMode string
		expectedName     string
		expectedVersion  string
	}{
		{
			name:             "Long name, no prefix",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine:3.14", Image: "alpine:3.14"},
			useShortName:     false,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "tag",
			expectedName:     "docker.io/library/alpine",
			expectedVersion:  "3.14",
		},
		{
			name:             "Short name, prefix mode",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine:3.14", Image: "alpine:3.14"},
			useShortName:     true,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "prefix",
			expectedName:     "my-cluster-library/alpine",
			expectedVersion:  "3.14",
		},
		{
			name:             "Short name, tag mode",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine:3.14", Image: "alpine:3.14"},
			useShortName:     true,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "tag",
			expectedName:     "library/alpine",
			expectedVersion:  "3.14",
		},
		{
			name:             "SHA version",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300", Image: "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300"},
			useShortName:     true,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "tag",
			expectedName:     "library/alpine",
			expectedVersion:  "sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version := getRepoWithVersion(tt.image, tt.useShortName, tt.k8sClusterId, tt.k8sClusterIdMode)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedVersion, version)
		})
	}
}

func TestContainsTag(t *testing.T) {
	tags := []dtrack.Tag{
		{Name: "tag1"},
		{Name: "kubernetes-cluster=my-cluster"},
	}

	assert.True(t, containsTag(tags, "tag1"))
	assert.True(t, containsTag(tags, "kubernetes-cluster=my-cluster"))
	assert.True(t, containsTag(tags, "kubernetes-cluster="))
	assert.False(t, containsTag(tags, "tag2"))
}

func TestRemoveTag(t *testing.T) {
	tags := []dtrack.Tag{
		{Name: "tag1"},
		{Name: "tag2"},
	}

	newTags := removeTag(tags, "tag1")
	assert.Len(t, newTags, 1)
	assert.Equal(t, "tag2", newTags[0].Name)

	newTags = removeTag(tags, "tag3")
	assert.Len(t, newTags, 2)
}

func TestGetNameAndVersionFromString(t *testing.T) {
	n, v := getNameAndVersionFromString("name:version", ":")
	assert.Equal(t, "name", n)
	assert.Equal(t, "version", v)

	n, v = getNameAndVersionFromString("name", ":")
	assert.Equal(t, "name", n)
	assert.Equal(t, "latest", v)
}

func TestGetContainerNameFromAnnotationKey(t *testing.T) {
	c := getContainerNameFromAnnotationKey("prefix/container", "/")
	assert.Equal(t, "container", c)

	c = getContainerNameFromAnnotationKey("container", "/")
	assert.Equal(t, "", c)
}

func TestNewDependencyTrackTarget(t *testing.T) {
	target := NewDependencyTrackTarget("url", "api", "matcher", "ca", "cert", "key", "cluster", "tag", "parent", "p-ann", "n-ann", true)
	assert.Equal(t, "url", target.baseUrl)
	assert.Equal(t, "api", target.apiKey)
	assert.Equal(t, "matcher", target.podLabelTagMatcher)
	assert.Equal(t, "ca", target.caCertFile)
	assert.Equal(t, "cert", target.clientCertFile)
	assert.Equal(t, "key", target.clientKeyFile)
	assert.Equal(t, "cluster", target.k8sClusterId)
	assert.Equal(t, "tag", target.k8sClusterIdMode)
	assert.Equal(t, "parent", target.defaultParentProject)
	assert.Equal(t, "p-ann", target.parentProjectAnnotationKey)
	assert.Equal(t, "n-ann", target.projectNameAnnotationKey)
	assert.True(t, target.useShortName)
}

func TestInitialize(t *testing.T) {
	target := &DependencyTrackTarget{
		apiKey: "apikey",
	}
	err := target.Initialize()
	assert.NoError(t, err)
	assert.Len(t, target.clientOptions, 1)

	target.caCertFile = "ca.crt"
	err = target.Initialize()
	assert.NoError(t, err)
	assert.Len(t, target.clientOptions, 2)
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		target  *DependencyTrackTarget
		wantErr bool
	}{
		{
			name: "Valid config",
			target: &DependencyTrackTarget{
				baseUrl: "http://localhost:8080",
				apiKey:  "apikey",
			},
			wantErr: false,
		},
		{
			name: "Missing baseUrl",
			target: &DependencyTrackTarget{
				apiKey: "apikey",
			},
			wantErr: true,
		},
		{
			name: "Missing apiKey",
			target: &DependencyTrackTarget{
				baseUrl: "http://localhost:8080",
			},
			wantErr: true,
		},
		{
			name: "Invalid UUID for parent project",
			target: &DependencyTrackTarget{
				baseUrl:              "http://localhost:8080",
				apiKey:               "apikey",
				defaultParentProject: "invalid-uuid",
			},
			wantErr: true,
		},
		{
			name: "Missing client cert/key for mTLS",
			target: &DependencyTrackTarget{
				baseUrl:    "http://localhost:8080",
				apiKey:     "apikey",
				caCertFile: "ca.crt",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.target.ValidateConfig()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProcessSbomMinimal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/api/v1/project" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write([]byte("{\"version\": \"4.8.0\", \"token\": \"uuid-token\", \"name\": \"alpine\", \"version\": \"3.14\", \"uuid\": \"8c940608-8e62-431a-ac5d-2092b7c41372\", \"totalCount\": 0}"))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true)
	err := g.Initialize()
	assert.NoError(t, err)

	ctx := &target.TargetContext{
		Image:     &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"},
		Pod:       &libk8s_real.PodInfo{PodNamespace: "default"},
		Container: &libk8s_real.ContainerInfo{Name: "alpine"},
		Sbom:      "{}",
	}

	_ = g.ProcessSbom(ctx)
}

func TestRemoveMinimal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/api/v1/project" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write([]byte("{\"version\": \"4.8.0\", \"totalCount\": 0}"))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true)
	err := g.Initialize()
	assert.NoError(t, err)

	images := []*liboci.RegistryImage{
		{ImageID: "alpine:3.14", Image: "alpine:3.14"},
	}

	_ = g.Remove(images)
}

// TestRawImageIdTagIsRotated ensures the raw-image-id tag is updated to reflect
// the current container digest each time ProcessSbom runs against an existing
// project. The previous behaviour froze the first digest forever and produced
// false orphans during cleanup when the same (projectName, version) was backed
// by a different digest (mutable :latest, re-pushed tag, multiple pods).
func TestRawImageIdTagIsRotated(t *testing.T) {
	t.Run("first digest is added", func(t *testing.T) {
		project := dtrack.Project{Tags: []dtrack.Tag{{Name: sbomOperator}}}
		ctx := &target.TargetContext{Image: &liboci.RegistryImage{ImageID: "alpine@sha256:aaa"}}

		project.Tags = rotateRawImageIdTag(project.Tags, ctx.Image.ImageID)

		assert.Len(t, project.Tags, 2)
		assert.Equal(t, sbomOperator, project.Tags[0].Name)
		assert.Equal(t, "raw-image-id=alpine@sha256:aaa", project.Tags[1].Name)
	})

	t.Run("existing digest is replaced, not appended", func(t *testing.T) {
		project := dtrack.Project{Tags: []dtrack.Tag{
			{Name: sbomOperator},
			{Name: "raw-image-id=alpine@sha256:aaa"},
			{Name: "kubernetes-cluster=my-cluster"},
		}}

		project.Tags = rotateRawImageIdTag(project.Tags, "alpine@sha256:bbb")

		assert.Len(t, project.Tags, 3)
		// raw-image-id replaced, other tags kept
		var rawTags []string
		for _, tag := range project.Tags {
			if strings.HasPrefix(tag.Name, "raw-image-id=") {
				rawTags = append(rawTags, tag.Name)
			}
		}
		assert.Equal(t, []string{"raw-image-id=alpine@sha256:bbb"}, rawTags)
		assert.True(t, containsTag(project.Tags, sbomOperator))
		assert.True(t, containsTag(project.Tags, "kubernetes-cluster=my-cluster"))
	})

	t.Run("multiple stale raw-image-id tags collapsed to one", func(t *testing.T) {
		project := dtrack.Project{Tags: []dtrack.Tag{
			{Name: "raw-image-id=alpine@sha256:aaa"},
			{Name: "raw-image-id=alpine@sha256:bbb"},
			{Name: sbomOperator},
		}}

		project.Tags = rotateRawImageIdTag(project.Tags, "alpine@sha256:ccc")

		var rawTags []string
		for _, tag := range project.Tags {
			if strings.HasPrefix(tag.Name, "raw-image-id=") {
				rawTags = append(rawTags, tag.Name)
			}
		}
		assert.Equal(t, []string{"raw-image-id=alpine@sha256:ccc"}, rawTags)
	})
}

// TestLoadImagesResetsImageProjectMap ensures stale digest -> UUID entries do
// not survive across LoadImages calls. Without this, a re-pulled image would
// leave a stale entry pointing at a still-live project's UUID, and a subsequent
// Remove() on the stale digest would operate on the live project.
func TestLoadImagesResetsImageProjectMap(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/api/v1/project" && r.Method == "GET" {
			// One project tagged for our cluster, current raw-image-id=alpine@sha256:new
			_, _ = w.Write([]byte(`[{
				"name": "alpine", "version": "3.14",
				"uuid": "8c940608-8e62-431a-ac5d-2092b7c41372",
				"tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine@sha256:new"}
				]
			}]`))
			return
		}
		if r.URL.Path == "/api/v1/version" {
			_, _ = w.Write([]byte(`{"version": "4.8.0"}`))
			return
		}
		_, _ = w.Write([]byte(`{"totalCount": 1}`))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true)
	err := g.Initialize()
	assert.NoError(t, err)

	// Seed a stale entry from a previous reconcile cycle.
	g.imageProjectMap = map[string]uuid.UUID{
		"alpine@sha256:OLD": uuid.MustParse("8c940608-8e62-431a-ac5d-2092b7c41372"),
	}

	images, err := g.LoadImages()
	assert.NoError(t, err)

	// Returned set reflects the current DT state only.
	assert.Len(t, images, 1)
	assert.Equal(t, "alpine@sha256:new", images[0].ImageID)

	// The stale entry must be gone; only the current digest remains.
	_, staleStillPresent := g.imageProjectMap["alpine@sha256:OLD"]
	assert.False(t, staleStillPresent, "stale digest entry must be cleared on LoadImages")

	currentUUID, currentPresent := g.imageProjectMap["alpine@sha256:new"]
	assert.True(t, currentPresent)
	assert.Equal(t, "8c940608-8e62-431a-ac5d-2092b7c41372", currentUUID.String())
}

func TestLoadImagesTagMode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/api/v1/project" && r.Method == "GET" {
			_, _ = w.Write([]byte("[{\"name\": \"alpine\", \"version\": \"3.14\", \"tags\": [{\"name\": \"kubernetes-cluster=my-cluster\"}], \"uuid\": \"8c940608-8e62-431a-ac5d-2092b7c41372\"}]"))
			return
		}
		if r.Method == "PATCH" {
			_, _ = w.Write([]byte("{}"))
			return
		}
		if r.URL.Path == "/api/v1/version" {
			_, _ = w.Write([]byte("{\"version\": \"4.8.0\"}"))
			return
		}
		_, _ = w.Write([]byte("{\"totalCount\": 1}"))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true)
	err := g.Initialize()
	assert.NoError(t, err)

	_, _ = g.LoadImages()
}
