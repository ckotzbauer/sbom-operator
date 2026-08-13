package dtrack

import (
	"io"
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
			name:             "Long name, tag mode",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine:3.14", Image: "alpine:3.14"},
			useShortName:     false,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "tag",
			expectedName:     "docker.io/library/alpine",
			expectedVersion:  "3.14",
		},
		{
			name:             "Long name, prefix mode",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine:3.14", Image: "alpine:3.14"},
			useShortName:     false,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "prefix",
			expectedName:     "my-cluster-docker.io/library/alpine",
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
	target := NewDependencyTrackTarget("url", "api", "matcher", "ca", "cert", "key", "cluster", "tag", "parent", "p-ann", "n-ann", true, true)
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
	assert.True(t, target.manageProjectActiveStatus)
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
		{
			name: "Manage active status without parent project",
			target: &DependencyTrackTarget{
				baseUrl:                   "http://localhost:8080",
				apiKey:                    "apikey",
				manageProjectActiveStatus: true,
			},
			wantErr: true,
		},
		{
			name: "Manage active status with default parent",
			target: &DependencyTrackTarget{
				baseUrl:                   "http://localhost:8080",
				apiKey:                    "apikey",
				defaultParentProject:      "8c940608-8e62-431a-ac5d-2092b7c41372",
				manageProjectActiveStatus: true,
			},
			wantErr: false,
		},
		{
			name: "Manage active status with parent annotation key",
			target: &DependencyTrackTarget{
				baseUrl:                    "http://localhost:8080",
				apiKey:                     "apikey",
				parentProjectAnnotationKey: "example.com/parent",
				manageProjectActiveStatus:  true,
			},
			wantErr: false,
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
			if r.Method == "POST" {
				_, _ = w.Write([]byte("{}"))
			} else {
				_, _ = w.Write([]byte("[]"))
			}
			return
		}
		_, _ = w.Write([]byte("{\"version\": \"4.8.0\", \"token\": \"uuid-token\", \"name\": \"alpine\", \"version\": \"3.14\", \"uuid\": \"8c940608-8e62-431a-ac5d-2092b7c41372\", \"totalCount\": 0}"))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false)
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

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false)
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

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false)
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

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false)
	err := g.Initialize()
	assert.NoError(t, err)

	_, _ = g.LoadImages()
}

func TestGetRawImageId(t *testing.T) {
	assert.Equal(t, "", getRawImageId([]dtrack.Tag{{Name: "sbom-operator"}}))
	assert.Equal(t, "alpine@sha256:aaa", getRawImageId([]dtrack.Tag{{Name: "raw-image-id=alpine@sha256:aaa"}}))
	assert.Equal(t, "alpine@sha256:bbb", getRawImageId([]dtrack.Tag{
		{Name: "sbom-operator"},
		{Name: "raw-image-id=alpine@sha256:bbb"},
		{Name: "namespace=default"},
	}))
}

// TestProcessSbomReactivateWithoutUpload verifies the lookup-first optimization:
// when an inactive project already exists with a matching raw-image-id, the BOM is
// not re-uploaded and the project is reactivated instead.
func TestProcessSbomReactivateWithoutUpload(t *testing.T) {
	var postBomCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/api/v1/version":
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
		case "/api/v1/project/lookup":
			// existing inactive project with matching raw-image-id
			_, _ = w.Write([]byte(`{
				"name": "library/alpine", "version": "3.13", "active": false,
				"uuid": "11111111-2222-3333-4444-555555555555",
				"parent": {"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
				"tags": [{"name": "sbom-operator"}, {"name": "raw-image-id=alpine:3.13"}]
			}`))
		case "/api/v1/bom":
			postBomCount++
			_, _ = w.Write([]byte(`{"token": "tok"}`))
		case "/api/v1/project":
			if r.Method == "POST" {
				_, _ = w.Write([]byte(`{}`))
			} else {
				_, _ = w.Write([]byte(`[]`))
			}
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "8c940608-8e62-431a-ac5d-2092b7c41372", "", true, true)
	err := g.Initialize()
	assert.NoError(t, err)

	ctx := &target.TargetContext{
		Image:     &liboci.RegistryImage{ImageID: "alpine:3.13", Image: "alpine:3.13"},
		Pod:       &libk8s_real.PodInfo{PodNamespace: "default"},
		Container: &libk8s_real.ContainerInfo{Name: "alpine"},
		Sbom:      "{}",
	}

	_ = g.ProcessSbom(ctx)
	assert.Equal(t, 0, postBomCount, "BOM must not be re-uploaded when reactivating an existing project")
}

// TestProcessSbomDeactivatesSiblings verifies that uploading a new version causes
// sibling versions under the same parent to be patched as inactive.
func TestProcessSbomDeactivatesSiblings(t *testing.T) {
	parentUUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	activeUUID := "11111111-2222-3333-4444-555555555555"
	siblingUUID := "66666666-7777-8888-9999-000000000000"
	untaggedSiblingUUID := "77777777-8888-9999-aaaa-bbbbbbbbbbbb"

	var patchUUIDs []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/api/v1/version":
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
		case "/api/v1/project/lookup":
			_, _ = w.Write([]byte(`{
				"name": "library/alpine", "version": "3.14", "active": true,
				"uuid": "` + activeUUID + `",
				"parent": {"uuid": "` + parentUUID + `"},
				"tags": [{"name": "sbom-operator"}]
			}`))
		case "/api/v1/bom":
			_, _ = w.Write([]byte(`{"token": "tok"}`))
		case "/api/v1/project":
			if r.Method == "POST" {
				_, _ = w.Write([]byte(`{}`))
			} else if r.URL.Query().Get("name") != "" {
				// GetProjectsForName returns the current version + a sibling version
				_, _ = w.Write([]byte(`[
					{"name": "library/alpine", "version": "3.14", "active": true,
					 "uuid": "` + activeUUID + `", "parent": {"uuid": "` + parentUUID + `"},
					 "tags": [{"name": "sbom-operator"}]},
					{"name": "library/alpine", "version": "3.13", "active": true,
					 "uuid": "` + siblingUUID + `", "parent": {"uuid": "` + parentUUID + `"},
					 "tags": [{"name": "sbom-operator"}]},
					{"name": "library/alpine", "version": "3.12", "active": true,
					 "uuid": "` + untaggedSiblingUUID + `", "parent": {"uuid": "` + parentUUID + `"},
					 "tags": []}
				]`))
			} else {
				_, _ = w.Write([]byte(`[]`))
			}
		default:
			if r.Method == "PATCH" {
				patchUUIDs = append(patchUUIDs, strings.TrimPrefix(r.URL.Path, "/api/v1/project/"))
				_, _ = w.Write([]byte(`{}`))
			} else {
				_, _ = w.Write([]byte(`{}`))
			}
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "8c940608-8e62-431a-ac5d-2092b7c41372", "", true, true)
	err := g.Initialize()
	assert.NoError(t, err)

	ctx := &target.TargetContext{
		Image:     &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"},
		Pod:       &libk8s_real.PodInfo{PodNamespace: "default"},
		Container: &libk8s_real.ContainerInfo{Name: "alpine"},
		Sbom:      "{}",
	}

	_ = g.ProcessSbom(ctx)
	// Only the sbom-operator-tagged sibling should be patched as inactive. Neither
	// the current project nor the untagged sibling may be touched.
	assert.Equal(t, []string{siblingUUID}, patchUUIDs)
}

// TestDeactivate verifies that Deactivate patches projects as inactive instead of
// deleting them.
func TestDeactivate(t *testing.T) {
	projectUUID := "11111111-2222-3333-4444-555555555555"
	var patchCount, deleteCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch {
		case r.URL.Path == "/api/v1/version":
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
		case r.URL.Path == "/api/v1/project" && r.Method == "GET":
			_, _ = w.Write([]byte(`[{
				"name": "library/alpine", "version": "3.13", "active": true,
				"uuid": "` + projectUUID + `",
				"tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine:3.13"}
				]
			}]`))
		case r.URL.Path == "/api/v1/project/"+projectUUID && r.Method == "GET":
			_, _ = w.Write([]byte(`{
				"name": "library/alpine", "version": "3.13", "active": true,
				"uuid": "` + projectUUID + `",
				"tags": [{"name": "sbom-operator"}, {"name": "raw-image-id=alpine:3.13"}]
			}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/project/") && r.Method == "PATCH":
			patchCount++
			_, _ = w.Write([]byte(`{}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/project/") && r.Method == "DELETE":
			deleteCount++
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, true)
	err := g.Initialize()
	assert.NoError(t, err)

	images := []*liboci.RegistryImage{{ImageID: "alpine:3.13", Image: "alpine:3.13"}}
	_ = g.Deactivate(images)
	assert.Equal(t, 1, patchCount, "project should be patched as inactive")
	assert.Equal(t, 0, deleteCount, "project must not be deleted")
	assert.True(t, g.ShouldDeactivateOrphans())
}

// TestDeactivateTagModeMultiCluster verifies that in tag mode, Deactivate removes
// the current cluster's tag but does NOT deactivate the project when another
// cluster is still using it.
func TestDeactivateTagModeMultiCluster(t *testing.T) {
	projectUUID := "11111111-2222-3333-4444-555555555555"
	var patchCount int
	var updateBodies []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch {
		case r.URL.Path == "/api/v1/version":
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
		case r.URL.Path == "/api/v1/project" && r.Method == "GET":
			// LoadImages returns the project tagged for both my-cluster and other-cluster
			_, _ = w.Write([]byte(`[{
				"name": "library/alpine", "version": "3.13", "active": true,
				"uuid": "` + projectUUID + `",
				"tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "kubernetes-cluster=other-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine:3.13"}
				]
			}]`))
		case r.URL.Path == "/api/v1/project/"+projectUUID && r.Method == "GET":
			_, _ = w.Write([]byte(`{
				"name": "library/alpine", "version": "3.13", "active": true,
				"uuid": "` + projectUUID + `",
				"tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "kubernetes-cluster=other-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine:3.13"}
				]
			}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/project/") && r.Method == "PATCH":
			patchCount++
			_, _ = w.Write([]byte(`{}`))
		case r.URL.Path == "/api/v1/project" && r.Method == "POST":
			body, _ := io.ReadAll(r.Body)
			updateBodies = append(updateBodies, string(body))
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, true)
	err := g.Initialize()
	assert.NoError(t, err)

	images := []*liboci.RegistryImage{{ImageID: "alpine:3.13", Image: "alpine:3.13"}}
	_ = g.Deactivate(images)

	// Project must NOT be patched as inactive because another cluster still uses it.
	assert.Equal(t, 0, patchCount, "project must not be deactivated while another cluster uses it")

	// The cluster tag for my-cluster must have been removed in the Update body.
	assert.Len(t, updateBodies, 1)
	assert.Contains(t, updateBodies[0], `"kubernetes-cluster=other-cluster"`)
	assert.NotContains(t, updateBodies[0], `"kubernetes-cluster=my-cluster"`)
}

// TestLoadImagesSkipsInactiveProjects verifies that inactive projects are not
// returned when active-status management is enabled, so they don't surface as
// orphans and rolled-back images get re-scanned.
func TestLoadImagesSkipsInactiveProjects(t *testing.T) {
	activeUUID := "11111111-2222-3333-4444-555555555555"
	inactiveUUID := "66666666-7777-8888-9999-000000000000"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/api/v1/project" && r.Method == "GET" {
			_, _ = w.Write([]byte(`[
				{"name": "library/alpine", "version": "3.14", "active": true,
				 "uuid": "` + activeUUID + `",
				 "tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine:3.14"}
				 ]},
				{"name": "library/alpine", "version": "3.13", "active": false,
				 "uuid": "` + inactiveUUID + `",
				 "tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine:3.13"}
				 ]}
			]`))
			return
		}
		if r.URL.Path == "/api/v1/version" {
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
			return
		}
		_, _ = w.Write([]byte(`{"totalCount": 1}`))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, true)
	err := g.Initialize()
	assert.NoError(t, err)

	images, err := g.LoadImages()
	assert.NoError(t, err)
	assert.Len(t, images, 1)
	assert.Equal(t, "alpine:3.14", images[0].ImageID)
	_, inactivePresent := g.imageProjectMap["alpine:3.13"]
	assert.False(t, inactivePresent, "inactive project must not populate imageProjectMap")
}
