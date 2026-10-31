package dtrack

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dtrack "github.com/DependencyTrack/client-go"
	libk8s_real "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		scope            string
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
		{
			name:             "SHA version",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine:3.14", Image: "alpine:3.14"},
			useShortName:     true,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "tag",
			scope:            "testScope",
			expectedName:     "library/alpine-testScope",
			expectedVersion:  "3.14",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dtrackTarget := &DependencyTrackTarget{k8sClusterIdMode: tt.k8sClusterIdMode}
			ctx := &target.TargetContext{Image: tt.image, Attestation: &oci.AttestationSbom{Scope: tt.scope}}
			name, version := dtrackTarget.getRepoWithVersion(ctx, tt.useShortName, tt.k8sClusterId)
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
	assert.Equal(t, "", v)
}

func TestGetContainerNameFromAnnotationKey(t *testing.T) {
	c := getContainerNameFromAnnotationKey("prefix/container", "/")
	assert.Equal(t, "container", c)

	c = getContainerNameFromAnnotationKey("container", "/")
	assert.Equal(t, "", c)
}

func TestNewDependencyTrackTarget(t *testing.T) {
	target := NewDependencyTrackTarget("url", "api", "matcher", "ca", "cert", "key", "cluster", "tag", "parent", "p-ann", "n-ann", true, true, "")
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

func TestProcessSbomUnsupportedMediaType(t *testing.T) {
	ctx := &target.TargetContext{
		Image:       &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"},
		Pod:         &libk8s_real.PodInfo{PodNamespace: "default"},
		Containers:  []*libk8s_real.ContainerInfo{{Name: "alpine"}},
		Attestation: &oci.AttestationSbom{MediaType: "unsupported"},
	}
	g := NewDependencyTrackTarget("", "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "")
	err := g.ProcessSbom(ctx)
	assert.NoError(t, err)
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

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "")
	err := g.Initialize()
	assert.NoError(t, err)

	ctx := &target.TargetContext{
		Image:       &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"},
		Pod:         &libk8s_real.PodInfo{PodNamespace: "default"},
		Containers:  []*libk8s_real.ContainerInfo{{Name: "alpine"}},
		Attestation: &oci.AttestationSbom{},
	}

	_ = g.ProcessSbom(ctx)
}

func TestProcessSbomParentProject(t *testing.T) {
	parentUUID := "aaaaaaaa-1111-2222-3333-444444444444"

	tests := []struct {
		name            string
		annotationValue string
		parentProjects  string
		expectParentRef bool
	}{
		{
			name:            "parent project by name only (no version)",
			annotationValue: "MyParentProject",
			parentProjects:  `[{"name":"MyParentProject","version":"","uuid":"` + parentUUID + `"}]`,
			expectParentRef: true,
		},
		{
			name:            "parent project by name and version",
			annotationValue: "MyParentProject:1.0",
			parentProjects:  `[{"name":"MyParentProject","version":"1.0","uuid":"` + parentUUID + `"}]`,
			expectParentRef: true,
		},
		{
			name:            "explicit version does not match any returned project",
			annotationValue: "MyParentProject:2.0",
			parentProjects:  `[{"name":"MyParentProject","version":"1.0","uuid":"` + parentUUID + `"}]`,
			expectParentRef: false,
		},
		{
			name:            "no parent project found",
			annotationValue: "MyParentProject",
			parentProjects:  `[]`,
			expectParentRef: false,
		},
		{
			name:            "parent project with uuuid",
			annotationValue: "aaaaaaaa-1111-2222-3333-44444444444",
			parentProjects:  `[{"name":"MyParentProject","version":"","uuid":"` + parentUUID + `"}]`,
			expectParentRef: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updateBody := ""
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				switch {
				case r.URL.Path == "/api/v1/bom":
					_, _ = w.Write([]byte(`{"token": "uuid-token"}`))
				case r.URL.Path == "/api/v1/project/lookup":
					_, _ = w.Write([]byte(`{"name":"alpine","version":"3.14","uuid":"8c940608-8e62-431a-ac5d-2092b7c41372"}`))
				case r.URL.Path == "/api/v1/project" && r.Method == http.MethodGet:
					// GetProjectsForName for parent lookup
					_, _ = w.Write([]byte(tt.parentProjects))
				case r.URL.Path == "/api/v1/project" && r.Method == http.MethodPost:
					// Project.Update - capture the body to inspect ParentRef
					buf, _ := io.ReadAll(r.Body)
					updateBody = string(buf)
					logrus.Infof("%s", updateBody)
					_, _ = w.Write([]byte(`{}`))
				default:
					// any other output
					_, _ = w.Write([]byte(`{}`))
				}
			}))
			defer ts.Close()

			g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "my.parent.project", "", true, false, "")
			err := g.Initialize()
			assert.NoError(t, err)
			// Pre-populate so LoadImages is skipped during ProcessSbom.
			g.imageProjectMap = make(map[string]map[string]map[uuid.UUID]struct{})

			ctx := &target.TargetContext{
				Image:       &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"},
				Pod:         &libk8s_real.PodInfo{PodNamespace: "default", Annotations: map[string]string{"my.parent.project/alpine": tt.annotationValue}},
				Containers:  []*libk8s_real.ContainerInfo{{Name: "alpine"}},
				Attestation: &oci.AttestationSbom{Sbom: "{}"},
			}

			err = g.ProcessSbom(ctx)
			assert.NoError(t, err)

			if tt.expectParentRef {
				assert.Contains(t, updateBody, parentUUID)
			} else {
				assert.NotContains(t, updateBody, parentUUID)
			}
		})
	}
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

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "")
	err := g.Initialize()
	assert.NoError(t, err)

	images := []*target.TargetImage{{RegistryImage: &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"}}}

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
					{"name": "raw-image-id=alpine@sha256:new"},
					{"name": "namespace=default"}
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

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "")
	err := g.Initialize()
	assert.NoError(t, err)

	// Seed a stale entry from a previous reconcile cycle.
	staleUUID := uuid.MustParse("8c940608-8e62-431a-ac5d-2092b7c41372")
	g.imageProjectMap = map[string]map[string]map[uuid.UUID]struct{}{
		"alpine@sha256:OLD": {
			"default": {staleUUID: {}},
		},
	}

	images, err := g.LoadImages()
	assert.NoError(t, err)

	// Returned set reflects the current DT state only.
	if assert.Len(t, images, 1) {
		assert.Equal(t, "alpine@sha256:new", images[0].ImageID)
		assert.Equal(t, "default", images[0].Namespace)
	}

	// The stale entry must be gone; only the current digest remains.
	_, staleStillPresent := g.imageProjectMap["alpine@sha256:OLD"]
	assert.False(t, staleStillPresent, "stale digest entry must be cleared on LoadImages")

	currentUUID, currentPresent := g.imageProjectMap["alpine@sha256:new"]
	assert.True(t, currentPresent)
	assert.Len(t, currentUUID, 1)
	assert.Equal(t, map[string]map[uuid.UUID]struct{}{
		"default": {uuid.MustParse("8c940608-8e62-431a-ac5d-2092b7c41372"): {}},
	}, currentUUID)
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

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "")
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

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "8c940608-8e62-431a-ac5d-2092b7c41372", "", true, true, "")
	err := g.Initialize()
	assert.NoError(t, err)

	ctx := &target.TargetContext{
		Image:       &liboci.RegistryImage{ImageID: "alpine:3.13", Image: "alpine:3.13"},
		Pod:         &libk8s_real.PodInfo{PodNamespace: "default"},
		Containers:  []*libk8s_real.ContainerInfo{{Name: "alpine"}},
		Attestation: &oci.AttestationSbom{},
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
	inactiveSiblingUUID := "88888888-9999-aaaa-bbbb-cccccccccccc"

	var updatedUUIDs []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/api/version":
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
				var p dtrack.Project
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &p)
				if !p.Active {
					updatedUUIDs = append(updatedUUIDs, p.UUID.String())
				}
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
					 "tags": []},
					{"name": "library/alpine", "version": "3.11", "active": false,
					 "uuid": "` + inactiveSiblingUUID + `", "parent": {"uuid": "` + parentUUID + `"},
					 "tags": [{"name": "sbom-operator"}]}
				]`))
			} else {
				_, _ = w.Write([]byte(`[]`))
			}
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "8c940608-8e62-431a-ac5d-2092b7c41372", "", true, true, "")
	err := g.Initialize()
	assert.NoError(t, err)

	ctx := &target.TargetContext{
		Image:       &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"},
		Pod:         &libk8s_real.PodInfo{PodNamespace: "default"},
		Containers:  []*libk8s_real.ContainerInfo{{Name: "alpine"}},
		Attestation: &oci.AttestationSbom{Sbom: "{}"},
	}

	_ = g.ProcessSbom(ctx)
	// Only the active, sbom-operator-tagged sibling should be patched as inactive.
	// The current project, the untagged sibling, and the already-inactive sibling
	// must not be touched.
	assert.Equal(t, []string{siblingUUID}, updatedUUIDs)
}

// TestDeactivate verifies that Deactivate patches projects as inactive instead of
// deleting them.
func TestDeactivate(t *testing.T) {
	projectUUID := "11111111-2222-3333-4444-555555555555"
	inactiveUUID := "88888888-9999-aaaa-bbbb-cccccccccccc"
	var updateCount, deleteCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch {
		case r.URL.Path == "/api/version":
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
		case r.URL.Path == "/api/v1/project/"+projectUUID && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{
				"name": "library/alpine", "version": "3.13", "active": true,
				"uuid": "` + projectUUID + `",
				"tags": [{"name": "sbom-operator"}, {"name": "raw-image-id=alpine:3.13"}]
			}`))
		case r.URL.Path == "/api/v1/project/"+inactiveUUID && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{
				"name": "library/alpine", "version": "3.12", "active": false,
				"uuid": "` + inactiveUUID + `",
				"tags": [{"name": "sbom-operator"}, {"name": "raw-image-id=alpine:3.12"}]
			}`))
		case r.URL.Path == "/api/v1/project" && r.Method == http.MethodPost:
			updateCount++
			_, _ = w.Write([]byte(`{}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/project/") && r.Method == http.MethodDelete:
			deleteCount++
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, true, "")
	err := g.Initialize()
	assert.NoError(t, err)

	// Seed the map directly with one active and one already-inactive project.
	activeProjectUUID := uuid.MustParse(projectUUID)
	inactiveProjectUUID := uuid.MustParse(inactiveUUID)
	g.imageProjectMap = map[string]map[string]map[uuid.UUID]struct{}{
		"alpine:3.13": {"": {activeProjectUUID: {}}},
		"alpine:3.12": {"": {inactiveProjectUUID: {}}},
	}

	targetImages := []*target.TargetImage{
		{RegistryImage: &liboci.RegistryImage{ImageID: "alpine:3.13", Image: "alpine:3.13"}},
		{RegistryImage: &liboci.RegistryImage{ImageID: "alpine:3.12", Image: "alpine:3.12"}},
	}
	_ = g.Deactivate(targetImages)
	// Only the active project should be patched as inactive; the already-inactive
	// one must be skipped (no 304 PATCH).
	assert.Equal(t, 1, updateCount, "only the active project should be patched as inactive")
	assert.Equal(t, 0, deleteCount, "project must not be deleted")
	assert.True(t, g.ShouldDeactivateOrphans())
}

// TestDeactivateTagModeMultiCluster verifies that in tag mode, Deactivate removes
// the current cluster's tag but does NOT deactivate the project when another
// cluster is still using it.
func TestDeactivateTagModeMultiCluster(t *testing.T) {
	projectUUID := "11111111-2222-3333-4444-555555555555"
	var updateCount int
	var updateBodies []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch {
		case r.URL.Path == "/api/v1/version":
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
		case r.URL.Path == "/api/v1/project" && r.Method == http.MethodGet:
			// LoadImages returns the project tagged for both my-cluster and other-cluster
			_, _ = w.Write([]byte(`[{
				"name": "library/alpine", "version": "3.13", "active": true,
				"uuid": "` + projectUUID + `",
				"tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "kubernetes-cluster=other-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine:3.13"},
					{"name": "namespace="}
				]
			}]`))
		case r.URL.Path == "/api/v1/project/"+projectUUID && r.Method == http.MethodGet:
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
		case r.URL.Path == "/api/v1/project" && r.Method == http.MethodPost:
			updateCount++
			body, _ := io.ReadAll(r.Body)
			updateBodies = append(updateBodies, string(body))
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, true, "")
	err := g.Initialize()
	assert.NoError(t, err)

	targetImages := []*target.TargetImage{{RegistryImage: &liboci.RegistryImage{ImageID: "alpine:3.13", Image: "alpine:3.13"}}}
	_ = g.Deactivate(targetImages)

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
					{"name": "raw-image-id=alpine:3.14"},
					{"name": "namespace=default"}
				 ]},
				{"name": "library/alpine", "version": "3.13", "active": false,
				 "uuid": "` + inactiveUUID + `",
				 "tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine:3.13"},
					{"name": "namespace=default"}
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

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, true, "")
	err := g.Initialize()
	assert.NoError(t, err)

	images, err := g.LoadImages()
	assert.NoError(t, err)
	assert.Len(t, images, 1)
	assert.Equal(t, "alpine:3.14", images[0].ImageID)
	_, inactivePresent := g.imageProjectMap["alpine:3.13"]
	assert.False(t, inactivePresent, "inactive project must not populate imageProjectMap")
}

func TestDeactivateSiblingVersions_TagMode_MultiCluster(t *testing.T) {
	parentUUID := uuid.New()
	currentUUID := uuid.New()
	siblingOtherClusterOnlyUUID := uuid.New()
	siblingSharedClusterUUID := uuid.New()
	siblingOwnClusterOnlyUUID := uuid.New()

	var updatedProjects []dtrack.Project
	var deactivatedUUIDs []string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"4.11.0"}`))
	})
	mux.HandleFunc("/api/v1/project", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			siblings := []dtrack.Project{
				{
					UUID:      currentUUID,
					Name:      "order-service-container",
					Version:   "1.2.0",
					Active:    true,
					ParentRef: &dtrack.ParentRef{UUID: parentUUID},
					Tags: []dtrack.Tag{
						{Name: "sbom-operator"},
						{Name: "kubernetes-cluster=approval_eu"},
					},
				},
				{
					// Scenario 1: Runs only in live_eu -> MUST NOT been touched by approval_eu
					UUID:      siblingOtherClusterOnlyUUID,
					Name:      "order-service-container",
					Version:   "1.0.0",
					Active:    true,
					ParentRef: &dtrack.ParentRef{UUID: parentUUID},
					Tags: []dtrack.Tag{
						{Name: "sbom-operator"},
						{Name: "kubernetes-cluster=live_eu"},
					},
				},
				{
					// Scenario 2: Runs in approval_eu AND approval_nar -> delete tag approval_eu, stays active: true
					UUID:      siblingSharedClusterUUID,
					Name:      "order-service-container",
					Version:   "1.1.0-rc1",
					Active:    true,
					ParentRef: &dtrack.ParentRef{UUID: parentUUID},
					Tags: []dtrack.Tag{
						{Name: "sbom-operator"},
						{Name: "kubernetes-cluster=approval_eu"},
						{Name: "kubernetes-cluster=approval_nar"},
					},
				},
				{
					// Scenario 3: Runs ONLY in approval_eu -> will be deactivated
					UUID:      siblingOwnClusterOnlyUUID,
					Name:      "order-service-container",
					Version:   "1.0.9",
					Active:    true,
					ParentRef: &dtrack.ParentRef{UUID: parentUUID},
					Tags: []dtrack.Tag{
						{Name: "sbom-operator"},
						{Name: "kubernetes-cluster=approval_eu"},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(siblings)
		case http.MethodPost:
			var p dtrack.Project
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &p)
			if !p.Active {
				deactivatedUUIDs = append(deactivatedUUIDs, p.UUID.String())
			}
			updatedProjects = append(updatedProjects, p)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(p)
			_, _ = w.Write([]byte(`{"active":false}`))
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := dtrack.NewClient(server.URL)
	require.NoError(t, err)

	target := &DependencyTrackTarget{
		k8sClusterId:              "approval_eu",
		k8sClusterIdMode:          "tag",
		manageProjectActiveStatus: true,
	}

	currentProject := dtrack.Project{
		UUID:      currentUUID,
		Name:      "order-service-container",
		Version:   "1.2.0",
		Active:    true,
		ParentRef: &dtrack.ParentRef{UUID: parentUUID},
	}

	target.deactivateSiblingVersions(client, &currentProject, &liboci.RegistryImage{}, &libk8s_real.PodInfo{})

	// Scenario 2 (siblingSharedClusterUUID): Only Tag-Update via PaTCH, is active
	require.Len(t, updatedProjects, 2)
	shared := updatedProjects[0]
	assert.Equal(t, siblingSharedClusterUUID, shared.UUID)
	assert.True(t, shared.Active)
	assert.False(t, containsTag(shared.Tags, "kubernetes-cluster=approval_eu"))
	assert.True(t, containsTag(shared.Tags, "kubernetes-cluster=approval_nar"))

	// Scenario 3 (siblingOwnClusterOnlyUUID): Deactivates via PATCH (and scenario 1 was ignored)
	assert.Equal(t, []string{siblingOwnClusterOnlyUUID.String()}, deactivatedUUIDs)
}

func TestPrefixMode_RemoveAndDeactivateOrphans(t *testing.T) {
	projectUUID := uuid.MustParse("8c940608-8e62-431a-ac5d-2092b7c41372")
	const imageID = "alpine@sha256:prefix123"

	tests := []struct {
		name           string
		removeAction   bool // true = Remove(), false = Deactivate()
		expectedMethod string
	}{
		{
			name:           "Prefix mode Remove deletes orphaned project seeded under real namespace tag",
			removeAction:   true,
			expectedMethod: http.MethodDelete,
		},
		{
			name:           "Prefix mode Deactivate patches orphaned project seeded under real namespace tag",
			removeAction:   false,
			expectedMethod: http.MethodPost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionCalled := false

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				// 1. LoadImages endpoint: returns a prefix-mode project with a real namespace tag
				if r.Method == http.MethodGet && r.URL.Path == "/api/v1/project" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`[{
						"uuid": "` + projectUUID.String() + `",
						"name": "my-cluster-alpine",
						"version": "3.18",
						"active": true,
						"tags": [
						{"name": "namespace=production"},
						{"name": "sbom-operator"},
						{"name": "raw-image-id=` + imageID + `"}
						]
						}]`))
					return
				}

				// 2. Single project GET during removeOrDeactivate
				if r.Method == http.MethodGet && r.URL.Path == "/api/v1/project/"+projectUUID.String() {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{
						"uuid": "` + projectUUID.String() + `",
						"name": "my-cluster-alpine",
						"version": "3.18",
						"active": true,
						"tags": [
						{"name": "namespace=production"},
						{"name": "sbom-operator"},
						{"name": "raw-image-id=` + imageID + `"}
						]
						}`))
					return
				}

				// 3. Verify DELETE or PATCH call on the project UUID
				if r.Method == tt.expectedMethod && strings.HasPrefix(r.URL.Path, "/api/v1/project") {
					actionCalled = true
					w.WriteHeader(http.StatusOK)
					return
				}

				if r.URL.Path == "/api/v1/version" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"version": "4.10.0"}`))
					return
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"totalCount": "1"}`))
			}))
			defer ts.Close()

			// Initialize target in "prefix" mode
			g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "prefix", "", "", "", true, !tt.removeAction, "")
			require.NoError(t, g.Initialize())

			// Precondition: prefix mode must report IsNamespaceAware() == false
			assert.False(t, g.IsNamespaceAware(), "Prefix mode must not be namespace-aware")

			// Step 1: LoadImages populates imageProjectMap under the real namespace ("production"), NOT ""
			loaded, err := g.LoadImages()
			require.NoError(t, err)
			require.Len(t, loaded, 1)
			require.Contains(t, g.imageProjectMap[imageID], "production")

			// Step 2: Processor passes Namespace == "" for non-namespace-aware targets
			orphanInput := []*target.TargetImage{
				{
					RegistryImage: &liboci.RegistryImage{ImageID: imageID},
					Namespace:     "", // Crucial: simulates handleOrphanImages / globalOrphans behavior
				},
			}

			if tt.removeAction {
				err = g.Remove(orphanInput)
			} else {
				err = g.Deactivate(orphanInput)
			}
			require.NoError(t, err)

			// Step 3: Verify DT API was called and local cache entry was cleaned up
			assert.True(t, actionCalled, "Expected %s request to be sent to Dependency-Track for prefix-mode project", tt.expectedMethod)
			assert.NotContains(t, g.imageProjectMap, imageID, "Expected project entry to be removed from imageProjectMap after cleanup")
		})
	}
}

func TestHandleProjectDeactivation_TagMode_RemovesNamespaceTagAndProtectsUnscannedNamespace(t *testing.T) {
	projectUUID := uuid.New()
	updateCalled := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Neither DELETE nor UPDATE (deactivate) must be called while ns-b is still on the project tags!
		if r.Method == http.MethodDelete && r.URL.Path == "/api/v1/project/"+projectUUID.String() {
			updateCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/project" {
			updateCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version": "4.10.0"}`))
	}))
	defer ts.Close()

	// Initialize in standard "tag" mode (NOT tag-namespace mode)
	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "")
	require.NoError(t, g.Initialize())

	// Scenario: In-memory cache ONLY knows about "ns-a" (simulating incomplete cache / unscanned "ns-b")
	g.imageProjectMap = map[string]map[string]map[uuid.UUID]struct{}{
		"alpine@sha256:shared": {
			"ns-a": {projectUUID: {}},
		},
	}

	// However, the DT project itself has tags for BOTH "ns-a" and "ns-b"
	project := &dtrack.Project{
		UUID:    projectUUID,
		Name:    "alpine",
		Version: "3.18",
		Active:  true,
		Tags: []dtrack.Tag{
			{Name: "kubernetes-cluster=my-cluster"},
			{Name: podNamespaceTagKey + "=ns-a"},
			{Name: podNamespaceTagKey + "=ns-b"},
			{Name: "sbom-operator"},
			{Name: "raw-image-id=alpine@sha256:shared"},
		},
	}

	imgToRemove := &target.TargetImage{
		RegistryImage: &liboci.RegistryImage{ImageID: "alpine@sha256:shared"},
		Namespace:     "ns-a",
	}

	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	require.NoError(t, err)

	err = g.handleProjectDeactivation(client, project, imgToRemove, false)
	require.NoError(t, err)

	// Verify "namespace=ns-a" was removed and Project.Update was called
	assert.True(t, updateCalled, "Expected Project.Update to be called to remove stale namespace=ns-a tag")

	remainingTags := make([]string, 0, len(project.Tags))
	for _, tag := range project.Tags {
		remainingTags = append(remainingTags, tag.Name)
	}
	assert.NotContains(t, remainingTags, podNamespaceTagKey+"=ns-a", "Stale namespace tag must be removed")
	assert.Contains(t, remainingTags, podNamespaceTagKey+"=ns-b", "Other active namespace tag must be kept")
	assert.Contains(t, remainingTags, "kubernetes-cluster=my-cluster", "Cluster tag must be kept while ns-b is active")

}
