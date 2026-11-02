package dtrack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseStageIntervals_EdgeCasesAndErrors(t *testing.T) {
	// Empty string and whitespace-only parts
	ivs, err := ParseStageIntervals("   ")
	assert.NoError(t, err)
	assert.Nil(t, ivs)

	ivs, err = ParseStageIntervals("2026-10-01T10:00:00Z/.. , , ")
	assert.NoError(t, err)
	assert.Len(t, ivs, 1)

	// Invalid start timestamp
	_, err = ParseStageIntervals("not-a-timestamp/..")
	assert.Error(t, err)

	// Invalid end timestamp
	_, err = ParseStageIntervals("2026-10-01T10:00:00Z/not-a-timestamp")
	assert.Error(t, err)

	// Older candidateStart adjusts existing open interval start
	earlier := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	updated := OpenStageInterval("2026-10-01T10:00:00Z/..", earlier)
	assert.Equal(t, "2026-09-01T00:00:00Z/..", updated)

	// CloseStageInterval with deactivatedAt before start clamps to start
	clamped := CloseStageInterval("2026-10-01T10:00:00Z/..", earlier)
	assert.Equal(t, "2026-10-01T10:00:00Z/2026-10-01T10:00:00Z", clamped)
}

func TestSyncAndCloseStageIntervalProperty_Lifecycle(t *testing.T) {
	projectUUID := uuid.New()
	var currentProps []dtrack.ProjectProperty
	var updatedProject dtrack.Project
	var patchCalled bool
	var createCalls, updateCalls int

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		propPath := "/api/v1/project/" + projectUUID.String() + "/property"

		switch {
		case r.URL.Path == propPath && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(currentProps)
			return
		case r.URL.Path == propPath && r.Method == http.MethodPut:
			createCalls++
			var p dtrack.ProjectProperty
			_ = json.NewDecoder(r.Body).Decode(&p)
			currentProps = append(currentProps, p)
			_ = json.NewEncoder(w).Encode(p)
			return
		case r.URL.Path == propPath && r.Method == http.MethodPost:
			updateCalls++
			var p dtrack.ProjectProperty
			_ = json.NewDecoder(r.Body).Decode(&p)
			for i := range currentProps {
				if currentProps[i].Group == p.Group && currentProps[i].Name == p.Name {
					currentProps[i].Value = p.Value
				}
			}
			_ = json.NewEncoder(w).Encode(p)
			return
		case r.URL.Path == "/api/v1/project/"+projectUUID.String() && r.Method == http.MethodPatch:
			patchCalled = true
			_ = json.NewDecoder(r.Body).Decode(&updatedProject)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(updatedProject)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "cluster-a", "tag", "", "", "", true, true, "", true)
	require.NoError(t, g.Initialize())

	client, err := dtrack.NewClient(ts.URL, dtrack.WithAPIKey("apikey"))
	require.NoError(t, err)

	proj := dtrack.Project{
		UUID:    projectUUID,
		Name:    "app",
		Version: "1.0",
		Active:  true,
		Tags: []dtrack.Tag{
			{Name: sbomOperator},
			{Name: kubernetesCluster + "=cluster-a"},
			{Name: podNamespaceTagKey + "=payment"},
			{Name: deployedStageTagKey + "=cluster-a"},
		},
	}
	tRelease := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

	// 1. Initial sync creates property with open interval
	g.syncStageIntervalProperty(context.Background(), client, proj, "cluster-a", false, tRelease, tRelease)
	assert.Equal(t, 1, createCalls)
	require.Len(t, currentProps, 1)
	assert.Equal(t, "2026-10-01T10:00:00Z/..", currentProps[0].Value)

	// 2. Second sync with identical timestamp is a no-op (no extra update call)
	g.syncStageIntervalProperty(context.Background(), client, proj, "cluster-a", true, tRelease, tRelease)
	assert.Equal(t, 0, updateCalls)

	// 3. Deactivating project patches tags/active state, retains deployed-stage tag, and closes interval
	img := &target.TargetImage{
		RegistryImage: &oci.RegistryImage{ImageID: "app:1.0"},
		Namespace:     "payment",
	}
	err = g.handleProjectDeactivation(client, &proj, img, false)
	assert.NoError(t, err)

	assert.True(t, patchCalled)
	assert.Equal(t, 1, updateCalls)
	assert.False(t, strings.HasSuffix(currentProps[0].Value, "/.."))
	assert.False(t, containsTag(updatedProject.Tags, kubernetesCluster+"=cluster-a"))
	assert.False(t, containsTag(updatedProject.Tags, podNamespaceTagKey+"=payment"))
	assert.True(t, containsTag(updatedProject.Tags, deployedStageTagKey+"=cluster-a"))
}

func TestHandleProjectDeactivation_MultiClusterClosesCurrentClusterIntervalOnly(t *testing.T) {
	projectUUID := uuid.New()
	currentProps := []dtrack.ProjectProperty{
		{
			Group: deploymentTimestampGroup,
			Name:  "cluster-a",
			Value: "2026-10-01T10:00:00Z/..",
			Type:  "STRING",
		},
		{
			Group: deploymentTimestampGroup,
			Name:  "cluster-b",
			Value: "2026-10-05T10:00:00Z/..",
			Type:  "STRING",
		},
	}
	var patchedProject dtrack.Project

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		propPath := "/api/v1/project/" + projectUUID.String() + "/property"

		switch {
		case r.URL.Path == propPath && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(currentProps)
			return
		case r.URL.Path == propPath && r.Method == http.MethodPost:
			var p dtrack.ProjectProperty
			_ = json.NewDecoder(r.Body).Decode(&p)
			for i := range currentProps {
				if currentProps[i].Group == p.Group && currentProps[i].Name == p.Name {
					currentProps[i].Value = p.Value
				}
			}
			_ = json.NewEncoder(w).Encode(p)
			return
		case r.URL.Path == "/api/v1/project/"+projectUUID.String() && r.Method == http.MethodPatch:
			_ = json.NewDecoder(r.Body).Decode(&patchedProject)
			_ = json.NewEncoder(w).Encode(patchedProject)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "cluster-a", "tag", "", "", "", true, true, "", true)
	require.NoError(t, g.Initialize())

	client, err := dtrack.NewClient(ts.URL, dtrack.WithAPIKey("apikey"))
	require.NoError(t, err)

	// Project is shared between cluster-a and cluster-b
	proj := dtrack.Project{
		UUID:    projectUUID,
		Name:    "shared-service",
		Version: "2.0.0",
		Active:  true,
		Tags: []dtrack.Tag{
			{Name: sbomOperator},
			{Name: kubernetesCluster + "=cluster-a"},
			{Name: kubernetesCluster + "=cluster-b"},
			{Name: deployedStageTagKey + "=cluster-a"},
			{Name: deployedStageTagKey + "=cluster-b"},
		},
	}

	img := &target.TargetImage{
		RegistryImage: &oci.RegistryImage{ImageID: "shared-service:2.0.0"},
		Namespace:     "default",
	}

	err = g.handleProjectDeactivation(client, &proj, img, false)
	require.NoError(t, err)

	// Project must remain active because cluster-b still uses it
	assert.True(t, patchedProject.Active)
	assert.False(t, containsTag(patchedProject.Tags, kubernetesCluster+"=cluster-a"))
	assert.True(t, containsTag(patchedProject.Tags, kubernetesCluster+"=cluster-b"))

	// cluster-a interval MUST be closed, while cluster-b interval remains open!
	assert.False(t, strings.HasSuffix(currentProps[0].Value, "/.."), "cluster-a interval must be closed")
	assert.Equal(t, "2026-10-05T10:00:00Z/..", currentProps[1].Value, "cluster-b interval must remain open")
}

func TestHandleProjectDeactivation_DeleteModeDeletesAlreadyInactiveProject(t *testing.T) {
	projectUUID := uuid.New()
	deleteCalled := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodDelete && r.URL.Path == "/api/v1/project/"+projectUUID.String() {
			deleteCalled = true
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "cluster-a", "tag", "", "", "", true, false, "", false)
	require.NoError(t, g.Initialize())

	client, err := dtrack.NewClient(ts.URL, dtrack.WithAPIKey("apikey"))
	require.NoError(t, err)

	// Project is ALREADY inactive in Dependency-Track
	proj := dtrack.Project{
		UUID:    projectUUID,
		Name:    "legacy-app",
		Version: "1.0.0",
		Active:  false,
		Tags: []dtrack.Tag{
			{Name: sbomOperator},
			{Name: kubernetesCluster + "=cluster-a"},
		},
	}

	img := &target.TargetImage{
		RegistryImage: &oci.RegistryImage{ImageID: "legacy-app:1.0.0"},
		Namespace:     "default",
	}

	err = g.handleProjectDeactivation(client, &proj, img, true)
	require.NoError(t, err)
	assert.True(t, deleteCalled, "already-inactive orphan project must still be deleted when deleteProject is true")
}
