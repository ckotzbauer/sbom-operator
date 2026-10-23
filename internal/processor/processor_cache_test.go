package processor

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	oci "github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
)

func TestCaching_CrossNamespaceProcessSbomFlow(t *testing.T) {
	p := &Processor{
		imageMap: make(map[string]*cachedImage),
	}

	sampleAttestations := []*oci.AttestationSbom{
		{
			Scope:     oci.ScopeAll,
			MediaType: oci.CycloneDXJSONMediaType,
			Sbom:      `{"bomFormat":"CycloneDX"}`,
		},
	}

	// Step 1: Image has never been seen before -> must scan with Syft and call ProcessSbom
	alreadyInNs, att := p.getCachedAttestations("ns-alpha", "sha256:111")
	assert.False(t, alreadyInNs)
	assert.Nil(t, att)

	// Mark as scanned and processed in "ns-alpha"
	p.imageScanned("ns-alpha", "sha256:111", sampleAttestations)

	// Step 2: Another pod in the SAME namespace ("ns-alpha") uses the image -> skip completely
	alreadyInSameNs, attSameNs := p.getCachedAttestations("ns-alpha", "sha256:111")
	assert.True(t, alreadyInSameNs, "Expected image to be marked as already processed in ns-alpha")
	assert.Nil(t, attSameNs)

	// Step 3: A pod in a DIFFERENT namespace ("ns-beta") uses the same image ->
	// must NOT re-scan with Syft, but MUST return cached attestations so ProcessSbom is called for "ns-beta"
	alreadyInOtherNs, attOtherNs := p.getCachedAttestations("ns-beta", "sha256:111")
	assert.False(t, alreadyInOtherNs, "Expected ns-beta to not be marked as processed yet")
	require.NotNil(t, attOtherNs, "Expected cached attestations from ns-alpha to be returned for ns-beta")
	assert.Equal(t, sampleAttestations, attOtherNs)

	// After ProcessSbom succeeds for "ns-beta", mark "ns-beta" as processed
	p.imageScanned("ns-beta", "sha256:111", attOtherNs)

	// Step 4: Subsequent pods in "ns-beta" must now also be skipped
	alreadyInBetaAfter, _ := p.getCachedAttestations("ns-beta", "sha256:111")
	assert.True(t, alreadyInBetaAfter)
}

func TestCaching_MemoryFreedOnlyWhenLastNamespaceRemovesImage(t *testing.T) {
	p := &Processor{
		imageMap: make(map[string]*cachedImage),
	}

	att := []*oci.AttestationSbom{{Sbom: "cyclonedx-payload"}}
	p.imageScanned("ns-alpha", "sha256:shared", att)
	p.imageScanned("ns-beta", "sha256:shared", att)

	// Remove image from "ns-alpha" only -> "ns-beta" still runs it, so SBOM remains cached
	p.imageRemoved("sha256:shared", "ns-alpha")

	// If "ns-alpha" deploys the image again later, it can still reuse the SBOM from "ns-beta"
	alreadyInAlpha, cachedAtt := p.getCachedAttestations("ns-alpha", "sha256:shared")
	assert.False(t, alreadyInAlpha)
	assert.Equal(t, att, cachedAtt)

	// Remove image from the last remaining namespace ("ns-beta") -> entry must be deleted from RAM
	p.imageRemoved("sha256:shared", "ns-beta")
	assert.Empty(t, p.imageMap, "Expected imageMap entry to be completely removed once no namespace uses it")
}

// recordingTarget tracks all ProcessSbom calls and allows simulating target failures.
type recordingTarget struct {
	mockTarget
	processedContexts []*target.TargetContext
	processErr        error
}

func (r *recordingTarget) ProcessSbom(ctx *target.TargetContext) error {
	if r.processErr != nil {
		return r.processErr
	}
	r.processedContexts = append(r.processedContexts, ctx)
	return nil
}

// 1. Table-Driven Tests for Cache State Transitions & Edge Cases
func TestCache_StateTransitionsAndEdgeCases(t *testing.T) {
	att1 := []*oci.AttestationSbom{
		{Scope: oci.ScopeAll, MediaType: oci.CycloneDXJSONMediaType, Sbom: `{"id":"sbom-1"}`},
	}
	attMulti := []*oci.AttestationSbom{
		{Scope: oci.ScopeAll, MediaType: oci.CycloneDXJSONMediaType, Sbom: `{"id":"sbom-base"}`},
		{Scope: "custom-scope", MediaType: oci.CycloneDXJSONMediaType, Sbom: `{"id":"sbom-layer"}`},
	}

	t.Run("Nil map initialization safety on imageScanned and ImageRemoved", func(t *testing.T) {
		p := &Processor{imageMap: nil}

		// Calling ImageRemoved on nil map must not panic
		assert.NotPanics(t, func() {
			p.imageRemoved("sha256:non-existent", "ns-a")
		})

		// Calling getCachedAttestations on nil map must return false, nil
		alreadyInNs, cached := p.getCachedAttestations("ns-a", "sha256:111")
		assert.False(t, alreadyInNs)
		assert.Nil(t, cached)

		// Calling imageScanned on nil map must initialize the map and store the entry
		p.imageScanned("ns-a", "sha256:111", att1)
		require.NotNil(t, p.imageMap)

		alreadyInNsAfter, _ := p.getCachedAttestations("ns-a", "sha256:111")
		assert.True(t, alreadyInNsAfter)
	})

	t.Run("Idempotent imageScanned calls in the same namespace do not duplicate data", func(t *testing.T) {
		p := &Processor{imageMap: make(map[string]*cachedImage)}

		p.imageScanned("ns-a", "sha256:111", att1)
		p.imageScanned("ns-a", "sha256:111", att1)

		require.Contains(t, p.imageMap, "sha256:111")
		assert.Len(t, p.imageMap["sha256:111"].namespaces, 1)
		assert.Len(t, p.imageMap["sha256:111"].attestations, 1)
	})

	t.Run("Multiple attestations per image are preserved across namespaces", func(t *testing.T) {
		p := &Processor{imageMap: make(map[string]*cachedImage)}

		p.imageScanned("ns-a", "sha256:multi", attMulti)

		// Query from ns-b must return both attestations referencing the exact same slice elements
		alreadyInNs, cached := p.getCachedAttestations("ns-b", "sha256:multi")
		assert.False(t, alreadyInNs)
		require.Len(t, cached, 2)
		assert.Same(t, attMulti[0], cached[0], "Expected exact pointer reuse without copying SBOM struct")
		assert.Same(t, attMulti[1], cached[1], "Expected exact pointer reuse without copying SBOM struct")
	})

	t.Run("Global ImageRemoved with empty namespace immediately frees memory across all namespaces", func(t *testing.T) {
		p := &Processor{imageMap: make(map[string]*cachedImage)}

		p.imageScanned("ns-a", "sha256:global-del", att1)
		p.imageScanned("ns-b", "sha256:global-del", att1)
		p.imageScanned("ns-c", "sha256:global-del", att1)

		// Global removal via namespace == ""
		p.imageRemoved("sha256:global-del", "")

		assert.NotContains(t, p.imageMap, "sha256:global-del")
		alreadyInA, cachedA := p.getCachedAttestations("ns-a", "sha256:global-del")
		assert.False(t, alreadyInA)
		assert.Nil(t, cachedA)
	})

	t.Run("Removing non-existent namespace from existing image keeps other namespaces intact", func(t *testing.T) {
		p := &Processor{imageMap: make(map[string]*cachedImage)}

		p.imageScanned("ns-a", "sha256:keep", att1)

		// Remove from a namespace that never ran the image
		p.imageRemoved("sha256:keep", "ns-unknown")

		// ns-a must still be marked as processed and entry must remain in cache
		alreadyInA, _ := p.getCachedAttestations("ns-a", "sha256:keep")
		assert.True(t, alreadyInA)
		assert.Contains(t, p.imageMap, "sha256:keep")
	})

	t.Run("Re-deployment lifecycle: scan -> remove from 1st NS -> re-deploy in 1st NS -> remove all -> re-deploy", func(t *testing.T) {
		p := &Processor{imageMap: make(map[string]*cachedImage)}

		// 1. Initial scan in ns-a and ns-b
		p.imageScanned("ns-a", "sha256:lifecycle", att1)
		p.imageScanned("ns-b", "sha256:lifecycle", att1)

		// 2. Pod deleted in ns-a, but still running in ns-b
		p.imageRemoved("sha256:lifecycle", "ns-a")

		// 3. Re-deployed in ns-a: must NOT be marked as processed in ns-a,
		//    but MUST reuse cached SBOM from ns-b without running Syft again!
		alreadyInA, cachedForA := p.getCachedAttestations("ns-a", "sha256:lifecycle")
		assert.False(t, alreadyInA, "Re-deployed pod in ns-a needs ProcessSbom to be called again")
		assert.Equal(t, att1, cachedForA, "Must reuse SBOM still held by ns-b")

		// Mark ns-a as processed again
		p.imageScanned("ns-a", "sha256:lifecycle", cachedForA)

		// 4. Now remove from both namespaces -> memory freed completely
		p.imageRemoved("sha256:lifecycle", "ns-a")
		p.imageRemoved("sha256:lifecycle", "ns-b")
		assert.Empty(t, p.imageMap)

		// 5. Re-deployed in ns-a after full cluster removal -> full cache miss (Syft required)
		alreadyInAFresh, cachedFresh := p.getCachedAttestations("ns-a", "sha256:lifecycle")
		assert.False(t, alreadyInAFresh)
		assert.Nil(t, cachedFresh, "Full cache miss expected after all namespaces removed the image")
	})
}

// 2. Cache Synchronization during executeSyftScans
func TestExecuteSyftScans_SyncsProcessorCacheWithClusterState(t *testing.T) {
	att := []*oci.AttestationSbom{{Sbom: `{"bomFormat":"CycloneDX"}`}}

	p := &Processor{
		imageMap: make(map[string]*cachedImage),
		Targets:  []target.Target{}, // Focus purely on internal cache reconciliation
	}

	// Pre-populate cache with 3 scenarios:
	// - img-shared: cached in "ns-active" and "ns-terminated-pod"
	// - img-dead-ns: cached in "ns-deleted-entirely"
	// - img-gone: cached in "ns-active", but pod was replaced
	p.imageScanned("ns-active", "img-shared", att)
	p.imageScanned("ns-terminated-pod", "img-shared", att)
	p.imageScanned("ns-deleted-entirely", "img-dead-ns", att)
	p.imageScanned("ns-active", "img-gone", att)

	// Current cluster reality passed via allImages:
	// Only "img-shared" is running in "ns-active".
	allClusterImages := map[string][]*liboci.RegistryImage{
		"ns-active": {
			{ImageID: "img-shared"},
		},
		"ns-terminated-pod": {}, // Namespace exists, but pod is gone
		// "ns-deleted-entirely" is completely absent from the map
	}

	p.executeSyftScans([]libk8s.PodInfo{}, allClusterImages)

	// Verify 1: "img-shared" is still cached for "ns-active", but removed for "ns-terminated-pod"
	require.Contains(t, p.imageMap, "img-shared")
	alreadyInActive, _ := p.getCachedAttestations("ns-active", "img-shared")
	assert.True(t, alreadyInActive, "img-shared must remain marked as processed in ns-active")

	alreadyInTerminated, cachedFromActive := p.getCachedAttestations("ns-terminated-pod", "img-shared")
	assert.False(t, alreadyInTerminated, "ns-terminated-pod must be cleared from img-shared cache")
	assert.Equal(t, att, cachedFromActive, "SBOM payload must still be available from ns-active")

	// Verify 2: "img-dead-ns" was in a deleted namespace -> completely evicted from memory
	assert.NotContains(t, p.imageMap, "img-dead-ns", "Image from deleted namespace must be evicted from RAM")

	// Verify 3: "img-gone" is no longer running in "ns-active" -> completely evicted from memory
	assert.NotContains(t, p.imageMap, "img-gone", "Stopped image must be evicted from RAM")
}

// 3. Target Failure Resilience (Do not cache if ProcessSbom fails)
func TestCache_NotMarkedAsProcessedWhenTargetFails(t *testing.T) {
	att := []*oci.AttestationSbom{{Scope: oci.ScopeAll, Sbom: `{"bomFormat":"CycloneDX"}`}}

	p := &Processor{
		imageMap: make(map[string]*cachedImage),
	}

	// Image is already scanned and cached in "ns-alpha"
	p.imageScanned("ns-alpha", "sha256:retry-me", att)

	// Now "ns-beta" tries to process the cached SBOM, so it fetches from cache:
	alreadyInBeta, cachedAtt := p.getCachedAttestations("ns-beta", "sha256:retry-me")
	require.False(t, alreadyInBeta)
	require.NotNil(t, cachedAtt)

	// Simulate target.ProcessSbom failing during delivery for "ns-beta"
	failingTarget := &recordingTarget{
		processErr: errors.New("dependency-track 503 service unavailable"),
	}
	p.Targets = []target.Target{failingTarget}

	imageErr := false
	for _, a := range cachedAtt {
		for _, tgt := range p.Targets {
			if err := tgt.ProcessSbom(&target.TargetContext{Attestation: a}); err != nil {
				imageErr = true
			}
		}
	}

	// Only call imageScanned if !imageErr (mirrors scanPod logic)
	if !imageErr {
		p.imageScanned("ns-beta", "sha256:retry-me", cachedAtt)
	}

	// Verify: Because ProcessSbom failed, "ns-beta" must NOT be marked as processed,
	// allowing the next reconcile loop to retry sending the cached SBOM to the target.
	alreadyInBetaAfterFail, retryAtt := p.getCachedAttestations("ns-beta", "sha256:retry-me")
	assert.False(t, alreadyInBetaAfterFail, "Failed target delivery must not mark namespace as processed")
	assert.Equal(t, att, retryAtt, "Cached SBOM from ns-alpha must still be returned for retry")
}
