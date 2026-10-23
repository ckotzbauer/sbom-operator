package processor

import (
	"testing"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/stretchr/testify/assert"
)

func TestInitTargets(t *testing.T) {
	internal.OperatorConfig = &internal.Config{
		Targets:       []string{"dtrack", "configmap"},
		DtrackBaseUrl: "http://localhost",
		DtrackApiKey:  "api",
	}

	targets := initTargets(nil)
	assert.Len(t, targets, 2)
}

func TestIsNamespaceAllowed(t *testing.T) {
	p := &Processor{
		allowedNamespaces: make(map[string]bool),
	}

	internal.OperatorConfig = &internal.Config{NamespaceLabelSelector: ""}
	assert.True(t, p.isNamespaceAllowed("default"))

	internal.OperatorConfig = &internal.Config{NamespaceLabelSelector: "scan=true"}
	assert.False(t, p.isNamespaceAllowed("default"))

	p.addAllowedNamespace("default")
	assert.True(t, p.isNamespaceAllowed("default"))

	p.removeAllowedNamespace("default")
	assert.False(t, p.isNamespaceAllowed("default"))
}

func TestNamespaceLabelMatches(t *testing.T) {
	p := &Processor{}
	selector := "scan=true"

	labels1 := map[string]string{"scan": "true"}
	assert.True(t, p.namespaceLabelMatches(labels1, selector))

	labels2 := map[string]string{"scan": "false"}
	assert.False(t, p.namespaceLabelMatches(labels2, selector))

	labels3 := map[string]string{"foo": "bar"}
	assert.False(t, p.namespaceLabelMatches(labels3, selector))
}

type mockTarget struct {
	namespaceAware bool
	loadedImages   []*target.TargetImage
	loadErr        error

	removedImages []*target.TargetImage
	removeCalled  bool
}

func (m *mockTarget) Initialize() error                           { return nil }
func (m *mockTarget) ValidateConfig() error                       { return nil }
func (m *mockTarget) ProcessSbom(ctx *target.TargetContext) error { return nil }
func (m *mockTarget) IsNamespaceAware() bool                      { return m.namespaceAware }
func (m *mockTarget) LoadImages() ([]*target.TargetImage, error) {
	return m.loadedImages, m.loadErr
}
func (m *mockTarget) Remove(images []*target.TargetImage) error {
	m.removeCalled = true
	m.removedImages = images
	return nil
}

// mockDeactivateTarget extends mockTarget with target.DeactivateTarget
type mockDeactivateTarget struct {
	*mockTarget
	shouldDeactivate  bool
	deactivatedImages []*target.TargetImage
	deactivateCalled  bool
}

func (m *mockDeactivateTarget) ShouldDeactivateOrphans() bool {
	return m.shouldDeactivate
}

func (m *mockDeactivateTarget) Deactivate(images []*target.TargetImage) error {
	m.deactivateCalled = true
	m.deactivatedImages = images
	return nil
}

// Helper function to create TargetImages fast
func newTargetImg(id, namespace string) *target.TargetImage {
	return &target.TargetImage{
		RegistryImage: &liboci.RegistryImage{ImageID: id},
		Namespace:     namespace,
	}
}

func TestHandleOrphanImages_NamespaceBehavior(t *testing.T) {
	tests := []struct {
		name               string
		namespaceAware     bool
		deleteOrphansFlag  bool
		inputImages        []*target.TargetImage
		expectedCount      int
		expectEmptyNs      bool
		expectRemoveCalled bool
	}{
		{
			name:              "Namespace-aware Target retains same ImageID in different Namespaces",
			namespaceAware:    true,
			deleteOrphansFlag: true,
			inputImages: []*target.TargetImage{
				newTargetImg("sha256:111", "ns-alpha"),
				newTargetImg("sha256:111", "ns-beta"),
				newTargetImg("sha256:222", "ns-alpha"),
			},
			expectedCount:      3,
			expectEmptyNs:      false,
			expectRemoveCalled: true,
		},
		{
			name:              "Not namespace-aware target deduplicates ImageIDs and empties Namespace",
			namespaceAware:    false,
			deleteOrphansFlag: true,
			inputImages: []*target.TargetImage{
				newTargetImg("sha256:111", "ns-alpha"),
				newTargetImg("sha256:111", "ns-beta"),
				newTargetImg("sha256:222", "ns-alpha"),
			},
			expectedCount:      2, // sha256:111 und sha256:222
			expectEmptyNs:      true,
			expectRemoveCalled: true,
		},
		{
			name:              "No Remove call when DeleteOrphanImages is deactivated",
			namespaceAware:    true,
			deleteOrphansFlag: false,
			inputImages: []*target.TargetImage{
				newTargetImg("sha256:111", "ns-alpha"),
			},
			expectedCount:      0,
			expectRemoveCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			internal.OperatorConfig.DeleteOrphanImages = tt.deleteOrphansFlag
			p := &Processor{}
			mt := &mockTarget{namespaceAware: tt.namespaceAware}

			p.handleOrphanImages(mt, tt.inputImages)

			if mt.removeCalled != tt.expectRemoveCalled {
				t.Fatalf("removeCalled = %v, expected %v", mt.removeCalled, tt.expectRemoveCalled)
			}

			if len(mt.removedImages) != tt.expectedCount {
				t.Fatalf("Number of deleted images = %d, expected %d", len(mt.removedImages), tt.expectedCount)
			}

			for _, img := range mt.removedImages {
				if tt.expectEmptyNs && img.Namespace != "" {
					t.Errorf("expected empy Namespace with not namespace-aware target, but got: %q", img.Namespace)
				}
				if !tt.expectEmptyNs && img.Namespace == "" {
					t.Errorf("Namespace was wrongly emptied for image %s", img.ImageID)
				}
			}
		})
	}
}

func TestHandleOrphanImages_DeactivateTarget(t *testing.T) {
	// Deactivate shall also be used if DeleteOrphanImages global is false
	internal.OperatorConfig.DeleteOrphanImages = false
	p := &Processor{}

	dt := &mockDeactivateTarget{
		mockTarget:       &mockTarget{namespaceAware: true},
		shouldDeactivate: true,
	}

	input := []*target.TargetImage{
		newTargetImg("sha256:111", "prod"),
		newTargetImg("sha256:111", "staging"),
	}

	p.handleOrphanImages(dt, input)

	if !dt.deactivateCalled {
		t.Fatal("Deactivate() was not called, although ShouldDeactivateOrphans() is true")
	}
	if dt.removeCalled {
		t.Fatal("Remove() must not be called when Deactivate() is active")
	}
	if len(dt.deactivatedImages) != 2 {
		t.Fatalf("expected 2 deactivated images, but got: %d", len(dt.deactivatedImages))
	}
}

func TestExecuteSyftScans_NamespaceFiltering(t *testing.T) {
	internal.OperatorConfig.DeleteOrphanImages = true

	// active cluster images:
	// - "img-shared" runs ONLY NUR in "ns-keep" (was deleted in "ns-remove")
	// - "img-active" runs in "ns-keep"
	// - "img-orphan" runs nowhere anymore
	allClusterImages := map[string][]*liboci.RegistryImage{
		"ns-keep": {
			{ImageID: "img-shared"},
			{ImageID: "img-active"},
		},
		"ns-remove": {},
	}

	t.Run("Namespace-aware Target deletes image only in the Namespace, in which it is missing", func(t *testing.T) {
		nsTarget := &mockTarget{
			namespaceAware: true,
			loadedImages: []*target.TargetImage{
				newTargetImg("img-shared", "ns-keep"),   // Still active in ns-keep -> retain
				newTargetImg("img-shared", "ns-remove"), // Missing in ns-remove -> delete!
				newTargetImg("img-active", "ns-keep"),   // Still active in ns-keep -> retain
			},
		}

		p := &Processor{
			Targets: []target.Target{nsTarget},
			imageMap: map[string]*cachedImage{
				"img-shared": {namespaces: map[string]struct{}{
					"ns-keep":   {},
					"ns-remove": {},
				}},
				"img-active": {namespaces: map[string]struct{}{
					"ns-keep": {},
				}},
			},
		}

		p.executeSyftScans([]libk8s.PodInfo{}, allClusterImages)

		if len(nsTarget.removedImages) != 1 {
			t.Fatalf("expects exactly 1 image to delete, but was: %d", len(nsTarget.removedImages))
		}
		if nsTarget.removedImages[0].ImageID != "img-shared" || nsTarget.removedImages[0].Namespace != "ns-remove" {
			t.Errorf("wrong image deleted: %+v (Namespace: %s)",
				nsTarget.removedImages[0].ImageID, nsTarget.removedImages[0].Namespace)
		}
	})

	t.Run("Not namespace-aware target keeps image while it is running in any Namespace", func(t *testing.T) {
		globalTarget := &mockTarget{
			namespaceAware: false,
			loadedImages: []*target.TargetImage{
				newTargetImg("img-shared", ""), // Still runs in ns-keep -> retain!
				newTargetImg("img-orphan", ""), // Runs in no Namespace anymore -> delete!
			},
		}

		p := &Processor{
			Targets:  []target.Target{globalTarget},
			imageMap: make(map[string]*cachedImage),
		}

		p.executeSyftScans([]libk8s.PodInfo{}, allClusterImages)

		if len(globalTarget.removedImages) != 1 {
			t.Fatalf("expects exactly 1 image to delete, but was: %d", len(globalTarget.removedImages))
		}
		if globalTarget.removedImages[0].ImageID != "img-orphan" {
			t.Errorf("expects 'img-orphan', but was: %s", globalTarget.removedImages[0].ImageID)
		}
	})
}
