package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	internaloci "github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestInitTargets(t *testing.T) {
	internal.OperatorConfig = &internal.Config{
		Targets:       []string{"dtrack", "configmap"},
		DtrackBaseUrl: "http://localhost",
		DtrackApiKey:  "api",
		Format:        "cyclonedx",
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

	// failImage makes ProcessSbom fail for the given ImageID
	failImage       string
	processedImages []string

	// rejectMediaType makes ProcessSbom return target.ErrUnsupportedSbom for that media type
	rejectMediaType types.MediaType
	received        []*internaloci.AttestationSbom
}

func (m *mockTarget) Initialize() error { return nil }
func (m *mockTarget) ValidateConfig() error {
	return nil
}
func (m *mockTarget) ProcessSbom(ctx context.Context, tctx *target.TargetContext) error {
	m.processedImages = append(m.processedImages, tctx.Image.ImageID)
	m.received = append(m.received, tctx.Attestation)
	if m.rejectMediaType != "" && tctx.Attestation.MediaType == m.rejectMediaType {
		return fmt.Errorf("%w: %s", target.ErrUnsupportedSbom, m.rejectMediaType)
	}
	if m.failImage != "" && tctx.Image.ImageID == m.failImage {
		return fmt.Errorf("upload failed for %s", m.failImage)
	}
	return nil
}
func (m *mockTarget) IsNamespaceAware() bool { return m.namespaceAware }
func (m *mockTarget) LoadImages(ctx context.Context) ([]*target.TargetImage, error) {
	return m.loadedImages, m.loadErr
}
func (m *mockTarget) Remove(ctx context.Context, images []*target.TargetImage) error {
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

func (m *mockDeactivateTarget) Deactivate(ctx context.Context, images []*target.TargetImage) error {
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

func TestCollectAllImages_IncludesEveryContainerImage(t *testing.T) {
	// Regression test for #1063: during initial sync, allImages must contain
	// every running container's image, regardless of whether the pod needs
	// analysis. Otherwise the SBOMs of containers after the first one in a pod
	// are removed as orphans.
	pods := []libk8s.PodInfo{
		{
			PodNamespace: "ns-1",
			Containers: []*libk8s.ContainerInfo{
				{Name: "app", Image: &liboci.RegistryImage{ImageID: "img-app"}},
				{Name: "sidecar", Image: &liboci.RegistryImage{ImageID: "img-sidecar"}},
			},
		},
	}

	allImages := collectAllImages(pods)

	images := allImages["ns-1"]
	if len(images) != 2 {
		t.Fatalf("expected 2 container images in allImages, got %d", len(images))
	}
	var ids []string
	for _, img := range images {
		ids = append(ids, img.ImageID)
	}
	assert.ElementsMatch(t, []string{"img-app", "img-sidecar"}, ids)
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

func TestScanPodAnnotatesOnlySuccessfulContainersAndRetries(t *testing.T) {
	internal.OperatorConfig = &internal.Config{}

	kc, updated := fakeKubeClient(t, podWith("app-pod-1", "prod", "img-good", "img-bad"))

	mt := &mockTarget{failImage: "img-bad"}
	p := &Processor{
		K8s:     kc,
		Targets: []target.Target{mt},
		imageMap: map[string]*cachedImage{
			"img-good": {attestations: []*internaloci.AttestationSbom{{Scope: internaloci.ScopeAll, Sbom: "{}"}}, namespaces: map[string]struct{}{}},
			"img-bad":  {attestations: []*internaloci.AttestationSbom{{Scope: internaloci.ScopeAll, Sbom: "{}"}}, namespaces: map[string]struct{}{}},
		},
	}

	pod := libk8s.PodInfo{
		PodName:      "app-pod-1",
		PodNamespace: "prod",
		Annotations:  map[string]string{},
		Containers: []*libk8s.ContainerInfo{
			{Name: "c1", Image: &liboci.RegistryImage{ImageID: "img-good"}},
			{Name: "c2", Image: &liboci.RegistryImage{ImageID: "img-bad"}},
		},
	}

	// First attempt: c1 succeeds, c2 fails.
	p.scanPod(pod)
	assert.Equal(t, "img-good", updated["app-pod-1"].Annotations["ckotzbauer.sbom-operator.io/c1"])
	if _, ok := updated["app-pod-1"].Annotations["ckotzbauer.sbom-operator.io/c2"]; ok {
		t.Fatal("failed container c2 was annotated as processed")
	}

	// Retry (as the periodic resync would do): c1 is skipped via its annotation,
	// c2 is uploaded again because it was never marked as processed.
	p.scanPod(pod)
	assert.ElementsMatch(t, []string{"img-good", "img-bad", "img-bad"}, mt.processedImages)
	if _, ok := updated["app-pod-1"].Annotations["ckotzbauer.sbom-operator.io/c2"]; ok {
		t.Fatal("failed container c2 was annotated as processed after retry")
	}
}

func TestResolveSyftCatalogers(t *testing.T) {
	origConfig := internal.OperatorConfig
	t.Cleanup(func() {
		internal.OperatorConfig = origConfig
	})

	t.Run("Nil OperatorConfig returns nil safely", func(t *testing.T) {
		internal.OperatorConfig = nil
		assert.Nil(t, resolveSyftCatalogers(nil))
	})

	t.Run("Matching scope rule wins (case-insensitive contains) and overrides global catalogers", func(t *testing.T) {
		internal.OperatorConfig = &internal.Config{
			FetchOciAttestations:     true,
			SyftCatalogers:           []string{"golang"},
			SyftCatalogersScopeRules: []string{"application:os,alpine", "infra:python"},
		}
		attestations := []*internaloci.AttestationSbom{
			{Scope: "my-APPLICATION-sbom"},
		}

		got := resolveSyftCatalogers(attestations)
		assert.Equal(t, []string{"os", "alpine"}, got)
	})

	t.Run("Comma-split environment variable tokens are grouped into preceding rule", func(t *testing.T) {
		// Simulates []string flag/env splitting "application:os,alpine,infra:golang" on commas
		internal.OperatorConfig = &internal.Config{
			FetchOciAttestations:     true,
			SyftCatalogersScopeRules: []string{"application:os", "alpine", "infra:golang"},
		}
		attestations := []*internaloci.AttestationSbom{
			{Scope: "application"},
		}

		got := resolveSyftCatalogers(attestations)
		assert.Equal(t, []string{"os", "alpine"}, got)
	})

	t.Run("Rule ordering: first matching rule wins", func(t *testing.T) {
		internal.OperatorConfig = &internal.Config{
			FetchOciAttestations:     true,
			SyftCatalogersScopeRules: []string{"app:os", "application:golang"},
		}
		attestations := []*internaloci.AttestationSbom{
			{Scope: "application"},
		}

		got := resolveSyftCatalogers(attestations)
		assert.Equal(t, []string{"os"}, got)
	})

	t.Run("Malformed scope rules are ignored and fall back to global catalogers", func(t *testing.T) {
		internal.OperatorConfig = &internal.Config{
			FetchOciAttestations:     true,
			SyftCatalogers:           []string{"debian"},
			SyftCatalogersScopeRules: []string{"orphan-token", ":missing-scope", "empty-cat:", "   "},
		}
		attestations := []*internaloci.AttestationSbom{
			{Scope: "application"},
		}

		got := resolveSyftCatalogers(attestations)
		assert.Equal(t, []string{"debian"}, got)
	})

	t.Run("No matching scope rule falls back to global catalogers", func(t *testing.T) {
		internal.OperatorConfig = &internal.Config{
			FetchOciAttestations:     true,
			SyftCatalogers:           []string{"os"},
			SyftCatalogersScopeRules: []string{"infra:golang"},
		}
		attestations := []*internaloci.AttestationSbom{
			{Scope: "application"},
		}

		got := resolveSyftCatalogers(attestations)
		assert.Equal(t, []string{"os"}, got)
	})

	t.Run("No attestations present falls back to global catalogers", func(t *testing.T) {
		internal.OperatorConfig = &internal.Config{
			FetchOciAttestations:     true,
			SyftCatalogers:           []string{"golang,javascript"},
			SyftCatalogersScopeRules: []string{"application:os"},
		}

		got := resolveSyftCatalogers(nil)
		assert.Equal(t, []string{"golang,javascript"}, got)
	})
}

func TestRunCtxDefaultsToBackground(t *testing.T) {
	p := &Processor{}
	assert.NotNil(t, p.runCtx())
	assert.NoError(t, p.runCtx().Err())
}

func TestRunCtxReturnsProcessorContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Processor{ctx: ctx}
	cancel()
	assert.ErrorIs(t, p.runCtx().Err(), context.Canceled)
}

// podWith returns a pod whose containers c1, c2, ... run the given image IDs.
func podWith(name, namespace string, imageIDs ...string) *corev1.Pod {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	for i, id := range imageIDs {
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses,
			corev1.ContainerStatus{Name: fmt.Sprintf("c%d", i+1), ImageID: id})
	}
	return pod
}

// podInfo is the scanner's view of a pod from podWith, without annotations.
func podInfo(pod *corev1.Pod) libk8s.PodInfo {
	info := libk8s.PodInfo{PodName: pod.Name, PodNamespace: pod.Namespace, Annotations: map[string]string{}}
	for _, cs := range pod.Status.ContainerStatuses {
		info.Containers = append(info.Containers, &libk8s.ContainerInfo{Name: cs.Name, Image: &liboci.RegistryImage{ImageID: cs.ImageID}})
	}
	return info
}

// fakeKubeClient serves GET and PUT for the given pods. The returned map holds
// the last pod written per name (empty until the operator annotates it).
func fakeKubeClient(t *testing.T, pods ...*corev1.Pod) (*kubernetes.KubeClient, map[string]*corev1.Pod) {
	t.Helper()
	updated := make(map[string]*corev1.Pod)
	for _, p := range pods {
		updated[p.Name] = &corev1.Pod{}
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for _, p := range pods {
			if !strings.HasSuffix(r.URL.Path, "/namespaces/"+p.Namespace+"/pods/"+p.Name) {
				continue
			}
			switch r.Method {
			case http.MethodGet:
				_ = json.NewEncoder(w).Encode(p)
			case http.MethodPut:
				u := &corev1.Pod{}
				_ = json.NewDecoder(r.Body).Decode(u)
				updated[p.Name] = u
				_ = json.NewEncoder(w).Encode(u)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(ts.Close)

	clientset, err := k8s.NewForConfig(&rest.Config{
		Host:          ts.URL,
		ContentConfig: rest.ContentConfig{ContentType: "application/json"},
	})
	require.NoError(t, err)
	return &kubernetes.KubeClient{Client: &libk8s.KubeClient{Client: clientset}}, updated
}

type fakeScanner struct {
	sbom       string
	err        error
	calls      int
	catalogers []string
	mediaType  types.MediaType
}

func (f *fakeScanner) MediaType() types.MediaType {
	if f.mediaType == "" {
		return internaloci.CycloneDXJSONMediaType
	}
	return f.mediaType
}

func (f *fakeScanner) ExecuteSyft(img *liboci.RegistryImage, catalogers []string) (string, error) {
	f.calls++
	f.catalogers = catalogers
	return f.sbom, f.err
}

var (
	spdxSbom  = &internaloci.AttestationSbom{Scope: internaloci.ScopeAll, MediaType: internaloci.SPDXJSONMediaType, Sbom: "{spdx}"}
	spdxSbom2 = &internaloci.AttestationSbom{Scope: internaloci.ScopeAll, MediaType: internaloci.SPDXJSONMediaType, Sbom: "{spdx2}"}
	cdxSbom   = &internaloci.AttestationSbom{Scope: internaloci.ScopeAll, MediaType: internaloci.CycloneDXJSONMediaType, Sbom: "{cdx}"}
)

// fallbackProcessor returns a processor with dt (rejects SPDX) and cm (accepts all), and
// the image "img" cached from namespace "other" with the given attestations.
func fallbackProcessor(kc *kubernetes.KubeClient, sc *fakeScanner, atts ...*internaloci.AttestationSbom) (*Processor, *mockTarget, *mockTarget) {
	internal.OperatorConfig = &internal.Config{}
	dt := &mockTarget{rejectMediaType: internaloci.SPDXJSONMediaType}
	cm := &mockTarget{}
	p := &Processor{
		K8s:     kc,
		sy:      sc,
		Targets: []target.Target{dt, cm},
		imageMap: map[string]*cachedImage{
			"img": {attestations: atts, namespaces: map[string]struct{}{"other": {}}},
		},
	}
	return p, dt, cm
}

func sbomsOf(atts []*internaloci.AttestationSbom) []string {
	out := make([]string, 0, len(atts))
	for _, a := range atts {
		out = append(out, a.Sbom)
	}
	return out
}

const annotationC1 = "ckotzbauer.sbom-operator.io/c1"

func TestScanPodFallsBackToSyftOnlyForRejectingTarget(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, updated := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}"}
	p, dt, cm := fallbackProcessor(kc, sc, spdxSbom)

	p.scanPod(podInfo(pod))

	assert.Equal(t, 1, sc.calls)
	assert.Equal(t, []string{"{spdx}", "{syft}"}, sbomsOf(dt.received))
	assert.Equal(t, types.MediaType(internaloci.CycloneDXJSONMediaType), dt.received[1].MediaType)
	assert.Equal(t, internaloci.ScopeAll, dt.received[1].Scope)
	assert.Equal(t, []string{"{spdx}"}, sbomsOf(cm.received))
	assert.Equal(t, "img", updated["pod-a"].Annotations[annotationC1])
	require.NotNil(t, p.imageMap["img"].fallback)
	assert.Equal(t, "{syft}", p.imageMap["img"].fallback.Sbom)
}

func TestScanPodReusesFallbackInOtherNamespace(t *testing.T) {
	podA := podWith("pod-a", "prod", "img")
	podB := podWith("pod-b", "staging", "img")
	kc, updated := fakeKubeClient(t, podA, podB)
	sc := &fakeScanner{sbom: "{syft}"}
	p, dt, cm := fallbackProcessor(kc, sc, spdxSbom)

	p.scanPod(podInfo(podA))
	p.scanPod(podInfo(podB))

	assert.Equal(t, 1, sc.calls)
	assert.Equal(t, []string{"{spdx}", "{syft}", "{spdx}", "{syft}"}, sbomsOf(dt.received))
	assert.Equal(t, []string{"{spdx}", "{spdx}"}, sbomsOf(cm.received))
	assert.Equal(t, "img", updated["pod-b"].Annotations[annotationC1])
}

func TestScanPodFallbackScanFailureIsRetried(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, updated := fakeKubeClient(t, pod)
	sc := &fakeScanner{err: errors.New("syft failed")}
	p, _, _ := fallbackProcessor(kc, sc, spdxSbom)

	p.scanPod(podInfo(pod))
	_, annotated := updated["pod-a"].Annotations[annotationC1]
	assert.False(t, annotated, "pod annotated although the fallback scan failed")
	_, processed := p.imageMap["img"].namespaces["prod"]
	assert.False(t, processed, "namespace cached as processed although the fallback scan failed")

	p.scanPod(podInfo(pod))
	assert.Equal(t, 2, sc.calls)
}

func TestScanPodFallbackUploadFailureIsRetried(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, updated := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}"}
	p, dt, _ := fallbackProcessor(kc, sc, spdxSbom)
	dt.failImage = "img"

	p.scanPod(podInfo(pod))

	assert.Equal(t, []string{"{spdx}", "{syft}"}, sbomsOf(dt.received))
	_, annotated := updated["pod-a"].Annotations[annotationC1]
	assert.False(t, annotated, "pod annotated although the fallback upload failed")
}

func TestScanPodFallbackSentOnceForTwoRejectedSboms(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, updated := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}"}
	p, dt, _ := fallbackProcessor(kc, sc, spdxSbom, spdxSbom2)

	p.scanPod(podInfo(pod))

	assert.Equal(t, 1, sc.calls)
	assert.Equal(t, []string{"{spdx}", "{spdx2}", "{syft}"}, sbomsOf(dt.received))
	assert.Equal(t, "img", updated["pod-a"].Annotations[annotationC1])
}

func TestScanPodNoFallbackWhenAWholeImageSbomWasAccepted(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, updated := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}"}
	p, dt, _ := fallbackProcessor(kc, sc, cdxSbom, spdxSbom)

	p.scanPod(podInfo(pod))

	assert.Equal(t, 0, sc.calls)
	assert.Equal(t, []string{"{cdx}", "{spdx}"}, sbomsOf(dt.received))
	assert.Equal(t, "img", updated["pod-a"].Annotations[annotationC1])
}

func TestScanPodScopedRejectDoesNotFallBack(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, updated := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}"}
	scoped := &internaloci.AttestationSbom{Scope: "application", MediaType: internaloci.SPDXJSONMediaType, Sbom: "{app}"}
	p, dt, _ := fallbackProcessor(kc, sc, cdxSbom, scoped)

	p.scanPod(podInfo(pod))

	assert.Equal(t, 0, sc.calls)
	assert.Equal(t, []string{"{cdx}", "{app}"}, sbomsOf(dt.received))
	assert.Equal(t, "img", updated["pod-a"].Annotations[annotationC1])
}

// A retry after a failed upload reuses the cached fallback instead of scanning again.
func TestScanPodFallbackReusedAfterUploadFailure(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, _ := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}"}
	p, dt, _ := fallbackProcessor(kc, sc, spdxSbom)
	dt.failImage = "img"

	p.scanPod(podInfo(pod))
	p.scanPod(podInfo(pod))

	assert.Equal(t, 1, sc.calls)
	assert.Equal(t, []string{"{spdx}", "{syft}", "{spdx}", "{syft}"}, sbomsOf(dt.received))
	require.NotNil(t, p.imageMap["img"].fallback)
	assert.Equal(t, "{syft}", p.imageMap["img"].fallback.Sbom)
	assert.NotContains(t, p.imageMap["img"].namespaces, "prod")
}

func TestScanPodSyftResultReusedAfterUploadFailure(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, _ := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}"}
	p, _, cm := fallbackProcessor(kc, sc)
	p.imageMap = map[string]*cachedImage{}
	cm.failImage = "img"

	p.scanPod(podInfo(pod))
	p.scanPod(podInfo(pod))

	assert.Equal(t, 1, sc.calls)
	assert.Equal(t, []string{"{syft}", "{syft}"}, sbomsOf(cm.received))
}

func TestScanPodPendingScanReusedInOtherNamespace(t *testing.T) {
	podA := podWith("pod-a", "prod", "img")
	podB := podWith("pod-b", "staging", "img")
	kc, updated := fakeKubeClient(t, podA, podB)
	sc := &fakeScanner{sbom: "{syft}"}
	p, _, cm := fallbackProcessor(kc, sc)
	p.imageMap = map[string]*cachedImage{}
	cm.failImage = "img"

	p.scanPod(podInfo(podA))
	cm.failImage = ""
	p.scanPod(podInfo(podB))

	assert.Equal(t, 1, sc.calls)
	assert.Contains(t, p.imageMap["img"].namespaces, "staging")
	assert.NotContains(t, p.imageMap["img"].namespaces, "prod")
	assert.Equal(t, "img", updated["pod-b"].Annotations[annotationC1])
	_, annotated := updated["pod-a"].Annotations[annotationC1]
	assert.False(t, annotated)
}

func TestImageRemovedFreesPendingEntry(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, _ := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}"}
	p, _, cm := fallbackProcessor(kc, sc)
	p.imageMap = map[string]*cachedImage{}
	cm.failImage = "img"

	p.scanPod(podInfo(pod))
	require.Contains(t, p.imageMap, "img")
	p.imageRemoved("img", "prod")

	assert.NotContains(t, p.imageMap, "img")
}

// Scope rules are matched as for a regular scan: the rejected whole-image SBOM
// must not match, but the image's scoped SBOMs do.
func TestScanPodFallbackResolvesCatalogersFromScopedSboms(t *testing.T) {
	appSbom := &internaloci.AttestationSbom{Scope: "application", MediaType: internaloci.CycloneDXJSONMediaType, Sbom: "{app}"}

	t.Run("whole-image SBOM does not match a scope rule", func(t *testing.T) {
		pod := podWith("pod-a", "prod", "img")
		kc, _ := fakeKubeClient(t, pod)
		sc := &fakeScanner{sbom: "{syft}"}
		p, _, _ := fallbackProcessor(kc, sc, spdxSbom)
		internal.OperatorConfig.SyftCatalogers = []string{"debian"}
		internal.OperatorConfig.SyftCatalogersScopeRules = []string{"all:golang"}

		p.scanPod(podInfo(pod))

		assert.Equal(t, []string{"debian"}, sc.catalogers)
	})

	t.Run("scoped SBOM matches a scope rule", func(t *testing.T) {
		pod := podWith("pod-a", "prod", "img")
		kc, _ := fakeKubeClient(t, pod)
		sc := &fakeScanner{sbom: "{syft}"}
		p, _, _ := fallbackProcessor(kc, sc, spdxSbom, appSbom)
		internal.OperatorConfig.SyftCatalogers = []string{"debian"}
		internal.OperatorConfig.SyftCatalogersScopeRules = []string{"all:golang", "application:os"}

		p.scanPod(podInfo(pod))

		assert.Equal(t, []string{"os"}, sc.catalogers)
	})
}

func TestScanPodFallbackUsesScannerMediaType(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, _ := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}", mediaType: internaloci.CycloneDXXMLMediaType}
	p, dt, _ := fallbackProcessor(kc, sc, spdxSbom)

	p.scanPod(podInfo(pod))

	require.Len(t, dt.received, 2)
	assert.Equal(t, types.MediaType(internaloci.CycloneDXXMLMediaType), dt.received[1].MediaType)
}

func TestScanPodSyftSbomUsesScannerMediaType(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, _ := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}", mediaType: internaloci.CycloneDXXMLMediaType}
	p, dt, _ := fallbackProcessor(kc, sc)
	p.imageMap = map[string]*cachedImage{}

	p.scanPod(podInfo(pod))

	require.Len(t, dt.received, 1)
	assert.Equal(t, types.MediaType(internaloci.CycloneDXXMLMediaType), dt.received[0].MediaType)
}

func TestValidateDtrackFormat(t *testing.T) {
	valid := []struct{ format, formatVersion string }{
		{"cyclonedx", ""}, {"cyclone", ""}, {"cyclonedxxml", ""}, {"cyclonedxjson", ""}, {"json", "1.5"},
	}
	for _, tt := range valid {
		assert.NoError(t, validateDtrackFormat(tt.format, tt.formatVersion), "%s/%s", tt.format, tt.formatVersion)
	}
	for _, format := range []string{"json", "spdxjson", "text", "", "1.6", " cyclonedx"} {
		err := validateDtrackFormat(format, "")
		require.Error(t, err, format)
		assert.Contains(t, err.Error(), "dependency-track only accepts CycloneDX")
	}
}

func TestScanPodFallbackSharedByTwoRejectingTargets(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, updated := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}"}
	p, dt1, cm := fallbackProcessor(kc, sc, spdxSbom)
	dt2 := &mockTarget{rejectMediaType: internaloci.SPDXJSONMediaType}
	p.Targets = []target.Target{dt1, dt2, cm}

	p.scanPod(podInfo(pod))

	assert.Equal(t, 1, sc.calls)
	assert.Equal(t, []string{"{spdx}", "{syft}"}, sbomsOf(dt1.received))
	assert.Equal(t, []string{"{spdx}", "{syft}"}, sbomsOf(dt2.received))
	assert.Equal(t, []string{"{spdx}"}, sbomsOf(cm.received))
	assert.Equal(t, "img", updated["pod-a"].Annotations[annotationC1])
}

// fallbackLogs returns the log entries a scanPod run wrote, at all levels.
func fallbackLogs(t *testing.T, run func()) []*logrus.Entry {
	t.Helper()
	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)
	run()
	return hook.AllEntries()
}

func TestScanPodFallbackLogsRejectionOnce(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, _ := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}"}
	p, _, _ := fallbackProcessor(kc, sc, spdxSbom)

	entries := fallbackLogs(t, func() { p.scanPod(podInfo(pod)) })

	var mentions []*logrus.Entry
	for _, e := range entries {
		if err, ok := e.Data[logrus.ErrorKey].(error); ok && errors.Is(err, target.ErrUnsupportedSbom) {
			mentions = append(mentions, e)
		}
	}
	require.Len(t, mentions, 1, "the rejection is logged exactly once")
	assert.Equal(t, logrus.InfoLevel, mentions[0].Level)
	assert.Contains(t, mentions[0].Message, "Falling back to a Syft SBOM of image img for target")
}

func TestScanPodFallbackScanFailureLogsSkippedTargets(t *testing.T) {
	pod := podWith("pod-a", "prod", "img")
	kc, _ := fakeKubeClient(t, pod)
	sc := &fakeScanner{err: errors.New("syft failed")}
	p, dt1, cm := fallbackProcessor(kc, sc, spdxSbom)
	dt2 := &mockTarget{rejectMediaType: internaloci.SPDXJSONMediaType}
	p.Targets = []target.Target{dt1, dt2, cm}

	entries := fallbackLogs(t, func() { p.scanPod(podInfo(pod)) })

	var failures []*logrus.Entry
	for _, e := range entries {
		if strings.Contains(e.Message, "Fallback scan of image img failed") {
			failures = append(failures, e)
		}
	}
	require.Len(t, failures, 1)
	assert.Equal(t, logrus.WarnLevel, failures[0].Level)
	assert.Contains(t, failures[0].Message, "skipped targets: [*processor.mockTarget *processor.mockTarget]")
	assert.Equal(t, 1, sc.calls)
}

func TestScanPodInternal_ForceRescanHealsAnnotatedPodDrift(t *testing.T) {
	origConfig := internal.OperatorConfig
	t.Cleanup(func() { internal.OperatorConfig = origConfig })
	internal.OperatorConfig = &internal.Config{}

	const imageID = "registry.example.io/dlcm/cc-shell@sha256:1dc026e889"

	pod := podWith("cc-shell-abc", "dlcm", imageID)
	kc, updated := fakeKubeClient(t, pod)
	sc := &fakeScanner{err: errors.New("syft must not be called when cache is populated")}
	mt := &mockTarget{}
	p := &Processor{
		K8s:      kc,
		sy:       sc,
		Targets:  []target.Target{mt},
		imageMap: make(map[string]*cachedImage),
	}

	// Annotate the pod through the real KubeClient so HasAnnotation matches the configured key format
	initialInfo := podInfo(pod)
	kc.UpdatePodAnnotation(initialInfo, []string{initialInfo.Containers[0].Name})
	updatedPod := updated[pod.Name]
	require.NotEmpty(t, updatedPod.Annotations)

	annotatedInfo := podInfo(pod)
	annotatedInfo.Annotations = updatedPod.Annotations
	require.True(t, kc.HasAnnotation(annotatedInfo.Annotations, annotatedInfo.Containers[0]))

	p.imageScanned("dlcm", imageID, []*internaloci.AttestationSbom{cdxSbom})

	// Normal scan skips annotated/cached pod
	p.scanPodInternal(annotatedInfo, false)
	assert.Empty(t, mt.received, "expected regular scan to skip annotated & cached pod")
	assert.Equal(t, 0, sc.calls)

	// Forced drift rescan dispatches cached SBOM without re-running Syft
	p.scanPodInternal(annotatedInfo, true)
	assert.Equal(t, []string{"{cdx}"}, sbomsOf(mt.received), "expected forceRescan to re-process pod and heal target drift")
	assert.Equal(t, 0, sc.calls)
}

func TestScanPodInternal_ForceRescanReusesCachedFallback(t *testing.T) {
	origConfig := internal.OperatorConfig
	t.Cleanup(func() { internal.OperatorConfig = origConfig })

	pod := podWith("pod-a", "dlcm", "img")
	kc, updated := fakeKubeClient(t, pod)
	sc := &fakeScanner{sbom: "{syft}"}
	p, dt, cm := fallbackProcessor(kc, sc, spdxSbom)

	// Initial scan generates and caches the Syft fallback for dt and annotates the pod
	p.scanPod(podInfo(pod))
	require.Equal(t, 1, sc.calls)
	require.Equal(t, "img", updated["pod-a"].Annotations[annotationC1])

	annotatedInfo := podInfo(pod)
	annotatedInfo.Annotations = updated["pod-a"].Annotations
	dt.received = nil
	cm.received = nil

	// Forced rescan must re-dispatch both cached attestations and cached fallback without invoking Syft again
	p.scanPodInternal(annotatedInfo, true)
	assert.Equal(t, 1, sc.calls, "expected forceRescan to reuse cached fallback without running Syft again")
	assert.Equal(t, []string{"{spdx}", "{syft}"}, sbomsOf(dt.received))
	assert.Equal(t, []string{"{spdx}"}, sbomsOf(cm.received))
}
