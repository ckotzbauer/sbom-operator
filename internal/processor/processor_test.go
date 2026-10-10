package processor

import (
	"errors"
	"sync"
	"testing"
	"time"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/stretchr/testify/assert"
)

type testTarget struct {
	err error
}

func (t *testTarget) Initialize() error {
	return nil
}

func (t *testTarget) ValidateConfig() error {
	return nil
}

func (t *testTarget) ProcessSbom(ctx *target.TargetContext) error {
	return t.err
}

func (t *testTarget) LoadImages() ([]*liboci.RegistryImage, error) {
	return nil, nil
}

func (t *testTarget) Remove(images []*liboci.RegistryImage) error {
	return nil
}

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

func TestScanPodSerializesSyftExecution(t *testing.T) {
	p := &Processor{
		K8s: &kubernetes.KubeClient{
			Client: &libk8s.KubeClient{},
		},
		Targets:           []target.Target{&testTarget{err: errors.New("skip annotation update")}},
		imageMap:          make(map[string]bool),
		allowedNamespaces: make(map[string]bool),
	}

	started := make(chan string, 2)
	release := make(chan struct{})
	p.executeSyft = func(img *liboci.RegistryImage) (string, error) {
		started <- img.ImageID
		<-release
		return "sbom", nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.scanPod(testPodInfo("pod-a", "image-a"))
	}()

	select {
	case imageID := <-started:
		assert.Equal(t, "image-a", imageID)
	case <-time.After(time.Second):
		t.Fatal("first scan did not start")
	}

	wg.Add(1)
	secondReady := make(chan struct{})
	go func() {
		defer wg.Done()
		close(secondReady)
		p.scanPod(testPodInfo("pod-b", "image-b"))
	}()
	<-secondReady

	select {
	case imageID := <-started:
		t.Fatalf("scan %s started while another scan was active", imageID)
	case <-time.After(200 * time.Millisecond):
	}

	release <- struct{}{}

	select {
	case imageID := <-started:
		assert.Equal(t, "image-b", imageID)
	case <-time.After(time.Second):
		t.Fatal("second scan did not start")
	}

	release <- struct{}{}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scans did not finish")
	}
}

func testPodInfo(name, imageID string) libk8s.PodInfo {
	return libk8s.PodInfo{
		PodName:      name,
		PodNamespace: "default",
		Annotations:  map[string]string{},
		Containers: []*libk8s.ContainerInfo{
			{
				Name: "container",
				Image: &liboci.RegistryImage{
					Image:   imageID,
					ImageID: imageID,
				},
			},
		},
	}
}
