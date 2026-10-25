package processor

import (
	"testing"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/stretchr/testify/assert"
)

func TestCollectPodImagesKeepsImagesAfterAnalysisNeeded(t *testing.T) {
	p := &Processor{K8s: &kubernetes.KubeClient{}}
	busybox := &liboci.RegistryImage{ImageID: "busybox@sha256:1"}
	alpine := &liboci.RegistryImage{ImageID: "alpine@sha256:2"}
	info := libk8s.PodInfo{
		Containers: []*libk8s.ContainerInfo{
			{Name: "main", Image: busybox},
			{Name: "sidecar", Image: alpine},
		},
	}

	images, needsAnalysis := p.collectPodImages(info, nil)

	assert.True(t, needsAnalysis)
	assert.Equal(t, []*liboci.RegistryImage{busybox, alpine}, images)
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
