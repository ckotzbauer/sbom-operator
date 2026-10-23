package target

import (
	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	internaloci "github.com/ckotzbauer/sbom-operator/internal/oci"
)

type TargetContext struct {
	Image       *oci.RegistryImage
	Containers  []*libk8s.ContainerInfo
	Pod         *libk8s.PodInfo
	Attestation *internaloci.AttestationSbom
}

type Target interface {
	Initialize() error
	ValidateConfig() error
	ProcessSbom(ctx *TargetContext) error
	LoadImages() ([]*TargetImage, error)
	Remove(images []*TargetImage) error
	// Returns whether the Target is able to persists the namespace information and hence provide it in #LoadImages
	// In case the Target is not namespace-aware, #Remove (and Deactive) methods would be called without namespace information
	// and particularily it would be always called for each image regardless in which namespace it was located.
	IsNamespaceAware() bool
}

type TargetImage struct {
	*oci.RegistryImage
	Namespace string
}

// DeactivateTarget is an optional extension of Target for backends that can
// deactivate (rather than delete) orphaned images. When ShouldDeactivateOrphans
// returns true, the processor calls Deactivate instead of Remove during orphan
// cleanup, regardless of the global delete-orphan-images flag.
type DeactivateTarget interface {
	Target
	Deactivate(images []*TargetImage) error
	ShouldDeactivateOrphans() bool
}

func NewContext(image *oci.RegistryImage, pod *libk8s.PodInfo, attestation *internaloci.AttestationSbom) *TargetContext {
	return &TargetContext{
		Image:       image,
		Pod:         pod,
		Attestation: attestation,
	}
}

func (c *TargetContext) WithContainers(containers []*libk8s.ContainerInfo) *TargetContext {
	c.Containers = containers
	return c
}
