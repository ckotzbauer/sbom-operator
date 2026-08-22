package target

import (
	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
)

type TargetContext struct {
	Image     *oci.RegistryImage
	Container *libk8s.ContainerInfo
	Pod       *libk8s.PodInfo
	Sbom      string
}

type Target interface {
	Initialize() error
	ValidateConfig() error
	ProcessSbom(ctx *TargetContext) error
	LoadImages() ([]*oci.RegistryImage, error)
	Remove(images []*oci.RegistryImage) error
}

// DeactivateTarget is an optional extension of Target for backends that can
// deactivate (rather than delete) orphaned images. When ShouldDeactivateOrphans
// returns true, the processor calls Deactivate instead of Remove during orphan
// cleanup, regardless of the global delete-orphan-images flag.
type DeactivateTarget interface {
	Target
	Deactivate(images []*oci.RegistryImage) error
	ShouldDeactivateOrphans() bool
}

func NewContext(sbom string, image *oci.RegistryImage, container *libk8s.ContainerInfo, pod *libk8s.PodInfo) *TargetContext {
	return &TargetContext{image, container, pod, sbom}
}
