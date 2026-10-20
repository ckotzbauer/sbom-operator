package target

import (
	"time"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
)

type TargetContext struct {
	Image          *oci.RegistryImage
	Containers     []*libk8s.ContainerInfo
	Pod            *libk8s.PodInfo
	Sbom           string
	Scope          string
	MediaType      string
	DeploymentTime time.Time
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

func NewContext(sbom string, image *oci.RegistryImage, pod *libk8s.PodInfo) *TargetContext {
	return &TargetContext{
		Image:          image,
		Pod:            pod,
		Sbom:           sbom,
		DeploymentTime: time.Now().UTC(),
	}
}

func (c *TargetContext) WithAttestation(scope string, mediaType string) *TargetContext {
	c.Scope = scope
	c.MediaType = mediaType
	return c
}

func (c *TargetContext) WithDeploymentTime(t time.Time) *TargetContext {
	if !t.IsZero() {
		c.DeploymentTime = t.UTC()
	}
	return c
}

func (c *TargetContext) WithContainers(containers []*libk8s.ContainerInfo) *TargetContext {
	c.Containers = containers
	return c
}
