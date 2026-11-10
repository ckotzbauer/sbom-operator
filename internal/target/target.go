package target

import (
	"time"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	internaloci "github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type TargetContext struct {
	Image           *oci.RegistryImage
	Containers      []*libk8s.ContainerInfo
	Pod             *libk8s.PodInfo
	Attestation     *internaloci.AttestationSbom
	DeploymentTime  time.Time // Birth date, i.e. first deployment
	PodCreationTime time.Time // Pod creation timestamp. Useful for rollbacks.
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

// FormatCapableTarget can be implemented by targets that only accept specific SBOM media types.
// Targets that do not implement this interface (or return an empty slice) accept any SBOM format.
type FormatCapableTarget interface {
	SupportedMediaTypes() []types.MediaType
}

func NewContext(image *oci.RegistryImage, pod *libk8s.PodInfo, attestation *internaloci.AttestationSbom, deploymentTime time.Time, podCreationTime time.Time, containers []*libk8s.ContainerInfo) *TargetContext {
	return &TargetContext{
		Image:           image,
		Pod:             pod,
		Attestation:     attestation,
		DeploymentTime:  deploymentTime,
		PodCreationTime: podCreationTime,
		Containers:      containers,
	}
}
