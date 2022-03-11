package target

import (
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
)

type Target interface {
	Initialize()
	ValidateConfig() error
	ProcessSbom(image kubernetes.ContainerImage, sbom string) error
	Cleanup(allImages []kubernetes.ContainerImage)
}
