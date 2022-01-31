package target

import (
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
)

type Target interface {
	Initialize()
	ValidateConfig() error
	ProcessSbom(imageID kubernetes.ContainerImage, sbom string)
	Cleanup(allImages []string)
}
