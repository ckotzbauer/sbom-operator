package target

import "github.com/ckotzbauer/sbom-operator/internal"

type Target interface {
	Initialize()
	ValidateConfig() error
	ProcessSbom(image internal.ContainerImage, sbom string) error
	Cleanup(allImages []internal.ContainerImage)
}
