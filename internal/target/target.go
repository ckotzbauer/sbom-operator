package target

import (
	libk8s "github.com/ckotzbauer/libk8soci/pkg/oci"
)

type Target interface {
	Initialize()
	ValidateConfig() error
	ProcessSbom(image *libk8s.RegistryImage, sbom string, podNamespace string) error
	LoadImages() []*libk8s.RegistryImage
	Remove(images []*libk8s.RegistryImage)
}
