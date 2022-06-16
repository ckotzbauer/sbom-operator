package target

import (
	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
)

type Target interface {
	Initialize()
	ValidateConfig() error
	ProcessSbom(image libk8s.KubeImage, sbom string) error
	Cleanup(allImages []libk8s.KubeImage)
}
