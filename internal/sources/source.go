package sources

import "github.com/ckotzbauer/libk8soci/pkg/oci"

type SBOMSource interface {
	GetSBOM(img *oci.RegistryImage) (string, error)
}
