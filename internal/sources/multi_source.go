package sources

import (
	"fmt"

	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/sirupsen/logrus"
)

// This SBOM source will use multiple SBOM sources to retrieve an appropriate SBOM
// It will iterate over the provided list and choose the first one that provides an SBOM
type MultiSBOMSource struct {
	sources map[string]SBOMSource
}

var _ SBOMSource = (*MultiSBOMSource)(nil)

func (s *MultiSBOMSource) AddSBOMSource(sourceKey string, sbomSource SBOMSource) {
	s.sources[sourceKey] = sbomSource
}

func (s MultiSBOMSource) GetSBOM(img *oci.RegistryImage) (string, error) {
	for sourceKey, v := range s.sources {
		sbom, err := v.GetSBOM(img)
		if err != nil {
			logrus.Warnf("Source %s did not find an appropriate SBOM. See Error above.", sourceKey)
		} else {
			return sbom, nil
		}
	}

	return "", fmt.Errorf("Could not find an SBOM for image %s", img.ImageID)
}
