package sources

import (
	"fmt"
	"strings"

	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/libstandard"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/sources/cosign"
	"github.com/ckotzbauer/sbom-operator/internal/sources/syft"
)

type SBOMSource interface {
	GetSBOM(img *oci.RegistryImage) (string, error)
}

func InitSource(appVersion string) (SBOMSource, error) {
	sourceOption := internal.OperatorConfig.Source
	// set syft as default source
	if sourceOption == "" {
		sourceOption = "syft"
	}

	// multiple sources are supported, they are separated by ","
	sources := strings.Split(sourceOption, ",")
	multiSBOMSource := &MultiSBOMSource{}

	for _, sourceKey := range sources {
		switch sourceKey {
		case "syft":
			multiSBOMSource.AddSBOMSource(
				sourceKey,
				syft.New(internal.OperatorConfig.Format, libstandard.ToMap(internal.OperatorConfig.RegistryProxies), appVersion),
			)
		case "cosign":
			multiSBOMSource.AddSBOMSource(
				sourceKey,
				cosign.New(),
			)
		default:
			return nil, fmt.Errorf("unknown source option `%s` provided", sourceOption)
		}

	}

	return multiSBOMSource, nil
}
