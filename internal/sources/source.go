package sources

import (
	"fmt"

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

	if sourceOption == "syft" {
		return syft.New(internal.OperatorConfig.Format, libstandard.ToMap(internal.OperatorConfig.RegistryProxies), appVersion), nil
	} else if sourceOption == "cosign" {
		return cosign.New(), nil
	} else {
		return nil, fmt.Errorf("unknown source option `%s` provided", sourceOption)
	}
}
