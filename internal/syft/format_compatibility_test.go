package syft_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	operatorsyft "github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type formatFamilyContract struct {
	family            string
	supportedVersions func() []string
	defaultVersion    func() string
	decoder           func() sbom.FormatDecoder
}

func formatFamilyContracts() []formatFamilyContract {
	return []formatFamilyContract{
		{
			family:            "cyclonedxjson",
			supportedVersions: cyclonedxjson.SupportedVersions,
			defaultVersion:    func() string { return cyclonedxjson.DefaultEncoderConfig().Version },
			decoder:           cyclonedxjson.NewFormatDecoder,
		},
		{
			family:            "cyclonedxxml",
			supportedVersions: cyclonedxxml.SupportedVersions,
			defaultVersion:    func() string { return cyclonedxxml.DefaultEncoderConfig().Version },
			decoder:           cyclonedxxml.NewFormatDecoder,
		},
		{
			family:            "spdxjson",
			supportedVersions: spdxjson.SupportedVersions,
			defaultVersion:    func() string { return spdxjson.DefaultEncoderConfig().Version },
			decoder:           spdxjson.NewFormatDecoder,
		},
		{
			family:            "spdxtagvalue",
			supportedVersions: spdxtagvalue.SupportedVersions,
			defaultVersion:    func() string { return spdxtagvalue.DefaultEncoderConfig().Version },
			decoder:           spdxtagvalue.NewFormatDecoder,
		},
	}
}

func minimalSBOM() sbom.SBOM {
	return sbom.SBOM{
		Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()},
		Source: source.Description{
			ID:       "format-version-test",
			Name:     "format-version-test",
			Metadata: source.DirectoryMetadata{Path: "."},
		},
		Descriptor: sbom.Descriptor{
			Name:    "sbom-operator-tests",
			Version: "test",
		},
	}
}

// TestPinnedSyftFormatVersionCompatibility is the single intentional snapshot
// of the version contract exposed by this operator. A Syft upgrade that changes
// support or defaults must update this table deliberately.
func TestPinnedSyftFormatVersionCompatibility(t *testing.T) {
	expected := map[string]struct {
		versions       []string
		defaultVersion string
	}{
		"cyclonedxjson": {versions: []string{"1.2", "1.3", "1.4", "1.5", "1.6", "1.7"}, defaultVersion: "1.7"},
		"cyclonedxxml":  {versions: []string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7"}, defaultVersion: "1.7"},
		"spdxjson":      {versions: []string{"2.2", "2.3", "3.0"}, defaultVersion: "2.3"},
		"spdxtagvalue":  {versions: []string{"2.1", "2.2", "2.3"}, defaultVersion: "2.3"},
	}

	for _, contract := range formatFamilyContracts() {
		t.Run(contract.family, func(t *testing.T) {
			want := expected[contract.family]
			assert.ElementsMatch(t, want.versions, contract.supportedVersions())
			assert.Equal(t, want.defaultVersion, contract.defaultVersion())
			assert.Contains(t, contract.supportedVersions(), contract.defaultVersion())
		})
	}
}

func TestFormatVersionHelpUsesPinnedSyftMetadata(t *testing.T) {
	help := operatorsyft.FormatVersionHelp()
	for _, contract := range formatFamilyContracts() {
		assert.Contains(t, help, strings.Join(contract.supportedVersions(), ", "))
		assert.Contains(t, help, "default "+contract.defaultVersion())
	}
}

// TestSupportedFormatVersionsAreEmitted proves the complete path from operator
// resolution through Syft encoding by reading the declaration from each output.
func TestSupportedFormatVersionsAreEmitted(t *testing.T) {
	for _, contract := range formatFamilyContracts() {
		for _, version := range contract.supportedVersions() {
			t.Run(fmt.Sprintf("%s-%s", contract.family, version), func(t *testing.T) {
				resolved := operatorsyft.ResolveFormatVersionWithFamily(contract.family, version)
				require.NoError(t, resolved.Err)
				assert.Equal(t, contract.family, resolved.Family)

				encoder, err := operatorsyft.GetEncoderWithVersion(resolved, contract.family)
				require.NoError(t, err)

				var output bytes.Buffer
				require.NoError(t, encoder.Encode(&output, minimalSBOM()))

				formatID, emittedVersion := contract.decoder().Identify(bytes.NewReader(output.Bytes()))
				assert.Equal(t, encoder.ID(), formatID)
				assert.Equal(t, version, emittedVersion)
			})
		}
	}
}
