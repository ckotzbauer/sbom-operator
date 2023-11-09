package syft

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/github"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/table"
	"github.com/anchore/syft/syft/format/text"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/syft/source"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/sirupsen/logrus"
)

type Syft struct {
	sbomFormat       string
	resolveVersion   func() string
	proxyRegistryMap map[string]string
}

func New(sbomFormat string, proxyRegistryMap map[string]string) *Syft {
	return &Syft{
		sbomFormat:       sbomFormat,
		resolveVersion:   getSyftVersion,
		proxyRegistryMap: proxyRegistryMap,
	}
}

func (s Syft) WithVersion(version string) Syft {
	s.resolveVersion = func() string { return version }
	return s
}

func (s *Syft) ExecuteSyft(img *oci.RegistryImage) (string, error) {
	logrus.Infof("Processing image %s", img.ImageID)
	err := kubernetes.ApplyProxyRegistry(img, true, s.proxyRegistryMap)
	if err != nil {
		return "", err
	}

	detection, err := source.Detect(fmt.Sprintf("registry:%s", img.ImageID), source.DefaultDetectConfig())
	if err != nil {
		logrus.WithError(fmt.Errorf("failed to parse input registry:%s: %w", img.ImageID, err)).Error("Input-Parsing failed")
		return "", err
	}

	opts := &image.RegistryOptions{Credentials: oci.ConvertSecrets(*img, s.proxyRegistryMap)}
	src, err := detection.NewSource(source.DetectionSourceConfig{RegistryOptions: opts})
	if err != nil {
		logrus.WithError(fmt.Errorf("failed to construct source from input registry:%s: %w", img.ImageID, err)).Error("Source-Creation failed")
		return "", err
	}

	result := sbom.SBOM{
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: s.resolveVersion(),
		},
		// TODO: we should have helper functions for getting this built from exported library functions
	}

	c := cataloger.DefaultConfig()
	c.Search.Scope = source.SquashedScope
	packageCatalog, relationships, theDistro, err := syft.CatalogPackages(src, c)
	if err != nil {
		logrus.WithError(err).Error("CatalogPackages failed")
		return "", err
	}

	result.Artifacts.Packages = packageCatalog
	result.Artifacts.LinuxDistribution = theDistro
	result.Relationships = relationships

	// you can use other formats such as format.CycloneDxJSONOption or format.SPDXJSONOption ...
	encoder, err := GetEncoder(s.sbomFormat)
	if err != nil {
		logrus.WithError(err).Error("Could not resolve encoder")
		return "", err
	}

	b, err := format.Encode(result, encoder)
	if err != nil {
		logrus.WithError(err).Error("Encoding of result failed")
		return "", err
	}

	return string(b), nil
}

func GetEncoder(sbomFormat string) (sbom.FormatEncoder, error) {
	switch sbomFormat {
	case "json", "syftjson":
		return syftjson.NewFormatEncoder(), nil
	case "cyclonedx", "cyclone", "cyclonedxxml":
		return cyclonedxxml.NewFormatEncoderWithConfig(cyclonedxxml.DefaultEncoderConfig())
	case "cyclonedxjson":
		return cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	case "spdx", "spdxtv", "spdxtagvalue":
		return spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig())
	case "spdxjson":
		return spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
	case "github", "githubjson":
		return github.NewFormatEncoder(), nil
	case "text":
		return text.NewFormatEncoder(), nil
	case "table":
		return table.NewFormatEncoder(), nil
	default:
		return syftjson.NewFormatEncoder(), nil
	}
}

func GetFileName(sbomFormat string) string {
	switch sbomFormat {
	case "json", "syftjson", "cyclonedxjson", "spdxjson", "github", "githubjson":
		return "sbom.json"
	case "cyclonedx", "cyclone", "cyclonedxxml":
		return "sbom.xml"
	case "spdx", "spdxtv", "spdxtagvalue":
		return "sbom.spdx"
	case "text":
		return "sbom.txt"
	case "table":
		return "sbom.txt"
	default:
		return "sbom.json"
	}
}

func getSyftVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		logrus.Warnf("failed to read build info")
	}

	for _, dep := range bi.Deps {
		if strings.EqualFold("github.com/anchore/syft", dep.Path) {
			return dep.Version
		}
	}

	return ""
}
