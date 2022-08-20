package syft

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/syft/source"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/sirupsen/logrus"

	parser "github.com/novln/docker-parser"
)

type Syft struct {
	sbomFormat     string
	resolveVersion func() string
}

func New(sbomFormat string) *Syft {
	return &Syft{
		sbomFormat:     sbomFormat,
		resolveVersion: getSyftVersion,
	}
}

func (s Syft) WithVersion(version string) Syft {
	s.resolveVersion = func() string { return version }
	return s
}

func (s *Syft) ExecuteSyft(img *oci.RegistryImage) (string, error) {
	logrus.Infof("Processing image %s", img.ImageID)

	fullRef, err := parser.Parse(img.ImageID)
	if err != nil {
		logrus.WithError(err).Errorf("Could not parse imageID %s", img.ImageID)
		return "", err
	}

	imagePath := "/tmp/" + strings.ReplaceAll(fullRef.Tag(), ":", "_") + ".tar.gz"
	err = oci.SaveImage(imagePath, oci.RegistryImage{ImageID: img.ImageID, PullSecrets: img.PullSecrets})

	if err != nil {
		logrus.WithError(err).Error("Image-Pull failed")
		return "", err
	}

	input, err := source.ParseInput(filepath.Join("docker-archive:", imagePath), "", false)
	if err != nil {
		logrus.WithError(fmt.Errorf("failed to parse input %s: %w", imagePath, err)).Error("Input-Parsing failed")
		return "", err
	}

	src, cleanup, err := source.New(*input, nil, nil)
	if err != nil {
		logrus.WithError(fmt.Errorf("failed to construct source from input %s: %w", imagePath, err)).Error("Source-Creation failed")
		return "", err
	}

	if cleanup != nil {
		defer cleanup()
	}

	result := sbom.SBOM{
		Source: src.Metadata,
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

	result.Artifacts.PackageCatalog = packageCatalog
	result.Artifacts.LinuxDistribution = theDistro
	result.Relationships = relationships

	// you can use other formats such as format.CycloneDxJSONOption or format.SPDXJSONOption ...
	b, err := syft.Encode(result, syft.FormatByName(s.sbomFormat))
	if err != nil {
		logrus.WithError(err).Error("Encoding of result failed")
		return "", err
	}

	err = os.Remove(imagePath)
	if err != nil {
		logrus.WithError(err).Warnf("Image %s could not be deleted", imagePath)
	}

	return string(b), nil
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
