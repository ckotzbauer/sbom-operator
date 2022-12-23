package syft

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/syft/source"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/sirupsen/logrus"

	parser "github.com/novln/docker-parser"
	"github.com/novln/docker-parser/docker"
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
	err := s.ApplyProxyRegistry(img)
	if err != nil {
		return "", err
	}

	input, err := source.ParseInput(fmt.Sprintf("registry:%s", img.ImageID), "", false)
	if err != nil {
		logrus.WithError(fmt.Errorf("failed to parse input registry:%s: %w", img.ImageID, err)).Error("Input-Parsing failed")
		return "", err
	}

	opts := &image.RegistryOptions{Credentials: oci.ConvertSecrets(*img, s.proxyRegistryMap)}
	src, cleanup, err := source.New(*input, opts, nil)
	if err != nil {
		logrus.WithError(fmt.Errorf("failed to construct source from input registry:%s: %w", img.ImageID, err)).Error("Source-Creation failed")
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

func (s *Syft) ApplyProxyRegistry(img *oci.RegistryImage) error {
	imageRef, err := parser.Parse(img.ImageID)
	if err != nil {
		logrus.WithError(err).Errorf("Could not parse image %s", img.ImageID)
		return err
	}

	for registryToReplace, proxyRegistry := range s.proxyRegistryMap {
		if imageRef.Registry() == registryToReplace {
			shortName := strings.TrimPrefix(imageRef.ShortName(), docker.DefaultRepoPrefix)
			fullName := fmt.Sprintf("%s/%s", imageRef.Registry(), shortName)
			if strings.HasPrefix(imageRef.Tag(), "sha256") {
				fullName = fmt.Sprintf("%s@%s", fullName, imageRef.Tag())
			} else {
				fullName = fmt.Sprintf("%s:%s", fullName, imageRef.Tag())
			}

			img.ImageID = strings.ReplaceAll(fullName, registryToReplace, proxyRegistry)
			img.Image = strings.ReplaceAll(img.Image, registryToReplace, proxyRegistry)
			logrus.Debugf("Applied Registry-Proxy %s", img.ImageID)
			break
		}
	}

	return nil
}
