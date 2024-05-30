package syft

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/github"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/table"
	"github.com/anchore/syft/syft/format/text"
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
	appVersion       string
}

func New(sbomFormat string, proxyRegistryMap map[string]string, appVersion string) *Syft {
	return &Syft{
		sbomFormat:       sbomFormat,
		resolveVersion:   getSyftVersion,
		proxyRegistryMap: proxyRegistryMap,
		appVersion:       appVersion,
	}
}

func (s Syft) WithSyftVersion(version string) Syft {
	s.resolveVersion = func() string { return version }
	return s
}

func (s *Syft) ExecuteSyft(img *oci.RegistryImage) (string, error) {
	logrus.Infof("Processing image %s", img.ImageID)

	oriImage := img.Image
	oriImageID := img.ImageID

	err := kubernetes.ApplyProxyRegistry(img, true, s.proxyRegistryMap)
	if err != nil {
		return "", err
	}

	opts := &image.RegistryOptions{Credentials: oci.ConvertSecrets(*img, s.proxyRegistryMap)}
	src, err := getSource(context.Background(), opts, img.ImageID)

	// revert image info to the original value - we want to register with original names
	img.Image = oriImage
	img.ImageID = oriImageID

	if err != nil {
		logrus.WithError(fmt.Errorf("failed to construct source from input registry:%s: %w", img.ImageID, err)).Error("Source-Creation failed")
		return "", err
	}

	defer func() {
		if src != nil {
			if err := src.Close(); err != nil {
				logrus.WithError(err).Infof("unable to close source")
			}
		}
	}()

	cfg := syft.DefaultCreateSBOMConfig().
		WithParallelism(5).
		WithTool("sbom-operator", s.appVersion).
		WithFilesConfig(
			filecataloging.DefaultConfig().
				WithSelection(file.FilesOwnedByPackageSelection).
				WithHashers(
					crypto.SHA1,
					crypto.SHA256,
				),
		)

	result, err := syft.CreateSBOM(context.Background(), src, cfg)
	if err != nil {
		logrus.WithError(err).Error("SBOM-Creation failed")
		return "", err
	}

	// you can use other formats such as format.CycloneDxJSONOption or format.SPDXJSONOption ...
	encoder, err := GetEncoder(s.sbomFormat)
	if err != nil {
		logrus.WithError(err).Error("Could not resolve encoder")
		return "", err
	}

	b, err := format.Encode(*result, encoder)
	if err != nil {
		logrus.WithError(err).Error("Encoding of result failed")
		return "", err
	}

	bom := string(b)
	err = removeTempContents()
	if err != nil {
		logrus.WithError(err).Warn("Could not cleanup tmp directory")
	}

	return bom, nil
}

func getSource(ctx context.Context, registryOptions *image.RegistryOptions, userInput string) (source.Source, error) {
	cfg := syft.DefaultGetSourceConfig().
		WithSources("registry").
		WithRegistryOptions(registryOptions)

	var err error
	src, err := syft.GetSource(ctx, userInput, cfg)
	if err != nil {
		return nil, fmt.Errorf("could not determine source: %w", err)
	}

	return src, nil
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

func removeTempContents() error {
	dir := "/tmp"
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer closeOrLog(d)
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}

func closeOrLog(c io.Closer) {
	if err := c.Close(); err != nil {
		logrus.WithError(err).Warnf("Could not close file")
	}
}
