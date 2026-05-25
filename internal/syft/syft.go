package syft

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

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
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
)

var ecrTokenCache = newTokenCache()

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

	credentials := oci.ConvertSecrets(*img, s.proxyRegistryMap)

	var opts *image.RegistryOptions
	switch {
	case hasUsableCredentials(credentials):
		opts = &image.RegistryOptions{Credentials: credentials}
	case isGCPArtifactRegistry(img.ImageID):
		logrus.Debugf("No pull secrets found for GCP Artifact Registry %s, attempting Workload Identity", img.ImageID)
		if gcpCreds := getGCPCredentials(context.Background()); gcpCreds != nil {
			opts = &image.RegistryOptions{Credentials: []image.RegistryCredentials{*gcpCreds}}
		} else {
			logrus.Debugf("Failed to get GCP credentials, using empty options")
			opts = &image.RegistryOptions{}
		}
	case isECRRegistry(img.ImageID):
		logrus.Debugf("No pull secrets found for AWS ECR %s, attempting IRSA / Pod Identity", img.ImageID)
		if ecrCreds := getECRCredentials(context.Background(), img.ImageID); ecrCreds != nil {
			opts = &image.RegistryOptions{Credentials: []image.RegistryCredentials{*ecrCreds}}
		} else {
			logrus.Debugf("Failed to get ECR credentials, using empty options")
			opts = &image.RegistryOptions{}
		}
	default:
		opts = &image.RegistryOptions{Credentials: credentials}
	}

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

func isGCPArtifactRegistry(imageID string) bool {
	return strings.Contains(imageID, "-docker.pkg.dev/")
}

// hasUsableCredentials reports whether at least one credential entry carries
// a non-empty Username, Password, or Token. libk8soci's ConvertSecrets always
// returns one entry per pod pull secret, even when the secret has no auth for
// the image's registry - in that case the entry has only Authority set and
// empty u/p/t. Counting such phantom entries would block GCP/ECR auto-auth
// branches whenever a pod carries any unrelated pull secret.
func hasUsableCredentials(creds []image.RegistryCredentials) bool {
	for _, c := range creds {
		if c.Username != "" || c.Password != "" || c.Token != "" {
			return true
		}
	}
	return false
}

func isECRRegistry(imageID string) bool {
	return strings.Contains(imageID, ".dkr.ecr.") && strings.Contains(imageID, ".amazonaws.com")
}

func parseECRRegistry(imageID string) (registry, region string, err error) {
	host := imageID
	if slash := strings.Index(host, "/"); slash >= 0 {
		host = host[:slash]
	}
	// Expected layout: <account>.dkr.ecr.<region>.amazonaws.com
	parts := strings.Split(host, ".")
	if len(parts) < 6 || parts[1] != "dkr" || parts[2] != "ecr" || parts[len(parts)-2] != "amazonaws" || parts[len(parts)-1] != "com" {
		return "", "", fmt.Errorf("not a valid ECR host: %q", imageID)
	}
	return host, parts[3], nil
}

func getECRCredentials(ctx context.Context, imageID string) *image.RegistryCredentials {
	registry, region, err := parseECRRegistry(imageID)
	if err != nil {
		logrus.WithError(err).Debug("Failed to parse ECR registry host")
		return nil
	}

	if username, password, ok := ecrTokenCache.get(registry); ok {
		return &image.RegistryCredentials{Username: username, Password: password}
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctxTimeout, config.WithRegion(region))
	if err != nil {
		logrus.WithError(err).Debug("Failed to load AWS default config")
		return nil
	}

	out, err := ecr.NewFromConfig(cfg).GetAuthorizationToken(ctxTimeout, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		logrus.WithError(err).Debug("Failed to call ecr:GetAuthorizationToken")
		return nil
	}
	if len(out.AuthorizationData) == 0 || out.AuthorizationData[0].AuthorizationToken == nil {
		logrus.Debug("ECR returned empty authorization data")
		return nil
	}

	tokenB64 := *out.AuthorizationData[0].AuthorizationToken
	decoded, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		logrus.WithError(err).Debug("Failed to base64-decode ECR token")
		return nil
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		logrus.Debug("Decoded ECR token has unexpected format")
		return nil
	}
	username, password := parts[0], parts[1] /* #nosec G101 */

	now := time.Now()
	maxExpiry := now.Add(11 * time.Hour)
	awsExpiry := maxExpiry // fallback if API gives no expiry
	if out.AuthorizationData[0].ExpiresAt != nil {
		awsExpiry = out.AuthorizationData[0].ExpiresAt.Add(-5 * time.Minute)
	}
	effectiveExpiry := awsExpiry
	if effectiveExpiry.After(maxExpiry) {
		effectiveExpiry = maxExpiry
	}

	ecrTokenCache.put(registry, username, password, effectiveExpiry)

	return &image.RegistryCredentials{Username: username, Password: password}
}

func getGCPCredentials(ctx context.Context) *image.RegistryCredentials {
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		logrus.WithError(err).Debug("Failed to find default GCP credentials")
		return nil
	}

	token, err := creds.TokenSource.Token()
	if err != nil {
		logrus.WithError(err).Debug("Failed to get GCP access token")
		return nil
	}

	logrus.Debugf("Successfully obtained GCP access token via default credentials (expires: %v)", token.Expiry)

	return &image.RegistryCredentials{
		Username: "oauth2accesstoken",
		Password: token.AccessToken,
	}
}

type tokenCacheEntry struct {
	username string
	password string
	expiry   time.Time
}

type tokenCache struct {
	mu      sync.RWMutex
	entries map[string]tokenCacheEntry
}

func newTokenCache() *tokenCache {
	return &tokenCache{entries: map[string]tokenCacheEntry{}}
}

func (c *tokenCache) get(registry string) (username, password string, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, found := c.entries[registry]
	if !found {
		return "", "", false
	}
	if time.Until(entry.expiry) < 5*time.Minute {
		return "", "", false
	}
	return entry.username, entry.password, true
}

func (c *tokenCache) put(registry, username, password string, expiry time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[registry] = tokenCacheEntry{username: username, password: password, expiry: expiry}
}
