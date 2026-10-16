package oci

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/google/go-containerregistry/pkg/authn"
	ggcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
)

var ecrTokenCache = newTokenCache()

type tokenCache struct {
	mu     sync.Mutex
	tokens map[string]cachedToken
}

type cachedToken struct {
	username string
	password string
	expires  time.Time
}

func newTokenCache() *tokenCache {
	return &tokenCache{tokens: make(map[string]cachedToken)}
}

func (c *tokenCache) get(registry string) (string, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	token, ok := c.tokens[registry]
	if !ok {
		return "", "", false
	}
	if !time.Now().Before(token.expires) {
		delete(c.tokens, registry)
		return "", "", false
	}
	return token.username, token.password, true
}

func (c *tokenCache) put(registry, username, password string, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[registry] = cachedToken{username: username, password: password, expires: expires}
}

// ResolveCredentials get the necessary Registry-Credentials for an Image
// via PullSecrets (libk8soci) or Cloud-Provider-Fallbacks (GCP / AWS ECR).
func ResolveCredentials(img *liboci.RegistryImage, proxyRegistryMap map[string]string) []image.RegistryCredentials {
	credentials := liboci.ConvertSecrets(*img, proxyRegistryMap)

	switch {
	case hasUsableCredentials(credentials):
		return credentials
	case isGCPArtifactRegistry(img.ImageID):
		logrus.Debugf("No pull secrets found for GCP Artifact Registry %s, attempting default credentials", img.ImageID)
		if gcpCreds := getGCPCredentials(context.Background()); gcpCreds != nil {
			return []image.RegistryCredentials{*gcpCreds}
		}
		logrus.Debugf("Failed to get GCP credentials, using empty options")
		return nil
	case isECRRegistry(img.ImageID):
		logrus.Debugf("No pull secrets found for AWS ECR %s, attempting IRSA / Pod Identity", img.ImageID)
		if ecrCreds := getECRCredentials(context.Background(), img.ImageID); ecrCreds != nil {
			return []image.RegistryCredentials{*ecrCreds}
		}
		logrus.Debugf("Failed to get ECR credentials, using empty options")
		return nil
	default:
		return credentials
	}
}

// RemoteAuthOption translates the resolved Credentials in go-containerregistry Option.
func RemoteAuthOption(creds []image.RegistryCredentials) ggcrremote.Option {
	for _, c := range creds {
		if c.Username != "" || c.Password != "" || c.Token != "" {
			return ggcrremote.WithAuth(authn.FromConfig(authn.AuthConfig{
				Username:      c.Username,
				Password:      c.Password,
				RegistryToken: c.Token,
			}))
		}
	}
	return ggcrremote.WithAuthFromKeychain(authn.DefaultKeychain)
}

func isGCPArtifactRegistry(imageID string) bool {
	return strings.Contains(imageID, "-docker.pkg.dev/")
}

// hasUsableCredentials reports whether at least one credential entry can
// actually authenticate against an OCI registry. stereoscope requires both
// Username AND Password for basic auth, or a Token for bearer auth, or an
// explicit Authenticator. libk8soci's ConvertSecrets always returns one entry
// per pod pull secret, even when the secret has no auth for the image's
// registry - in that case the entry has only Authority set and empty u/p/t.
// Counting such phantom entries would block GCP/ECR auto-auth branches
// whenever a pod carries any unrelated pull secret.
func hasUsableCredentials(creds []image.RegistryCredentials) bool {
	for _, c := range creds {
		if (c.Username != "" && c.Password != "") || c.Token != "" || c.Authenticator != nil {
			return true
		}
	}
	return false
}

func isECRRegistry(imageID string) bool {
	return strings.Contains(imageID, ".dkr.ecr.") && strings.Contains(imageID, ".amazonaws.com")
}

func getECRCredentials(ctx context.Context, imageID string) *image.RegistryCredentials {
	registry, region, err := parseECRRegistry(imageID)
	if err != nil {
		logrus.WithError(err).Debug("Failed to parse ECR registry host")
		return nil
	}

	if username, password, ok := ecrTokenCache.get(registry); ok {
		return &image.RegistryCredentials{Authority: registry, Username: username, Password: password}
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

	return &image.RegistryCredentials{Authority: registry, Username: username, Password: password}
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

func parseECRRegistry(imageID string) (registry, region string, err error) {
	host := imageID
	if slash := strings.Index(host, "/"); slash >= 0 {
		host = host[:slash]
	}
	// Expected layouts:
	//   <account>.dkr.ecr.<region>.amazonaws.com     (commercial + GovCloud)
	//   <account>.dkr.ecr.<region>.amazonaws.com.cn  (China partition)
	parts := strings.Split(host, ".")
	if len(parts) < 6 || parts[1] != "dkr" || parts[2] != "ecr" {
		return "", "", fmt.Errorf("not a valid ECR host: %q", imageID)
	}
	if !strings.HasSuffix(host, ".amazonaws.com") && !strings.HasSuffix(host, ".amazonaws.com.cn") {
		return "", "", fmt.Errorf("not a valid ECR host: %q", imageID)
	}
	return host, parts[3], nil
}
