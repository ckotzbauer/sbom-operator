package registry

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"

	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"

	parser "github.com/novln/docker-parser"
)

var (
	ErrorNoValidPullSecret = errors.New("No valid or valid-but-unauthorized PullSecret found from ContainerImage")
)

func SaveImage(imagePath string, image kubernetes.ContainerImage) error {
	imageMap := map[string]v1.Image{}
	o := crane.GetOptions()
	var err error
	var cfg types.AuthConfig
	empty := types.AuthConfig{}
	pullSecrets := image.PullSecrets

	if len(pullSecrets) == 0 {
		pullSecrets = []kubernetes.KubeCreds{{SecretName: "noAuth"}}
	}

	for _, pullSecret := range pullSecrets {

		if pullSecret.SecretName != "noAuth" && len(pullSecret.SecretCredsData) > 0 {
			cfg, err = ResolveAuthConfigWithPullSecret(image, pullSecret)

			if err != nil {
				logrus.Debugf("image: %s, Read Authentication Configuration from secret: %s failed. Error: %s", image.ImageID, pullSecret.SecretName, err)
				continue
			}

			if cfg != empty {
				o.Remote = []remote.Option{
					remote.WithAuth(authn.FromConfig(authn.AuthConfig{
						Username:      cfg.Username,
						Password:      cfg.Password,
						Auth:          cfg.Auth,
						IdentityToken: cfg.IdentityToken,
						RegistryToken: cfg.RegistryToken,
					})),
				}
			}
		}

		ref, err := name.ParseReference(image.ImageID, o.Name...)

		if err != nil {
			// should be immediately returned because it seems that no other pullSecret will solve this problem
			return fmt.Errorf("parsing reference %q: %w", image.ImageID, err)
		}

		rmt, err := remote.Get(ref, o.Remote...)
		if err != nil {
			// should not be returned, because, this might be an Authentication Error
			logrus.Debugf("image: %s, Image-Pull Error: %s", image.ImageID, err)
			continue
		}

		img, err := rmt.Image()
		if err != nil {
			// should be immediately returned because no other pullSecret will solve this problem
			return err
		}

		imageMap[image.ImageID] = img

		if err := crane.MultiSave(imageMap, imagePath); err != nil {
			// should be immediately returned because no other pullSecret will solve this problem
			return fmt.Errorf("saving tarball %s: %w", imagePath, err)
		}

		logrus.Debugf("Image %s successfully pulled with PullSecret: %s", image.ImageID, pullSecret.SecretName)
		// pull was sucessfull - no error occurred
		return nil
	}

	// no valid pull request found for this image - returning an error
	return ErrorNoValidPullSecret
}

func ResolveAuthConfigWithPullSecret(image kubernetes.ContainerImage, pullSecret kubernetes.KubeCreds) (types.AuthConfig, error) {
	var cf *configfile.ConfigFile
	var err error

	if pullSecret.IsLegacySecret {
		cf = configfile.New("")
		err = LegacyLoadFromReader(bytes.NewReader(pullSecret.SecretCredsData), cf)
	} else {
		cf, err = config.LoadFromReader(bytes.NewReader(pullSecret.SecretCredsData))
	}

	if err != nil {
		return types.AuthConfig{}, err
	}

	fullRef, err := parser.Parse(image.ImageID)
	if err != nil {
		return types.AuthConfig{}, err
	}

	reg, err := name.NewRegistry(fullRef.Registry())
	if err != nil {
		return types.AuthConfig{}, err
	}

	regKey := reg.RegistryStr()

	if regKey == name.DefaultRegistry {
		regKey = authn.DefaultAuthKey
	}

	cfg, err := cf.GetAuthConfig(regKey)
	if err != nil {
		return types.AuthConfig{}, err
	}

	return cfg, nil
}

func ResolveAuthConfig(image kubernetes.ContainerImage) (types.AuthConfig, error) {
	// to not break JobImages this function needs to redirect to the actual resolve-function, using the first pullSecret from the list if exists
	if len(image.PullSecrets) > 0 {
		return ResolveAuthConfigWithPullSecret(image, image.PullSecrets[0])
	} else {
		return types.AuthConfig{}, nil
	}

}
