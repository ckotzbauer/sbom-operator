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

func SaveImage(imagePath string, image kubernetes.ContainerImage) error {
	imageMap := map[string]v1.Image{}
	o := crane.GetOptions()

	if len(image.PullSecrets) == 0 {
		return nil
	}

	for _, pullSecret := range image.PullSecrets {

		if len(pullSecret.SecretCredsData) > 0 {
			cfg, err := ResolveAuthConfigWithPullSecret(image, pullSecret)
			empty := types.AuthConfig{}

			if err != nil {
				logrus.Debugf("image: %s Image-Pull failed with PullSecret: %s", image.ImageID, pullSecret.SecretName)
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

			ref, err := name.ParseReference(image.ImageID, o.Name...)

			if err != nil {
				return fmt.Errorf("parsing reference %q: %w", image.ImageID, err)
			}

			rmt, err := remote.Get(ref, o.Remote...)
			if err != nil {
				return err
			}

			img, err := rmt.Image()
			if err != nil {
				return err
			}

			imageMap[image.ImageID] = img

			if err := crane.MultiSave(imageMap, imagePath); err != nil {
				return fmt.Errorf("saving tarball %s: %w", imagePath, err)
			}

			logrus.Debugf("Image %s successfully pulled with PullSecret: %s", image.ImageID, pullSecret.SecretName)
			break
		}

		logrus.Debugf("image: %s load next pull secret", image.ImageID)
	}

	return nil
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
	var err error
	// to not break JobImages this function needs to redirect to the actual resolve-function, using the first pullSecret from the list if exists
	if len(image.PullSecrets) > 0 {
		return ResolveAuthConfigWithPullSecret(image, image.PullSecrets[0])
	} else {
		err = errors.New("No PullSecret found for image")
		return types.AuthConfig{}, err
	}

}
