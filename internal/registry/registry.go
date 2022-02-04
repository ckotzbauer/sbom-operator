package registry

import (
	"bytes"
	"fmt"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"

	parser "github.com/novln/docker-parser"
)

func SaveImage(imagePath string, image kubernetes.ContainerImage) error {
	imageMap := map[string]v1.Image{}

	o := crane.GetOptions()

	if len(image.Auth) > 0 {
		var cf *configfile.ConfigFile
		var err error

		if image.LegacyAuth {
			cf = configfile.New("")
			err = LegacyLoadFromReader(bytes.NewReader(image.Auth), cf)
		} else {
			cf, err = config.LoadFromReader(bytes.NewReader(image.Auth))
		}

		if err != nil {
			return err
		}

		fullRef, err := parser.Parse(image.ImageID)
		if err != nil {
			return err
		}

		reg, err := name.NewRegistry(fullRef.Registry())
		if err != nil {
			return err
		}

		regKey := reg.RegistryStr()

		if regKey == name.DefaultRegistry {
			regKey = authn.DefaultAuthKey
		}

		cfg, err := cf.GetAuthConfig(regKey)
		if err != nil {
			return err
		}

		empty := types.AuthConfig{}

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

	return nil
}
