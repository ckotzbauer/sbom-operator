package oci

import (
	"fmt"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"
)

type OciTarget struct {
	registry   string
	userName   string
	token      string
	sbomFormat string
}

func NewOciTarget(registry, userName, token, format string) *OciTarget {
	return &OciTarget{
		registry:   registry,
		userName:   userName,
		token:      token,
		sbomFormat: format,
	}
}

func (g *OciTarget) ValidateConfig() error {
	if g.registry == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyGitRepository)
	}

	if g.userName == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyOciUser)
	}

	if g.token == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyOciToken)
	}

	if g.sbomFormat == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyFormat)
	}

	return nil
}

func (g *OciTarget) Initialize() error {
	return nil
}

func (g *OciTarget) ProcessSbom(ctx *target.TargetContext) error {
	ref, err := name.ParseReference(ctx.Image.ImageID)
	if err != nil {
		logrus.WithError(err).Errorf("failed to parse reference %s", ctx.Image.ImageID)
		return err
	}

	b := []byte(ctx.Sbom)
	opts := []remote.Option{
		remote.WithAuth(authn.FromConfig(authn.AuthConfig{
			Username:      g.userName,
			Password:      g.token,
			Auth:          "",
			IdentityToken: "",
			RegistryToken: "",
		})),
	}

	dstRef, err := CreateTag(ref, g.registry)
	if err != nil {
		logrus.WithError(err).Error("failed to create tag")
		return err
	}

	sbomType := GetMediaType(g.sbomFormat)
	logrus.Debugf("Uploading SBOM file for [%s] to [%s] with mediaType [%s]", ref.Name(), dstRef.Name(), sbomType)
	img, err := CreateImage(b, sbomType)
	if err != nil {
		logrus.WithError(err).Error("failed to create image")
		return err
	}

	err = remote.Write(dstRef, img, opts...)
	if err != nil {
		logrus.WithError(err).Error("failed to write image to oci-registrys")
	}

	return err
}

func (g *OciTarget) LoadImages() ([]*libk8s.RegistryImage, error) {
	return []*libk8s.RegistryImage{}, nil
}

func (g *OciTarget) Remove(allImages []*libk8s.RegistryImage) error {
	return nil
}
