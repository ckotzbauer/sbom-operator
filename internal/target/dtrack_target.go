package target

import (
	"context"
	"encoding/base64"
	"fmt"

	parser "github.com/novln/docker-parser"
	dtrack "github.com/nscuro/dtrack-client"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
)

type DependencyTrackTarget struct {
	baseUrl string
	apiKey  string
}

func NewDependencyTrackTarget() *DependencyTrackTarget {
	baseUrl := viper.GetString(internal.ConfigKeyDependencyTrackBaseUrl)
	apiKey := viper.GetString(internal.ConfigKeyDependencyTrackApiKey)
	return &DependencyTrackTarget{
		baseUrl: baseUrl,
		apiKey:  apiKey,
	}
}

func (g *DependencyTrackTarget) ValidateConfig() error {
	if g.baseUrl == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyDependencyTrackBaseUrl)
	}
	if g.apiKey == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyDependencyTrackApiKey)
	}
	return nil
}

func (g *DependencyTrackTarget) Initialize() {
}

func (g *DependencyTrackTarget) ProcessSbom(image kubernetes.ContainerImage, sbom string) {
	fullRef, err := parser.Parse(image.Image)
	if err != nil {
		logrus.WithError(err).Errorf("Could not parse imageID %s", image.ImageID)
		return
	}

	imageName := fullRef.Repository()
	tagName := fullRef.Tag()
	if tagName == "" {
		tagName = "latest"
	}

	if sbom == "" {
		logrus.Infof("Empty SBOM - skip image (image=%s)", image.ImageID)
		return
	}

	client, _ := dtrack.NewClient(g.baseUrl, dtrack.WithAPIKey(g.apiKey))

	logrus.Infof("Sending SBOM to Dependency Track (project=%s, version=%s)", imageName, tagName)

	sbomBase64 := base64.StdEncoding.EncodeToString([]byte(sbom))
	uploadToken, err := client.BOM.Upload(
		context.TODO(),
		dtrack.BOMUploadRequest{ProjectName: imageName, ProjectVersion: tagName, AutoCreate: true, BOM: sbomBase64},
	)
	if err != nil {
		logrus.Errorf("Could not upload BOM: %v", err)
	}
	logrus.Infof("Uploaded SBOM (upload-token=%s)", uploadToken)
}

func (g *DependencyTrackTarget) Cleanup(allImages []string) {
}
