package target

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/uuid"
	dtrack "github.com/nscuro/dtrack-client"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/ckotzbauer/sbom-operator/internal"
)

type DependencaTrackTarget struct {
	baseUrl        string
	apiKey         string
	imageToProject map[string]uuid.UUID
}

func NewDependencaTrackTarget() *DependencaTrackTarget {
	baseUrl := viper.GetString(internal.ConfigKeyDependencaTrackBaseUrl)
	apiKey := viper.GetString(internal.ConfigKeyDependencaTrackApiKey)
	return &DependencaTrackTarget{
		baseUrl: baseUrl,
		apiKey:  apiKey,
	}
}

func (g *DependencaTrackTarget) ValidateConfig() error {
	if g.baseUrl == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyDependencaTrackBaseUrl)
	}
	if g.apiKey == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyDependencaTrackApiKey)
	}
	return nil
}

func (g *DependencaTrackTarget) Initialize() {
	client, _ := dtrack.NewClient(g.baseUrl, dtrack.WithAPIKey(g.apiKey))
	g.imageToProject = make(map[string]uuid.UUID)

	const pageSize = 10
	pageNumber := 1
	for {
		projectsPage, err := client.Project.GetAll(context.TODO(), dtrack.PageOptions{
			PageNumber: pageNumber,
			PageSize:   pageSize,
		})
		if err != nil {
			logrus.Errorf("Could not fetch projects: %v", err)
			return
		}

		for _, project := range projectsPage.Projects {
			for _, property := range project.Properties {
				if property.Name == "image-name" {
					g.imageToProject[property.Value] = project.UUID
				}
			}
		}

		if pageNumber*pageSize >= projectsPage.TotalCount {
			break
		}

		pageNumber++
	}
}

func (g *DependencaTrackTarget) ProcessSbom(imageID, sbom string) {
	if sbom == "" {
		logrus.Infof("Empty SBOM - skip image (image=%s)", imageID)
		return
	}

	client, _ := dtrack.NewClient(g.baseUrl, dtrack.WithAPIKey(g.apiKey))
	logrus.Infof("Sending SBOM to Dependency Track (image=%s)", imageID)

	if !strings.ContainsRune(imageID, '@') {
		logrus.Warnf("Image id %s does not contain an @sha256", imageID)
		return
	}
	imageSplit := strings.Split(imageID, "@")
	imageName := imageSplit[0]

	projectId := g.imageToProject[imageName]
	if projectId == uuid.Nil {
		project, err := client.Project.Create(context.TODO(),
			dtrack.Project{
				Active:     true,
				Classifier: "APPLICATION",
				Name:       imageName,
				Properties: []dtrack.ProjectProperty{
					{Name: "image-name", Group: "container", Value: imageName, Type: "STRING"},
				},
				// TODO check if to add PURL: "pkg:docker/" + imageID,
			})
		if err != nil {
			logrus.Errorf("Could not create project (%s): %v", imageName, err)
		}
		projectId = project.UUID
		g.imageToProject[imageName] = projectId
	}

	if projectId == uuid.Nil {
		logrus.Warnf("No project id for image %s", imageName)
		return
	}

	sbomBase64 := base64.StdEncoding.EncodeToString([]byte(sbom))
	uploadToken, err := client.BOM.Upload(context.TODO(), dtrack.BOMUploadRequest{ProjectUUID: &projectId, BOM: sbomBase64, AutoCreate: false})
	if err != nil {
		logrus.Errorf("Could not upload BOM: %v", err)
	}
	logrus.Infof("Uploaded SBOM (upload-token=%s)", uploadToken)
}

func (g *DependencaTrackTarget) Cleanup(allImages []string) {
	g.imageToProject = nil
}
