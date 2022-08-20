package dtrack

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/uuid"
	parser "github.com/novln/docker-parser"
	dtrack "github.com/nscuro/dtrack-client"
	"github.com/sirupsen/logrus"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
)

type DependencyTrackTarget struct {
	baseUrl         string
	apiKey          string
	k8sClusterId    string
	imageProjectMap map[string]uuid.UUID
}

const (
	kubernetesCluster = "kubernetes-cluster"
	sbomOperator      = "sbom-operator"
	rawImageId        = "raw-image-id"
)

func NewDependencyTrackTarget(baseUrl, apiKey, k8sClusterId string) *DependencyTrackTarget {
	return &DependencyTrackTarget{
		baseUrl:      baseUrl,
		apiKey:       apiKey,
		k8sClusterId: k8sClusterId,
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

func (g *DependencyTrackTarget) ProcessSbom(image *libk8s.RegistryImage, sbom string) error {
	projectName, version := getRepoWithVersion(image)

	if sbom == "" {
		logrus.Infof("Empty SBOM - skip image (image=%s)", image.ImageID)
		return nil
	}

	client, err := dtrack.NewClient(g.baseUrl, dtrack.WithAPIKey(g.apiKey))
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
		return err
	}

	logrus.Infof("Sending SBOM to Dependency Track (project=%s, version=%s)", projectName, version)

	sbomBase64 := base64.StdEncoding.EncodeToString([]byte(sbom))
	uploadToken, err := client.BOM.Upload(
		context.Background(),
		dtrack.BOMUploadRequest{ProjectName: projectName, ProjectVersion: version, AutoCreate: true, BOM: sbomBase64},
	)
	if err != nil {
		logrus.Errorf("Could not upload BOM: %v", err)
		return err
	}

	logrus.Infof("Uploaded SBOM (upload-token=%s)", uploadToken)

	project, err := client.Project.Lookup(context.Background(), projectName, version)
	if err != nil {
		logrus.Errorf("Could not find project: %v", err)
		return err
	}

	kubernetesClusterTag := kubernetesCluster + "=" + g.k8sClusterId
	if !containsTag(project.Tags, kubernetesClusterTag) {
		project.Tags = append(project.Tags, dtrack.Tag{Name: kubernetesClusterTag})
	}
	if !containsTag(project.Tags, sbomOperator) {
		project.Tags = append(project.Tags, dtrack.Tag{Name: sbomOperator})
	}
	if !containsTag(project.Tags, rawImageId) {
		project.Tags = append(project.Tags, dtrack.Tag{Name: fmt.Sprintf("%s=%s", rawImageId, image.ImageID)})
	}

	_, err = client.Project.Update(context.Background(), project)
	if err != nil {
		logrus.WithError(err).Errorf("Could not update project tags")
	}

	return nil
}

func (g *DependencyTrackTarget) LoadImages() []*libk8s.RegistryImage {
	client, _ := dtrack.NewClient(g.baseUrl, dtrack.WithAPIKey(g.apiKey))

	if g.imageProjectMap == nil {
		g.imageProjectMap = make(map[string]uuid.UUID)
	}

	var (
		pageNumber = 1
		pageSize   = 50
	)

	images := make([]*libk8s.RegistryImage, 0)
	for {
		projectsPage, err := client.Project.GetAll(context.Background(), dtrack.PageOptions{
			PageNumber: pageNumber,
			PageSize:   pageSize,
		})
		if err != nil {
			logrus.Errorf("Could not load projects: %v", err)
		}

		var imageId string

		for _, project := range projectsPage.Items {
			sbomOperatorPropFound := false
			imageRelatesToCluster := false
			for _, tag := range project.Tags {
				imageId = ""
				if strings.Index(tag.Name, kubernetesCluster) == 0 {
					clusterId := string(tag.Name[len(kubernetesCluster)+1:])
					if clusterId == g.k8sClusterId {
						imageRelatesToCluster = true
					}
				}
				if tag.Name == sbomOperator {
					sbomOperatorPropFound = true
				}

				if strings.Index(tag.Name, rawImageId) == 0 {
					imageId = string(tag.Name[len(rawImageId)+1:])
				}
			}

			if imageRelatesToCluster && sbomOperatorPropFound && len(imageId) > 0 {
				images = append(images, &libk8s.RegistryImage{ImageID: imageId})
				g.imageProjectMap[imageId] = project.UUID
			}
		}

		if pageNumber*pageSize >= projectsPage.TotalCount {
			break
		}

		pageNumber++
	}

	return images
}

func (g *DependencyTrackTarget) Remove(images []*libk8s.RegistryImage) {
	if g.imageProjectMap == nil {
		// prepropulate imageProjectMap
		g.LoadImages()
	}

	client, _ := dtrack.NewClient(g.baseUrl, dtrack.WithAPIKey(g.apiKey))

	for _, img := range images {
		uuid := g.imageProjectMap[img.ImageID]
		if uuid.String() == "" {
			logrus.Warnf("No project found for imageID: %s", img.ImageID)
			continue
		}

		project, err := client.Project.Get(context.Background(), uuid)
		if err != nil {
			logrus.Errorf("Could not load project: %v", err)
			continue
		}

		// check all tags, remove the current cluster and aggregate a list of other clusters
		currentImageName := fmt.Sprintf("%v:%v", project.Name, project.Version)
		otherClusterIds := []string{}
		sbomOperatorPropFound := false
		for _, tag := range project.Tags {
			if strings.Index(tag.Name, kubernetesCluster) == 0 {
				clusterId := string(tag.Name[len(kubernetesCluster)+1:])
				if clusterId == g.k8sClusterId {
					logrus.Infof("Removing %v=%v tag from project %v", kubernetesCluster, g.k8sClusterId, currentImageName)
					project.Tags = removeTag(project.Tags, kubernetesCluster+"="+g.k8sClusterId)
					_, err := client.Project.Update(context.Background(), project)
					if err != nil {
						logrus.WithError(err).Warnf("Project %s could not be updated", project.UUID.String())
					}
				} else {
					otherClusterIds = append(otherClusterIds, clusterId)
				}
			}
			if tag.Name == sbomOperator {
				sbomOperatorPropFound = true
			}
		}

		// if not in other cluster delete the project
		if sbomOperatorPropFound && len(otherClusterIds) == 0 {
			logrus.Infof("Image not running in any cluster - removing %v", currentImageName)
			err := client.Project.Delete(context.Background(), project.UUID)
			if err != nil {
				logrus.WithError(err).Warnf("Project %s could not be deleted", project.UUID.String())
			}
		}
	}
}

func containsTag(tags []dtrack.Tag, tagString string) bool {
	for _, tag := range tags {
		if tag.Name == tagString || strings.Index(tag.Name, tagString) == 0 {
			return true
		}
	}
	return false
}

func removeTag(tags []dtrack.Tag, tagString string) []dtrack.Tag {
	newTags := []dtrack.Tag{}
	for _, tag := range tags {
		if tag.Name != tagString {
			newTags = append(newTags, tag)
		}
	}
	return newTags
}

func getRepoWithVersion(image *libk8s.RegistryImage) (string, string) {
	imageRef, err := parser.Parse(image.ImageID)
	if err != nil {
		logrus.WithError(err).Errorf("Could not parse image %s", image.ImageID)
		return "", ""
	}

	projectName := imageRef.Repository()

	if strings.Index(image.Image, "sha256") != 0 {
		imageRef, err = parser.Parse(image.Image)
		if err != nil {
			logrus.WithError(err).Errorf("Could not parse image %s", image.Image)
			return "", ""
		}
	}

	version := imageRef.Tag()
	return projectName, version
}
