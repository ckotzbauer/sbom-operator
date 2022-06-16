package dtrack

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	parser "github.com/novln/docker-parser"
	dtrack "github.com/nscuro/dtrack-client"
	"github.com/sirupsen/logrus"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal"
)

type DependencyTrackTarget struct {
	baseUrl      string
	apiKey       string
	k8sClusterId string
}

const (
	kubernetesCluster = "kubernetes-cluster"
	sbomOperator      = "sbom-operator"
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

func (g *DependencyTrackTarget) ProcessSbom(image libk8s.KubeImage, sbom string) error {
	imageRef, err := parser.Parse(image.Image.Image)
	if err != nil {
		logrus.WithError(err).Errorf("Could not parse image %s", image.Image.Image)
		return nil
	}

	projectName := imageRef.Repository()
	version := imageRef.Tag()

	if sbom == "" {
		logrus.Infof("Empty SBOM - skip image (image=%s)", image.Image.ImageID)
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

	_, err = client.Project.Update(context.Background(), *project)
	if err != nil {
		logrus.WithError(err).Errorf("Could not update project tags")
	}

	return nil
}

func (g *DependencyTrackTarget) Cleanup(allImages []libk8s.KubeImage) {
	client, _ := dtrack.NewClient(g.baseUrl, dtrack.WithAPIKey(g.apiKey))

	var (
		pageNumber = 1
		pageSize   = 50
	)

	allImageRefs := make([]parser.Reference, len(allImages))
	for _, image := range allImages {
		ref, err := parser.Parse(image.Image.Image)
		if err != nil {
			logrus.WithError(err).Errorf("Could not parse image %s", image.Image.Image)
			continue
		}
		allImageRefs = append(allImageRefs, *ref)
	}

	for {
		projectsPage, err := client.Project.GetAll(context.Background(), dtrack.PageOptions{
			PageNumber: pageNumber,
			PageSize:   pageSize,
		})
		if err != nil {
			logrus.Errorf("Could not load projects: %v", err)
		}

	projectLoop:
		for _, project := range projectsPage.Projects {
			currentImageName := fmt.Sprintf("%v:%v", project.Name, project.Version)

			// Image used in current cluster
			for _, image := range allImages {
				if image.Image.Image == currentImageName {
					continue projectLoop
				}
			}

			// check all tags, remove the current cluster and aggregate a list of other clusters
			otherClusterIds := []string{}
			sbomOperatorPropFound := false
			for _, tag := range project.Tags {
				if strings.Index(tag.Name, kubernetesCluster) == 0 {
					clusterId := string(tag.Name[len(kubernetesCluster)+1:])
					if clusterId == g.k8sClusterId {
						logrus.Infof("Removing %v=%v tag from project %v", kubernetesCluster, g.k8sClusterId, currentImageName)
						project.Tags = removeTag(project.Tags, kubernetesCluster+"="+g.k8sClusterId)
						client.Project.Update(context.Background(), project)
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
				client.Project.Delete(context.Background(), project.UUID)
			}
		}

		if pageNumber*pageSize >= projectsPage.TotalCount {
			break
		}

		pageNumber++
	}
}

func containsTag(tags []dtrack.Tag, tagString string) bool {
	for _, tag := range tags {
		if tag.Name == tagString {
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
