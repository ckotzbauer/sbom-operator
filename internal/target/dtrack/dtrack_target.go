package dtrack

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	parser "github.com/novln/docker-parser"
	"github.com/sirupsen/logrus"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/target"
)

type DependencyTrackTarget struct {
	clientOptions []dtrack.ClientOption

	baseUrl                    string
	apiKey                     string
	podLabelTagMatcher         string
	parentProjectAnnotationKey string
	projectNameAnnotationKey   string
	caCertFile                 string
	clientCertFile             string
	clientKeyFile              string
	k8sClusterId               string
	imageProjectMap            map[string]uuid.UUID
}

const (
	kubernetesCluster  = "kubernetes-cluster"
	sbomOperator       = "sbom-operator"
	rawImageId         = "raw-image-id"
	podNamespaceTagKey = "namespace"
)

func NewDependencyTrackTarget(baseUrl, apiKey, podLabelTagMatcher, caCertFile, clientCertFile, clientKeyFile, k8sClusterId string, parentProjectAnnotationKey string, projectNameAnnotationKey string) *DependencyTrackTarget {
	return &DependencyTrackTarget{
		baseUrl:                    baseUrl,
		apiKey:                     apiKey,
		podLabelTagMatcher:         podLabelTagMatcher,
		caCertFile:                 caCertFile,
		clientCertFile:             clientCertFile,
		clientKeyFile:              clientKeyFile,
		k8sClusterId:               k8sClusterId,
		parentProjectAnnotationKey: parentProjectAnnotationKey,
		projectNameAnnotationKey:   projectNameAnnotationKey,
	}
}

func (g *DependencyTrackTarget) ValidateConfig() error {
	if g.baseUrl == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyDependencyTrackBaseUrl)
	}
	if g.apiKey == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyDependencyTrackApiKey)
	}
	if g.caCertFile != "" {
		if g.clientCertFile == "" {
			return fmt.Errorf(
				"%s provided but %s is empty",
				internal.ConfigKeyDependencyTrackCaCertFile,
				internal.ConfigKeyDependencyTrackClientCertFile,
			)
		}

		if g.clientKeyFile == "" {
			return fmt.Errorf(
				"%s provided but %s is empty",
				internal.ConfigKeyDependencyTrackCaCertFile,
				internal.ConfigKeyDependencyTrackClientKeyFile,
			)
		}
	}

	return nil
}

func (g *DependencyTrackTarget) Initialize() error {
	g.clientOptions = []dtrack.ClientOption{}

	g.clientOptions = append(g.clientOptions, dtrack.WithAPIKey(g.apiKey))

	if len(g.caCertFile) > 0 {
		g.clientOptions = append(g.clientOptions, dtrack.WithMTLS(g.caCertFile, g.clientCertFile, g.clientKeyFile))
	}

	return nil
}

func (g *DependencyTrackTarget) ProcessSbom(ctx *target.TargetContext) error {
	projectName := ""
	version := ""

	logrus.Debugf("%v", g)
	// Set custom project name by kubernetes annotation?
	if g.projectNameAnnotationKey != "" {
		logrus.Debugf(`Try to set project name by configured annotationkey "%s"`, g.projectNameAnnotationKey)
		for podAnnotationKey, podAnnotationValue := range ctx.Pod.Annotations {
			if strings.HasPrefix(podAnnotationKey, g.projectNameAnnotationKey) {
				if podAnnotationValue != "" {
					// determine container name from annotation key
					containerName := getContainerNameFromAnnotationKey(podAnnotationKey, "/")
					if containerName != "" {
						logrus.Debugf(`ContainerName found: "%s"`, containerName)
						// correct container?
						if containerName == ctx.Container.Name {
							projectName, version = getNameAndVersionFromString(podAnnotationValue, ":")
							logrus.Infof(`Custom project name found at annotation "%s" for container "%s": "%s:%s"`, podAnnotationKey, containerName, projectName, version)
							break
						}
					} else {
						logrus.Errorf(`Containername could not be determined from annotation "%s". Skip setting project name.`, podAnnotationKey)
					}
				} else {
					logrus.Errorf(`Empty value for custom project name annotation "%s". Skip setting custom project name.`, podAnnotationKey)
				}
			}
		}
	}

	// If projectNameAnnotationKey is not set or could not be parsed correctly, use image instead
	if projectName == "" || version == "" {
		projectName, version = getRepoWithVersion(ctx.Image)
	}

	if ctx.Sbom == "" {
		logrus.Infof("Empty SBOM - skip image (image=%s)", ctx.Image.ImageID)
		return nil
	}

	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
		return err
	}

	logrus.Infof("Sending SBOM to Dependency Track (project=%s, version=%s)", projectName, version)

	sbomBase64 := base64.StdEncoding.EncodeToString([]byte(ctx.Sbom))
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
		project.Tags = append(project.Tags, dtrack.Tag{Name: fmt.Sprintf("%s=%s", rawImageId, ctx.Image.ImageID)})
	}
	podNamespaceTag := podNamespaceTagKey + "=" + ctx.Pod.PodNamespace
	if !containsTag(project.Tags, podNamespaceTag) {
		project.Tags = append(project.Tags, dtrack.Tag{Name: podNamespaceTag})
	}

	var reg *regexp.Regexp
	if g.podLabelTagMatcher != "" {
		reg, err = regexp.Compile(g.podLabelTagMatcher)
		if err != nil {
			logrus.Errorf("Could not parse regex: %v", err)
			return err
		}
	}

	for podLabelKey, podLabelValue := range ctx.Pod.Labels {
		podLabel := fmt.Sprintf("%s=%s", podLabelKey, podLabelValue)
		if !containsTag(project.Tags, podLabel) && (reg == nil || reg.MatchString(podLabelKey)) {
			project.Tags = append(project.Tags, dtrack.Tag{Name: podLabel})
		}
	}

	if g.parentProjectAnnotationKey != "" {
		logrus.Debugf("Try to set parent project by configured annotationkey %s", g.parentProjectAnnotationKey)
		for podAnnotationKey, podAnnotationValue := range ctx.Pod.Annotations {
			logrus.Debugf("AnnotationKey %s starts with %s?", podAnnotationKey, g.parentProjectAnnotationKey)
			if strings.HasPrefix(podAnnotationKey, g.parentProjectAnnotationKey) {
				// determine container name from annotation key
				containerName := getContainerNameFromAnnotationKey(podAnnotationKey, "/")
				if containerName != "" {
					if podAnnotationValue != "" {
						// correct container found?
						if containerName == ctx.Container.Name {
							parentProjectName, parentProjectVersion := getNameAndVersionFromString(podAnnotationValue, ":")
							logrus.Debugf("Try to find parent project by name from annotation \"%s\", for container %s, parentProjectName \"%s\" and parentProjectVersion \"%s\"", podAnnotationKey, containerName, parentProjectName, parentProjectVersion)
							parentProject, err := client.Project.Lookup(context.Background(), parentProjectName, parentProjectVersion)
							if err != nil {
								logrus.WithError(err).Errorf(`Could not find parent project "%s"`, parentProjectName)
							} else {
								logrus.Infof(`Found parent project with name "%s:%s" and UUID "%s" for container "%s": %+v\n`, parentProjectName, parentProjectVersion, parentProject.UUID, containerName, parentProject)
								project.ParentRef = &dtrack.ParentRef{UUID: parentProject.UUID}
							}
							break
						}
					} else {
						logrus.Errorf(`Empty value for parent project annotation "%s". Skip setting parent project.`, podAnnotationKey)
					}
				} else {
					logrus.Errorf(`Containername could not be determined from annotation "%s". Skip setting parent project.`, podAnnotationKey)
				}
			}
		}
	}

	_, err = client.Project.Update(context.Background(), project)
	if err != nil {
		logrus.WithError(err).Errorf("Could not update project")
	}

	if g.imageProjectMap == nil {
		// prepropulate imageProjectMap
		g.LoadImages()
	}

	g.imageProjectMap[ctx.Image.ImageID] = project.UUID
	return nil
}

func (g *DependencyTrackTarget) LoadImages() []*libk8s.RegistryImage {
	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
	}

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
			imageId = ""
			for _, tag := range project.Tags {
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

	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
	}

	for _, img := range images {
		uuid := g.imageProjectMap[img.ImageID]
		if uuid.String() == "00000000-0000-0000-0000-000000000000" {
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
					delete(g.imageProjectMap, img.ImageID)
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
			delete(g.imageProjectMap, img.ImageID)
			if err != nil {
				logrus.WithError(err).Warnf("Project %s could not be deleted", project.UUID.String())
			}
		}
	}
}

func getNameAndVersionFromString(input string, delimiter string) (string, string) {
	parts := strings.Split(input, delimiter)
	name := parts[0]
	version := "latest"
	if len(parts) == 2 {
		version = parts[1]
	}
	return name, version
}

func getContainerNameFromAnnotationKey(annotationKey string, delimiter string) string {
	parts := strings.Split(annotationKey, delimiter)
	containerName := ""
	if len(parts) == 2 {
		containerName = parts[1]
	}
	return containerName
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
