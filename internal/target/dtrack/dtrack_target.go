package dtrack

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	parser "github.com/novln/docker-parser"
	"github.com/sirupsen/logrus"

	"text/template"

	"github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	libk8s "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
)

type DependencyTrackTarget struct {
	clientOptions []dtrack.ClientOption

	baseUrl                    string
	apiKey                     string
	podLabelTagMatcher         string
	defaultParentProject       string
	parentProjectAnnotationKey string
	projectNameAnnotationKey   string
	caCertFile                 string
	clientCertFile             string
	clientKeyFile              string
	k8sClusterId               string
	k8sClusterIdMode           string
	useShortName               bool
	manageProjectActiveStatus  bool
	imageProjectMap            map[string][]*uuid.UUID

	defaultParentProjectParsed *uuid.UUID
}

const (
	kubernetesCluster        string = "kubernetes-cluster"
	sbomOperator             string = "sbom-operator"
	rawImageId               string = "raw-image-id"
	sbomScopeTagKey          string = "sbom-scope"
	podNamespaceTagKey       string = "namespace"
	deploymentTimestampGroup string = "deployment-timestamp"
	tsPropertyType           string = "STRING"
)

var nameTemplate = template.New("NameTemplate")

func NewDependencyTrackTarget(baseUrl, apiKey, podLabelTagMatcher, caCertFile, clientCertFile, clientKeyFile, k8sClusterId string, k8sClusterIdMode string, defaultParentProject string, parentProjectAnnotationKey string, projectNameAnnotationKey string, useShortName bool, manageProjectActiveStatus bool) *DependencyTrackTarget {
	return &DependencyTrackTarget{
		baseUrl:                    baseUrl,
		apiKey:                     apiKey,
		podLabelTagMatcher:         podLabelTagMatcher,
		caCertFile:                 caCertFile,
		clientCertFile:             clientCertFile,
		clientKeyFile:              clientKeyFile,
		k8sClusterId:               k8sClusterId,
		k8sClusterIdMode:           k8sClusterIdMode,
		defaultParentProject:       defaultParentProject,
		parentProjectAnnotationKey: parentProjectAnnotationKey,
		projectNameAnnotationKey:   projectNameAnnotationKey,
		useShortName:               useShortName,
		manageProjectActiveStatus:  manageProjectActiveStatus,
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
	if g.defaultParentProject != "" {
		uuid, err := uuid.Parse(g.defaultParentProject)
		if err != nil {
			return fmt.Errorf(
				"default parent project is not a valid UUID",
			)
		}
		g.defaultParentProjectParsed = &uuid
	} else {
		g.defaultParentProjectParsed = nil
	}

	if g.manageProjectActiveStatus && g.parentProjectAnnotationKey == "" && g.defaultParentProjectParsed == nil {
		return fmt.Errorf(
			"%s is enabled but no parent project is configured (set %s or %s)",
			internal.ConfigKeyDependencyTrackManageProjectActiveStatus,
			internal.ConfigKeyDependencyTrackDtrackParentProjectAnnotationKey,
			internal.ConfigKeyDefaultParentProject,
		)
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

func (g *DependencyTrackTarget) identifyProjectNameAndVersion(ctx *target.TargetContext) (string, string) {
	projectName := ""
	version := ""
	// Set custom project name by kubernetes annotation?
	if g.projectNameAnnotationKey != "" {
		logrus.Debugf(`Try to set project name by configured annotationkey "%s"`, g.projectNameAnnotationKey)
		for podAnnotationKey, podAnnotationValue := range ctx.Pod.Annotations {
			var err error
			projectName, version, err = g.getContainerNameAndVersion(podAnnotationKey, podAnnotationValue, g.projectNameAnnotationKey, ctx)
			if err != nil {
				logrus.WithError(err).Errorf("Wrong project name configuration. Skip setting custom project name for image '%s'", ctx.Image.Image)
				continue
			}
			if projectName != "" {
				break
			}
		}
	}

	// If projectNameAnnotationKey is not set or could not be parsed correctly, use image instead
	if projectName == "" || version == "" {
		logrus.Debugf("No custom project name configured (correctly). Falling back to name identification using image.")
		projectName, version = getRepoWithVersion(ctx, g.useShortName, g.k8sClusterId, g.k8sClusterIdMode)
	}
	return projectName, version
}

func (g *DependencyTrackTarget) identifiyParentProjectUuid(ctx *target.TargetContext, client *dtrack.Client) *uuid.UUID {
	if g.parentProjectAnnotationKey != "" {
		logrus.Debugf("Try to set parent project by configured annotationkey %s", g.parentProjectAnnotationKey)
		for podAnnotationKey, podAnnotationValue := range ctx.Pod.Annotations {
			logrus.Debugf("AnnotationKey %s starts with %s?", podAnnotationKey, g.parentProjectAnnotationKey)

			parentProjectName, parentProjectVersion, err := g.getContainerNameAndVersion(podAnnotationKey, podAnnotationValue, g.parentProjectAnnotationKey, ctx)
			if err != nil {
				logrus.WithError(err).Errorf("Wrong parent project configuration. Skipping parent for image '%s'", ctx.Image.Image)
				continue
			}
			if parentProjectName == "" {
				continue
			}
			parentProjectUuid, err := uuid.Parse(parentProjectName)
			if err == nil {
				return &parentProjectUuid
			}
			hasExplicitVersion := strings.Contains(podAnnotationValue, ":")
			logrus.Debugf("Try to find parent project by name from annotation \"%s\", for image %s, parentProjectName \"%s\" and parentProjectVersion \"%s\"", podAnnotationKey, ctx.Image.Image, parentProjectName, parentProjectVersion)
			parentProjects, err := client.Project.GetProjectsForName(context.Background(), parentProjectName, false, true)
			if err != nil {
				logrus.WithError(err).Errorf(`Could not find parent project "%s"`, parentProjectName)
			} else if len(parentProjects) == 0 {
				logrus.Errorf(`No parent project found with name "%s"`, parentProjectName)
			} else {
				var parentProject dtrack.Project
				found := false
				if hasExplicitVersion {
					for _, p := range parentProjects {
						if p.Version == parentProjectVersion {
							parentProject = p
							found = true
							break
						}
					}
					if !found {
						logrus.Errorf(`No parent project found with name "%s" and version "%s"`, parentProjectName, parentProjectVersion)
					}
				} else {
					if len(parentProjects) > 1 {
						logrus.Warnf(`Multiple root projects found with name "%s", using the first one`, parentProjectName)
					}
					parentProject = parentProjects[0]
					found = true
				}
				if found {
					logrus.Infof(`Found parent project with name "%s" and UUID "%s" for image "%s"`, parentProjectName, parentProject.UUID, ctx.Image.Image)
					return &parentProject.UUID
				}
			}
			break

		}
	}
	return g.defaultParentProjectParsed
}

func (g *DependencyTrackTarget) ProcessSbom(ctx *target.TargetContext) error {
	if ctx.MediaType != "" && ctx.MediaType != oci.CycloneDXJSONMediaType && ctx.MediaType != oci.CycloneDXXMLMediaType {
		logrus.Warnf("Skipping attestation SBOM (scope=%s) with unsupported mediaType %s for Dependency-Track", ctx.Scope, ctx.MediaType)
		return nil
	}

	logrus.Debugf("%v", g)
	projectName, version := g.identifyProjectNameAndVersion(ctx)

	if ctx.Sbom == "" {
		logrus.Infof("Empty SBOM - skip image (image=%s)", ctx.Image.ImageID)
		return nil
	}

	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
		return err
	}
	// When active-status management is enabled, try to reactivate an existing
	// inactive project without re-uploading the SBOM (e.g. a rollback to a
	// previously deployed image with a matching digest).
	project, skipUpload := dtrack.Project{}, false
	if g.manageProjectActiveStatus {
		existing, lookupErr := client.Project.Lookup(context.Background(), projectName, version)
		if lookupErr == nil && !existing.Active && getRawImageId(existing.Tags) == ctx.Image.ImageID {
			project = existing
			skipUpload = true
			logrus.Infof("Reactivating existing project %s:%s without re-uploading SBOM", projectName, version)
		}
	}

	parentUuid := g.identifiyParentProjectUuid(ctx, client)
	if !skipUpload {
		logrus.Infof("Sending SBOM to Dependency Track (project=%s, version=%s, parent=%s)", projectName, version, parentUuid)
		uploadToken, err := client.BOM.PostBom(
			context.Background(),
			dtrack.BOMUploadRequest{ProjectName: projectName, ProjectVersion: version, ParentUUID: parentUuid, AutoCreate: true, BOM: ctx.Sbom},
		)
		if err != nil {
			logrus.Errorf("Could not upload BOM: %v", err)
			return err
		}
		logrus.Infof("Uploaded SBOM for project '%s:%s' (upload-token=%s)", projectName, version, uploadToken)
	}

	if !skipUpload {
		project, err = client.Project.Lookup(context.Background(), projectName, version)
		if err != nil {
			logrus.Errorf("Could not find project '%s:%s': %v", projectName, version, err)
			return err
		}
	}

	if parentUuid != nil {
		project.ParentRef = &dtrack.ParentRef{UUID: *parentUuid}
	}
	alreadyOnCluster := false
	kubernetesClusterTag := kubernetesCluster + "=" + g.k8sClusterId
	if g.k8sClusterIdMode == "tag" {
		if !containsTag(project.Tags, kubernetesClusterTag) {
			project.Tags = append(project.Tags, dtrack.Tag{Name: kubernetesClusterTag})
		} else {
			alreadyOnCluster = true
		}
	} else {
		if containsTag(project.Tags, kubernetesClusterTag) {
			project.Tags = removeTag(project.Tags, kubernetesClusterTag)
		}
	}

	if !containsTag(project.Tags, sbomOperator) {
		project.Tags = append(project.Tags, dtrack.Tag{Name: sbomOperator})
	}

	// Ensure the raw-image-id tag reflects the current container digest. Previously
	// `containsTag(project.Tags, rawImageId)` was a prefix match, so any
	// `raw-image-id=...` tag prevented the new one from being added. When the same
	// (projectName, version) pair was backed by different digests (mutable `:latest`,
	// re-pushed tag, multiple pods), DT kept the first digest forever. During cleanup
	// this caused `LoadImages()` to emit a stale digest and `Remove()` to operate on
	// the still-live project, deleting it.
	project.Tags = rotateRawImageIdTag(project.Tags, ctx.Image.ImageID)
	podNamespaceTag := podNamespaceTagKey + "=" + ctx.Pod.PodNamespace
	if !containsTag(project.Tags, podNamespaceTag) {
		project.Tags = append(project.Tags, dtrack.Tag{Name: podNamespaceTag})
	}
	if ctx.Scope != "" && ctx.Scope != oci.ScopeAll {
		scopeTag := sbomScopeTagKey + "=" + ctx.Scope
		if !containsTag(project.Tags, scopeTag) {
			project.Tags = append(project.Tags, dtrack.Tag{Name: scopeTag})
		}
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

	if g.manageProjectActiveStatus {
		project.Active = true
		project.IsLatest = dtrack.OptionalBoolOf(true)
	}

	_, err = client.Project.Update(context.Background(), project)
	if err != nil {
		logrus.WithError(err).Errorf("Could not update project")
	}

	if g.manageProjectActiveStatus {
		g.deactivateSiblingVersions(client, project, ctx.Image)
	}
	if err := g.upsertDeploymentTimestampProperty(client, ctx, project, alreadyOnCluster); err != nil {
		logrus.WithError(err).Warnf("Could not set deployment timestamp property for project '%s:%s'", project.Name, project.Version)
	}
	if g.imageProjectMap == nil {
		// prepropulate imageProjectMap
		_, err := g.LoadImages()
		if err != nil {
			return err
		}
	}
	g.imageProjectMap[ctx.Image.ImageID] = append(g.imageProjectMap[ctx.Image.ImageID], &project.UUID)
	return nil
}

type TemplateData struct {
	ContainerNames []*string
	SbomScope      string
	ImageId        string
	ImageName      string
	ShortName      string
	Repository     string
	Tag            string
}

func extractTemplateData(ctx *target.TargetContext, containers []*kubernetes.ContainerInfo) TemplateData {
	imageRef, err := parser.Parse(ctx.Image.ImageID)
	if err != nil {
		logrus.WithError(err).Errorf("Could not parse image %s", ctx.Image.ImageID)
	}
	var shortName, repository, tag string
	if imageRef != nil {
		shortName = imageRef.ShortName()
		repository = imageRef.Repository()
	}

	if strings.Index(ctx.Image.Image, "sha256") != 0 {
		imageRef, err = parser.Parse(ctx.Image.Image)
		if err != nil {
			logrus.WithError(err).Errorf("Could not parse image %s", ctx.Image.Image)
		}
	}
	tag = imageRef.Tag()
	cNames := make([]*string, 0, len(containers))
	for _, container := range containers {
		cNames = append(cNames, &container.Name)
	}
	return TemplateData{
		ContainerNames: cNames,
		SbomScope:      ctx.Scope,
		ImageId:        ctx.Image.ImageID,
		ImageName:      ctx.Image.Image,
		ShortName:      shortName,
		Repository:     repository,
		Tag:            tag,
	}
}

func (g *DependencyTrackTarget) getContainerNameAndVersion(podAnnotationKey string, podAnnotationValue string, expectedAnnotationKey string, ctx *target.TargetContext) (string, string, error) {
	if strings.HasPrefix(podAnnotationKey, expectedAnnotationKey) {
		// determine container name and scope from annotation key
		containerName := getContainerNameFromAnnotationKey(podAnnotationKey, "/")
		if podAnnotationValue != "" {
			var data TemplateData
			dataFound := false
			if containerName == "" {
				data = extractTemplateData(ctx, ctx.Containers)
				dataFound = true
			} else {
				for _, c := range ctx.Containers {
					if containerName == c.Name {
						data = extractTemplateData(ctx, []*kubernetes.ContainerInfo{c})
						dataFound = true
						break
					} else {
						logrus.Debugf("skipping container '%s' as not configured for annotation key '%s'", c.Name, expectedAnnotationKey)
					}
				}
			}
			if dataFound {
				tmpl, err := nameTemplate.Parse(podAnnotationValue)
				if err != nil {
					return "", "", err
				}
				var buf bytes.Buffer
				if err := tmpl.Execute(&buf, data); err != nil {
					return "", "", err
				}
				parsedValue := buf.String()
				name, version := getNameAndVersionFromString(parsedValue, ":")
				logrus.Infof(`Custom '%s' found at annotation '%s' for container '%s' with scope: '%s': '%s:%s'`, expectedAnnotationKey, podAnnotationKey, containerName, ctx.Scope, name, version)
				return name, version, nil
			}
		} else {
			return "", "", fmt.Errorf(`empty value for annotation '%s' in image '%s'`, podAnnotationKey, ctx.Image.Image)
		}
	}
	return "", "", nil
}

func (g *DependencyTrackTarget) LoadImages() ([]*libk8s.RegistryImage, error) {
	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
		return nil, err
	}

	// Always rebuild the imageProjectMap from DT state. Previously the map was
	// only initialised when nil, so entries accumulated across reconcile cycles.
	// After a pod/image update, stale `digest -> UUID` entries kept pointing at
	// UUIDs of still-live projects (because rotation of raw-image-id was broken,
	// see ProcessSbom). That caused `Remove()` to operate on live projects.
	// Resetting here guarantees the map mirrors the current DT state.
	g.imageProjectMap = make(map[string][]*uuid.UUID)

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
			return nil, err
		}

		var imageId string

		for _, project := range projectsPage.Items {
			sbomOperatorPropFound := false
			imageRelatesToCluster := false
			imageId = ""

			//extend lookup logic to support `prefix` mode to resolve image association
			if g.k8sClusterIdMode == "prefix" {
				imageRelatesToCluster = strings.HasPrefix(project.Name, g.k8sClusterId+"-")
			}

			for _, tag := range project.Tags {
				if g.k8sClusterIdMode == "tag" && strings.Index(tag.Name, kubernetesCluster) == 0 {
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

			// When active-status management is enabled, inactive projects are not
			// returned so they neither appear as orphans on every cycle nor block
			// re-scanning of a rolled-back image.
			if g.manageProjectActiveStatus && !project.Active {
				continue
			}
			if imageRelatesToCluster && sbomOperatorPropFound && len(imageId) > 0 {
				images = append(images, &libk8s.RegistryImage{ImageID: imageId})
				g.imageProjectMap[imageId] = append(g.imageProjectMap[imageId], &project.UUID)
			}
		}

		if pageNumber*pageSize >= projectsPage.TotalCount {
			break
		}

		pageNumber++
	}

	return images, nil
}

func (g *DependencyTrackTarget) Remove(images []*libk8s.RegistryImage) error {
	if g.imageProjectMap == nil {
		// prepropulate imageProjectMap
		_, err := g.LoadImages()
		if err != nil {
			return err
		}
	}

	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
		return err
	}

	for _, img := range images {
		for _, uuid := range g.imageProjectMap[img.ImageID] {
			if uuid.String() == "00000000-0000-0000-0000-000000000000" {
				logrus.Warnf("No project found for imageID: %s", img.ImageID)
				continue
			}

			project, err := client.Project.Get(context.Background(), *uuid)
			if err != nil {
				logrus.Errorf("Could not load project: %v", err)
				continue
			}
			_ = g.handleProjectDeactivation(client, &project, img, true)
		}
	}

	return nil
}

func (g *DependencyTrackTarget) ProjectDeleted(project *dtrack.Project, img *libk8s.RegistryImage) {
	projects := g.imageProjectMap[img.ImageID]
	for i, projectUUID := range projects {
		if projectUUID != nil && *projectUUID == project.UUID {
			g.imageProjectMap[img.ImageID] = append(projects[:i], projects[i+1:]...)
			if len(g.imageProjectMap[img.ImageID]) == 0 {
				delete(g.imageProjectMap, img.ImageID)
			}
		}
	}
}

// Deactivate sets the given projects as inactive (and not latest) instead of
// deleting them, preserving them for version history. Only invoked when
// ShouldDeactivateOrphans returns true. All tags are kept.
func (g *DependencyTrackTarget) Deactivate(images []*libk8s.RegistryImage) error {
	if g.imageProjectMap == nil {
		_, err := g.LoadImages()
		if err != nil {
			return err
		}
	}

	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
		return err
	}

	for _, img := range images {
		for _, uuid := range g.imageProjectMap[img.ImageID] {
			if uuid.String() == "00000000-0000-0000-0000-000000000000" {
				logrus.Warnf("No project found for imageID: %s", img.ImageID)
				continue
			}

			project, err := client.Project.Get(context.Background(), *uuid)
			if err != nil {
				logrus.Errorf("Could not load project: %v", err)
				continue
			}

			_ = g.handleProjectDeactivation(client, &project, img, false)
		}
	}

	return nil
}

func (g *DependencyTrackTarget) ShouldDeactivateOrphans() bool {
	return g.manageProjectActiveStatus
}

// deactivateSiblingVersions sets all other versions of the same project name
// under the same parent as inactive (and not latest), so that only the currently
// running version stays active.
func (g *DependencyTrackTarget) deactivateSiblingVersions(client *dtrack.Client, project dtrack.Project, img *libk8s.RegistryImage) {
	if project.ParentRef == nil {
		return
	}

	siblings, err := client.Project.GetProjectsForName(context.Background(), project.Name, false, false)
	if err != nil {
		logrus.WithError(err).Errorf("Could not load sibling projects for name %s", project.Name)
		return
	}

	for _, sibling := range siblings {
		if sibling.UUID == project.UUID {
			continue
		}
		if sibling.ParentRef == nil || sibling.ParentRef.UUID != project.ParentRef.UUID {
			continue
		}
		if sibling.Version == project.Version {
			continue
		}
		_ = g.handleProjectDeactivation(client, &sibling, img, false)
	}
}

func getNameAndVersionFromString(input string, delimiter string) (string, string) {
	parts := strings.Split(input, delimiter)
	name := strings.TrimSpace(parts[0])
	version := "latest"
	if len(parts) == 2 {
		version = strings.TrimSpace(parts[1])
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

// getRawImageId returns the value of the first `raw-image-id=<id>` tag, or an
// empty string if none is present.
func getRawImageId(tags []dtrack.Tag) string {
	prefix := rawImageId + "="
	for _, tag := range tags {
		if strings.HasPrefix(tag.Name, prefix) {
			return strings.TrimPrefix(tag.Name, prefix)
		}
	}
	return ""
}

// rotateRawImageIdTag drops any existing `raw-image-id=*` tag(s) from the slice
// and appends a single `raw-image-id=<digest>` tag with the current digest. Used
// to keep the project's recorded digest in sync with the container that the
// operator just processed. See ProcessSbom for the rationale.
func rotateRawImageIdTag(tags []dtrack.Tag, currentImageID string) []dtrack.Tag {
	prefix := rawImageId + "="
	out := make([]dtrack.Tag, 0, len(tags)+1)
	for _, tag := range tags {
		if !strings.HasPrefix(tag.Name, prefix) {
			out = append(out, tag)
		}
	}
	return append(out, dtrack.Tag{Name: prefix + currentImageID})
}

func getRepoWithVersion(ctx *target.TargetContext, useShortName bool, k8sClusterId string, k8sClusterIdMode string) (string, string) {
	data := extractTemplateData(ctx, ctx.Containers)

	var projectName string
	//add Cluster prefix to projectName if prefix mode is set
	if k8sClusterIdMode == "prefix" {
		projectName = k8sClusterId + "-"
	}
	if useShortName {
		projectName += data.ShortName
	} else {
		projectName += data.Repository
	}
	if data.SbomScope != "" && data.SbomScope != oci.ScopeAll {
		projectName += "-" + data.SbomScope
	}

	return projectName, data.Tag
}

// handleProjectDeactivation removes the current cluster tag in "tag" mode
// and persists the updated tags. If no other clusters are referencing the
// project anymore, it patches the project to be inactive (and not latest).
func (g *DependencyTrackTarget) handleProjectDeactivation(client *dtrack.Client, project *dtrack.Project, img *libk8s.RegistryImage, deleteProject bool) error {
	if !project.Active {
		return nil
	}
	sbomOperatorPropFound := false
	for _, tag := range project.Tags {
		if tag.Name == sbomOperator {
			sbomOperatorPropFound = true
			break
		}
	}
	if !sbomOperatorPropFound {
		return nil
	}

	if g.k8sClusterIdMode == "tag" {
		ownClusterTagFound := false
		otherClusterIds := []string{}

		for _, tag := range project.Tags {
			if strings.Index(tag.Name, kubernetesCluster) == 0 {
				clusterId := string(tag.Name[len(kubernetesCluster)+1:])
				if clusterId == g.k8sClusterId {
					ownClusterTagFound = true
					logrus.Infof("Removing %s=%s tag from project '%s:%s'", kubernetesCluster, g.k8sClusterId, project.Name, project.Version)
					project.Tags = removeTag(project.Tags, kubernetesCluster+"="+g.k8sClusterId)
				} else {
					otherClusterIds = append(otherClusterIds, clusterId)
				}
			}
		}

		if ownClusterTagFound && (!deleteProject || len(otherClusterIds) != 0) { // no need to call update in case we anyhow delete the project
			_, err := client.Project.Update(context.Background(), *project)
			if err != nil {
				logrus.WithError(err).Warnf("Project tags could not be updated for project '%s:%s'", project.Name, project.Version)
				return err
			}
		}
		if len(otherClusterIds) > 0 {
			return nil
		}
	}

	// No other clusters are using it (or tag mode is disabled) -> deactivate/delete
	g.ProjectDeleted(project, img)

	action := "Deactivating"
	if deleteProject {
		action = "Deleting"
	}
	logrus.Infof("%s project '%s:%s' as it is not used by any other clusters", action, project.Name, project.Version)
	if deleteProject {
		err := client.Project.Delete(context.Background(), project.UUID)
		if err != nil {
			logrus.WithError(err).Warnf("Project could not be deleted '%s:%s'", project.Name, project.Version)
			return err
		}
	} else {
		_, err := client.Project.Patch(context.Background(), project.UUID, dtrack.Project{
			Active:   false,
			IsLatest: dtrack.OptionalBoolOf(false),
		})
		if err != nil {
			logrus.WithError(err).Warnf("Project '%s:%s' could not be deactivated", project.Name, project.Version)
			return err
		}
	}

	return nil
}

func (g *DependencyTrackTarget) deploymentPropertyName() string {
	clusterID := g.k8sClusterId
	if clusterID == "" {
		clusterID = "default"
	}
	if g.k8sClusterIdMode == "tag" {
		return fmt.Sprintf("%s=%s", kubernetesCluster, clusterID)
	}
	return clusterID
}

func (g *DependencyTrackTarget) upsertDeploymentTimestampProperty(
	client *dtrack.Client,
	ctx *target.TargetContext,
	project dtrack.Project,
	alreadyOnCluster bool,
) error {
	ts := time.Now().UTC()
	if ctx != nil && !ctx.DeploymentTime.IsZero() {
		ts = ctx.DeploymentTime.UTC()
	}

	propName := g.deploymentPropertyName()
	prop := dtrack.ProjectProperty{
		Group:       deploymentTimestampGroup,
		Name:        propName,
		Value:       strconv.FormatInt(ts.UnixMilli(), 10),
		Type:        tsPropertyType,
		Description: "Deployment timestamp reported by sbom-operator",
	}

	// Properties needs to be loaded using ProjectProperty-API separatly
	existingProps, err := client.ProjectProperty.GetAll(context.Background(), project.UUID, dtrack.PageOptions{})
	if err != nil {
		return fmt.Errorf("fetching project properties: %w", err)
	}

	propertyExists := hasProjectProperty(existingProps.Items, prop.Group, prop.Name)

	// 1. Project was already active on this Cluster (e.g. Operator restart / new replica)
	//    and property already existss -> hold original Deployment-Timestamp!
	if alreadyOnCluster && propertyExists {
		logrus.Debugf("Project %s:%s already active on %s, keeping existing deployment timestamp", project.Name, project.Version, propName)
		return nil
	}

	// 2. Property already exists, but project was again deployed on this stage (Rollback / Redeploy) -> POST (Update)
	if propertyExists {
		logrus.Infof("Updating deployment timestamp property (%s/%s) for redeployed project %s:%s", prop.Group, prop.Name, project.Name, project.Version)
		_, err = client.ProjectProperty.Update(context.Background(), project.UUID, prop)
		return err
	}

	// 3. Property does not exist yet -> PUT (Create)
	logrus.Infof("Creating deployment timestamp property (%s/%s) for project %s:%s", prop.Group, prop.Name, project.Name, project.Version)
	_, err = client.ProjectProperty.Create(context.Background(), project.UUID, prop)
	if err != nil && err.(*dtrack.APIError).StatusCode == 409 {
		logrus.Debugf("Property (%s/%s) was created concurrently for project '%s:%s', ignoring 409 conflict", prop.Group, prop.Name, project.Name, project.Version)
		return nil
	}
	return err
}

func hasProjectProperty(props []dtrack.ProjectProperty, group, name string) bool {
	for _, p := range props {
		if p.Group == group && p.Name == name {
			return true
		}
	}
	return false
}
