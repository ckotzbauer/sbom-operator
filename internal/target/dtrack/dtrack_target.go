package dtrack

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"

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
	imageProjectMap            map[string]map[string]map[uuid.UUID]struct{}
	defaultParentProjectParsed *uuid.UUID
}

const (
	kubernetesCluster  string = "kubernetes-cluster"
	sbomOperator       string = "sbom-operator"
	rawImageId         string = "raw-image-id"
	sbomScopeTagKey    string = "sbom-scope"
	podNamespaceTagKey string = "namespace"
)

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
	if g.k8sClusterIdMode != "" {
		switch g.k8sClusterIdMode {
		case "tag", "tag-namespace", "prefix":
			break
		default:
			return fmt.Errorf("'dtrack-kubernetes-cluster-id-mode' has unknown value: %s", g.k8sClusterId)
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
		projectName, version = g.getRepoWithVersion(ctx, g.useShortName, g.k8sClusterId)
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

func (g *DependencyTrackTarget) isTagMode() bool {
	return strings.HasPrefix(g.k8sClusterIdMode, "tag")
}

func (g *DependencyTrackTarget) isNamespaceMode() bool {
	return strings.HasSuffix(g.k8sClusterIdMode, "namespace")
}

func (g *DependencyTrackTarget) isPrefixMode() bool {
	return strings.HasPrefix(g.k8sClusterIdMode, "prefix")
}

func (g *DependencyTrackTarget) ProcessSbom(ctx *target.TargetContext) error {
	if ctx.Attestation.MediaType != "" && ctx.Attestation.MediaType != oci.CycloneDXJSONMediaType && ctx.Attestation.MediaType != oci.CycloneDXXMLMediaType {
		logrus.Warnf("Skipping attestation SBOM (scope=%s) with unsupported mediaType %s for Dependency-Track", ctx.Attestation.Scope, ctx.Attestation.MediaType)
		return nil
	}

	logrus.Debugf("%v", g)
	projectName, version := g.identifyProjectNameAndVersion(ctx)

	if ctx.Attestation.Sbom == "" {
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
			dtrack.BOMUploadRequest{ProjectName: projectName, ProjectVersion: version, ParentUUID: parentUuid, AutoCreate: true, BOM: ctx.Attestation.Sbom},
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
	kubernetesClusterTag := kubernetesCluster + "=" + g.k8sClusterId
	if g.isNamespaceMode() {
		kubernetesClusterTag += "/" + ctx.Pod.PodNamespace
	} else {
		// don't add namespace tag in namespace mode as it is already in clusterId tag
		podNamespaceTag := podNamespaceTagKey + "=" + ctx.Pod.PodNamespace
		if !containsTag(project.Tags, podNamespaceTag) {
			project.Tags = append(project.Tags, dtrack.Tag{Name: podNamespaceTag})
		}
	}
	if g.isTagMode() {
		if !containsTag(project.Tags, kubernetesClusterTag) {
			project.Tags = append(project.Tags, dtrack.Tag{Name: kubernetesClusterTag})
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
	if ctx.Attestation.Scope != "" && ctx.Attestation.Scope != oci.ScopeAll {
		scopeTag := sbomScopeTagKey + "=" + ctx.Attestation.Scope
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
		g.deactivateSiblingVersions(client, &project, ctx.Image, ctx.Pod)
	}

	err = g.addProjectToCache(ctx.Pod.PodNamespace, ctx.Image.ImageID, project)

	return err
}

func (g *DependencyTrackTarget) addProjectToCache(namespace string, imageId string, project dtrack.Project) error {
	if g.imageProjectMap == nil {
		// prepropulate imageProjectMap
		_, err := g.LoadImages()
		if err != nil {
			return err
		}
	}
	if _, ok := g.imageProjectMap[imageId]; !ok {
		g.imageProjectMap[imageId] = make(map[string]map[uuid.UUID]struct{})
	}
	if _, ok := g.imageProjectMap[imageId][namespace]; !ok {
		g.imageProjectMap[imageId][namespace] = make(map[uuid.UUID]struct{})
	}
	g.imageProjectMap[imageId][namespace][project.UUID] = struct{}{}
	return nil
}

type TemplateData struct {
	ContainerNames []string
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
	cNames := make([]string, 0, len(containers))
	for _, container := range containers {
		cNames = append(cNames, container.Name)
	}
	return TemplateData{
		ContainerNames: cNames,
		SbomScope:      ctx.Attestation.Scope,
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
				tmpl, err := template.New("NameTemplate").Parse(podAnnotationValue)
				if err != nil {
					return "", "", err
				}
				var buf bytes.Buffer
				if err := tmpl.Execute(&buf, data); err != nil {
					return "", "", err
				}
				parsedValue := buf.String()
				name, version := getNameAndVersionFromString(parsedValue, ":")
				logrus.Infof(`Custom '%s' found at annotation '%s' for container '%s' with scope: '%s': '%s:%s'`, expectedAnnotationKey, podAnnotationKey, containerName, ctx.Attestation.Scope, name, version)
				return name, version, nil
			}
		} else {
			return "", "", fmt.Errorf(`empty value for annotation '%s' in image '%s'`, podAnnotationKey, ctx.Image.Image)
		}
	}
	return "", "", nil
}

func (g *DependencyTrackTarget) LoadImages() ([]*target.TargetImage, error) {
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
	g.imageProjectMap = make(map[string]map[string]map[uuid.UUID]struct{})

	var (
		pageNumber = 1
		pageSize   = 50
	)

	images := make([]*target.TargetImage, 0)
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
			// When active-status management is enabled, inactive projects are not
			// returned so they neither appear as orphans on every cycle nor block
			// re-scanning of a rolled-back image.
			if g.manageProjectActiveStatus && !project.Active {
				continue
			}

			sbomOperatorPropFound := false
			imageRelatesToCluster := false
			imageId = ""
			var namespaces []string

			if g.isPrefixMode() {
				imageRelatesToCluster = strings.HasPrefix(project.Name, g.k8sClusterId+"-")
			}

			podNsPrefix := podNamespaceTagKey + "="
			clusterPrefix := kubernetesCluster + "="
			rawImgPrefix := rawImageId + "="

			for _, tag := range project.Tags {
				if strings.HasPrefix(tag.Name, podNsPrefix) {
					namespaces = append(namespaces, strings.TrimPrefix(tag.Name, podNsPrefix))
				}

				if g.isTagMode() && strings.HasPrefix(tag.Name, clusterPrefix) {
					clusterId := strings.TrimPrefix(tag.Name, clusterPrefix)

					if g.isNamespaceMode() {
						ownClusterPrefix := g.k8sClusterId + "/"
						if strings.HasPrefix(clusterId, ownClusterPrefix) {
							imageRelatesToCluster = true
							ns := strings.TrimPrefix(clusterId, ownClusterPrefix)
							if ns != "" {
								namespaces = append(namespaces, ns)
							}

						}
					} else if clusterId == g.k8sClusterId {
						imageRelatesToCluster = true
					}
				}

				if tag.Name == sbomOperator {
					sbomOperatorPropFound = true
				}

				if strings.HasPrefix(tag.Name, rawImgPrefix) {
					imageId = strings.TrimPrefix(tag.Name, rawImgPrefix)
				}
			}

			if imageRelatesToCluster && sbomOperatorPropFound && len(imageId) > 0 {
				for _, ns := range namespaces {
					images = append(images, &target.TargetImage{
						RegistryImage: &libk8s.RegistryImage{ImageID: imageId},
						Namespace:     ns,
					})
					_ = g.addProjectToCache(ns, imageId, project)
				}
			}
		}

		if pageNumber*pageSize >= projectsPage.TotalCount {
			break
		}

		pageNumber++
	}

	return images, nil
}

func (g *DependencyTrackTarget) projectDeleted(project *dtrack.Project, img *target.TargetImage) {
	nsMap, ok := g.imageProjectMap[img.ImageID]
	if !ok {
		return
	}
	// If Namespace is empty (e.g. prefix mode / non-namespace-aware),
	// remove the project UUID across all cached namespaces for this image.
	if img.Namespace == "" {
		for ns, projects := range nsMap {
			delete(projects, project.UUID)
			if len(projects) == 0 {
				delete(nsMap, ns)
			}
		}
		if len(nsMap) == 0 {
			delete(g.imageProjectMap, img.ImageID)
		}
		return
	}

	if projects, ok := nsMap[img.Namespace]; ok {
		delete(projects, project.UUID)
		if len(projects) == 0 {
			delete(nsMap, img.Namespace)
			if len(nsMap) == 0 {
				delete(g.imageProjectMap, img.ImageID)
			}
		}
	}
}

func (g *DependencyTrackTarget) removeOrDeactivate(images []*target.TargetImage, remove bool) error {
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
		var projects map[uuid.UUID]struct{}
		if img.Namespace == "" {
			projects = make(map[uuid.UUID]struct{})
			for _, nsProjects := range g.imageProjectMap[img.ImageID] {
				for projectUUID := range nsProjects {
					projects[projectUUID] = struct{}{}
				}
			}
		} else {
			projects = g.imageProjectMap[img.ImageID][img.Namespace]
		}

		for projectUUID := range projects {
			if projectUUID == uuid.Nil {
				logrus.Warnf("No project found for imageID: %s", img.ImageID)
				continue
			}

			project, err := client.Project.Get(context.Background(), projectUUID)
			if err != nil {
				logrus.Errorf("Could not load project: %v", err)
				continue
			}

			_ = g.handleProjectDeactivation(client, &project, img, remove)
		}
	}

	return nil
}

func (g *DependencyTrackTarget) Remove(images []*target.TargetImage) error {
	return g.removeOrDeactivate(images, true)
}

// Deactivate sets the given projects as inactive (and not latest) instead of
// deleting them, preserving them for version history. Only invoked when
// ShouldDeactivateOrphans returns true. All tags are kept.
func (g *DependencyTrackTarget) Deactivate(images []*target.TargetImage) error {
	return g.removeOrDeactivate(images, false)
}

func (g *DependencyTrackTarget) ShouldDeactivateOrphans() bool {
	return g.manageProjectActiveStatus
}

// deactivateSiblingVersions sets all other versions of the same project name
// under the same parent as inactive (and not latest), so that only the currently
// running version stays active.
func (g *DependencyTrackTarget) deactivateSiblingVersions(client *dtrack.Client, project *dtrack.Project, img *libk8s.RegistryImage, pod *kubernetes.PodInfo) {
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
		_ = g.handleProjectDeactivation(client, &sibling, &target.TargetImage{RegistryImage: img, Namespace: pod.PodNamespace}, false)
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

func (g *DependencyTrackTarget) getRepoWithVersion(ctx *target.TargetContext, useShortName bool, k8sClusterId string) (string, string) {
	data := extractTemplateData(ctx, ctx.Containers)

	var projectName string
	//add Cluster prefix to projectName if prefix mode is set
	if g.isPrefixMode() {
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
func (g *DependencyTrackTarget) handleProjectDeactivation(client *dtrack.Client, project *dtrack.Project, img *target.TargetImage, deleteProject bool) error {
	if !project.Active {
		return nil
	}
	sbomOperatorPropFound := false
	podNsPrefix := podNamespaceTagKey + "="
	remainingNamespacesOnProject := 0

	// 1. Pre-scan tags once to verify ownership and count remaining active namespaces
	for _, tag := range project.Tags {
		if tag.Name == sbomOperator {
			sbomOperatorPropFound = true
		} else if img.Namespace != "" && strings.HasPrefix(tag.Name, podNsPrefix) {
			if strings.TrimPrefix(tag.Name, podNsPrefix) != img.Namespace {
				remainingNamespacesOnProject++
			}
		}
	}
	if !sbomOperatorPropFound {
		return nil
	}

	// 2. Check if another namespace in our cluster still uses this project (relevant for standard tag mode)
	sameProjectInOtherNs := remainingNamespacesOnProject > 0
	if !sameProjectInOtherNs && g.isTagMode() && !g.isNamespaceMode() && img.Namespace != "" {
		for ns, nsImages := range g.imageProjectMap[img.ImageID] {
			if ns != img.Namespace {
				if _, exists := nsImages[project.UUID]; exists {
					sameProjectInOtherNs = true
					break
				}
			}
		}
	}

	expectedClusterId := g.k8sClusterId
	if g.isNamespaceMode() {
		expectedClusterId = g.k8sClusterId + "/" + img.Namespace
	}
	clusterPrefix := kubernetesCluster + "="

	// 3. Single-pass tag filtering for both "namespace=" and "kubernetes-cluster=" tags
	tagsModified := false
	stillInUse := false
	filteredTags := make([]dtrack.Tag, 0, len(project.Tags))

	for _, tag := range project.Tags {
		// Remove stale "namespace=<ns>" tag
		if img.Namespace != "" && tag.Name == podNsPrefix+img.Namespace {
			tagsModified = true
			logrus.Infof("Removing %s tag from project '%s:%s'", tag.Name, project.Name, project.Version)
			continue
		}

		// Handle "kubernetes-cluster=" tags in tag mode
		if g.isTagMode() && strings.HasPrefix(tag.Name, clusterPrefix) {
			clusterId := strings.TrimPrefix(tag.Name, clusterPrefix)
			if !sameProjectInOtherNs && clusterId == expectedClusterId {
				tagsModified = true
				logrus.Infof("Removing %s tag from project '%s:%s'", tag.Name, project.Name, project.Version)
				continue
			}
			// Another cluster (or our own cluster via another active namespace) still holds a tag
			stillInUse = true
		}

		filteredTags = append(filteredTags, tag)
	}
	project.Tags = filteredTags

	// 4. only update tags if modified AND the project won't be deleted right after
	if tagsModified && (!deleteProject || stillInUse) {
		if _, err := client.Project.Update(context.Background(), *project); err != nil {
			logrus.WithError(err).Warnf("Project tags could not be updated for project '%s:%s'", project.Name, project.Version)
			return err
		}
	}

	g.projectDeleted(project, img)

	if stillInUse {
		return nil
	}

	// 5. No other clusters/namespaces are using it -> deactivate or delete
	if deleteProject {
		logrus.Infof("Deleting project '%s:%s' as it is not used by any other clusters", project.Name, project.Version)
		if err := client.Project.Delete(context.Background(), project.UUID); err != nil {
			logrus.WithError(err).Warnf("Project could not be deleted '%s:%s'", project.Name, project.Version)
			return err
		}
		return nil
	}

	logrus.Infof("Deactivating project '%s:%s' as it is not used by any other clusters", project.Name, project.Version)
	if _, err := client.Project.Patch(context.Background(), project.UUID, dtrack.Project{
		Active:   false,
		IsLatest: dtrack.OptionalBoolOf(false),
	}); err != nil {
		logrus.WithError(err).Warnf("Project '%s:%s' could not be deactivated", project.Name, project.Version)
		return err
	}

	return nil
}

func (g *DependencyTrackTarget) IsNamespaceAware() bool {
	return !g.isPrefixMode()
}
