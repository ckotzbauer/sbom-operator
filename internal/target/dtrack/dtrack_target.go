package dtrack

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
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
	imageProjectMap            map[string]map[string]map[uuid.UUID]struct{}
	defaultParentProjectParsed *uuid.UUID
	templateProjectName        string
	parsedProjectTemplate      *template.Template
}

const (
	kubernetesCluster        string = "kubernetes-cluster"
	sbomOperator             string = "sbom-operator"
	rawImageId               string = "raw-image-id"
	sbomScopeTagKey          string = "sbom-scope"
	podNamespaceTagKey       string = "namespace"
	deploymentTimestampGroup string = "deployment-timestamp"
)

func NewDependencyTrackTarget(baseUrl, apiKey, podLabelTagMatcher, caCertFile, clientCertFile, clientKeyFile, k8sClusterId string, k8sClusterIdMode string, defaultParentProject string, parentProjectAnnotationKey string, projectNameAnnotationKey string, useShortName bool, manageProjectActiveStatus bool, templateProjectName string) *DependencyTrackTarget {
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
		templateProjectName:        templateProjectName,
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
			return fmt.Errorf("'dtrack-kubernetes-cluster-id-mode' has unknown value: %s", g.k8sClusterIdMode)
		}
	}
	if g.templateProjectName != "" {
		tmpl, err := template.New("GlobalNameTemplate").Option("missingkey=error").Parse(g.templateProjectName)
		if err != nil {
			return fmt.Errorf("invalid global project name template %q: %w", g.templateProjectName, err)
		}
		g.parsedProjectTemplate = tmpl
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
	projectName, version := g.getRepoWithVersion(ctx, g.useShortName, g.k8sClusterId)
	if g.templateProjectName != "" {
		var err error
		projectName, version, err = g.getTemplatedNameAndVersion(ctx, g.templateProjectName, ctx.Containers, projectName, version)
		if err != nil {
			logrus.WithError(err).Warnf("Failed to parse templated project name '%s'.", g.templateProjectName)
		}
	}

	// 1. Priority: Custom project name via Kubernetes pod annotation
	if g.projectNameAnnotationKey != "" && ctx.Pod != nil {
		logrus.Debugf("Try to set project name by configured annotationkey '%s'", g.projectNameAnnotationKey)

		// Step 1a: Evaluate pod-wide annotation first (exact key match)
		if podWideValue, ok := ctx.Pod.Annotations[g.projectNameAnnotationKey]; ok {
			var err error
			_, projectName, version, err = g.getContainerNameAndVersion(projectName, version, g.projectNameAnnotationKey, podWideValue, g.projectNameAnnotationKey, ctx)
			if err != nil {
				logrus.WithError(err).Errorf("Wrong project name configuration. Skip setting custom project name for image '%s'", ctx.Image.Image)
			}
		}

		// Step 1b: Evaluate container-specific annotations ("<key>/<containerName>"), taking precedence
		containerPrefix := g.projectNameAnnotationKey + "/"
		for podAnnotationKey, podAnnotationValue := range ctx.Pod.Annotations {
			if !strings.HasPrefix(podAnnotationKey, containerPrefix) {
				continue
			}

			var err error
			var found bool
			found, projectName, version, err = g.getContainerNameAndVersion(projectName, version, podAnnotationKey, podAnnotationValue, g.projectNameAnnotationKey, ctx)
			if err != nil {
				logrus.WithError(err).Errorf("Wrong project name configuration. Skip setting custom project name for image '%s'", ctx.Image.Image)
				continue
			}
			if found {
				break
			}
		}
	}

	return projectName, version
}

func (g *DependencyTrackTarget) identifyParentProjectUuid(ctx *target.TargetContext, client *dtrack.Client) *uuid.UUID {
	if g.parentProjectAnnotationKey != "" && ctx.Pod != nil {
		logrus.Debugf("Try to set parent project by configured annotationkey %s", g.parentProjectAnnotationKey)

		parentProjectName := ""
		parentProjectVersion := ""
		matchedAnnotationKey := ""
		matchedAnnotationValue := ""

		// 1. Evaluate pod-wide parent annotation first (exact key match)
		if podWideValue, ok := ctx.Pod.Annotations[g.parentProjectAnnotationKey]; ok {
			found, name, version, err := g.getContainerNameAndVersion(parentProjectName, parentProjectVersion, g.parentProjectAnnotationKey, podWideValue, g.parentProjectAnnotationKey, ctx)
			if err != nil {
				logrus.WithError(err).Errorf("Wrong parent project configuration. Skipping parent for image '%s'", ctx.Image.Image)
			} else if found {
				parentProjectName = name
				parentProjectVersion = version
				matchedAnnotationKey = g.parentProjectAnnotationKey
				matchedAnnotationValue = podWideValue
			}
		}

		// 2. Evaluate container-specific parent annotations ("<key>/<containerName>"), taking precedence
		containerPrefix := g.parentProjectAnnotationKey + "/"
		for podAnnotationKey, podAnnotationValue := range ctx.Pod.Annotations {
			if !strings.HasPrefix(podAnnotationKey, containerPrefix) {
				continue
			}
			logrus.Debugf("AnnotationKey %s starts with %s?", podAnnotationKey, g.parentProjectAnnotationKey)

			found, name, version, err := g.getContainerNameAndVersion(parentProjectName, parentProjectVersion, podAnnotationKey, podAnnotationValue, g.parentProjectAnnotationKey, ctx)
			if err != nil {
				logrus.WithError(err).Errorf("Wrong parent project configuration. Skipping parent for image '%s'", ctx.Image.Image)
				continue
			}
			if found {
				parentProjectName = name
				parentProjectVersion = version
				matchedAnnotationKey = podAnnotationKey
				matchedAnnotationValue = podAnnotationValue
				break
			}
		}

		if parentProjectName != "" {
			// Directly return if the resolved parent project name is already a valid UUID
			parentProjectUuid, err := uuid.Parse(parentProjectName)
			if err == nil {
				return &parentProjectUuid
			}

			// Only check for explicit version if the annotation value actually contained ":"
			// (because getNameAndVersionFromString defaults version to "latest" when ":" is absent)
			hasExplicitVersion := strings.Contains(matchedAnnotationValue, ":")
			logrus.Debugf("Try to find parent project by name from annotation \"%s\", for image %s, parentProjectName \"%s\" and parentProjectVersion \"%s\"", matchedAnnotationKey, ctx.Image.Image, parentProjectName, parentProjectVersion)
			parentProjects, err := client.Project.GetProjectsForName(context.Background(), parentProjectName, false, true)
			if err != nil {
				logrus.WithError(err).Errorf("Could not find parent project \"%s\"", parentProjectName)
			} else if len(parentProjects) == 0 {
				logrus.Errorf("No parent project found with name \"%s\"", parentProjectName)
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
						logrus.Errorf("No parent project found with name \"%s\" and version \"%s\"", parentProjectName, parentProjectVersion)
					}
				} else {
					if len(parentProjects) > 1 {
						logrus.Warnf("Multiple root projects found with name \"%s\", using the first one", parentProjectName)
					}
					parentProject = parentProjects[0]
					found = true
				}
				if found {
					logrus.Infof("Found parent project with name \"%s\" and UUID \"%s\" for image \"%s\"", parentProjectName, parentProject.UUID, ctx.Image.Image)
					return &parentProject.UUID
				}
			}
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

	parentUuid := g.identifyParentProjectUuid(ctx, client)
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
	alreadyOnCluster := false
	clusterId := g.k8sClusterId
	if g.isNamespaceMode() {
		clusterId += "/" + ctx.Pod.PodNamespace
	} else {
		// don't add namespace tag in namespace mode as it is already in clusterId tag
		podNamespaceTag := podNamespaceTagKey + "=" + ctx.Pod.PodNamespace
		if !containsTag(project.Tags, podNamespaceTag) {
			project.Tags = append(project.Tags, dtrack.Tag{Name: podNamespaceTag})
		}
	}
	kubernetesClusterTag := kubernetesCluster + "=" + clusterId
	if g.isTagMode() {
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

	g.syncStageIntervalProperty(context.Background(), client, project, clusterId, alreadyOnCluster, ctx.DeploymentTime, ctx.PodCreationTime)
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

// TemplateData holds the context fields exposed to project name templates.
type TemplateData struct {
	ContainerNames    []string
	SbomScope         string
	ImageId           string
	ImageName         string
	ShortName         string
	Repository        string
	Tag               string
	Namespace         string // Helpful for cluster-wide templates!
	PredefinedName    string
	PredefinedVersion string
}

func extractTemplateData(ctx *target.TargetContext, containers []*kubernetes.ContainerInfo, predefinedName string, predefinedVersion string) TemplateData {
	var shortName, repository, tag string

	imageRef, err := parser.Parse(ctx.Image.ImageID)
	if err != nil {
		logrus.WithError(err).Errorf("Could not parse image %s", ctx.Image.ImageID)
	} else if imageRef != nil {
		shortName = imageRef.ShortName()
		repository = imageRef.Repository()
		tag = imageRef.Tag()
	}

	if strings.Index(ctx.Image.Image, "sha256") != 0 {
		if parsedImg, err := parser.Parse(ctx.Image.Image); err != nil {
			logrus.WithError(err).Errorf("Could not parse image %s", ctx.Image.Image)
		} else if parsedImg != nil {
			if shortName == "" {
				shortName = parsedImg.ShortName()
			}
			if repository == "" {
				repository = parsedImg.Repository()
			}
			tag = parsedImg.Tag()
		}
	}

	cNames := make([]string, 0, len(containers))
	for _, container := range containers {
		if container != nil {
			cNames = append(cNames, container.Name)
		}
	}

	var namespace string
	if ctx.Pod != nil {
		namespace = ctx.Pod.PodNamespace
	}

	var sbomScope string
	if ctx.Attestation != nil {
		sbomScope = ctx.Attestation.Scope
	}

	return TemplateData{
		ContainerNames:    cNames,
		SbomScope:         sbomScope,
		ImageId:           ctx.Image.ImageID,
		ImageName:         ctx.Image.Image,
		ShortName:         shortName,
		Repository:        repository,
		Tag:               tag,
		Namespace:         namespace,
		PredefinedName:    predefinedName,
		PredefinedVersion: predefinedVersion,
	}
}

// getTemplatedNameAndVersion parses and executes a template string (used for dynamic pod annotations).
func (g *DependencyTrackTarget) getTemplatedNameAndVersion(ctx *target.TargetContext, templateContent string, containers []*kubernetes.ContainerInfo, predefinedName string, predefinedVersion string) (string, string, error) {
	if templateContent == "" {
		return predefinedName, predefinedVersion, nil
	}

	// Reuse pre-compiled template if it matches the global template configuration
	var tmpl *template.Template
	if templateContent == g.templateProjectName && g.parsedProjectTemplate != nil {
		tmpl = g.parsedProjectTemplate
	} else {
		var err error
		tmpl, err = template.New("NameTemplate").Option("missingkey=error").Parse(templateContent)
		if err != nil {
			return predefinedName, predefinedVersion, err
		}
	}

	return g.executeNameTemplate(ctx, tmpl, containers, predefinedName, predefinedVersion)
}

func (g *DependencyTrackTarget) executeNameTemplate(ctx *target.TargetContext, tmpl *template.Template, containers []*kubernetes.ContainerInfo, predefinedName string, predefinedVersion string) (string, string, error) {
	data := extractTemplateData(ctx, containers, predefinedName, predefinedVersion)

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return predefinedName, predefinedVersion, err
	}

	parsedValue := strings.TrimSpace(buf.String())
	if parsedValue == "" {
		return predefinedName, predefinedVersion, nil
	}

	name, version := getNameAndVersionFromString(parsedValue, ":")
	if name == "" {
		name = predefinedName
	}
	if version == "" {
		if predefinedVersion != "" {
			version = predefinedVersion
		} else {
			version = "latest"
		}
	}
	return name, version, nil
}

func (g *DependencyTrackTarget) getContainerNameAndVersion(foundProjectName string, foundVersion string, podAnnotationKey string, podAnnotationValue string, expectedAnnotationKey string, ctx *target.TargetContext) (bool, string, string, error) {
	// Match only exact pod-wide key ("<key>") or container-specific key ("<key>/<container>")
	if podAnnotationKey == expectedAnnotationKey || strings.HasPrefix(podAnnotationKey, expectedAnnotationKey+"/") {
		// Extract container name relative to expectedAnnotationKey so slashes inside expectedAnnotationKey do not break parsing
		containerName := strings.TrimPrefix(podAnnotationKey, expectedAnnotationKey)
		containerName = strings.TrimPrefix(containerName, "/")

		if podAnnotationValue != "" {
			var containers []*kubernetes.ContainerInfo
			if containerName == "" {
				containers = ctx.Containers
			} else {
				for _, c := range ctx.Containers {
					if containerName == c.Name {
						containers = []*kubernetes.ContainerInfo{c}
						break
					} else {
						logrus.Debugf("skipping container '%s' as not configured for annotation key '%s'", c.Name, expectedAnnotationKey)
					}
				}
			}
			if len(containers) > 0 {
				name, version, err := g.getTemplatedNameAndVersion(ctx, podAnnotationValue, containers, foundProjectName, foundVersion)
				if err != nil {
					return false, foundProjectName, foundVersion, err
				}

				logger := logrus.WithFields(logrus.Fields{
					"expectedAnnotation": expectedAnnotationKey,
					"podAnnotation":      podAnnotationKey,
					"container":          containerName,
					"name":               name,
					"version":            version,
				})

				if ctx.Attestation != nil {
					logger = logger.WithField("scope", ctx.Attestation.Scope)
				}
				logger.Info("Custom name annotation found")
				return true, name, version, nil
			}
		} else {
			return false, foundProjectName, foundVersion, fmt.Errorf("empty value for annotation '%s' in image '%s'", podAnnotationKey, ctx.Image.Image)
		}
	}
	return false, foundProjectName, foundVersion, nil
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
		if !sibling.Active {
			continue
		}
		_ = g.handleProjectDeactivation(client, &sibling, &target.TargetImage{RegistryImage: img, Namespace: pod.PodNamespace}, false)
	}
}

func getNameAndVersionFromString(input string, delimiter string) (string, string) {
	parts := strings.Split(input, delimiter)
	name := strings.TrimSpace(parts[0])
	version := ""
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
	data := extractTemplateData(ctx, ctx.Containers, "", "")

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
	ctx := context.Background()
	podNsPrefix := podNamespaceTagKey + "="
	clusterPrefix := kubernetesCluster + "="

	expectedClusterId := g.k8sClusterId
	if g.isNamespaceMode() {
		expectedClusterId = g.k8sClusterId + "/" + img.Namespace
	}

	sameProjectInOtherNs := g.isStillUsedInOtherNamespace(project, img)

	// 1. Single-pass tag check & filtering
	isManaged := false
	tagsModified := false
	stillInUse := false
	filteredTags := make([]dtrack.Tag, 0, len(project.Tags))

	for _, tag := range project.Tags {
		if tag.Name == sbomOperator {
			isManaged = true
		}

		// Drop stale "namespace=<ns>" tag
		if img.Namespace != "" && tag.Name == podNsPrefix+img.Namespace {
			tagsModified = true
			logrus.Infof("Removing %s tag from project '%s:%s'", tag.Name, project.Name, project.Version)
			continue
		}

		// Drop or retain "kubernetes-cluster=" tags in tag mode
		if g.isTagMode() && strings.HasPrefix(tag.Name, clusterPrefix) {
			clusterId := strings.TrimPrefix(tag.Name, clusterPrefix)
			if !sameProjectInOtherNs && clusterId == expectedClusterId {
				tagsModified = true
				logrus.Infof("Removing %s tag from project '%s:%s'", tag.Name, project.Name, project.Version)
				continue
			}
			stillInUse = true
		}

		filteredTags = append(filteredTags, tag)
	}

	if !isManaged {
		return nil
	}

	g.projectDeleted(project, img)
	// 2. Fast exit if the project is completely orphaned and should be deleted
	if !stillInUse && deleteProject {
		logrus.Infof("Deleting project '%s:%s' as it is not used by any other clusters", project.Name, project.Version)
		if err := client.Project.Delete(ctx, project.UUID); err != nil {
			logrus.WithError(err).Warnf("Project could not be deleted '%s:%s'", project.Name, project.Version)
			return err
		}
		return nil
	}

	// 3. Immediately persist tag/status changes to minimize the race window after Project.Get
	project.Tags = filteredTags
	activenessChange := project.Active != stillInUse
	if activenessChange {
		if stillInUse {
			logrus.Infof("Activating project '%s:%s' as it is still used by other clusters", project.Name, project.Version)
		} else {
			logrus.Infof("Deactivating project '%s:%s' as it is not used by any other clusters", project.Name, project.Version)
		}
	}
	if activenessChange {
		project.Active = stillInUse
		// Keep IsLatest consistent with the reactivation path in ProcessSbom:
		// a project still in use is the latest, an orphaned one is not.
		project.IsLatest = dtrack.OptionalBoolOf(stillInUse)
	}
	if activenessChange || tagsModified { // Only patch if there actually was a change
		if _, err := client.Project.Update(ctx, *project); err != nil {
			logrus.WithError(err).Warnf("Project '%s:%s' could not be updated", project.Name, project.Version)
			return err
		}
	}

	// 4. Close stage deployment interval last. Only close it when no other namespace
	// in this cluster still uses the project: in "tag" mode the property is shared
	// across namespaces, so closing it while another namespace is still deploying
	// would record false downtime.
	if tagsModified && !sameProjectInOtherNs {
		return g.closeStageInterval(ctx, expectedClusterId, client, project)
	}

	return nil
}

// isStillUsedInOtherNamespace checks if another namespace in the same cluster still uses this project.
func (g *DependencyTrackTarget) isStillUsedInOtherNamespace(project *dtrack.Project, img *target.TargetImage) bool {
	if !g.isTagMode() || g.isNamespaceMode() || img.Namespace == "" {
		return false
	}

	podNsPrefix := podNamespaceTagKey + "="
	for _, tag := range project.Tags {
		if strings.HasPrefix(tag.Name, podNsPrefix) && strings.TrimPrefix(tag.Name, podNsPrefix) != img.Namespace {
			return true
		}
	}

	for ns, nsImages := range g.imageProjectMap[img.ImageID] {
		if ns != img.Namespace {
			if _, exists := nsImages[project.UUID]; exists {
				return true
			}
		}
	}
	return false
}

// closeStageInterval closes the active ISO-8601 deployment timestamp interval for the current cluster.
func (g *DependencyTrackTarget) closeStageInterval(ctx context.Context, clusterId string, client *dtrack.Client, project *dtrack.Project) error {
	props, err := client.ProjectProperty.GetAll(ctx, project.UUID, dtrack.PageOptions{})
	if err != nil {
		logrus.WithError(err).Warnf("Project properties could not be updated for project '%s:%s'", project.Name, project.Version)
		return err
	}

	if existingVal, ok := findProperty(props.Items, clusterId); ok {
		closedVal := CloseStageInterval(existingVal, time.Now().UTC())
		if err := g.upsertProjectProperty(
			ctx,
			client,
			project.UUID,
			props.Items,
			clusterId,
			closedVal,
			"ISO-8601 deployment intervals in stage "+clusterId,
		); err != nil {
			logrus.WithError(err).Warnf("Could not close deployment interval for project '%s:%s'", project.Name, project.Version)
		}
	}
	return nil
}

func (g *DependencyTrackTarget) IsNamespaceAware() bool {
	return !g.isPrefixMode()
}

// upsertProjectProperty creates a new ProjectProperty or updates its value if it already exists.
func (g *DependencyTrackTarget) upsertProjectProperty(
	ctx context.Context,
	client *dtrack.Client,
	projectUUID uuid.UUID,
	existingProps []dtrack.ProjectProperty,
	propName string,
	propValue string,
	description string,
) error {
	for _, p := range existingProps {
		if p.Group == deploymentTimestampGroup && p.Name == propName {
			if p.Value == propValue {
				return nil // Value is already up to date, no API call required
			}
			p.Value = propValue
			_, err := client.ProjectProperty.Update(ctx, projectUUID, p)
			return err
		}
	}

	_, err := client.ProjectProperty.Create(ctx, projectUUID, dtrack.ProjectProperty{
		Group:       deploymentTimestampGroup,
		Name:        propName,
		Value:       propValue,
		Type:        "STRING",
		Description: description,
	})
	return err
}

func findProperty(props []dtrack.ProjectProperty, propName string) (string, bool) {
	for _, p := range props {
		if p.Group == deploymentTimestampGroup && p.Name == propName && p.Value != "" {
			return p.Value, true
		}
	}
	return "", false
}

// syncStageIntervalProperty opens or updates the ISO-8601 deployment interval for the given stage.
func (g *DependencyTrackTarget) syncStageIntervalProperty(
	ctx context.Context,
	client *dtrack.Client,
	project dtrack.Project,
	clusterId string,
	wasAlreadyActiveInCluster bool,
	releaseTimestamp time.Time,
	podTimestamp time.Time,
) {
	props, err := client.ProjectProperty.GetAll(ctx, project.UUID, dtrack.PageOptions{})
	if err != nil {
		logrus.WithError(err).Warnf("Failed to fetch properties for project %s", project.UUID)
		props.Items = project.Properties
	}

	existingVal, hasExistingInterval := findProperty(props.Items, clusterId)

	// Determine the appropriate timestamp:
	// - Initial deployment in this stage (!hasExistingInterval): use ReleaseTimestamp (ReplicaSet creation time).
	// - Rollback in this stage (hasExistingInterval && !wasAlreadyActiveInCluster): use PodTimestamp (rollback pod creation time).
	// - Already active in this stage: pass ReleaseTimestamp so OpenStageInterval can adjust if an older ReplicaSet was found.
	startTime := releaseTimestamp
	if hasExistingInterval && !wasAlreadyActiveInCluster && !podTimestamp.IsZero() {
		startTime = podTimestamp
	}
	if startTime.IsZero() {
		startTime = time.Now().UTC()
	}

	newVal := OpenStageInterval(existingVal, startTime)

	if err := g.upsertProjectProperty(
		ctx,
		client,
		project.UUID,
		props.Items,
		clusterId,
		newVal,
		"ISO-8601 deployment intervals in stage "+clusterId,
	); err != nil {
		logrus.WithError(err).Warnf("Could not sync deployment interval for project '%s:%s'", project.Name, project.Version)
	}
}
