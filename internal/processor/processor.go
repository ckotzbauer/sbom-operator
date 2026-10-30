package processor

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/libstandard"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/job"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/ckotzbauer/sbom-operator/internal/target/configmap"
	"github.com/ckotzbauer/sbom-operator/internal/target/dtrack"
	"github.com/ckotzbauer/sbom-operator/internal/target/git"
	targetoci "github.com/ckotzbauer/sbom-operator/internal/target/oci"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type Processor struct {
	K8s               *kubernetes.KubeClient
	sy                *syft.Syft
	Targets           []target.Target
	imageMap          map[string]*cachedImage
	allowedNamespaces map[string]bool
	namespaceMutex    sync.RWMutex
}

// cachedImage holds the scanned SBOM attestations once per image ID
// and tracks which namespaces have already processed them via ProcessSbom.
type cachedImage struct {
	attestations []*oci.AttestationSbom
	namespaces   map[string]struct{}
}

func New(k8s *kubernetes.KubeClient, sy *syft.Syft) *Processor {
	targets := make([]target.Target, 0)
	if !HasJobImage() {
		logrus.Debugf("Targets set to: %v", internal.OperatorConfig.Targets)
		targets = initTargets(k8s)
	}

	return &Processor{K8s: k8s, sy: sy, Targets: targets, imageMap: make(map[string]*cachedImage), allowedNamespaces: make(map[string]bool)}
}

func (p *Processor) ListenForPods() {
	// Load allowed namespaces based on namespace-label-selector
	namespaceSelector := internal.OperatorConfig.NamespaceLabelSelector
	if namespaceSelector != "" {
		// Initial load of namespaces
		namespaces, err := p.K8s.Client.ListNamespaces(namespaceSelector)
		if err != nil {
			logrus.WithError(err).Fatalf("Failed to list namespaces with selector: %s", namespaceSelector)
			return
		}

		logrus.Debugf("Discovered %v namespaces matching selector '%s'", len(namespaces), namespaceSelector)
		for _, ns := range namespaces {
			p.allowedNamespaces[ns.Name] = true
			logrus.Tracef("Allowing namespace: %s", ns.Name)
		}

		// Start namespace informer to watch for namespace changes
		// We use an unfiltered informer and check labels manually to properly handle
		// the case where a namespace's labels are updated to no longer match the selector
		namespaceInformer, err := p.K8s.StartNamespaceInformer("", cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				ns := obj.(*corev1.Namespace)
				// Check if namespace matches the selector
				if p.namespaceLabelMatches(ns.Labels, namespaceSelector) {
					p.addAllowedNamespace(ns.Name)
				}
			},
			UpdateFunc: func(old, new interface{}) {
				newNs := new.(*corev1.Namespace)
				wasAllowed := p.isNamespaceAllowed(newNs.Name)
				shouldBeAllowed := p.namespaceLabelMatches(newNs.Labels, namespaceSelector)

				if shouldBeAllowed && !wasAllowed {
					p.addAllowedNamespace(newNs.Name)
				} else if !shouldBeAllowed && wasAllowed {
					p.removeAllowedNamespace(newNs.Name)
				}
			},
			DeleteFunc: func(obj interface{}) {
				ns := obj.(*corev1.Namespace)
				// Only remove if it was in the allowed list
				if p.isNamespaceAllowed(ns.Name) {
					p.removeAllowedNamespace(ns.Name)
				}
			},
		})

		if err != nil {
			logrus.WithError(err).Fatal("Can't create namespace informer")
			return
		}

		// Start the namespace informer asynchronously
		go func() {
			logrus.Info("Starting namespace informer")
			namespaceInformer.Run(make(chan struct{}))
		}()
	} else {
		logrus.Debug("No namespace-label-selector configured, all namespaces will be processed")
	}

	var informer cache.SharedIndexInformer
	informer, err := p.K8s.StartPodInformer(internal.OperatorConfig.PodLabelSelector, cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			oldPod := old.(*corev1.Pod)
			newPod := new.(*corev1.Pod)

			// Filter by namespace if selector is configured
			if !p.isNamespaceAllowed(newPod.Namespace) {
				logrus.Tracef("Skipping pod %s/%s - namespace not in allowed list", newPod.Namespace, newPod.Name)
				return
			}

			oldInfo := p.K8s.Client.ExtractPodInfos(*oldPod)
			newInfo := p.K8s.Client.ExtractPodInfos(*newPod)
			logrus.Tracef("Pod %s/%s was updated.", newInfo.PodNamespace, newInfo.PodName)

			var removedContainers []*libk8s.ContainerInfo
			newInfo.Containers, removedContainers = getChangedContainers(oldInfo, newInfo)
			p.scanPod(newInfo)
			p.cleanupImagesIfNeeded(removedContainers, oldInfo.PodNamespace, informer.GetStore().List())
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)

			// Filter by namespace if selector is configured
			if !p.isNamespaceAllowed(pod.Namespace) {
				logrus.Tracef("Skipping pod %s/%s - namespace not in allowed list", pod.Namespace, pod.Name)
				return
			}

			info := p.K8s.Client.ExtractPodInfos(*pod)
			logrus.Tracef("Pod %s/%s was removed.", info.PodNamespace, info.PodName)
			p.cleanupImagesIfNeeded(info.Containers, info.PodNamespace, informer.GetStore().List())
		},
	})

	if err != nil {
		logrus.WithError(err).Fatal("Can't listen for pod-changes.")
		return
	}

	p.runInformerAsync(informer)
}

func (p *Processor) isNamespaceAllowed(namespace string) bool {
	// If no namespace selector is configured, allow all namespaces
	if internal.OperatorConfig.NamespaceLabelSelector == "" {
		return true
	}

	// Check if namespace is in the allowed list (thread-safe read)
	p.namespaceMutex.RLock()
	defer p.namespaceMutex.RUnlock()
	return p.allowedNamespaces[namespace]
}

func (p *Processor) addAllowedNamespace(namespace string) {
	p.namespaceMutex.Lock()
	defer p.namespaceMutex.Unlock()
	p.allowedNamespaces[namespace] = true
	logrus.Infof("Namespace %s is now allowed for scanning", namespace)
}

func (p *Processor) removeAllowedNamespace(namespace string) {
	p.namespaceMutex.Lock()
	defer p.namespaceMutex.Unlock()
	delete(p.allowedNamespaces, namespace)
	logrus.Infof("Namespace %s is no longer allowed for scanning", namespace)
}

func (p *Processor) namespaceLabelMatches(nsLabels map[string]string, selector string) bool {
	// Parse the label selector
	labelSelector, err := labels.Parse(selector)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to parse namespace label selector: %s", selector)
		return false
	}

	// Check if the namespace labels match the selector
	return labelSelector.Matches(labels.Set(nsLabels))
}

func (p *Processor) ProcessAllPods(pods []libk8s.PodInfo, allImages map[string][]*liboci.RegistryImage) {
	if !HasJobImage() {
		p.executeSyftScans(pods, allImages)
	} else {
		p.executeJobImage(pods)
	}
}

// imageScanned records the attestations for the given imageId and marks
// the namespace as processed.
func (p *Processor) imageScanned(namespace string, imageId string, attestations []*oci.AttestationSbom) {
	if p.imageMap == nil {
		p.imageMap = make(map[string]*cachedImage)
	}

	entry, exists := p.imageMap[imageId]
	if !exists {
		entry = &cachedImage{
			attestations: attestations,
			namespaces:   make(map[string]struct{}),
		}
		p.imageMap[imageId] = entry
	}
	entry.namespaces[namespace] = struct{}{}
}

// getCachedAttestations checks the cache:
// - alreadyInNamespace == true: ProcessSbom was already called for this namespace (skip everything).
// - attestations != nil: Image was scanned in another namespace (skip Syft, but run ProcessSbom).
// - both false/nil: Image has never been scanned (run Syft + ProcessSbom).
func (p *Processor) getCachedAttestations(namespace string, imageId string) (alreadyInNamespace bool, attestations []*oci.AttestationSbom) {
	entry, exists := p.imageMap[imageId]
	if !exists {
		return false, nil
	}

	if _, processed := entry.namespaces[namespace]; processed {
		return true, nil
	}

	return false, entry.attestations
}

func (p *Processor) scanPod(pod libk8s.PodInfo) {
	errOccurred := false
	p.K8s.InjectPullSecrets(pod)

	// Group containers by ImageID to avoid duplicate scans within the same pod
	containersByImageID := make(map[string][]*libk8s.ContainerInfo)
	imageByID := make(map[string]*liboci.RegistryImage)

	for _, container := range pod.Containers {
		if p.K8s.HasAnnotation(pod.Annotations, container) {
			logrus.Debugf("Skip image %s", container.Image.ImageID)
			continue
		}
		imgID := container.Image.ImageID
		containersByImageID[imgID] = append(containersByImageID[imgID], container)
		imageByID[imgID] = container.Image
	}

	for imgID, containerList := range containersByImageID {
		image := imageByID[imgID]

		alreadyInNs, cachedAttestations := p.getCachedAttestations(pod.PodNamespace, imgID)
		if alreadyInNs {
			continue // Already scanned and sent to targets for this namespace -> nothing to do
		}

		attestations := cachedAttestations
		if len(attestations) == 0 {
			// Image has not been scanned in any namespace yet -> fetch OCI or run Syft
			foundDefaultScopeSbom := false
			if internal.OperatorConfig.FetchOciAttestations {
				logrus.Tracef("Starting to fetch SBOM attestations")
				fetchedAttestations, err := oci.FetchSbomAttestations(
					context.Background(),
					image,
					libstandard.ToMap(internal.OperatorConfig.RegistryProxies),
				)
				if err != nil {
					logrus.WithError(err).Warnf("Could not fetch OCI attestations for image %s", imgID)
				} else {
					for _, attestation := range fetchedAttestations {
						if attestation.Scope == oci.ScopeAll {
							foundDefaultScopeSbom = true
							logrus.Debugf("Found attestation for image with MediaType: %s. Skipping Syft scan...", attestation.MediaType)
						}
						attestations = append(attestations, attestation)
					}
				}
			}

			if !foundDefaultScopeSbom {
				sbom, err := p.sy.ExecuteSyft(image)
				if err != nil {
					errOccurred = true
					continue
				}
				attestations = append(attestations, &oci.AttestationSbom{
					Scope:     oci.ScopeAll,
					MediaType: oci.CycloneDXJSONMediaType,
					Sbom:      sbom,
				})
			}
		}

		// Send attestations to all targets for the current pod's namespace
		imageErr := false
		for _, att := range attestations {
			for _, t := range p.Targets {
				ctx := target.NewContext(image, &pod, att)
				if err := t.ProcessSbom(ctx.WithContainers(containerList)); err != nil {
					imageErr = true
					errOccurred = true
				}
			}
		}

		// Mark this namespace as processed and cache the attestations for other namespaces
		if !imageErr {
			p.imageScanned(pod.PodNamespace, imgID, attestations)
		}
	}

	if !errOccurred && len(pod.Containers) > 0 {
		p.K8s.UpdatePodAnnotation(pod)
	}
}

func initTargets(k8s *kubernetes.KubeClient) []target.Target {
	targets := make([]target.Target, 0)

	for _, ta := range internal.OperatorConfig.Targets {
		var err error

		// nolint QF1003
		if ta == "git" {
			workingTree := internal.OperatorConfig.GitWorkingTree
			workPath := internal.OperatorConfig.GitPath
			repository := internal.OperatorConfig.GitRepository
			branch := internal.OperatorConfig.GitBranch
			format := internal.OperatorConfig.Format
			token := internal.OperatorConfig.GitAccessToken
			userName := internal.OperatorConfig.GitUserName
			password := internal.OperatorConfig.GitPassword
			name := internal.OperatorConfig.GitAuthorName
			email := internal.OperatorConfig.GitAuthorEmail
			githubAppId := internal.OperatorConfig.GitHubAppId
			githubAppInstallationId := internal.OperatorConfig.GitHubAppInstallationId
			githubAppPrivateKey := internal.OperatorConfig.GitHubPrivateKey
			t := git.NewGitTarget(workingTree, workPath, repository, branch, name, email, token, userName, password, githubAppId, githubAppInstallationId, githubAppPrivateKey, format)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else if ta == "dtrack" {
			baseUrl := internal.OperatorConfig.DtrackBaseUrl
			apiKey := internal.OperatorConfig.DtrackApiKey
			podLabelTagMatcher := internal.OperatorConfig.DtrackLabelTagMatcher
			parentProjectAnnotationKey := internal.OperatorConfig.DtrackParentProjectAnnotationKey
			projectNameAnnotationKey := internal.OperatorConfig.DtrackProjectNameAnnotationKey
			caCertFile := internal.OperatorConfig.DtrackCaCertFile
			clientCertFile := internal.OperatorConfig.DtrackClientCertFile
			clientKeyFile := internal.OperatorConfig.DtrackClientKeyFile
			k8sClusterId := internal.OperatorConfig.KubernetesClusterId
			k8sClusterIdMode := internal.OperatorConfig.DtrackKubernetesClusterIdMode
			defaultParentProject := internal.OperatorConfig.DtrackDefaultParentProject
			useShortName := internal.OperatorConfig.DtrackUseShortName
			manageProjectActiveStatus := internal.OperatorConfig.DtrackManageProjectActiveStatus
			templateProjectName := internal.OperatorConfig.DtrackTemplatedProjectName
			t := dtrack.NewDependencyTrackTarget(baseUrl, apiKey, podLabelTagMatcher, caCertFile, clientCertFile, clientKeyFile, k8sClusterId, k8sClusterIdMode, defaultParentProject, parentProjectAnnotationKey, projectNameAnnotationKey, useShortName, manageProjectActiveStatus, templateProjectName)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else if ta == "oci" {
			registry := internal.OperatorConfig.OciRegistry
			username := internal.OperatorConfig.OciUser
			token := internal.OperatorConfig.OciToken
			format := internal.OperatorConfig.Format
			t := targetoci.NewOciTarget(registry, username, token, format)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else if ta == "configmap" {
			t := configmap.NewConfigMapTarget(k8s)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else {
			logrus.Fatalf("Unknown target %s", ta)
		}

		if err != nil {
			logrus.WithError(err).Fatal("Config-Validation failed!")
		}
	}

	if len(targets) == 0 {
		logrus.Fatalf("Please specify at least one target.")
	}

	return targets
}

func HasJobImage() bool {
	return internal.OperatorConfig.JobImage != ""
}

// ImageRemoved removes the namespace association for an image from the cache.
// If no namespace uses the image anymore (or if namespace is empty),
// the entire entry including the cached SBOM is freed from memory.
func (p *Processor) imageRemoved(imageId string, namespace string) {
	if p.imageMap == nil {
		return
	}

	entry, exists := p.imageMap[imageId]
	if !exists {
		return
	}

	if namespace == "" {
		delete(p.imageMap, imageId)
		return
	}

	delete(entry.namespaces, namespace)
	if len(entry.namespaces) == 0 {
		// Last namespace removed this image -> free SBOM payload from RAM
		delete(p.imageMap, imageId)
	}
}

func (p *Processor) executeSyftScans(pods []libk8s.PodInfo, allImages map[string][]*liboci.RegistryImage) {
	for _, pod := range pods {
		p.scanPod(pod)
	}

	// Build O(1) lookup sets of currently active images in the cluster
	globalActiveIDs := make(map[string]struct{})
	nsActiveIDs := make(map[string]map[string]struct{}, len(allImages))

	for ns, imgs := range allImages {
		nsSet := make(map[string]struct{}, len(imgs))
		for _, img := range imgs {
			globalActiveIDs[img.ImageID] = struct{}{}
			nsSet[img.ImageID] = struct{}{}
		}
		nsActiveIDs[ns] = nsSet
	}

	// Sync Processor cache with cluster reality (independent of target configurations)
	for imgID, cached := range p.imageMap {
		for ns := range cached.namespaces {
			if activeInNs, ok := nsActiveIDs[ns]; !ok {
				p.imageRemoved(imgID, ns) // Entire namespace has no active images anymore
			} else if _, stillRunning := activeInNs[imgID]; !stillRunning {
				p.imageRemoved(imgID, ns) // Image is no longer running in this specific namespace
			}
		}
	}

	// Reconcile orphan images per target
	for _, t := range p.Targets {
		targetImages, err := t.LoadImages()
		if err != nil {
			logrus.WithError(err).Error("Failed to load images from target")
			continue
		}

		var removableImages []*target.TargetImage
		for _, targetImg := range targetImages {
			var isActive bool
			if !t.IsNamespaceAware() || targetImg.Namespace == "" {
				_, isActive = globalActiveIDs[targetImg.ImageID]
			} else if nsSet, ok := nsActiveIDs[targetImg.Namespace]; ok {
				_, isActive = nsSet[targetImg.ImageID]
			}

			if !isActive {
				removableImages = append(removableImages, targetImg)
				logrus.Debugf("Image %s marked for removal in namespace %s", targetImg.ImageID, targetImg.Namespace)
			}
		}

		if len(removableImages) > 0 {
			p.handleOrphanImages(t, removableImages)
		}
	}
}

func (p *Processor) executeJobImage(pods []libk8s.PodInfo) {
	jobClient := job.New(
		p.K8s,
		internal.OperatorConfig.JobImage,
		internal.OperatorConfig.JobImagePullSecret,
		internal.OperatorConfig.KubernetesClusterId,
		internal.OperatorConfig.JobTimeout)

	filteredPods := make([]libk8s.PodInfo, 0)
	for _, pod := range pods {
		filteredContainers := make([]*libk8s.ContainerInfo, 0)
		for _, container := range pod.Containers {
			if p.K8s.HasAnnotation(pod.Annotations, container) {
				logrus.Debugf("Skip image %s", container.Image.ImageID)
				continue
			}

			filteredContainers = append(filteredContainers, container)
		}

		if len(filteredContainers) > 0 {
			filteredPods = append(filteredPods, pod)
		}
	}

	j, err := jobClient.StartJob(filteredPods)
	if err != nil {
		// Already handled from job-module
		return
	}

	if jobClient.WaitForJob(j) {
		for _, pod := range filteredPods {
			p.K8s.UpdatePodAnnotation(pod)
		}
	}
}

func getChangedContainers(oldPod, newPod libk8s.PodInfo) ([]*libk8s.ContainerInfo, []*libk8s.ContainerInfo) {
	addedContainers := make([]*libk8s.ContainerInfo, 0)
	removedContainers := make([]*libk8s.ContainerInfo, 0)
	for _, c := range newPod.Containers {
		if !containsContainerImage(oldPod.Containers, c.Image.ImageID) {
			addedContainers = append(addedContainers, c)
		}
	}

	for _, c := range oldPod.Containers {
		if !containsContainerImage(newPod.Containers, c.Image.ImageID) {
			removedContainers = append(removedContainers, c)
		}
	}

	return addedContainers, removedContainers
}

func containsImage(images []*target.TargetImage, namespace string, image string) bool {
	for _, i := range images {
		if i.ImageID == image && (namespace == "" || i.Namespace == namespace) {
			return true
		}
	}

	return false
}

func containsContainerImage(containers []*libk8s.ContainerInfo, image string) bool {
	for _, c := range containers {
		if c.Image.ImageID == image {
			return true
		}
	}

	return false
}

func (p *Processor) cleanupImagesIfNeeded(removedContainers []*libk8s.ContainerInfo, namespace string, allPods []interface{}) {
	if len(removedContainers) == 0 {
		return
	}

	var namespaceOrphans []*target.TargetImage
	var globalOrphans []*target.TargetImage

	for _, c := range removedContainers {
		foundInNamespace := false
		foundInCluster := false

		for _, po := range allPods {
			pod, ok := po.(*corev1.Pod)
			if !ok {
				continue
			}

			info := p.K8s.Client.ExtractPodInfos(*pod)
			if containsContainerImage(info.Containers, c.Image.ImageID) {
				foundInCluster = true
				if pod.Namespace == namespace {
					foundInNamespace = true
					break
				}
			}
		}

		// Not running in this namespace anymore -> remove namespace from Processor cache
		if !foundInNamespace {
			namespaceOrphans = append(namespaceOrphans, &target.TargetImage{
				RegistryImage: c.Image,
				Namespace:     namespace,
			})
			// Remove only this namespace association from the cache. If no other namespace uses it, ImageRemoved automatically deletes the whole entry.
			p.imageRemoved(c.Image.ImageID, namespace)
			logrus.Debugf("Image %s marked for removal in namespace %s", c.Image.ImageID, namespace)
		}

		// Not running anywhere in the cluster anymore -> relevant for non-namespace-aware targets
		if !foundInCluster {
			globalOrphans = append(globalOrphans, &target.TargetImage{
				RegistryImage: c.Image,
				Namespace:     "",
			})
			logrus.Debugf("Image %s marked for global removal", c.Image.ImageID)
		}
	}

	for _, t := range p.Targets {
		if t.IsNamespaceAware() {
			if len(namespaceOrphans) > 0 {
				p.handleOrphanImages(t, namespaceOrphans)
			}
		} else {
			if len(globalOrphans) > 0 {
				p.handleOrphanImages(t, globalOrphans)
			}
		}
	}
}

// handleOrphanImages dispatches orphan cleanup for a single target. Targets that
// implement DeactivateTarget and opt in via ShouldDeactivateOrphans have their
// orphans deactivated (rather than deleted) regardless of the global
// delete-orphan-images flag. All other targets follow delete-orphan-images.
func (p *Processor) handleOrphanImages(t target.Target, images []*target.TargetImage) {
	dt, isDeactivatable := t.(target.DeactivateTarget)
	shouldDeactivate := isDeactivatable && dt.ShouldDeactivateOrphans()

	if !shouldDeactivate && !internal.OperatorConfig.DeleteOrphanImages {
		return
	}

	actualOrphanedImages := images
	if !t.IsNamespaceAware() {
		seen := make(map[string]struct{}, len(images))
		actualOrphanedImages = make([]*target.TargetImage, 0, len(images))
		for _, img := range images {
			if _, exists := seen[img.ImageID]; !exists {
				seen[img.ImageID] = struct{}{}
				actualOrphanedImages = append(actualOrphanedImages, &target.TargetImage{
					RegistryImage: img.RegistryImage,
					Namespace:     "",
				})
			}
		}
	}

	if shouldDeactivate {
		if err := dt.Deactivate(actualOrphanedImages); err != nil {
			logrus.WithError(err).Error("Failed to deactivate images in target")
		}
		return
	}

	if err := t.Remove(actualOrphanedImages); err != nil {
		logrus.WithError(err).Error("Failed to remove images from target")
	}
}

func (p *Processor) runInformerAsync(informer cache.SharedIndexInformer) {
	stop := make(chan struct{})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		run := true
		for run {
			sig := <-sigs
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				logrus.Infof("Received signal %s", sig)
				close(stop)
				run = false
			}
		}
	}()

	go func() {
		if !HasJobImage() {
			for _, t := range p.Targets {
				err := t.Initialize()
				if err != nil {
					logrus.WithError(err).Fatal("Target could not be initialized,")
				}
			}
		}

		logrus.Info("Start pod-informer")
		informer.Run(stop)
		logrus.Info("Pod-informer has stopped")
		os.Exit(0)
	}()

	go func() {
		if !HasJobImage() {
			logrus.Info("Wait for cache to be synced")
			if !cache.WaitForCacheSync(stop, informer.HasSynced) {
				logrus.Fatal("Timed out waiting for the cache to sync")
			}

			logrus.Info("Finished cache sync")
			pods := informer.GetStore().List()
			missingPods := make([]libk8s.PodInfo, 0)
			allImages := make(map[string][]*liboci.RegistryImage)

			validPods := make([]libk8s.PodInfo, 0, len(pods))
			for _, po := range pods {
				pod, ok := po.(*corev1.Pod)
				if !ok {
					continue
				}
				if !p.isNamespaceAllowed(pod.Namespace) {
					logrus.Tracef("Skipping pod %s/%s during initial sync - namespace not in allowed list", pod.Namespace, pod.Name)
					continue
				}

				info := p.K8s.Client.ExtractPodInfos(*pod)
				validPods = append(validPods, info)

				for _, c := range info.Containers {
					allImages[info.PodNamespace] = append(allImages[info.PodNamespace], c.Image)
				}
			}

			type loadedTarget struct {
				target target.Target
				images []*target.TargetImage
			}
			var activeTargets []loadedTarget
			for _, t := range p.Targets {
				targetImages, err := t.LoadImages()
				if err != nil {
					logrus.WithError(err).Error("Failed to load images from target")
					continue
				}
				activeTargets = append(activeTargets, loadedTarget{target: t, images: targetImages})
			}

			for _, info := range validPods {
				podNeedsScan := false
				for _, c := range info.Containers {
					if p.K8s.HasAnnotation(info.Annotations, c) {
						continue
					}
					for _, lt := range activeTargets {
						expectedNs := ""
						if lt.target.IsNamespaceAware() {
							expectedNs = info.PodNamespace
						}

						if !containsImage(lt.images, expectedNs, c.Image.ImageID) {
							podNeedsScan = true
							break
						}
					}
					if podNeedsScan {
						break
					}
				}

				if podNeedsScan {
					missingPods = append(missingPods, info)
					logrus.Debugf("Pod %s/%s needs to be analyzed", info.PodNamespace, info.PodName)
				}
			}

			p.executeSyftScans(missingPods, allImages)
		}
	}()
}
