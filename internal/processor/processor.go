package processor

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/job"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/ckotzbauer/sbom-operator/internal/target/configmap"
	"github.com/ckotzbauer/sbom-operator/internal/target/dtrack"
	"github.com/ckotzbauer/sbom-operator/internal/target/git"
	"github.com/ckotzbauer/sbom-operator/internal/target/oci"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type Processor struct {
	K8s               *kubernetes.KubeClient
	sy                *syft.Syft
	Targets           []target.Target
	imageMap          map[string]bool
	allowedNamespaces map[string]bool
	namespaceMutex    sync.RWMutex
}

func New(k8s *kubernetes.KubeClient, sy *syft.Syft) *Processor {
	targets := make([]target.Target, 0)
	if !HasJobImage() {
		logrus.Debugf("Targets set to: %v", internal.OperatorConfig.Targets)
		targets = initTargets(k8s)
	}

	return &Processor{K8s: k8s, sy: sy, Targets: targets, imageMap: make(map[string]bool), allowedNamespaces: make(map[string]bool)}
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
			p.cleanupImagesIfNeeded(removedContainers, informer.GetStore().List())
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
			p.cleanupImagesIfNeeded(info.Containers, informer.GetStore().List())
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

func (p *Processor) ProcessAllPods(pods []libk8s.PodInfo, allImages []*liboci.RegistryImage) {
	if !HasJobImage() {
		p.executeSyftScans(pods, allImages)
	} else {
		p.executeJobImage(pods)
	}
}

func (p *Processor) scanPod(pod libk8s.PodInfo) {
	errOccurred := false
	p.K8s.InjectPullSecrets(pod)

	for _, container := range pod.Containers {
		alreadyScanned := p.imageMap[container.Image.ImageID]
		if p.K8s.HasAnnotation(pod.Annotations, container) || alreadyScanned {
			logrus.Debugf("Skip image %s", container.Image.ImageID)
			continue
		}

		p.imageMap[container.Image.ImageID] = true
		sbom, err := p.sy.ExecuteSyft(container.Image)
		if err != nil {
			// Error is already handled from syft module.
			continue
		}

		for _, t := range p.Targets {
			err = t.ProcessSbom(target.NewContext(sbom, container.Image, container, &pod))
			errOccurred = errOccurred || err != nil
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
			defaultParentProject := internal.OperatorConfig.DtrackDefaultParentProject
			useShortName := internal.OperatorConfig.DtrackUseShortName
			t := dtrack.NewDependencyTrackTarget(baseUrl, apiKey, podLabelTagMatcher, caCertFile, clientCertFile, clientKeyFile, k8sClusterId, defaultParentProject, parentProjectAnnotationKey, projectNameAnnotationKey, useShortName)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else if ta == "oci" {
			registry := internal.OperatorConfig.OciRegistry
			username := internal.OperatorConfig.OciUser
			token := internal.OperatorConfig.OciToken
			format := internal.OperatorConfig.Format
			t := oci.NewOciTarget(registry, username, token, format)
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

func (p *Processor) executeSyftScans(pods []libk8s.PodInfo, allImages []*liboci.RegistryImage) {
	for _, pod := range pods {
		p.scanPod(pod)
	}

	for _, t := range p.Targets {
		targetImages, err := t.LoadImages()
		if err != nil {
			logrus.WithError(err).Error("Failed to load images from target")
			continue
		}

		removableImages := make([]*liboci.RegistryImage, 0)
		for _, t := range targetImages {
			if !containsImage(allImages, t.ImageID) {
				removableImages = append(removableImages, t)
				delete(p.imageMap, t.ImageID)
				logrus.Debugf("Image %s marked for removal", t.ImageID)
			}
		}

		if len(removableImages) > 0 && internal.OperatorConfig.DeleteOrphanImages {
			err := t.Remove(removableImages)
			if err != nil {
				logrus.WithError(err).Error("Failed to remove images from target")
			}
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

func containsImage(images []*liboci.RegistryImage, image string) bool {
	for _, i := range images {
		if i.ImageID == image {
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

func (p *Processor) cleanupImagesIfNeeded(removedContainers []*libk8s.ContainerInfo, allPods []interface{}) {
	images := make([]*liboci.RegistryImage, 0)

	for _, c := range removedContainers {
		found := false
		for _, po := range allPods {
			pod := po.(*corev1.Pod)
			info := p.K8s.Client.ExtractPodInfos(*pod)
			found = found || containsContainerImage(info.Containers, c.Image.ImageID)
		}

		if !found {
			images = append(images, c.Image)
			delete(p.imageMap, c.Image.ImageID)
			logrus.Debugf("Image %s marked for removal", c.Image.ImageID)
		}
	}

	if len(images) > 0 {
		for _, t := range p.Targets {
			if internal.OperatorConfig.DeleteOrphanImages {
				err := t.Remove(images)
				if err != nil {
					logrus.WithError(err).Error("Failed to remove images from target")
				}
			}
		}
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
			allImages := make([]*liboci.RegistryImage, 0)

			for _, t := range p.Targets {
				targetImages, err := t.LoadImages()
				if err != nil {
					logrus.WithError(err).Error("Failed to load images from target")
					continue
				}

				for _, po := range pods {
					pod := po.(*corev1.Pod)

					// Filter by namespace if selector is configured
					if !p.isNamespaceAllowed(pod.Namespace) {
						logrus.Tracef("Skipping pod %s/%s during initial sync - namespace not in allowed list", pod.Namespace, pod.Name)
						continue
					}

					info := p.K8s.Client.ExtractPodInfos(*pod)
					for _, c := range info.Containers {
						allImages = append(allImages, c.Image)
						if !containsImage(targetImages, c.Image.ImageID) && !p.K8s.HasAnnotation(info.Annotations, c) {
							missingPods = append(missingPods, info)
							logrus.Debugf("Pod %s/%s needs to be analyzed", info.PodNamespace, info.PodName)
							break
						}
					}
				}
			}

			if len(missingPods) > 0 {
				p.executeSyftScans(missingPods, allImages)
			}
		}
	}()
}
