package processor

import (
	"os"
	"os/signal"
	"syscall"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/job"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/ckotzbauer/sbom-operator/internal/target/dtrack"
	"github.com/ckotzbauer/sbom-operator/internal/target/git"
	"github.com/ckotzbauer/sbom-operator/internal/target/oci"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

type Processor struct {
	K8s     *kubernetes.KubeClient
	sy      *syft.Syft
	Targets []target.Target
}

func New(k8s *kubernetes.KubeClient, sy *syft.Syft) *Processor {
	targets := make([]target.Target, 0)
	if !HasJobImage() {
		logrus.Debugf("Targets set to: %v", internal.OperatorConfig.Targets)
		targets = initTargets()
	}

	return &Processor{K8s: k8s, sy: sy, Targets: targets}
}

func (p *Processor) ListenForPods() {
	if !HasJobImage() {
		for _, t := range p.Targets {
			t.Initialize()
		}
	}

	c := make(chan struct{})
	var informer cache.SharedIndexInformer
	informer = p.K8s.StartPodInformer(internal.OperatorConfig.PodLabelSelector, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			podInfo := obj.(libk8s.PodInfo)
			// TODO: Check if scan is needed
			p.ScanPod(podInfo)
		},
		UpdateFunc: func(old, new interface{}) {
			oldPod := old.(libk8s.PodInfo)
			newPod := new.(libk8s.PodInfo)

			var removedContainers []libk8s.ContainerInfo
			newPod.Containers, removedContainers = getChangedContainers(oldPod, newPod)
			p.ScanPod(newPod)
			p.cleanupImagesIfNeeded(removedContainers, informer.GetStore().List())
		},
		DeleteFunc: func(obj interface{}) {
			podInfo := obj.(libk8s.PodInfo)
			p.cleanupImagesIfNeeded(podInfo.Containers, informer.GetStore().List())
		},
	})
	listenOnSignals(c)
	informer.Run(c)
}

func (p *Processor) ProcessAllPods(pods []libk8s.PodInfo, allImages []liboci.RegistryImage) {
	if !HasJobImage() {
		p.executeSyftScans(pods, allImages)
	} else {
		p.executeJobImage(pods)
	}
}

func (p *Processor) ScanPod(pod libk8s.PodInfo) {
	errOccurred := false

	for _, container := range pod.Containers {
		sbom, err := p.sy.ExecuteSyft(container.Image)
		if err != nil {
			// Error is already handled from syft module.
			continue
		}

		for _, t := range p.Targets {
			err = t.ProcessSbom(container.Image, sbom)
			errOccurred = errOccurred || err != nil
		}
	}

	if !errOccurred {
		p.K8s.UpdatePodAnnotation(pod)
	}
}

func initTargets() []target.Target {
	targets := make([]target.Target, 0)

	for _, ta := range internal.OperatorConfig.Targets {
		var err error

		if ta == "git" {
			workingTree := internal.OperatorConfig.GitWorkingTree
			workPath := internal.OperatorConfig.GitPath
			repository := internal.OperatorConfig.GitRepository
			branch := internal.OperatorConfig.GitBranch
			format := internal.OperatorConfig.Format
			token := internal.OperatorConfig.GitAccessToken
			name := internal.OperatorConfig.GitAuthorName
			email := internal.OperatorConfig.GitAuthorEmail
			t := git.NewGitTarget(workingTree, workPath, repository, branch, token, name, email, format)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else if ta == "dtrack" {
			baseUrl := internal.OperatorConfig.DtrackBaseUrl
			apiKey := internal.OperatorConfig.DtrackApiKey
			k8sClusterId := internal.OperatorConfig.KubernetesClusterId
			t := dtrack.NewDependencyTrackTarget(baseUrl, apiKey, k8sClusterId)
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

func (p *Processor) executeSyftScans(pods []libk8s.PodInfo, allImages []liboci.RegistryImage) {
	for _, pod := range pods {
		p.ScanPod(pod)
	}

	for _, t := range p.Targets {
		targetImages := t.LoadImages()
		removableImages := make([]liboci.RegistryImage, 0)
		for _, t := range targetImages {
			if !containsImage(allImages, t.ImageID) {
				removableImages = append(removableImages, t)
			}
		}

		t.Remove(removableImages)
	}
}

func (p *Processor) executeJobImage(pods []libk8s.PodInfo) {
	jobClient := job.New(
		p.K8s,
		internal.OperatorConfig.JobImage,
		internal.OperatorConfig.JobImagePullSecret,
		internal.OperatorConfig.KubernetesClusterId,
		internal.OperatorConfig.JobTimeout)

	j, err := jobClient.StartJob(pods)
	if err != nil {
		// Already handled from job-module
		return
	}

	if jobClient.WaitForJob(j) {
		for _, pod := range pods {
			p.K8s.UpdatePodAnnotation(pod)
		}
	}
}

func getChangedContainers(oldPod, newPod libk8s.PodInfo) ([]libk8s.ContainerInfo, []libk8s.ContainerInfo) {
	addedContainers := make([]libk8s.ContainerInfo, 0)
	removedContainers := make([]libk8s.ContainerInfo, 0)
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

func containsImage(images []liboci.RegistryImage, image string) bool {
	for _, i := range images {
		if i.ImageID == image {
			return true
		}
	}

	return false
}

func containsContainerImage(containers []libk8s.ContainerInfo, image string) bool {
	for _, c := range containers {
		if c.Image.ImageID == image {
			return true
		}
	}

	return false
}

func (p *Processor) cleanupImagesIfNeeded(removedContainers []libk8s.ContainerInfo, allPods []interface{}) {
	images := make([]liboci.RegistryImage, 0)

	for _, c := range removedContainers {
		found := false
		for _, p := range allPods {
			pod := p.(libk8s.PodInfo)
			found = found || containsContainerImage(pod.Containers, c.Image.ImageID)
		}

		if !found {
			images = append(images, c.Image)
		}
	}

	for _, t := range p.Targets {
		t.Remove(images)
	}
}

func listenOnSignals(informerChan chan struct{}) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			sig := <-sigs
			switch sig {
			case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
				informerChan <- struct{}{}
			}
		}
	}()
}
