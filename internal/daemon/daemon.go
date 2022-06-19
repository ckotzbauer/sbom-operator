package daemon

import (
	"time"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/job"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/ckotzbauer/sbom-operator/internal/target/dtrack"
	"github.com/ckotzbauer/sbom-operator/internal/target/git"
	"github.com/ckotzbauer/sbom-operator/internal/target/oci"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type CronService struct {
	cron    string
	targets []target.Target
}

var running = false

func Start(cronTime string) {
	cr := internal.Unescape(cronTime)
	targetKeys := viper.GetStringSlice(internal.ConfigKeyTargets)

	logrus.Debugf("Cron set to: %v", cr)
	targets := make([]target.Target, 0)

	if !hasJobImage() {
		logrus.Debugf("Targets set to: %v", targetKeys)
		targets = initTargets(targetKeys)
	}

	cs := CronService{cron: cr, targets: targets}
	cs.printNextExecution()

	c := cron.New()
	err := c.AddFunc(cr, func() { cs.runBackgroundService() })
	if err != nil {
		logrus.WithError(err).Fatal("Could not configure cron")
	}

	c.Start()
}

func (c *CronService) printNextExecution() {
	s, err := cron.Parse(c.cron)
	if err != nil {
		logrus.WithError(err).Fatal("Cron cannot be parsed")
	}

	nextRun := s.Next(time.Now())
	logrus.Debugf("Next background-service run at: %v", nextRun)
}

func (c *CronService) runBackgroundService() {
	if running {
		return
	}

	running = true

	logrus.Info("Execute background-service")
	format := viper.GetString(internal.ConfigKeyFormat)

	if !hasJobImage() {
		for _, t := range c.targets {
			t.Initialize()
		}
	}

	k8s := kubernetes.NewClient(viper.GetBool(internal.ConfigKeyIgnoreAnnotations))
	namespaceSelector := viper.GetString(internal.ConfigKeyNamespaceLabelSelector)
	namespaces, err := k8s.Client.ListNamespaces(namespaceSelector)
	if err != nil {
		logrus.WithError(err).Errorf("failed to list namespaces with selector: %s, abort background-service", namespaceSelector)
		return
	}
	logrus.Debugf("Discovered %v namespaces", len(namespaces))
	containerImages, allImages := k8s.LoadImageInfos(namespaces, viper.GetString(internal.ConfigKeyPodLabelSelector))

	if !hasJobImage() {
		c.executeSyftScans(format, k8s, containerImages, allImages)
	} else {
		executeJobImage(k8s, containerImages)
	}

	c.printNextExecution()
	running = false
}

func (c *CronService) executeSyftScans(format string, k8s *kubernetes.KubeClient,
	containerImages []libk8s.KubeImage, allImages map[string]libk8s.KubeImage) {
	sy := syft.New(format)

	for _, image := range containerImages {
		sbom, err := sy.ExecuteSyft(image.Image)
		if err != nil {
			// Error is already handled from syft module.
			continue
		}

		errOccurred := false

		for _, t := range c.targets {
			err = t.ProcessSbom(image, sbom)
			errOccurred = errOccurred || err != nil
		}

		if !errOccurred {
			for _, pod := range image.Pods {
				k8s.UpdatePodAnnotation(pod)
			}
		}
	}

	/*for _, t := range c.targets {
		t.Cleanup(allImages)
	}*/
}

func executeJobImage(k8s *kubernetes.KubeClient, containerImages []libk8s.KubeImage) {
	jobClient := job.New(
		k8s,
		viper.GetString(internal.ConfigKeyJobImage),
		viper.GetString(internal.ConfigKeyJobImagePullSecret),
		viper.GetString(internal.ConfigKeyKubernetesClusterId),
		viper.GetInt64(internal.ConfigKeyJobTimeout))

	j, err := jobClient.StartJob(containerImages)
	if err != nil {
		// Already handled from job-module
		return
	}

	if jobClient.WaitForJob(j) {
		for _, i := range containerImages {
			for _, pod := range i.Pods {
				k8s.UpdatePodAnnotation(pod)
			}
		}
	}
}

func initTargets(targetKeys []string) []target.Target {
	targets := make([]target.Target, 0)

	for _, ta := range targetKeys {
		var err error

		if ta == "git" {
			workingTree := viper.GetString(internal.ConfigKeyGitWorkingTree)
			workPath := viper.GetString(internal.ConfigKeyGitPath)
			repository := viper.GetString(internal.ConfigKeyGitRepository)
			branch := viper.GetString(internal.ConfigKeyGitBranch)
			format := viper.GetString(internal.ConfigKeyFormat)
			token := viper.GetString(internal.ConfigKeyGitAccessToken)
			name := viper.GetString(internal.ConfigKeyGitAuthorName)
			email := viper.GetString(internal.ConfigKeyGitAuthorEmail)
			t := git.NewGitTarget(workingTree, workPath, repository, branch, token, name, email, format)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else if ta == "dtrack" {
			baseUrl := viper.GetString(internal.ConfigKeyDependencyTrackBaseUrl)
			apiKey := viper.GetString(internal.ConfigKeyDependencyTrackApiKey)
			k8sClusterId := viper.GetString(internal.ConfigKeyKubernetesClusterId)
			t := dtrack.NewDependencyTrackTarget(baseUrl, apiKey, k8sClusterId)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else if ta == "oci" {
			registry := viper.GetString(internal.ConfigKeyOciRegistry)
			username := viper.GetString(internal.ConfigKeyOciUser)
			token := viper.GetString(internal.ConfigKeyOciToken)
			format := viper.GetString(internal.ConfigKeyFormat)
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

func hasJobImage() bool {
	return viper.GetString(internal.ConfigKeyJobImage) != ""
}
