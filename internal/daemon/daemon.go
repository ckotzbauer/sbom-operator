package daemon

import (
	"time"

	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type CronService struct {
	cron    string
	targets []target.Target
}

func Start(cronTime string) {
	cr := internal.Unescape(cronTime)
	targetKeys := viper.GetStringSlice(internal.ConfigKeyTargets)

	logrus.Debugf("Cron set to: %v", cr)
	logrus.Debugf("Targets set to: %v", targetKeys)

	targets := initTargets(targetKeys)
	cs := CronService{cron: cr, targets: targets}
	cs.printNextExecution()

	c := cron.New()
	c.AddFunc(cr, func() { cs.runBackgroundService() })
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
	logrus.Info("Execute background-service")
	format := viper.GetString(internal.ConfigKeyFormat)

	for _, t := range c.targets {
		t.Initialize()
	}

	client := kubernetes.NewClient()
	namespaces := client.ListNamespaces(viper.GetString(internal.ConfigKeyNamespaceLabelSelector))
	logrus.Debugf("Discovered %v namespaces", len(namespaces))

	sy := syft.New(viper.GetString(internal.ConfigKeyGitWorkingTree), viper.GetString(internal.ConfigKeyGitPath), format)
	allImages := []string{}

	for _, ns := range namespaces {
		pods := client.ListPods(ns.Name, viper.GetString(internal.ConfigKeyPodLabelSelector))
		logrus.Debugf("Discovered %v pods in namespace %v", len(pods), ns.Name)

		for _, pod := range pods {
			filteredDigests, allPodImages := client.GetContainerDigests(pod)
			allImages = append(allImages, allPodImages...)

			for _, d := range filteredDigests {
				// TODO: Avoid duplicate scans of the same image in different pods.
				_, err := sy.ExecuteSyft(d)
				// Error is already handled from syft module.
				if err == nil {
					client.UpdatePodAnnotation(pod)
				}
			}
		}

		for _, t := range c.targets {
			t.ProcessSboms(ns.Name)
		}
	}

	for _, t := range c.targets {
		t.Cleanup(allImages)
	}

	c.printNextExecution()
}

func initTargets(targetKeys []string) []target.Target {
	targets := make([]target.Target, 0)

	for _, ta := range targetKeys {
		var err error

		if ta == "git" {
			t := target.NewGitTarget()
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
