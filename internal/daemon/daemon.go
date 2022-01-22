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
	targets []string
}

func Start(cronTime string) {
	cr := internal.Unescape(cronTime)
	targets := viper.GetStringSlice(internal.ConfigKeyTargets)

	logrus.Debugf("Cron set to: %v", cr)
	logrus.Debugf("Targets set to: %v", targets)

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
	targets := c.initTargets()

	client := kubernetes.NewClient()
	namespaces := client.ListNamespaces(viper.GetString(internal.ConfigKeyNamespaceLabelSelector))
	logrus.Debugf("Discovered %v namespaces", len(namespaces))

	sy := syft.New(viper.GetString(internal.ConfigKeyGitWorkingTree), viper.GetString(internal.ConfigKeyGitPath), format)

	for _, ns := range namespaces {
		pods := client.ListPods(ns.Name, viper.GetString(internal.ConfigKeyPodLabelSelector))
		logrus.Debugf("Discovered %v pods in namespace %v", len(pods), ns.Name)
		digests := client.GetContainerDigests(pods)
		processedSbomFiles := []string{}

		for _, d := range digests {
			sbomPath := sy.ExecuteSyft(d)
			processedSbomFiles = append(processedSbomFiles, sbomPath)
		}

		for _, t := range targets {
			t.ProcessSboms(processedSbomFiles, ns.Name)
		}
	}

	for _, t := range targets {
		t.Cleanup()
	}

	c.printNextExecution()
}

func (c *CronService) initTargets() []target.Target {
	targets := make([]target.Target, 0)

	for _, ta := range c.targets {
		if ta == "git" {
			targets = append(targets, target.NewGitTarget())
		}
	}

	return targets
}
