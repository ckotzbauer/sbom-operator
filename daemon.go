package main

import (
	"log/slog"
	"time"

	"github.com/ckotzbauer/libstandard"

	"github.com/l3montree-dev/devguard-operator/kubernetes"

	"github.com/robfig/cron"
)

type CronService struct {
	cron      string
	processor *Processor
}

var running = false

func StartDaemon(cronTime string, appVersion string) {
	cr := libstandard.Unescape(cronTime)
	slog.Debug("settings cron", "cronTime", cronTime)

	k8s := kubernetes.NewClient(OperatorConfig.IgnoreAnnotations, OperatorConfig.FallbackPullSecret)
	triv := NewTrivyScanner(libstandard.ToMap(OperatorConfig.RegistryProxies), appVersion)
	processor := NewProcessor(k8s, triv)

	cs := CronService{cron: cr, processor: processor}
	cs.printNextExecution()

	c := cron.New()
	err := c.AddFunc(cr, func() { cs.runBackgroundService() })
	if err != nil {
		slog.Error("could not configure cron", "err", err)
		return
	}

	c.Start()
}

func (c *CronService) printNextExecution() {
	s, err := cron.Parse(c.cron)
	if err != nil {
		slog.Error("could not parse cron", "err", err)
		return
	}

	nextRun := s.Next(time.Now())

	slog.Info("Next execution", "time", nextRun.Format(time.RFC3339))
}

func (c *CronService) runBackgroundService() {
	if running {
		return
	}

	running = true
	slog.Info("Execute background-service")

	for _, t := range c.processor.Targets {
		t.LoadImages()
	}

	namespaceSelector := OperatorConfig.NamespaceLabelSelector
	namespaces, err := c.processor.K8s.Client.ListNamespaces(namespaceSelector)
	if err != nil {
		slog.Error("failed to list namespaces", "err", err)
		running = false
		return
	}

	slog.Debug("Discovered namespaces", "namespaces", namespaces)

	pods, allImages := c.processor.K8s.LoadImageInfos(namespaces, OperatorConfig.PodLabelSelector)
	c.processor.ProcessAllPods(pods, allImages)

	c.printNextExecution()
	running = false
}
