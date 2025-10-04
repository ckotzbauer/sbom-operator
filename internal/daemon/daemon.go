package daemon

import (
	"sync"
	"time"

	"github.com/ckotzbauer/libstandard"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/processor"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
)

type CronService struct {
	cron      string
	processor *processor.Processor
	mu        sync.Mutex
	running   bool
}

func Start(cronTime string, appVersion string) {
	cr := libstandard.Unescape(cronTime)
	logrus.Debugf("Cron set to: %v", cr)

	k8s := kubernetes.NewClient(internal.OperatorConfig.IgnoreAnnotations, internal.OperatorConfig.FallbackPullSecret)
	sy := syft.New(internal.OperatorConfig.Format, libstandard.ToMap(internal.OperatorConfig.RegistryProxies), appVersion)
	processor := processor.New(k8s, sy)

	cs := CronService{cron: cr, processor: processor}
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
	// Atomically check and set running flag
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		logrus.Info("Background-service already running, skipping execution")
		return
	}
	c.running = true
	c.mu.Unlock()

	// Ensure running flag is reset even on panic
	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	logrus.Info("Execute background-service")

	if !processor.HasJobImage() {
		for _, t := range c.processor.Targets {
			err := t.Initialize()
			if err != nil {
				logrus.WithError(err).Fatal("Target could not be initialized,")
			}

			_, err = t.LoadImages()
			if err != nil {
				logrus.WithError(err).Error("Failed to load images from target")
			}
		}
	}

	namespaceSelector := internal.OperatorConfig.NamespaceLabelSelector
	namespaces, err := c.processor.K8s.Client.ListNamespaces(namespaceSelector)
	if err != nil {
		logrus.WithError(err).Errorf("failed to list namespaces with selector: %s, abort background-service", namespaceSelector)
		return
	}

	logrus.Debugf("Discovered %v namespaces", len(namespaces))
	pods, allImages := c.processor.K8s.LoadImageInfos(namespaces, internal.OperatorConfig.PodLabelSelector)
	c.processor.ProcessAllPods(pods, allImages)

	c.printNextExecution()
}
