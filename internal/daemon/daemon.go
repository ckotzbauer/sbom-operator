package daemon

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/git"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type CronService struct {
	cron string
}

func Start(cronTime string) {
	cr := internal.Unescape(cronTime)
	logrus.Debugf("Cron set to: %v", cr)

	cs := CronService{cron: cr}
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
	workingTree := viper.GetString(internal.ConfigKeyGitWorkingTree)
	gitPath := viper.GetString(internal.ConfigKeyGitPath)
	format := viper.GetString(internal.ConfigKeyFormat)
	workPath := path.Join(workingTree, gitPath)

	gitAccount := git.New(
		viper.GetString(internal.ConfigKeyGitAccessToken),
		viper.GetString(internal.ConfigKeyGitAuthorName),
		viper.GetString(internal.ConfigKeyGitAuthorEmail))

	gitAccount.PrepareRepository(
		viper.GetString(internal.ConfigKeyGitRepository), workingTree,
		viper.GetString(internal.ConfigKeyGitBranch))

	client := kubernetes.NewClient()
	namespaces := client.ListNamespaces(viper.GetString(internal.ConfigKeyNamespaceLabelSelector))
	logrus.Debugf("Discovered %v namespaces", len(namespaces))

	processedSbomFiles := []string{}

	sy := syft.New(workingTree, gitPath, format)

	for _, ns := range namespaces {
		pods := client.ListPods(ns.Name, viper.GetString(internal.ConfigKeyPodLabelSelector))
		logrus.Debugf("Discovered %v pods in namespace %v", len(pods), ns.Name)
		digests := client.GetContainerDigests(pods)

		for _, d := range digests {
			sbomPath := sy.ExecuteSyft(d)
			processedSbomFiles = append(processedSbomFiles, sbomPath)
		}

		gitAccount.CommitAll(workingTree, fmt.Sprintf("Created new SBOMs for pods in namespace %s", ns.Name))
	}

	logrus.Debug("Start to remove old SBOMs")
	ignoreDirs := []string{".git"}
	fileName := syft.GetFileName(format)

	err := filepath.Walk(workPath, deleteObsoleteFiles(workingTree, fileName, ignoreDirs, processedSbomFiles, gitAccount))
	if err != nil {
		logrus.WithError(err).Error("Could not cleanup old SBOMs")
	} else {
		gitAccount.CommitAndPush(workingTree, "Deleted old SBOMs")
	}

	c.printNextExecution()
}

func deleteObsoleteFiles(workPath, fileName string, ignoreDirs, processedSbomFiles []string, gitAccount git.GitAccount) filepath.WalkFunc {
	return func(p string, info os.FileInfo, err error) error {
		if err != nil {
			logrus.WithError(err).Errorf("An error occurred while processing %s", p)
			return nil
		}

		if info.IsDir() {
			dir := filepath.Base(p)
			for _, d := range ignoreDirs {
				if d == dir {
					return filepath.SkipDir
				}
			}
		}

		if info.Name() == fileName {
			found := false
			for _, f := range processedSbomFiles {
				if f == p {
					found = true
					break
				}
			}

			if !found {
				rel, _ := filepath.Rel(workPath, p)
				dir := filepath.Dir(rel)
				gitAccount.Remove(workPath, dir)
				if err != nil {
					logrus.WithError(err).Errorf("File could not be deleted %s", p)
				} else {
					logrus.Debugf("Deleted old SBOM: %s", p)
				}
			}
		}

		return nil
	}
}
