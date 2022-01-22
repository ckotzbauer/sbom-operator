package target

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/ckotzbauer/sbom-operator/internal/target/git"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type GitTarget struct {
	workingTree        string
	workPath           string
	repository         string
	branch             string
	gitAccount         git.GitAccount
	processedSbomFiles []string
}

func NewGitTarget() *GitTarget {
	workingTree := viper.GetString(internal.ConfigKeyGitWorkingTree)
	workPath := path.Join(workingTree, viper.GetString(internal.ConfigKeyGitPath))
	repository := viper.GetString(internal.ConfigKeyGitRepository)
	branch := viper.GetString(internal.ConfigKeyGitBranch)

	gitAccount := git.New(
		viper.GetString(internal.ConfigKeyGitAccessToken),
		viper.GetString(internal.ConfigKeyGitAuthorName),
		viper.GetString(internal.ConfigKeyGitAuthorEmail))

	return &GitTarget{
		workingTree:        workingTree,
		workPath:           workPath,
		repository:         repository,
		branch:             branch,
		gitAccount:         gitAccount,
		processedSbomFiles: []string{},
	}
}

func (g *GitTarget) ValidateConfig() error {
	if g.workingTree == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyGitWorkingTree)
	}

	if g.repository == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyGitRepository)
	}

	if g.branch == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyGitBranch)
	}

	if g.gitAccount.Token == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyGitAccessToken)
	}

	if g.gitAccount.Name == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyGitAuthorName)
	}

	if g.gitAccount.Email == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyGitAuthorEmail)
	}

	return nil
}

func (g *GitTarget) Initialize() {
	g.gitAccount.PrepareRepository(
		g.repository, g.workingTree,
		viper.GetString(internal.ConfigKeyGitBranch))
}

func (g *GitTarget) ProcessSboms(sbomFiles []string, namespace string) {
	g.gitAccount.CommitAll(g.workingTree, fmt.Sprintf("Created new SBOMs for pods in namespace %s", namespace))
	g.processedSbomFiles = append(g.processedSbomFiles, sbomFiles...)
}

func (g *GitTarget) Cleanup() {
	logrus.Debug("Start to remove old SBOMs")
	ignoreDirs := []string{".git"}
	format := viper.GetString(internal.ConfigKeyFormat)

	fileName := syft.GetFileName(format)

	err := filepath.Walk(g.workPath, g.deleteObsoleteFiles(fileName, ignoreDirs))
	if err != nil {
		logrus.WithError(err).Error("Could not cleanup old SBOMs")
	} else {
		g.gitAccount.CommitAndPush(g.workingTree, "Deleted old SBOMs")
	}
}

func (g *GitTarget) deleteObsoleteFiles(fileName string, ignoreDirs []string) filepath.WalkFunc {
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
			for _, f := range g.processedSbomFiles {
				if f == p {
					found = true
					break
				}
			}

			if !found {
				rel, _ := filepath.Rel(g.workingTree, p)
				dir := filepath.Dir(rel)
				g.gitAccount.Remove(g.workingTree, dir)
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
