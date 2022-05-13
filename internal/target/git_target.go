package target

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/ckotzbauer/sbom-operator/internal/target/git"
	"github.com/sirupsen/logrus"
)

type GitTarget struct {
	workingTree string
	workPath    string
	repository  string
	branch      string
	gitAccount  git.GitAccount
	sbomFormat  string
}

func NewGitTarget(workingTree, path, repo, branch, token, name, email, format string) *GitTarget {
	gitAccount := git.New(token, name, email)

	return &GitTarget{
		workingTree: workingTree,
		workPath:    path,
		repository:  repo,
		branch:      branch,
		sbomFormat:  format,
		gitAccount:  gitAccount,
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
	g.gitAccount.PrepareRepository(g.repository, g.workingTree, g.branch)
}

func (g *GitTarget) ProcessSbom(image kubernetes.ContainerImage, sbom string) error {
	imageID := image.ImageID
	filePath := g.ImageIDToFilePath(imageID)

	dir := filepath.Dir(filePath)
	err := os.MkdirAll(dir, 0777)
	if err != nil {
		logrus.WithError(err).Error("Directory could not be created")
		return err
	}

	err = os.WriteFile(filePath, []byte(sbom), 0640)
	if err != nil {
		logrus.WithError(err).Error("SBOM could not be saved")
	}

	return g.gitAccount.CommitAll(g.workingTree, fmt.Sprintf("Created new SBOM for image %s", imageID))
}

func (g *GitTarget) Cleanup(allImages []kubernetes.ContainerImage) {
	logrus.Debug("Start to remove old SBOMs")
	ignoreDirs := []string{".git"}

	fileName := syft.GetFileName(g.sbomFormat)
	allProcessedFiles := g.mapToFiles(allImages)

	err := filepath.Walk(filepath.Join(g.workingTree, g.workPath), g.deleteObsoleteFiles(fileName, ignoreDirs, allProcessedFiles))
	if err != nil {
		logrus.WithError(err).Error("Could not cleanup old SBOMs")
	} else {
		g.gitAccount.CommitAndPush(g.workingTree, "Deleted old SBOMs")
	}
}

func (g *GitTarget) mapToFiles(allImages []kubernetes.ContainerImage) []string {
	paths := []string{}
	for _, img := range allImages {
		paths = append(paths, g.ImageIDToFilePath(img.ImageID))
	}

	return paths
}

func (g *GitTarget) ImageIDToFilePath(id string) string {
	fileName := syft.GetFileName(g.sbomFormat)
	filePath := strings.ReplaceAll(id, "@", "/")
	return strings.ReplaceAll(path.Join(g.workingTree, g.workPath, filePath, fileName), ":", "_")
}

func (g *GitTarget) deleteObsoleteFiles(fileName string, ignoreDirs, allProcessedFiles []string) filepath.WalkFunc {
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
			for _, f := range allProcessedFiles {
				if f == p {
					found = true
					break
				}
			}

			if !found {
				rel, _ := filepath.Rel(g.workingTree, p)
				dir := filepath.Dir(rel)
				err = g.gitAccount.Remove(g.workingTree, dir)
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
