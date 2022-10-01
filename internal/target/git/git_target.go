package git

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/ckotzbauer/libk8soci/pkg/git"
	libk8s "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/ckotzbauer/sbom-operator/internal/target"
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

func NewGitTarget(workingTree, path, repo, branch, name, email, token, userName, password, githubAppID, githubAppInstallationID, githubAppPrivateKey, format string, fallbackClone bool) *GitTarget {
	gitAccount := git.New(name, email, token, userName, password, githubAppID, githubAppInstallationID, githubAppPrivateKey, fallbackClone)

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

	if g.gitAccount.Name == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyGitAuthorName)
	}

	if g.gitAccount.Email == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyGitAuthorEmail)
	}

	return nil
}

func (g *GitTarget) Initialize() error {
	return g.gitAccount.PrepareRepository(g.repository, g.workingTree, g.branch)
}

func (g *GitTarget) ProcessSbom(ctx *target.TargetContext) error {
	imageID := ctx.Image.ImageID
	filePath := g.ImageIDToFilePath(imageID)

	dir := filepath.Dir(filePath)
	err := os.MkdirAll(dir, 0777)
	if err != nil {
		logrus.WithError(err).Error("Directory could not be created")
		return err
	}

	err = os.WriteFile(filePath, []byte(ctx.Sbom), 0640)
	if err != nil {
		logrus.WithError(err).Error("SBOM could not be saved")
	}

	return g.gitAccount.CommitAll(g.workingTree, fmt.Sprintf("Created new SBOM for image %s", imageID))
}

func (g *GitTarget) LoadImages() []*libk8s.RegistryImage {
	ignoreDirs := []string{".git"}
	fileName := syft.GetFileName(g.sbomFormat)
	basePath := filepath.Join(g.workingTree, g.workPath)
	images := make([]*libk8s.RegistryImage, 0)

	err := filepath.Walk(basePath, func(p string, info os.FileInfo, err error) error {
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

		if filepath.Base(p) == fileName {
			sbomPath, _ := filepath.Rel(basePath, p)
			s := filepath.Dir(sbomPath)
			images = append(images, &libk8s.RegistryImage{ImageID: strings.Replace(s, "/sha256_", "@sha256:", 1)})
		}

		return nil
	})

	if err != nil {
		logrus.WithError(err).Error("Could not list all SBOMs")
		return []*libk8s.RegistryImage{}
	}

	return images
}

func (g *GitTarget) Remove(images []*libk8s.RegistryImage) {
	logrus.Debug("Start to remove old SBOMs")
	sbomFiles := g.mapToFiles(images)

	for _, f := range sbomFiles {
		rel, _ := filepath.Rel(g.workingTree, f)
		dir := filepath.Dir(rel)
		err := g.gitAccount.Remove(g.workingTree, dir)
		if err != nil {
			logrus.WithError(err).Errorf("File could not be deleted %s", f)
		} else {
			logrus.Debugf("Deleted old SBOM: %s", f)
		}
	}

	err := g.gitAccount.CommitAndPush(g.workingTree, "Deleted old SBOMs")
	if err != nil {
		logrus.WithError(err).Error("Could not commit SBOM removal to git")
	}
}

func (g *GitTarget) mapToFiles(allImages []*libk8s.RegistryImage) []string {
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
