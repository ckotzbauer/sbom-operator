package syft

import (
	"bytes"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/registry"
	"github.com/sirupsen/logrus"
)

type Syft struct {
	GitWorkingTree string
	GitPath        string
	SbomFormat     string
}

func New(gitWorkingTree, gitPath, sbomFormat string) Syft {
	return Syft{
		GitWorkingTree: gitWorkingTree,
		GitPath:        gitPath,
		SbomFormat:     sbomFormat,
	}
}

func (s *Syft) ExecuteSyft(img kubernetes.ImageDigest) string {
	fileName := GetFileName(s.SbomFormat)
	filePath := strings.ReplaceAll(img.Digest, "@", "/")
	filePath = strings.ReplaceAll(path.Join(s.GitWorkingTree, s.GitPath, filePath, fileName), ":", "_")

	if pathExists(filePath) {
		logrus.Debugf("Skip image %s", img.Digest)
		return filePath
	}

	logrus.Debugf("Processing image %s", img.Digest)

	workDir := "/tmp/" + randStringBytes(10)
	imagePath := workDir + "/image.tar.gz"
	os.Mkdir(workDir, 0777)

	err := registry.SaveImage(imagePath, workDir, img)

	if err != nil {
		logrus.WithError(err).Error("Image-Pull failed")
		return filePath
	}

	cmd := exec.Command("syft", imagePath, "-o", s.SbomFormat)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	stdout, err := cmd.Output()

	os.RemoveAll(workDir)

	if err != nil {
		logrus.WithError(err).WithField("stderr", errb.String()).Error("Syft stopped with error")
		return filePath
	}

	dir := filepath.Dir(filePath)
	err = os.MkdirAll(dir, 0777)

	if err != nil {
		logrus.WithError(err).Error("Directory could not be created")
		return filePath
	}

	data := []byte(stdout)
	err = os.WriteFile(filePath, data, 0640)

	if err != nil {
		logrus.WithError(err).Error("SBOM could not be saved")
	}

	return filePath
}

func GetFileName(sbomFormat string) string {
	switch sbomFormat {
	case "json":
		return "sbom.json"
	case "text":
		return "sbom.txt"
	case "cyclonedx":
		return "sbom.xml"
	case "cyclonedx-json":
		return "sbom.json"
	case "spdx":
		return "sbom.spdx"
	case "spdx-json":
		return "sbom.json"
	case "table":
		return "sbom.txt"
	default:
		return "sbom.json"
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
