package syft

import (
	"bytes"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/ckotzbauer/sbom-git-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-git-operator/internal/registry"
	"github.com/sirupsen/logrus"
)

func ExecuteSyft(img kubernetes.ImageDigest, gitWorkingTree, gitPath string) string {
	name := strings.ReplaceAll(img.Digest, "@", "/")
	name = strings.ReplaceAll(path.Join(gitWorkingTree, gitPath, name, "sbom.json"), ":", "_")

	if pathExists(name) {
		logrus.Debugf("Skip image %s", img.Digest)
		return name
	}

	logrus.Debugf("Processing image %s", img.Digest)

	workDir := "/tmp/" + randStringBytes(10)
	imagePath := workDir + "/image.tar.gz"
	os.Mkdir(workDir, 0777)

	err := registry.SaveImage(imagePath, workDir, img)

	if err != nil {
		logrus.WithError(err).Error("Image-Pull failed")
		return name
	}

	cmd := exec.Command("syft", imagePath, "-o", "json")
	var errb bytes.Buffer
	cmd.Stderr = &errb
	stdout, err := cmd.Output()

	os.RemoveAll(workDir)

	if err != nil {
		logrus.WithError(err).WithField("stderr", errb.String()).Error("Syft stopped with error")
		return name
	}

	dir := filepath.Dir(name)
	err = os.MkdirAll(dir, 0777)

	if err != nil {
		logrus.WithError(err).Error("Directory could not be created")
		return name
	}

	data := []byte(stdout)
	err = os.WriteFile(name, data, 0640)

	if err != nil {
		logrus.WithError(err).Error("SBOM could not be saved")
	}

	return name
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
