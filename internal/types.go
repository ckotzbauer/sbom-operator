package internal

import (
	"os"

	corev1 "k8s.io/api/core/v1"
)

type ContainerImage struct {
	Image       string
	ImageID     string
	Auth        []byte
	LegacyAuth  bool
	Pods        []corev1.Pod
	ArchivePath string
}

type File struct {
	Path string
}

func (f File) Identifier() string {
	return f.Path
}

func (c ContainerImage) Identifier() string {
	return c.ImageID
}

func (f File) FilePath() string {
	return f.Path
}

func (c ContainerImage) FilePath() string {
	return c.ArchivePath
}

func (f File) Type() string {
	return "file"
}

func (c ContainerImage) Type() string {
	return "docker-archive"
}

func (f File) Cleanup() {
	os.Remove(f.Path)
}

func (c ContainerImage) Cleanup() {
	os.Remove(c.ArchivePath)
}

type ScanItem interface {
	Identifier() string
	FilePath() string
	Type() string
	Cleanup()
}
