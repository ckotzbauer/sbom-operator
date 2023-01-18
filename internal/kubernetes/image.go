package kubernetes

import (
	"fmt"
	"strings"

	"github.com/ckotzbauer/libk8soci/pkg/oci"
	parser "github.com/novln/docker-parser"
	"github.com/novln/docker-parser/docker"
	"github.com/sirupsen/logrus"
)

func ApplyProxyRegistry(img *oci.RegistryImage, log bool, registryProxyMap map[string]string) error {
	imageRef, err := parser.Parse(img.ImageID)
	if err != nil {
		logrus.WithError(err).Errorf("Could not parse image %s", img.ImageID)
		return err
	}

	for registryToReplace, proxyRegistry := range registryProxyMap {
		if imageRef.Registry() == registryToReplace {
			shortName := strings.TrimPrefix(imageRef.ShortName(), docker.DefaultRepoPrefix)
			fullName := fmt.Sprintf("%s/%s", imageRef.Registry(), shortName)
			if strings.HasPrefix(imageRef.Tag(), "sha256") {
				fullName = fmt.Sprintf("%s@%s", fullName, imageRef.Tag())
			} else {
				fullName = fmt.Sprintf("%s:%s", fullName, imageRef.Tag())
			}

			img.ImageID = strings.ReplaceAll(fullName, registryToReplace, proxyRegistry)
			img.Image = strings.ReplaceAll(img.Image, registryToReplace, proxyRegistry)

			if log {
				logrus.Debugf("Applied Registry-Proxy %s", img.ImageID)
			}

			break
		}
	}

	return nil
}
