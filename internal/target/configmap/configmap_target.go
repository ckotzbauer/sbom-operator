package configmap

import (
	"fmt"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/libstandard"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/sirupsen/logrus"
)

type ConfigMapTarget struct {
	k8s *kubernetes.KubeClient
}

func NewConfigMapTarget(k8s *kubernetes.KubeClient) *ConfigMapTarget {
	return &ConfigMapTarget{
		k8s: k8s,
	}
}

func (g *ConfigMapTarget) ValidateConfig() error {
	return nil
}

func (g *ConfigMapTarget) Initialize() error {
	return nil
}

func (g *ConfigMapTarget) ProcessSbom(ctx *target.TargetContext) error {
	b := []byte(ctx.Sbom)
	compressed, err := libstandard.Compress(b)
	if err != nil {
		logrus.WithError(err).Error("Could not compress data.")
		return err
	}

	name := fmt.Sprintf("%s-%s", ctx.Pod.PodName, ctx.Container.Name)
	err = g.k8s.CreateConfigMap(ctx.Pod.PodNamespace, name, ctx.Image.ImageID, compressed)
	if err != nil {
		logrus.WithError(err).Errorf("Could not create configmap %s/%s.", ctx.Pod.PodNamespace, name)
	} else {
		logrus.Debugf("Created configmap %s/%s.", ctx.Pod.PodNamespace, name)
	}

	return err
}

func (g *ConfigMapTarget) LoadImages() ([]*libk8s.RegistryImage, error) {
	configMaps, err := g.k8s.ListConfigMaps()
	if err != nil {
		logrus.WithError(err).Error("Could not load configmaps.")
		return nil, err
	}

	images := make([]*libk8s.RegistryImage, 0)
	for _, c := range configMaps {
		if imageId, ok := c.Annotations[fmt.Sprintf(kubernetes.AnnotationTemplate, "image-id")]; ok {
			images = append(images, &libk8s.RegistryImage{ImageID: imageId})
		} else {
			logrus.Warnf("ConfigMap %s/%s has no image-id annotation.", c.Namespace, c.Name)
		}
	}

	return images, nil
}

func (g *ConfigMapTarget) Remove(allImages []*libk8s.RegistryImage) error {
	configMaps, err := g.k8s.ListConfigMaps()
	if err != nil {
		logrus.WithError(err).Error("failed to load configmaps")
		return err
	}

	for _, i := range allImages {
		for _, cm := range configMaps {
			if imageId, ok := cm.Annotations[fmt.Sprintf(kubernetes.AnnotationTemplate, "image-id")]; ok && imageId == i.ImageID {
				err = g.k8s.DeleteConfigMap(cm)
				if err != nil {
					logrus.WithError(err).Errorf("Could not delete configmap from imageID %s.", i.ImageID)
				}
			}
		}
	}

	return nil
}
