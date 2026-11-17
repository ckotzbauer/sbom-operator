package configmap

import (
	"context"
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

func (g *ConfigMapTarget) ProcessSbom(ctx context.Context, tctx *target.TargetContext) error {
	b := []byte(tctx.Attestation.Sbom)
	compressed, err := libstandard.Compress(b)
	if err != nil {
		logrus.WithError(err).Error("Could not compress data.")
		return err
	}

	for _, container := range tctx.Containers {
		name := fmt.Sprintf("%s-%s", tctx.Pod.PodName, container.Name)
		err = g.k8s.CreateConfigMap(tctx.Pod.PodNamespace, name, tctx.Image.ImageID, compressed)
		if err != nil {
			logrus.WithError(err).Errorf("Could not create configmap %s/%s.", tctx.Pod.PodNamespace, name)
		} else {
			logrus.Debugf("Created configmap %s/%s.", tctx.Pod.PodNamespace, name)
		}
	}

	return err
}

func (g *ConfigMapTarget) LoadImages(ctx context.Context) ([]*target.TargetImage, error) {
	configMaps, err := g.k8s.ListConfigMaps()
	if err != nil {
		logrus.WithError(err).Error("Could not load configmaps.")
		return nil, err
	}

	images := make([]*target.TargetImage, 0)
	for _, c := range configMaps {
		if imageId, ok := c.Annotations[fmt.Sprintf(kubernetes.AnnotationTemplate, "image-id")]; ok {
			images = append(images, &target.TargetImage{RegistryImage: &libk8s.RegistryImage{ImageID: imageId}, Namespace: c.Namespace})
		} else {
			logrus.Warnf("ConfigMap %s/%s has no image-id annotation.", c.Namespace, c.Name)
		}
	}

	return images, nil
}

func (g *ConfigMapTarget) Remove(ctx context.Context, allImages []*target.TargetImage) error {
	configMaps, err := g.k8s.ListConfigMaps()
	if err != nil {
		logrus.WithError(err).Error("failed to load configmaps")
		return err
	}

	for _, i := range allImages {
		for _, cm := range configMaps {
			if cm.Namespace == i.Namespace {
				if imageId, ok := cm.Annotations[fmt.Sprintf(kubernetes.AnnotationTemplate, "image-id")]; ok && imageId == i.ImageID {
					err = g.k8s.DeleteConfigMap(cm)
					if err != nil {
						logrus.WithError(err).Errorf("Could not delete configmap from imageID %s.", i.ImageID)
					}
				}
			}
		}
	}

	return nil
}

func (g *ConfigMapTarget) IsNamespaceAware() bool {
	return true
}
