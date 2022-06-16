package oci

import (
	"fmt"
	"os"
	"testing"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/stretchr/testify/assert"
)

func TestOci(t *testing.T) {
	fmt.Printf("Image: %s", os.Getenv("TEST_DIGEST"))
	oci := NewOciTarget("ghcr.io/ckotzbauer/sbom-operator/oci-test", os.Getenv("REGISTRY_USER"), os.Getenv("REGISTRY_TOKEN"), "json")
	sbom, err := os.ReadFile("./fixtures/sbom.json")
	assert.NoError(t, err)

	img := libk8s.KubeImage{Image: liboci.RegistryImage{ImageID: os.Getenv("TEST_DIGEST")}}

	err = oci.ProcessSbom(img, string(sbom))
	assert.NoError(t, err)
}
