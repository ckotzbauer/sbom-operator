package oci

import (
	"fmt"
	"os"
	"testing"

	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/stretchr/testify/assert"
)

func TestOci(t *testing.T) {
	fmt.Printf("Image: %s", os.Getenv("TEST_DIGEST"))
	oci := NewOciTarget("ghcr.io/ckotzbauer/sbom-operator/oci-test", os.Getenv("REGISTRY_USER"), os.Getenv("REGISTRY_TOKEN"), "json")
	sbom, err := os.ReadFile("./oci/fixtures/sbom.json")
	assert.NoError(t, err)

	img := kubernetes.ContainerImage{ImageID: os.Getenv("TEST_DIGEST")}

	err = oci.ProcessSbom(img, string(sbom))
	assert.NoError(t, err)
}
