package oci

import (
	"fmt"
	"os"
	"testing"

	"github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/stretchr/testify/assert"
)

func TestOci(t *testing.T) {
	fmt.Printf("Image: %s", os.Getenv("TEST_DIGEST"))
	fmt.Printf("Date: %s", os.Getenv("DATE"))
	oci := NewOciTarget(fmt.Sprintf("ttl.sh/sbom-operator-oci-test-%s", os.Getenv("DATE")), "", "", "json")
	sbom, err := os.ReadFile("./fixtures/sbom.json")
	assert.NoError(t, err)

	img := liboci.RegistryImage{ImageID: os.Getenv("TEST_DIGEST")}
	err = oci.ProcessSbom(target.NewContext(string(sbom), &img, &kubernetes.ContainerInfo{}, &kubernetes.PodInfo{}))
	assert.NoError(t, err)
}
