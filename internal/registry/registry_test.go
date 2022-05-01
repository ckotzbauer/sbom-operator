package registry_test

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/registry"
	"github.com/stretchr/testify/assert"
)

type testData struct {
	registry string
	image    string
	legacy   bool
}

func TestRegistry(t *testing.T) {
	tests := []testData{
		{
			registry: "gcr",
			image:    "gcr.io/sbom-git-operator/integration-test-image:1.0.0",
			legacy:   false,
		},
		{
			registry: "gar",
			image:    "europe-west3-docker.pkg.dev/sbom-git-operator/sbom-git-operator/integration-test-image:1.0.0",
			legacy:   false,
		},
		{
			registry: "ecr",
			image:    "055403865123.dkr.ecr.eu-central-1.amazonaws.com/sbom-git-operator/integration-test-image:1.0.0",
			legacy:   false,
		},
		/*{
			registry: "acr",
			image:  "sbomgitoperator.azurecr.io/integration-test-image:1.0.0",
			legacy: false,
		},*/
		{
			registry: "hub",
			image:    "docker.io/ckotzbauer/integration-test-image:1.0.0",
			legacy:   false,
		},
		{
			registry: "ghcr",
			image:    "ghcr.io/ckotzbauer-kubernetes-bot/sbom-git-operator-integration-test:1.0.0",
			legacy:   false,
		},
		{
			registry: "legacy-ghcr",
			image:    "ghcr.io/ckotzbauer-kubernetes-bot/sbom-git-operator-integration-test:1.0.0",
			legacy:   true,
		},
	}

	for _, v := range tests {
		t.Run(v.registry, func(t *testing.T) {
			testRegistry(t, v.registry, v.image, v.legacy)
		})
	}
}

func testRegistry(t *testing.T, name, image string, legacy bool) {
	b, err := os.ReadFile("../../auth/" + name + ".yaml")
	assert.NoError(t, err)

	decoded, err := base64.StdEncoding.DecodeString(string(b))
	assert.NoError(t, err)

	file := "/tmp/1.0.0.tar.gz"
	err = registry.SaveImage(file, kubernetes.ContainerImage{ImageID: image, Auth: []byte(decoded), LegacyAuth: legacy})

	if err == nil {
		stat, _ := os.Stat(file)
		assert.Equal(t, 2823168, stat.Size())
	}

	os.Remove(file)
	assert.NoError(t, err)
}
