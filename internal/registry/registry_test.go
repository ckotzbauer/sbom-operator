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
	registry  string
	image     string
	legacy    bool
	imageSize int64
}

func TestRegistry(t *testing.T) {
	tests := []testData{
		{
			registry:  "gcr",
			image:     "gcr.io/sbom-git-operator/integration-test-image:1.0.0",
			legacy:    false,
			imageSize: 2823168,
		},
		{
			registry:  "gar",
			image:     "europe-west3-docker.pkg.dev/sbom-git-operator/sbom-git-operator/integration-test-image:1.0.0",
			legacy:    false,
			imageSize: 2823168,
		},
		{
			registry:  "ecr",
			image:     "055403865123.dkr.ecr.eu-central-1.amazonaws.com/sbom-git-operator/integration-test-image:1.0.0",
			legacy:    false,
			imageSize: 2823168,
		},
		/*{
			registry: "acr",
			image:  "sbomgitoperator.azurecr.io/integration-test-image:1.0.0",
			legacy: false,
			imageSize: 2823168,
		},*/
		{
			registry:  "hub",
			image:     "docker.io/ckotzbauer/integration-test-image:1.0.0",
			legacy:    false,
			imageSize: 2823168,
		},
		{
			registry:  "ghcr",
			image:     "ghcr.io/ckotzbauer-kubernetes-bot/sbom-git-operator-integration-test:1.0.0",
			legacy:    false,
			imageSize: 2823168,
		},
		{
			registry:  "legacy-ghcr",
			image:     "ghcr.io/ckotzbauer-kubernetes-bot/sbom-git-operator-integration-test:1.0.0",
			legacy:    true,
			imageSize: 2823168,
		},
	}
	unauthenticatedPositiveTests := []testData{
		{
			registry:  "docker-io",
			image:     "hello-world:latest",
			legacy:    false,
			imageSize: 7168,
		},
	}
	unauthenticatedNegativeTests := []testData{
		{
			registry:  "ghcr",
			image:     "ghcr.io/ckotzbauer-kubernetes-bot/sbom-git-operator-integration-test:1.0.0",
			legacy:    false,
			imageSize: 2823168,
		},
	}

	for _, v := range tests {
		t.Run(v.registry, func(t *testing.T) {
			testRegistry(t, v.registry, v.image, v.legacy, v.imageSize)
		})
	}
	for _, v := range unauthenticatedPositiveTests {
		t.Run(v.registry, func(t *testing.T) {
			testRegistryWithoutPullSecretsPositive(t, v.image, v.imageSize)
		})
	}
	for _, v := range unauthenticatedNegativeTests {
		t.Run(v.registry, func(t *testing.T) {
			testRegistryWithoutPullSecretsNegative(t, v.image)
		})
	}
}

func testRegistry(t *testing.T, name, image string, legacy bool, imageSize int64) {
	b, err := os.ReadFile("../../auth/" + name + ".yaml")
	assert.NoError(t, err)

	decoded, err := base64.StdEncoding.DecodeString(string(b))
	assert.NoError(t, err)

	file := "/tmp/1.0.0.tar.gz"
	err = registry.SaveImage(file, kubernetes.ContainerImage{ImageID: image, PullSecrets: []kubernetes.KubeCreds{{SecretName: name, SecretCredsData: []byte(decoded), IsLegacySecret: legacy}}})

	if err == nil {
		stat, _ := os.Stat(file)
		assert.Equal(t, imageSize, stat.Size())
	}

	os.Remove(file)
	assert.NoError(t, err)
}

// this test should check if an image is pullable without pullSecrets (e.g. dockerhub - where it is really possible)
func testRegistryWithoutPullSecretsPositive(t *testing.T, image string, imageSize int64) {

	file := "/tmp/1.0.0.tar.gz"
	err := registry.SaveImage(file, kubernetes.ContainerImage{ImageID: image, PullSecrets: []kubernetes.KubeCreds{}})

	if err == nil {
		stat, _ := os.Stat(file)
		assert.Equal(t, imageSize, stat.Size())
	}

	os.Remove(file)
	assert.NoError(t, err)
}

// this test should check if an image is not pullable without pullSecrets (e.g. internal registry - where it is forbidden)
// an error must be returned
func testRegistryWithoutPullSecretsNegative(t *testing.T, image string) {

	file := "/tmp/1.0.0.tar.gz"
	err := registry.SaveImage(file, kubernetes.ContainerImage{ImageID: image, PullSecrets: []kubernetes.KubeCreds{}})

	assert.Error(t, registry.ErrorNoValidPullSecret)

	os.Remove(file)
	assert.NoError(t, err)
}
