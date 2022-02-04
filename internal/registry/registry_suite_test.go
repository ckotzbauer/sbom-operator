package registry_test

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/registry"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRegistry(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Registry Suite")
}

func testRegistry(name, image string, legacy bool) {
	b, err := os.ReadFile("../../auth/" + name + ".yaml")
	Expect(err).To(BeNil())

	decoded, err := base64.StdEncoding.DecodeString(string(b))
	Expect(err).To(BeNil())

	file := "/tmp/1.0.0.tar.gz"
	err = registry.SaveImage(file, kubernetes.ContainerImage{ImageID: image, Auth: []byte(decoded), LegacyAuth: legacy})

	if err == nil {
		stat, _ := os.Stat(file)
		Expect(stat.Size()).To(BeEquivalentTo(2823168))
	}

	os.Remove(file)
	Expect(err).To(BeNil())
}

var _ = Describe("Registry", func() {
	Describe("Storing image from GCR", func() {
		It("should work correctly", func() {
			testRegistry("gcr", "gcr.io/sbom-git-operator/integration-test-image:1.0.0", false)
		})
	})

	Describe("Storing image from GAR", func() {
		It("should work correctly", func() {
			testRegistry("gar", "europe-west3-docker.pkg.dev/sbom-git-operator/sbom-git-operator/integration-test-image:1.0.0", false)
		})
	})

	Describe("Storing image from ECR", func() {
		It("should work correctly", func() {
			testRegistry("ecr", "055403865123.dkr.ecr.eu-central-1.amazonaws.com/sbom-git-operator/integration-test-image:1.0.0", false)
		})
	})

	Describe("Storing image from ACR", func() {
		It("should work correctly", func() {
			testRegistry("acr", "sbomgitoperator.azurecr.io/integration-test-image:1.0.0", false)
		})
	})

	Describe("Storing image from DockerHub", func() {
		It("should work correctly", func() {
			testRegistry("hub", "docker.io/ckotzbauer/integration-test-image:1.0.0", false)
		})
	})

	Describe("Storing image from GHCR", func() {
		It("should work correctly", func() {
			testRegistry("ghcr", "ghcr.io/ckotzbauer-kubernetes-bot/sbom-git-operator-integration-test:1.0.0", false)
		})
	})

	Describe("Storing image from GHCR - legacy .dockercfg", func() {
		It("should work correctly", func() {
			testRegistry("legacy-ghcr", "ghcr.io/ckotzbauer-kubernetes-bot/sbom-git-operator-integration-test:1.0.0", true)
		})
	})
})
