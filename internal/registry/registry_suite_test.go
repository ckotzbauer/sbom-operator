package registry_test

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/ckotzbauer/sbom-git-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-git-operator/internal/registry"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRegistry(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Registry Suite")
}

func testRegistry(name, image string) {
	b, err := os.ReadFile("../../auth/" + name + ".yaml")
	Expect(err).To(BeNil())

	decoded, err := base64.StdEncoding.DecodeString(string(b))
	Expect(err).To(BeNil())

	os.Mkdir("/tmp/"+name, 0777)
	err = registry.SaveImage("/tmp/"+name+"/image.tar.gz", "/tmp/"+name, kubernetes.ImageDigest{Digest: image, Auth: []byte(decoded)})

	if err == nil {
		stat, _ := os.Stat("/tmp/" + name + "/image.tar.gz")
		Expect(stat.Size()).To(BeEquivalentTo(2823168))
	}

	os.RemoveAll("/tmp/" + name)
	Expect(err).To(BeNil())
}

var _ = Describe("Registry", func() {
	Describe("Storing image from GCR", func() {
		It("should work correctly", func() {
			testRegistry("gcr", "gcr.io/sbom-git-operator/integration-test-image:1.0.0")
		})
	})

	Describe("Storing image from GAR", func() {
		It("should work correctly", func() {
			testRegistry("gar", "europe-west3-docker.pkg.dev/sbom-git-operator/sbom-git-operator/integration-test-image:1.0.0")
		})
	})

	Describe("Storing image from ECR", func() {
		It("should work correctly", func() {
			testRegistry("ecr", "055403865123.dkr.ecr.eu-central-1.amazonaws.com/sbom-git-operator/integration-test-image:1.0.0")
		})
	})

	Describe("Storing image from ACR", func() {
		It("should work correctly", func() {
			testRegistry("acr", "sbomgitoperator.azurecr.io/integration-test-image:1.0.0")
		})
	})

	Describe("Storing image from DockerHub", func() {
		It("should work correctly", func() {
			testRegistry("hub", "docker.io/ckotzbauer/integration-test-image:1.0.0")
		})
	})

	Describe("Storing image from GHCR", func() {
		It("should work correctly", func() {
			testRegistry("ghcr", "ghcr.io/ckotzbauer/sbom-git-operator/integration-test-image:1.0.0")
		})
	})
})
