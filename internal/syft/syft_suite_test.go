package syft_test

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"testing"

	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type syftJsonOutput struct {
	Artifacts             interface{}
	ArtifactRelationships interface{}
	Files                 interface{}
	Distro                interface{}
}

type syftCyclonedxOutput struct {
	Components syftCyclonedxComponents `xml:"components"`
}

type syftCyclonedxComponents struct {
	Components string `xml:",innerxml"`
}

type syftSpdxOutput struct {
	SpdxVersion   string
	Packages      interface{}
	Files         interface{}
	Relationships interface{}
}

func marshalJson(x interface{}) []byte {
	s, err := json.Marshal(x)
	Expect(err).NotTo(HaveOccurred())
	return s
}

func marshalCyclonedx(x interface{}) []byte {
	s, err := xml.Marshal(x)
	Expect(err).NotTo(HaveOccurred())
	return s
}

func testJsonSbom(name, imageID string) {
	format := "json"
	s := syft.New(format).WithVersion("v9.9.9")
	sbom, err := s.ExecuteSyft(internal.ContainerImage{ImageID: imageID, Auth: []byte{}})
	Expect(err).NotTo(HaveOccurred())

	var output syftJsonOutput
	err = json.Unmarshal([]byte(sbom), &output)
	Expect(err).NotTo(HaveOccurred())

	data, err := os.ReadFile("./fixtures/" + name + "." + format)
	Expect(err).NotTo(HaveOccurred())

	var fixture syftJsonOutput
	err = json.Unmarshal(data, &fixture)
	Expect(err).NotTo(HaveOccurred())

	Expect(marshalJson(output.Artifacts)).To(MatchJSON(marshalJson(fixture.Artifacts)))
	Expect(marshalJson(output.ArtifactRelationships)).To(MatchJSON(marshalJson(fixture.ArtifactRelationships)))
	Expect(marshalJson(output.Files)).To(MatchJSON(marshalJson(fixture.Files)))
	Expect(marshalJson(output.Distro)).To(MatchJSON(marshalJson(fixture.Distro)))
}

func testCyclonedxSbom(name, imageID string) {
	format := "cyclonedx"
	s := syft.New(format).WithVersion("v9.9.9")
	sbom, err := s.ExecuteSyft(internal.ContainerImage{ImageID: imageID, Auth: []byte{}})
	Expect(err).NotTo(HaveOccurred())

	var output syftCyclonedxOutput
	err = xml.Unmarshal([]byte(sbom), &output)
	Expect(err).NotTo(HaveOccurred())

	data, err := os.ReadFile("./fixtures/" + name + "." + format)
	Expect(err).NotTo(HaveOccurred())

	var fixture syftCyclonedxOutput
	err = xml.Unmarshal(data, &fixture)
	Expect(err).NotTo(HaveOccurred())

	Expect(marshalCyclonedx(output.Components)).To(MatchXML(marshalCyclonedx(fixture.Components)))
}

func testSpdxSbom(name, imageID string) {
	format := "spdxjson"
	s := syft.New(format).WithVersion("v9.9.9")
	sbom, err := s.ExecuteSyft(internal.ContainerImage{ImageID: imageID, Auth: []byte{}})
	Expect(err).NotTo(HaveOccurred())

	var output syftSpdxOutput
	err = json.Unmarshal([]byte(sbom), &output)
	Expect(err).NotTo(HaveOccurred())

	data, err := os.ReadFile("./fixtures/" + name + "." + format)
	Expect(err).NotTo(HaveOccurred())

	var fixture syftSpdxOutput
	err = json.Unmarshal(data, &fixture)
	Expect(err).NotTo(HaveOccurred())

	Expect(marshalJson(output.Packages)).To(MatchJSON(marshalJson(fixture.Packages)))
	Expect(marshalJson(output.Relationships)).To(MatchJSON(marshalJson(fixture.Relationships)))
	Expect(marshalJson(output.Files)).To(MatchJSON(marshalJson(fixture.Files)))
	Expect(output.SpdxVersion).To(Equal(fixture.SpdxVersion))
}

func TestSyft(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Syft Suite")
}

var _ = Describe("Syft", func() {
	Describe("Catalogues correctly as JSON", func() {
		It("alpine", func() {
			testJsonSbom("alpine", "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300")
		})

		It("nginx", func() {
			testJsonSbom("nginx", "nginx@sha256:2834dc507516af02784808c5f48b7cbe38b8ed5d0f4837f16e78d00deb7e7767")
		})

		It("node", func() {
			testJsonSbom("node", "node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec")
		})
	})

	Describe("Catalogues correctly as Cyclonedx", func() {
		It("alpine", func() {
			testCyclonedxSbom("alpine", "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300")
		})

		It("nginx", func() {
			testCyclonedxSbom("nginx", "nginx@sha256:2834dc507516af02784808c5f48b7cbe38b8ed5d0f4837f16e78d00deb7e7767")
		})

		It("node", func() {
			testCyclonedxSbom("node", "node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec")
		})
	})

	Describe("Catalogues correctly as spdx-json", func() {
		It("alpine", func() {
			testSpdxSbom("alpine", "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300")
		})

		It("nginx", func() {
			testSpdxSbom("nginx", "nginx@sha256:2834dc507516af02784808c5f48b7cbe38b8ed5d0f4837f16e78d00deb7e7767")
		})

		It("node", func() {
			testSpdxSbom("node", "node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec")
		})
	})
})
