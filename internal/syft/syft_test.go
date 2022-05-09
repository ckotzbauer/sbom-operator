package syft_test

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"testing"

	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/stretchr/testify/assert"
)

type simpleTestData struct {
	input    string
	expected string
}

type testData struct {
	image  string
	digest string
	format string
}

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

func marshalJson(t *testing.T, x interface{}) string {
	s, err := json.Marshal(x)
	assert.NoError(t, err)
	return string(s)
}

func marshalCyclonedx(t *testing.T, x interface{}) string {
	s, err := xml.Marshal(x)
	assert.NoError(t, err)
	return string(s)
}

func testJsonSbom(t *testing.T, name, imageID string) {
	format := "json"
	s := syft.New(format).WithVersion("v9.9.9")
	sbom, err := s.ExecuteSyft(kubernetes.ContainerImage{ImageID: imageID, PullSecrets: []kubernetes.KubeCreds{{SecretName: "syft-test-creds", SecretCredsData: []byte{}}}})

	assert.NoError(t, err)

	var output syftJsonOutput
	err = json.Unmarshal([]byte(sbom), &output)
	assert.NoError(t, err)

	data, err := os.ReadFile("./fixtures/" + name + "." + format)
	assert.NoError(t, err)

	var fixture syftJsonOutput
	err = json.Unmarshal(data, &fixture)
	assert.NoError(t, err)

	assert.JSONEq(t, marshalJson(t, output.Artifacts), marshalJson(t, fixture.Artifacts))
	assert.JSONEq(t, marshalJson(t, output.ArtifactRelationships), marshalJson(t, fixture.ArtifactRelationships))
	assert.JSONEq(t, marshalJson(t, output.Files), marshalJson(t, fixture.Files))
	assert.JSONEq(t, marshalJson(t, output.Distro), marshalJson(t, fixture.Distro))
}

func testCyclonedxSbom(t *testing.T, name, imageID string) {
	format := "cyclonedx"
	s := syft.New(format).WithVersion("v9.9.9")
	sbom, err := s.ExecuteSyft(kubernetes.ContainerImage{ImageID: imageID, PullSecrets: []kubernetes.KubeCreds{{SecretName: "syft-test-creds", SecretCredsData: []byte{}}}})
	assert.NoError(t, err)

	var output syftCyclonedxOutput
	err = xml.Unmarshal([]byte(sbom), &output)
	assert.NoError(t, err)

	data, err := os.ReadFile("./fixtures/" + name + "." + format)
	assert.NoError(t, err)

	var fixture syftCyclonedxOutput
	err = xml.Unmarshal(data, &fixture)
	assert.NoError(t, err)

	assert.Equal(t, marshalCyclonedx(t, output.Components), marshalCyclonedx(t, fixture.Components))
}

func testSpdxSbom(t *testing.T, name, imageID string) {
	format := "spdxjson"
	s := syft.New(format).WithVersion("v9.9.9")
	sbom, err := s.ExecuteSyft(kubernetes.ContainerImage{ImageID: imageID, PullSecrets: []kubernetes.KubeCreds{{SecretName: "syft-test-creds", SecretCredsData: []byte{}}}})
	assert.NoError(t, err)

	var output syftSpdxOutput
	err = json.Unmarshal([]byte(sbom), &output)
	assert.NoError(t, err)

	data, err := os.ReadFile("./fixtures/" + name + "." + format)
	assert.NoError(t, err)

	var fixture syftSpdxOutput
	err = json.Unmarshal(data, &fixture)
	assert.NoError(t, err)

	assert.JSONEq(t, marshalJson(t, output.Packages), marshalJson(t, fixture.Packages))
	assert.JSONEq(t, marshalJson(t, output.Relationships), marshalJson(t, fixture.Relationships))
	assert.JSONEq(t, marshalJson(t, output.Files), marshalJson(t, fixture.Files))
	assert.Equal(t, output.SpdxVersion, fixture.SpdxVersion)
}

func TestSyft(t *testing.T) {
	tests := []testData{
		{
			image:  "alpine",
			digest: "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300",
			format: "json",
		},
		{
			image:  "nginx",
			digest: "nginx@sha256:2834dc507516af02784808c5f48b7cbe38b8ed5d0f4837f16e78d00deb7e7767",
			format: "json",
		},
		{
			image:  "node",
			digest: "node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec",
			format: "json",
		},
		{
			image:  "alpine",
			digest: "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300",
			format: "cyclonedx",
		},
		{
			image:  "nginx",
			digest: "nginx@sha256:2834dc507516af02784808c5f48b7cbe38b8ed5d0f4837f16e78d00deb7e7767",
			format: "cyclonedx",
		},
		{
			image:  "node",
			digest: "node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec",
			format: "cyclonedx",
		},
		{
			image:  "alpine",
			digest: "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300",
			format: "spdxjson",
		},
		{
			image:  "nginx",
			digest: "nginx@sha256:2834dc507516af02784808c5f48b7cbe38b8ed5d0f4837f16e78d00deb7e7767",
			format: "spdxjson",
		},
		{
			image:  "node",
			digest: "node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec",
			format: "spdxjson",
		},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("%s-%s", v.image, v.format), func(t *testing.T) {
			if v.format == "json" {
				testJsonSbom(t, v.image, v.digest)
			} else if v.format == "cyclonedx" {
				testCyclonedxSbom(t, v.image, v.digest)
			} else if v.format == "spdxjson" {
				testSpdxSbom(t, v.image, v.digest)
			}
		})
	}
}

func TestGetFileName(t *testing.T) {
	tests := []simpleTestData{
		{
			input:    "",
			expected: "sbom.json",
		},
		{
			input:    "json",
			expected: "sbom.json",
		},
		{
			input:    "text",
			expected: "sbom.txt",
		},
		{
			input:    "cyclonedx",
			expected: "sbom.xml",
		},
		{
			input:    "cyclonedxjson",
			expected: "sbom.json",
		},
		{
			input:    "spdx",
			expected: "sbom.spdx",
		},
		{
			input:    "spdxjson",
			expected: "sbom.json",
		},
		{
			input:    "table",
			expected: "sbom.txt",
		},
	}

	for _, v := range tests {
		t.Run(v.input, func(t *testing.T) {
			out := syft.GetFileName(v.input)
			assert.Equal(t, v.expected, out)
		})
	}
}
