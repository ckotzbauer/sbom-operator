package syft_test

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"testing"

	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/stretchr/testify/assert"
)

type simpleTestData struct {
	input    string
	expected string
}

type mapTestData struct {
	input    string
	expected string
	dataMap  map[string]string
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
	s := syft.New(format, map[string]string{}).WithVersion("v9.9.9")
	sbom, err := s.ExecuteSyft(&oci.RegistryImage{ImageID: imageID, PullSecrets: []*oci.KubeCreds{}})

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
	s := syft.New(format, map[string]string{}).WithVersion("v9.9.9")
	sbom, err := s.ExecuteSyft(&oci.RegistryImage{ImageID: imageID, PullSecrets: []*oci.KubeCreds{}})
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
	s := syft.New(format, map[string]string{}).WithVersion("v9.9.9")
	sbom, err := s.ExecuteSyft(&oci.RegistryImage{ImageID: imageID, PullSecrets: []*oci.KubeCreds{}})
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

// test for analysing an image completely without pullSecret
func testCyclonedxSbomWithoutPullSecrets(t *testing.T, name, imageID string) {
	format := "cyclonedx"
	s := syft.New(format, map[string]string{}).WithVersion("v9.9.9")
	sbom, err := s.ExecuteSyft(&oci.RegistryImage{ImageID: imageID, PullSecrets: []*oci.KubeCreds{}})
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

func TestSyft(t *testing.T) {
	tests := []testData{
		{
			image:  "alpine",
			digest: "alpine@sha256:36a03c95c2f0c83775d500101869054b927143a8320728f0e135dc151cb8ae61",
			format: "json",
		},
		{
			image:  "redis",
			digest: "redis@sha256:fdaa0102e0c66802845aa5c961cb89a091a188056811802383660cd9e10889da",
			format: "json",
		},
		{
			image:  "node",
			digest: "node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec",
			format: "json",
		},
		{
			image:  "alpine",
			digest: "alpine@sha256:36a03c95c2f0c83775d500101869054b927143a8320728f0e135dc151cb8ae61",
			format: "cyclonedx",
		},
		{
			image:  "redis",
			digest: "redis@sha256:fdaa0102e0c66802845aa5c961cb89a091a188056811802383660cd9e10889da",
			format: "cyclonedx",
		},
		{
			image:  "node",
			digest: "node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec",
			format: "cyclonedx",
		},
		/*{
			image:  "alpine",
			digest: "alpine@sha256:36a03c95c2f0c83775d500101869054b927143a8320728f0e135dc151cb8ae61",
			format: "spdxjson",
		},
		{
			image:  "redis",
			digest: "redis@sha256:fdaa0102e0c66802845aa5c961cb89a091a188056811802383660cd9e10889da",
			format: "spdxjson",
		},
		{
			image:  "node",
			digest: "node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec",
			format: "spdxjson",
		},*/
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("%s-%s", v.image, v.format), func(t *testing.T) {
			if v.format == "json" {
				testJsonSbom(t, v.image, v.digest)
			} else if v.format == "cyclonedx" {
				testCyclonedxSbom(t, v.image, v.digest)
				testCyclonedxSbomWithoutPullSecrets(t, v.image, v.digest)
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

func TestApplyProxyRegistry(t *testing.T) {
	tests := []mapTestData{
		{
			input:    "alpine:3.17",
			expected: "alpine:3.17",
			dataMap:  make(map[string]string),
		},
		{
			input:    "docker.io/alpine:3.17",
			expected: "ghcr.io/alpine:3.17",
			dataMap:  map[string]string{"docker.io": "ghcr.io"},
		},
		{
			input:    "alpine:3.17",
			expected: "ghcr.io/alpine:3.17",
			dataMap:  map[string]string{"docker.io": "ghcr.io"},
		},
		{
			input:    "alpine:3.17",
			expected: "alpine:3.17",
			dataMap:  map[string]string{"ghcr.io": "docker.io"},
		},
		{
			input:    "alpine:3.17",
			expected: "my.registry.com:5000/alpine:3.17",
			dataMap:  map[string]string{"docker.io": "my.registry.com:5000"},
		},
		{
			input:    "my.registry.com:5000/alpine:3.17",
			expected: "ghcr.io/alpine:3.17",
			dataMap:  map[string]string{"my.registry.com:5000": "ghcr.io"},
		},
	}

	for _, v := range tests {
		t.Run(v.input, func(t *testing.T) {
			s := syft.New("json", v.dataMap)
			img := &oci.RegistryImage{ImageID: v.input, Image: v.input}
			err := s.ApplyProxyRegistry(img)
			assert.NoError(t, err)
			assert.Equal(t, v.expected, img.ImageID)
		})
	}
}
