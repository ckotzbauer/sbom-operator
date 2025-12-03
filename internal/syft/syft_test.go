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
	_ "modernc.org/sqlite" // Required for RPM database cataloging in Syft
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

func writeErroredSbom(t *testing.T, assertResult bool, data, name, format string) {
	if !assertResult {
		err := os.WriteFile("./fixtures/"+name+"_generated."+format, []byte(data), 0644)
		assert.NoError(t, err)
	}
}

func testJsonSbom(t *testing.T, name, imageID string) {
	format := "json"
	s := syft.New(format, map[string]string{}, "0.0.0").WithSyftVersion("v9.9.9")
	sbom, err := s.GetSBOM(&oci.RegistryImage{ImageID: imageID, PullSecrets: []*oci.KubeCreds{}})

	assert.NoError(t, err)

	var output syftJsonOutput
	err = json.Unmarshal([]byte(sbom), &output)
	assert.NoError(t, err)

	data, err := os.ReadFile("./fixtures/" + name + "." + format)
	assert.NoError(t, err)

	var fixture syftJsonOutput
	err = json.Unmarshal(data, &fixture)
	assert.NoError(t, err)

	assertResult := assert.JSONEq(t, marshalJson(t, output.Artifacts), marshalJson(t, fixture.Artifacts))
	writeErroredSbom(t, assertResult, sbom, name, format)
	assertResult = assert.JSONEq(t, marshalJson(t, output.ArtifactRelationships), marshalJson(t, fixture.ArtifactRelationships))
	writeErroredSbom(t, assertResult, sbom, name, format)
	assertResult = assert.JSONEq(t, marshalJson(t, output.Files), marshalJson(t, fixture.Files))
	writeErroredSbom(t, assertResult, sbom, name, format)
	assertResult = assert.JSONEq(t, marshalJson(t, output.Distro), marshalJson(t, fixture.Distro))
	writeErroredSbom(t, assertResult, sbom, name, format)
}

func testCyclonedxSbom(t *testing.T, name, imageID string) {
	format := "cyclonedx"
	s := syft.New(format, map[string]string{}, "0.0.0").WithSyftVersion("v9.9.9")
	sbom, err := s.GetSBOM(&oci.RegistryImage{ImageID: imageID, PullSecrets: []*oci.KubeCreds{}})
	assert.NoError(t, err)

	var output syftCyclonedxOutput
	err = xml.Unmarshal([]byte(sbom), &output)
	assert.NoError(t, err)

	data, err := os.ReadFile("./fixtures/" + name + "." + format)
	assert.NoError(t, err)

	var fixture syftCyclonedxOutput
	err = xml.Unmarshal(data, &fixture)
	assert.NoError(t, err)

	assertResult := assert.Equal(t, marshalCyclonedx(t, output.Components), marshalCyclonedx(t, fixture.Components))
	writeErroredSbom(t, assertResult, sbom, name, format)
}

func testSpdxSbom(t *testing.T, name, imageID string) {
	format := "spdxjson"
	s := syft.New(format, map[string]string{}, "0.0.0").WithSyftVersion("v9.9.9")
	sbom, err := s.GetSBOM(&oci.RegistryImage{ImageID: imageID, PullSecrets: []*oci.KubeCreds{}})
	assert.NoError(t, err)

	var output syftSpdxOutput
	err = json.Unmarshal([]byte(sbom), &output)
	assert.NoError(t, err)

	data, err := os.ReadFile("./fixtures/" + name + "." + format)
	assert.NoError(t, err)

	var fixture syftSpdxOutput
	err = json.Unmarshal(data, &fixture)
	assert.NoError(t, err)

	assertResult := assert.JSONEq(t, marshalJson(t, output.Packages), marshalJson(t, fixture.Packages))
	writeErroredSbom(t, assertResult, sbom, name, format)
	assertResult = assert.JSONEq(t, marshalJson(t, output.Relationships), marshalJson(t, fixture.Relationships))
	writeErroredSbom(t, assertResult, sbom, name, format)
	assertResult = assert.JSONEq(t, marshalJson(t, output.Files), marshalJson(t, fixture.Files))
	writeErroredSbom(t, assertResult, sbom, name, format)
	assertResult = assert.Equal(t, output.SpdxVersion, fixture.SpdxVersion)
	writeErroredSbom(t, assertResult, sbom, name, format)
}

// test for analysing an image completely without pullSecret
func testCyclonedxSbomWithoutPullSecrets(t *testing.T, name, imageID string) {
	format := "cyclonedx"
	s := syft.New(format, map[string]string{}, "0.0.0").WithSyftVersion("v9.9.9")
	sbom, err := s.GetSBOM(&oci.RegistryImage{ImageID: imageID, PullSecrets: []*oci.KubeCreds{}})
	assert.NoError(t, err)

	var output syftCyclonedxOutput
	err = xml.Unmarshal([]byte(sbom), &output)
	assert.NoError(t, err)

	data, err := os.ReadFile("./fixtures/" + name + "." + format)
	assert.NoError(t, err)

	var fixture syftCyclonedxOutput
	err = xml.Unmarshal(data, &fixture)
	assert.NoError(t, err)

	assertResult := assert.Equal(t, marshalCyclonedx(t, output.Components), marshalCyclonedx(t, fixture.Components))
	writeErroredSbom(t, assertResult, sbom, name, format)
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
			image:  "fedora",
			digest: "fedora@sha256:89ed3ea10de7194c36524a290665960ddd4dae876a40beeadde2a9b4a0276681",
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
		{
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
		},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("%s-%s", v.image, v.format), func(t *testing.T) {
			// nolint QF1003
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
