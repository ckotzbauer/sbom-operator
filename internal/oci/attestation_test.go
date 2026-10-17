package oci

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
)

func TestMapPredicateTypeToMediaType(t *testing.T) {
	tests := []struct {
		name          string
		predicateType string
		expected      types.MediaType
	}{
		{
			name:          "CycloneDX Predicate",
			predicateType: "https://cyclonedx.org/bom/v1.4",
			expected:      GetMediaType(CycloneDXJSONMediaType),
		},
		{
			name:          "SPDX Predicate",
			predicateType: "https://spdx.dev/Document",
			expected:      GetMediaType(SPDXJSONMediaType),
		},
		{
			name:          "Syft Predicate",
			predicateType: "https://syft.anchore.com/document/v1",
			expected:      GetMediaType(SyftMediaType),
		},
		{
			name:          "Unknown Predicate",
			predicateType: "https://unknown.org/schema",
			expected:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := mapPredicateTypeToMediaType(tt.predicateType)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestExtractFromDsseEnvelope(t *testing.T) {
	// Erstelle ein echtes In-Toto-Statement und verpacke es in einen DSSE-Envelope (Base64)
	stmt := inTotoStatement{
		PredicateType: "https://cyclonedx.org/bom/v1.4",
		Predicate:     json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.4"}`),
	}
	stmtBytes, _ := json.Marshal(stmt)
	encodedPayload := base64.StdEncoding.EncodeToString(stmtBytes)

	env := dsseEnvelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     encodedPayload,
	}
	envBytes, _ := json.Marshal(env)

	t.Run("Valid DSSE Envelope Extraction", func(t *testing.T) {
		sbom, mt, ok := extractFromDsseEnvelope(envBytes)
		assert.True(t, ok)
		assert.Equal(t, GetMediaType(CycloneDXJSONMediaType), mt)
		assert.Contains(t, sbom, "CycloneDX")
	})

	t.Run("Invalid Base64 Payload", func(t *testing.T) {
		badEnv := dsseEnvelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     "not-valid-base64!!!",
		}
		badBytes, _ := json.Marshal(badEnv)

		_, _, ok := extractFromDsseEnvelope(badBytes)
		assert.False(t, ok)
	})
}

func TestIsSupportedSbomMediaType(t *testing.T) {
	assert.True(t, isSupportedSbomMediaType(GetMediaType(CycloneDXJSONMediaType)))
	assert.True(t, isSupportedSbomMediaType(GetMediaType(SPDXJSONMediaType)))
	assert.True(t, isSupportedSbomMediaType(GetMediaType(SyftMediaType)))
	assert.False(t, isSupportedSbomMediaType("application/octet-stream"))
}
