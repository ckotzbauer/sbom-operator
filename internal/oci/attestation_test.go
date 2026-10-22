package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		sbom, mt, err := extractFromDsseEnvelope(envBytes)
		assert.NoError(t, err)
		assert.Equal(t, GetMediaType(CycloneDXJSONMediaType), mt)
		assert.Contains(t, sbom, "CycloneDX")
	})

	t.Run("Invalid Base64 Payload", func(t *testing.T) {
		badEnv := dsseEnvelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     "not-valid-base64!!!",
		}
		badBytes, _ := json.Marshal(badEnv)

		_, _, err := extractFromDsseEnvelope(badBytes)
		assert.Error(t, err)
	})
}

func TestIsSupportedSbomMediaType(t *testing.T) {
	assert.True(t, isSupportedSbomMediaType(GetMediaType(CycloneDXJSONMediaType)))
	assert.True(t, isSupportedSbomMediaType(GetMediaType(SPDXJSONMediaType)))
	assert.True(t, isSupportedSbomMediaType(GetMediaType(SyftMediaType)))
	assert.False(t, isSupportedSbomMediaType("application/octet-stream"))
}

func TestFetchSbomAttestations_RestoresImageFieldsOnError(t *testing.T) {
	originalImage := "docker.io/library/alpine:3.18"
	// Invalid reference characters to trigger ParseReference error after ApplyProxyRegistry
	originalImageID := "docker.io/library/alpine:invalid::reference"

	img := &liboci.RegistryImage{
		Image:   originalImage,
		ImageID: originalImageID,
	}

	proxyMap := map[string]string{
		"docker.io": "my-proxy.local:5000",
	}

	// Execute function (expected to fail at ParseReference)
	res, err := FetchSbomAttestations(context.Background(), img, proxyMap)
	require.Error(t, err)
	assert.Nil(t, res)

	// Verify that the defer block restored the original Image and ImageID fields
	assert.Equal(t, originalImage, img.Image, "Expected original Image field to be restored by defer")
	assert.Equal(t, originalImageID, img.ImageID, "Expected original ImageID field to be restored by defer")
}

func TestParseAttestationPayload_DirectAndDSSE(t *testing.T) {
	sampleCycloneDX := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`

	// Helper to build a DSSE envelope with a base64-encoded in-toto statement
	buildDSSEPayload := func(predicateType string, sbomContent string) []byte {
		inTotoStatement := map[string]interface{}{
			"_type":         "https://in-toto.io/Statement/v0.1",
			"predicateType": predicateType,
			"predicate":     json.RawMessage(sbomContent),
		}
		stmtBytes, _ := json.Marshal(inTotoStatement)
		b64Stmt := base64.StdEncoding.EncodeToString(stmtBytes)

		dsse := map[string]interface{}{
			"payloadType": "application/vnd.in-toto+json",
			"payload":     b64Stmt,
		}
		dsseBytes, _ := json.Marshal(dsse)
		return dsseBytes
	}

	tests := []struct {
		name              string
		mediaType         types.MediaType
		rawPayload        []byte
		annotations       map[string]string
		expectedCount     int
		expectedMediaType types.MediaType
		expectedScope     string
	}{
		{
			name:              "Direct CycloneDX JSON attachment (cosign attach sbom)",
			mediaType:         CycloneDXJSONMediaType,
			rawPayload:        []byte(sampleCycloneDX),
			annotations:       nil,
			expectedCount:     1,
			expectedMediaType: CycloneDXJSONMediaType,
			expectedScope:     ScopeAll,
		},
		{
			name:              "DSSE Envelope with CycloneDX predicate",
			mediaType:         "application/vnd.dsse.envelope.v1+json",
			rawPayload:        buildDSSEPayload("https://cyclonedx.org/bom", sampleCycloneDX),
			annotations:       nil,
			expectedCount:     1,
			expectedMediaType: CycloneDXJSONMediaType,
			expectedScope:     ScopeAll,
		},
		{
			name:          "Corrupted / unsupported payload is ignored gracefully",
			mediaType:     "application/octet-stream",
			rawPayload:    []byte("not-a-valid-json-or-sbom"),
			annotations:   nil,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := parseAttestationPayload(tt.mediaType, tt.rawPayload, tt.annotations)
			require.Len(t, results, tt.expectedCount)

			if tt.expectedCount > 0 {
				assert.Equal(t, tt.expectedMediaType, results[0].MediaType)
				assert.Equal(t, tt.expectedScope, results[0].Scope)
				assert.NotEmpty(t, results[0].Sbom)
			}
		})
	}
}
