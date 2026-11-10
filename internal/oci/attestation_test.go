package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	ggcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
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

func TestParseAttestationPayload_InTotoAndHybridFormats(t *testing.T) {
	cdxPredicate := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"my-lib","version":"1.0.0"}]}`
	spdxPredicate := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"alpine-sbom"}`

	unsignedInTotoCdx := `{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://cyclonedx.org/bom","predicate":` + cdxPredicate + `}`
	unsignedInTotoSpdx := `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","predicate":` + spdxPredicate + `}`
	unsignedInTotoSlsa := `{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{}}}`

	dsseWrappedCdxBytes, err := json.Marshal(map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString([]byte(unsignedInTotoCdx)),
		"signatures":  []map[string]string{{"sig": "dGVzdC1zaWc="}},
	})
	require.NoError(t, err)

	tests := []struct {
		name              string
		layerMediaType    types.MediaType
		payload           []byte
		annotations       map[string]string
		expectedCount     int
		expectedScope     string
		expectedMediaType types.MediaType
		expectedContent   string
	}{
		{
			name:              "Unsigned in-toto CycloneDX statement with application scope",
			layerMediaType:    MediaTypeInToto,
			payload:           []byte(unsignedInTotoCdx),
			annotations:       map[string]string{"dev.sigstore.sbom.scope": "application"},
			expectedCount:     1,
			expectedScope:     "application",
			expectedMediaType: types.MediaType("application/vnd.cyclonedx+json"),
			expectedContent:   cdxPredicate,
		},
		{
			name:              "Unsigned in-toto SPDX statement from Docker BuildKit (default scope all)",
			layerMediaType:    MediaTypeInToto,
			payload:           []byte(unsignedInTotoSpdx),
			annotations:       map[string]string{"in-toto.io/predicate-type": "https://spdx.dev/Document"},
			expectedCount:     1,
			expectedScope:     "all",
			expectedMediaType: types.MediaType("application/spdx+json"),
			expectedContent:   spdxPredicate,
		},
		{
			name:              "Signed DSSE envelope inside application/vnd.in-toto+json layer",
			layerMediaType:    MediaTypeInToto,
			payload:           dsseWrappedCdxBytes,
			annotations:       map[string]string{"dev.sigstore.sbom.scope": "container"},
			expectedCount:     1,
			expectedScope:     "container",
			expectedMediaType: types.MediaType("application/vnd.cyclonedx+json"),
			expectedContent:   cdxPredicate,
		},
		{
			name:              "Hybrid in-toto statement attached with application/vnd.cyclonedx+json mediaType",
			layerMediaType:    types.MediaType("application/vnd.cyclonedx+json"),
			payload:           []byte(unsignedInTotoCdx),
			annotations:       map[string]string{"dev.sigstore.sbom.scope": "application"},
			expectedCount:     1,
			expectedScope:     "application",
			expectedMediaType: types.MediaType("application/vnd.cyclonedx+json"),
			expectedContent:   cdxPredicate,
		},
		{
			name:           "Non-SBOM in-toto statement (SLSA provenance) is ignored",
			layerMediaType: MediaTypeInToto,
			payload:        []byte(unsignedInTotoSlsa),
			annotations:    map[string]string{"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"},
			expectedCount:  0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parseAttestationPayload(tc.layerMediaType, tc.payload, tc.annotations)
			require.Len(t, res, tc.expectedCount)
			if tc.expectedCount > 0 {
				assert.Equal(t, tc.expectedScope, res[0].Scope)
				assert.Equal(t, tc.expectedMediaType, res[0].MediaType)
				assert.JSONEq(t, tc.expectedContent, res[0].Sbom)
			}
		})
	}
}

func TestFetchSbomAttestations_BuildxImageIndex(t *testing.T) {
	// Start an in-memory OCI registry
	srv := httptest.NewServer(registry.New())
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	internal.OperatorConfig = &internal.Config{
		InsecureHttpRegistry: true,
	}

	// 1. Create the base linux/amd64 container image
	baseLayer := static.NewLayer([]byte("binary-layer-content"), types.OCILayer)
	amd64Img, err := mutate.AppendLayers(empty.Image, baseLayer)
	require.NoError(t, err)
	amd64Img = mutate.MediaType(amd64Img, types.OCIManifestSchema1)
	amd64Digest, err := amd64Img.Digest()
	require.NoError(t, err)

	// 2. Create the Docker BuildKit attestation image containing an SPDX SBOM layer and a SLSA provenance layer
	spdxContent := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"buildx-sbom"}`
	inTotoSpdxStatement := `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","predicate":` + spdxContent + `}`
	inTotoSlsaStatement := `{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","predicate":{"builder":{"id":"buildkit"}}}`

	sbomLayer := static.NewLayer([]byte(inTotoSpdxStatement), MediaTypeInToto)
	slsaLayer := static.NewLayer([]byte(inTotoSlsaStatement), MediaTypeInToto)

	attImg := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	attImg, err = mutate.Append(
		attImg,
		mutate.Addendum{
			Layer:     sbomLayer,
			MediaType: MediaTypeInToto,
			Annotations: map[string]string{
				"in-toto.io/predicate-type": "https://spdx.dev/Document",
			},
		},
		mutate.Addendum{
			Layer:     slsaLayer,
			MediaType: MediaTypeInToto,
			Annotations: map[string]string{
				"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1",
			},
		},
	)
	require.NoError(t, err)

	// 3. Assemble the OCI Image Index (matching Docker Buildx layout)
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	idx = mutate.AppendManifests(
		idx,
		mutate.IndexAddendum{
			Add: amd64Img,
			Descriptor: v1.Descriptor{
				MediaType: types.OCIManifestSchema1,
				Platform:  &v1.Platform{Architecture: "amd64", OS: "linux"},
			},
		},
		mutate.IndexAddendum{
			Add: attImg,
			Descriptor: v1.Descriptor{
				MediaType: types.OCIManifestSchema1,
				Platform:  &v1.Platform{Architecture: "unknown", OS: "unknown"},
				Annotations: map[string]string{
					"vnd.docker.reference.type":   "attestation-manifest",
					"vnd.docker.reference.digest": amd64Digest.String(),
				},
			},
		},
	)

	indexDigest, err := idx.Digest()
	require.NoError(t, err)

	repoRefStr := host + "/test/buildx-app@" + indexDigest.String()
	ref, err := name.ParseReference(repoRefStr, name.Insecure)
	require.NoError(t, err)

	// Push the index (and its child manifests/blobs) to the in-memory registry
	err = ggcrremote.WriteIndex(ref, idx)
	require.NoError(t, err)

	// 4. Execute FetchSbomAttestations against the pushed Image Index
	containerImg := &liboci.RegistryImage{
		Image:   host + "/test/buildx-app:1.0.0",
		ImageID: repoRefStr,
	}

	attestations, err := FetchSbomAttestations(context.Background(), containerImg, nil)
	require.NoError(t, err)
	require.Len(t, attestations, 1, "Expected exactly 1 SBOM attestation (SLSA provenance must be filtered out)")

	assert.Equal(t, "all", attestations[0].Scope)
	assert.Equal(t, types.MediaType("application/spdx+json"), attestations[0].MediaType)
	assert.JSONEq(t, spdxContent, attestations[0].Sbom)
}
