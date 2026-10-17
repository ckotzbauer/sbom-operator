package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
)

const (
	ScopeAnnotationKey    string          = "sbom.scope"
	MediaTypeDsseEnvelope types.MediaType = "application/vnd.dsse.envelope.v1+json"
)

// dsseEnvelope represents the outer Dead Simple Signing Envelope stored by cosign attest.
type dsseEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
}

// inTotoStatement represents the decoded in-toto v0.1 / v1 statement inside the DSSE payload.
type inTotoStatement struct {
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// AttestationSbom holds an extracted SBOM string and its OCI layer annotations.
type AttestationSbom struct {
	Scope     string
	Sbom      string
	MediaType types.MediaType
}

// FetchSbomAttestations pulls OCI attestations for a given image reference
// and extracts all supported SBOMs (via direct MediaType or DSSE In-Toto predicateType).
func FetchSbomAttestations(ctx context.Context, img *liboci.RegistryImage, proxyRegistryMap map[string]string) ([]AttestationSbom, error) {
	oriImage := img.Image
	oriImageID := img.ImageID

	if err := kubernetes.ApplyProxyRegistry(img, true, proxyRegistryMap); err != nil {
		return nil, err
	}
	defer func() {
		img.Image = oriImage
		img.ImageID = oriImageID
	}()

	credentials := ResolveCredentials(img, proxyRegistryMap)

	ref, err := name.ParseReference(img.ImageID)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference %s: %w", img.ImageID, err)
	}

	regOpts := []ggcrremote.Option{
		ggcrremote.WithContext(ctx),
		RemoteAuthOption(credentials),
	}

	se, err := ociremote.SignedEntity(ref, ociremote.WithRemoteOptions(regOpts...))
	if err != nil {
		return nil, fmt.Errorf("resolving signed entity for %s: %w", img.ImageID, err)
	}

	atts, err := se.Attestations()
	if err != nil {
		return nil, fmt.Errorf("fetching attestations for %s: %w", img.ImageID, err)
	}

	sigs, err := atts.Get()
	if err != nil {
		return nil, fmt.Errorf("loading attestation signatures for %s: %w", img.ImageID, err)
	}

	var result []AttestationSbom
	for _, sig := range sigs {
		anns, _ := sig.Annotations()
		scope := ""
		if anns != nil {
			scope = strings.TrimSpace(anns[ScopeAnnotationKey])
		}
		layerMediaType, err := sig.MediaType()
		if err != nil {
			continue
		}

		rawPayload, err := sig.Payload()
		if err != nil || len(rawPayload) == 0 {
			continue
		}

		if isSupportedSbomMediaType(layerMediaType) {
			result = append(result, AttestationSbom{
				Scope:     scope,
				MediaType: layerMediaType,
				Sbom:      string(rawPayload),
			})
			continue
		}

		if layerMediaType == MediaTypeDsseEnvelope {
			if sbomContent, detectedMediaType, ok := extractFromDsseEnvelope(rawPayload); ok {
				result = append(result, AttestationSbom{
					Scope:     scope,
					MediaType: detectedMediaType,
					Sbom:      sbomContent,
				})
			}
		}
	}

	return result, nil
}

func isSupportedSbomMediaType(mt types.MediaType) bool {
	switch mt {
	case GetMediaType(CycloneDXJSONMediaType), GetMediaType(CycloneDXXMLMediaType), GetMediaType(SPDXJSONMediaType), GetMediaType(SPDXMediaType), GetMediaType(SyftMediaType):
		return true
	default:
		return false
	}
}

func extractFromDsseEnvelope(rawEnvelope []byte) (string, types.MediaType, bool) {
	var env dsseEnvelope
	if err := json.Unmarshal(rawEnvelope, &env); err != nil || env.Payload == "" {
		return "", "", false
	}
	decodedStatement, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return "", "", false
	}
	var stmt inTotoStatement
	if err := json.Unmarshal(decodedStatement, &stmt); err != nil || len(stmt.Predicate) == 0 {
		return "", "", false
	}
	mt := mapPredicateTypeToMediaType(stmt.PredicateType)
	if mt == "" {
		return "", "", false
	}
	return string(stmt.Predicate), mt, true
}

func mapPredicateTypeToMediaType(predicateType string) types.MediaType {
	switch {
	case strings.HasPrefix(predicateType, "https://cyclonedx.org/"):
		return GetMediaType(CycloneDXJSONMediaType)
	case strings.HasPrefix(predicateType, "https://spdx.dev/"):
		return GetMediaType(SPDXJSONMediaType)
	case strings.HasPrefix(predicateType, "https://syft.anchore.com/"):
		return GetMediaType(SyftMediaType)
	default:
		return ""
	}
}
