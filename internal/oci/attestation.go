package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ggcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sirupsen/logrus"
)

const (
	ScopeAnnotationKey    string          = "dev.sigstore.sbom.scope"
	ScopeAll              string          = "all"
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

type sigstoreBundle struct {
	MediaType    string          `json:"mediaType"`
	DsseEnvelope json.RawMessage `json:"dsseEnvelope"`
}

// FetchSbomAttestations pulls OCI attestations for a given image reference
// and extracts all supported SBOMs (via direct MediaType or DSSE In-Toto predicateType).
func FetchSbomAttestations(ctx context.Context, img *liboci.RegistryImage, proxyRegistryMap map[string]string) ([]*AttestationSbom, error) {
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

	var refOpts []name.Option
	if internal.OperatorConfig.InsecureHttpRegistry {
		refOpts = append(refOpts, name.Insecure)
	}
	ref, err := name.ParseReference(img.ImageID, refOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference %s: %w", img.ImageID, err)
	}

	regOpts := []ggcrremote.Option{
		ggcrremote.WithContext(ctx),
		RemoteAuthOption(credentials),
	}
	ociOpts := ociremote.WithRemoteOptions(regOpts...)

	var result []*AttestationSbom

	if se, err := ociremote.SignedEntity(ref, ociOpts); err == nil {
		// 1. Cosign SBOM Attachment (sha256-<digest>.sbom via "cosign attach sbom")
		if f, err := se.Attachment("sbom"); err == nil && f != nil {
			if mt, err := f.MediaType(); err == nil {
				if rawPayload, err := f.Payload(); err == nil && len(rawPayload) > 0 {
					result = append(result, parseAttestationPayload(mt, rawPayload, nil)...)
				}
			}
		}

		// 2. Cosign Attestations (sha256-<digest>.att via "cosign attest")
		if atts, err := se.Attestations(); err == nil {
			if sigs, err := atts.Get(); err == nil {
				for _, sig := range sigs {
					layerMediaType, err := sig.MediaType()
					if err != nil {
						continue
					}
					rawPayload, err := sig.Payload()
					if err != nil || len(rawPayload) == 0 {
						continue
					}
					anns, _ := sig.Annotations()
					result = append(result, parseAttestationPayload(layerMediaType, rawPayload, anns)...)
				}
			}
		}
	} else {
		logrus.WithError(err).Debugf("No signed entity found for image: '%s'", img.ImageID)
	}

	// 3. OCI 1.1 Referrers (Cosign v3 Bundles & ORAS Attached SBOMs)
	if digestRef, err := ociremote.ResolveDigest(ref, ociOpts); err == nil {
		if indexManifest, err := ociremote.Referrers(digestRef, "", ociOpts); err == nil && indexManifest != nil {
			for _, desc := range indexManifest.Manifests {
				referrerRef := digestRef.Context().Digest(desc.Digest.String())
				referrerImg, err := ggcrremote.Image(referrerRef, regOpts...)
				if err != nil {
					logrus.WithError(err).Debugf("Can't get referrer (MediaType: '%s', Size: '%d') for base image: '%s'", desc.MediaType, desc.Size, img.Image)
					continue
				}
				result = append(result, extractSbomsFromImageLayers(referrerImg, desc.Annotations)...)
			}
		} else {
			logrus.WithError(err).Debugf("Can't find referrers for image: '%s'", img.Image)
		}
	} else {
		logrus.WithError(err).Debugf("Can't resolve digest for image: '%s'", img.Image)
	}

	return result, err
}

func isSupportedSbomMediaType(mt types.MediaType) bool {
	switch mt {
	case CycloneDXJSONMediaType, CycloneDXXMLMediaType, SPDXJSONMediaType, SPDXMediaType, SyftMediaType:
		return true
	default:
		return false
	}
}

func extractFromDsseEnvelope(rawEnvelope []byte) (string, types.MediaType, error) {
	var env dsseEnvelope
	if err := json.Unmarshal(rawEnvelope, &env); err != nil || env.Payload == "" {
		return "", "", err
	}

	decodedStatement, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return "", "", err
	}

	var stmt inTotoStatement
	if err := json.Unmarshal(decodedStatement, &stmt); err != nil || len(stmt.Predicate) == 0 {
		return "", "", err
	}

	mt := mapPredicateTypeToMediaType(stmt.PredicateType)
	if mt == "" {
		return "", "", fmt.Errorf("not supported PredicateType: %s", stmt.PredicateType)
	}

	return string(stmt.Predicate), mt, err
}

func extractSbomsFromImageLayers(img v1.Image, manifestAnnotations map[string]string) []*AttestationSbom {
	var found []*AttestationSbom
	manifest, err := img.Manifest()
	if err != nil {
		logrus.WithError(err).Debugf("Failed to fetch manifest")
		return nil
	}

	layers, err := img.Layers()
	if err != nil {
		logrus.WithError(err).Debugf("Failed to fetch layers")
		return nil
	}
	logrus.Debugf("Found %d layers.", len(layers))
	for i, layer := range layers {
		logrus.Debugf("Checking layer: %d", i)
		mt, err := layer.MediaType()
		if err != nil {
			logrus.WithError(err).Debugf("Failed to fetch MediaType")
			continue
		}
		rc, err := layer.Uncompressed()
		if err != nil {
			logrus.WithError(err).Debugf("Failed to fetch Uncompressed data")
			continue
		}
		rawPayload, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil || len(rawPayload) == 0 {
			logrus.WithError(err).Debugf("Failed to read payload")
			continue
		}

		anns := make(map[string]string)
		for k, v := range manifestAnnotations {
			anns[k] = v
		}
		if i < len(manifest.Layers) {
			logrus.Debugf("Checking manifest: %s", manifest.Layers[i].Digest)
			for k, v := range manifest.Layers[i].Annotations {
				anns[k] = v
			}
		}

		found = append(found, parseAttestationPayload(mt, rawPayload, anns)...)
	}

	return found
}

func parseAttestationPayload(layerMediaType types.MediaType, rawPayload []byte, anns map[string]string) []*AttestationSbom {
	var sbomContent string
	var detectedMediaType types.MediaType
	var err error

	switch {
	case isSupportedSbomMediaType(layerMediaType):
		sbomContent = string(rawPayload)
		detectedMediaType = layerMediaType
		err = nil

	case layerMediaType == MediaTypeDsseEnvelope:
		sbomContent, detectedMediaType, err = extractFromDsseEnvelope(rawPayload)

	case strings.HasPrefix(string(layerMediaType), "application/vnd.dev.sigstore.bundle"):
		var bundle sigstoreBundle
		if err = json.Unmarshal(rawPayload, &bundle); err == nil && len(bundle.DsseEnvelope) > 0 {
			sbomContent, detectedMediaType, err = extractFromDsseEnvelope(bundle.DsseEnvelope)
		}
	}

	if err != nil || sbomContent == "" {
		logrus.WithError(err).Debugf("Found no content for layer MediaType: %s", layerMediaType)
		return nil
	}

	// According to SBOM_SPEC.md: if "dev.sigstore.sbom.scope" is missing, the scope "all" applies.
	scopes := resolveScopes(anns)
	var items []*AttestationSbom
	for _, scope := range scopes {
		logrus.Debugf("Extracted SBOM (mediaType=%s, scope=%s)", detectedMediaType, scope)
		items = append(items, &AttestationSbom{
			Scope:     scope,
			MediaType: detectedMediaType,
			Sbom:      sbomContent,
		})
	}

	return items
}

func resolveScopes(annotations map[string]string) []string {
	if annotations == nil {
		return []string{ScopeAll}
	}
	raw := strings.TrimSpace(annotations[ScopeAnnotationKey])
	if raw == "" {
		return []string{ScopeAll}
	}
	// Multiple scopes can be comma separated ("scope1,scope2").
	parts := strings.Split(raw, ",")
	var scopes []string
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}
	if len(scopes) == 0 {
		return []string{ScopeAll}
	}
	return scopes
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
