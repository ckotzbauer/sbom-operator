package oci

import (
	"bytes"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// This source is mostly ported from cosign 1.8.0

const (
	CycloneDXXMLMediaType  = "application/vnd.cyclonedx+xml"
	CycloneDXJSONMediaType = "application/vnd.cyclonedx+json"
	SyftMediaType          = "application/vnd.syft+json"
	SPDXMediaType          = "text/spdx"
	SPDXJSONMediaType      = "spdx+json"
)

func GetMediaType(format string) types.MediaType {
	switch format {
	case "json":
		return types.MediaType(SyftMediaType)
	case "cyclonedx":
		return types.MediaType(CycloneDXXMLMediaType)
	case "cyclonedxjson":
		return types.MediaType(CycloneDXJSONMediaType)
	case "spdx":
		return types.MediaType(SPDXMediaType)
	case "spdxjson":
		return types.MediaType(SPDXJSONMediaType)
	default:
		return types.MediaType(SyftMediaType)
	}
}

func CreateTag(ref name.Reference, repoName string) (name.Tag, error) {
	digest, _ := ref.(name.Digest)
	h, err := v1.NewHash(digest.DigestStr())
	if err != nil {
		return name.Tag{}, err
	}

	repo, err := name.NewRepository(repoName)
	if err != nil {
		return name.Tag{}, err
	}

	return repo.Tag(fmt.Sprint(h.Algorithm, "-", h.Hex, ".sbom")), nil
}

// CreateImage constructs a new v1.Image with the provided payload.
func CreateImage(payload []byte, layerMediaType types.MediaType) (v1.Image, error) {
	base := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	base = mutate.ConfigMediaType(base, types.OCIConfigJSON)
	layer := &staticLayer{
		payload:        payload,
		layerMediaType: layerMediaType,
	}

	img, err := mutate.Append(base, mutate.Addendum{
		Layer: layer,
	})
	if err != nil {
		return nil, err
	}
	return img, nil
}

type staticLayer struct {
	payload        []byte
	layerMediaType types.MediaType
}

var _ v1.Layer = (*staticLayer)(nil)

// Digest implements v1.Layer
func (l *staticLayer) Digest() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.payload))
	return h, err
}

// DiffID implements v1.Layer
func (l *staticLayer) DiffID() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.payload))
	return h, err
}

// Compressed implements v1.Layer
func (l *staticLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.payload)), nil
}

// Uncompressed implements v1.Layer
func (l *staticLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.payload)), nil
}

// Size implements v1.Layer
func (l *staticLayer) Size() (int64, error) {
	return int64(len(l.payload)), nil
}

// MediaType implements v1.Layer
func (l *staticLayer) MediaType() (types.MediaType, error) {
	return l.layerMediaType, nil
}
