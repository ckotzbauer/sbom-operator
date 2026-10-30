package target

import (
	"testing"

	"github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/stretchr/testify/assert"
)

func TestTargetContextWithAttestation(t *testing.T) {
	ctx := NewContext(nil, nil, &oci.AttestationSbom{Sbom: "dummy-sbom", Scope: "application", MediaType: oci.GetMediaType(oci.CycloneDXJSONMediaType)})
	assert.Equal(t, "application", ctx.Attestation.Scope)
	assert.Equal(t, oci.GetMediaType("application/vnd.cyclonedx+json"), ctx.Attestation.MediaType)
	assert.Equal(t, "dummy-sbom", ctx.Attestation.Sbom)
}
