package target

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTargetContextWithAttestation(t *testing.T) {
	ctx := NewContext("dummy-sbom", nil, nil, nil)
	assert.Empty(t, ctx.Scope)
	assert.Empty(t, ctx.MediaType)

	ctx.WithAttestation("application", "application/vnd.cyclonedx+json")
	assert.Equal(t, "application", ctx.Scope)
	assert.Equal(t, "application/vnd.cyclonedx+json", ctx.MediaType)
}
