package kubernetes_test

import (
	"testing"

	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/stretchr/testify/assert"
)

type mapTestData struct {
	input    string
	expected string
	dataMap  map[string]string
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
			img := &oci.RegistryImage{ImageID: v.input, Image: v.input}
			err := kubernetes.ApplyProxyRegistry(img, false, v.dataMap)
			assert.NoError(t, err)
			assert.Equal(t, v.expected, img.ImageID)
		})
	}
}
