package git

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testData struct {
	input    string
	expected string
	g        *GitTarget
}

func TestImageIDToFilePath(t *testing.T) {
	tests := []testData{
		{
			input:    "alpine:latest",
			expected: "alpine_latest/sbom.json",
			g:        NewGitTarget("", "", "", "", "", "", "", "", "", "", "", "", "", false),
		},
		{
			input:    "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300",
			expected: "alpine/sha256_21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300/sbom.json",
			g:        NewGitTarget("", "", "", "", "", "", "", "", "", "", "", "", "", false),
		},
		{
			input:    "",
			expected: "sbom.json",
			g:        NewGitTarget("", "", "", "", "", "", "", "", "", "", "", "", "", false),
		},
		{
			input:    "alpine:latest",
			expected: "/git/dev/alpine_latest/sbom.spdx",
			g:        NewGitTarget("/git", "dev", "", "", "", "", "", "", "", "", "", "", "spdx", false),
		},
		{
			input:    "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300",
			expected: "/git/sbom/prod/cluster1/alpine/sha256_21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300/sbom.spdx",
			g:        NewGitTarget("/git/sbom", "prod/cluster1", "", "", "", "", "", "", "", "", "", "", "spdx", false),
		},
		{
			input:    "",
			expected: "/git/sbom.json",
			g:        NewGitTarget("/git", "", "", "", "", "", "", "", "", "", "", "", "", false),
		},
	}

	for _, v := range tests {
		t.Run("", func(t *testing.T) {
			out := v.g.ImageIDToFilePath(v.input)
			assert.Equal(t, v.expected, out)
		})
	}
}
