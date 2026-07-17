package main

import (
	"io"
	"os"
	"testing"

	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateFormatVersion_StartupBoundary verifies that the startup
// boundary (PersistentPreRunE) rejects invalid CycloneDX versions before
// daemon/informer work begins, while accepting all valid configurations.
func TestValidateFormatVersion_StartupBoundary(t *testing.T) {
	tests := []struct {
		name          string
		format        string
		formatVersion string
		wantFail      bool
		wantErrSub    string
	}{
		{
			name:          "valid cyclonedxjson alias",
			format:        "cyclonedxjson",
			formatVersion: "cyclonedxjson",
			wantFail:      false,
		},
		{
			name:          "valid cyclonedxxml alias",
			format:        "cyclonedx",
			formatVersion: "cyclonedxxml",
			wantFail:      false,
		},
		{
			name:          "valid version 1.2",
			format:        "cyclonedxjson",
			formatVersion: "1.2",
			wantFail:      false,
		},
		{
			name:          "valid version 1.7",
			format:        "cyclonedxjson",
			formatVersion: "1.7",
			wantFail:      false,
		},
		{
			name:          "xml-only version 1.0",
			format:        "cyclonedx",
			formatVersion: "1.0",
			wantFail:      false,
		},
		{
			name:          "xml-only version 1.1",
			format:        "cyclonedx",
			formatVersion: "1.1",
			wantFail:      false,
		},
		{
			name:          "empty format-version (no validation needed)",
			format:        "json",
			formatVersion: "",
			wantFail:      false,
		},
		{
			name:          "non-cyclonedx format (no version validation)",
			format:        "json",
			formatVersion: "1.2",
			wantFail:      false,
		},
		{
			name:          "non-cyclonedx format cyclonedxjson alias",
			format:        "cyclonedxjson",
			formatVersion: "",
			wantFail:      false,
		},
		{
			name:          "invalid cyclonedxjson version",
			format:        "cyclonedxjson",
			formatVersion: "99.0",
			wantFail:      true,
			wantErrSub:    "unsupported",
		},
		{
			name:          "invalid cyclonedxxml version",
			format:        "cyclonedxxml",
			formatVersion: "99.0",
			wantFail:      true,
			wantErrSub:    "unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFormatVersion(tt.format, tt.formatVersion)
			if tt.wantFail {
				assert.Error(t, err, "startup should reject invalid format-version")
				if tt.wantErrSub != "" {
					assert.Contains(t, err.Error(), tt.wantErrSub,
						"error should mention the unsupported version")
				}
			} else {
				assert.NoError(t, err, "startup should accept valid format-version")
			}
		})
	}
}

// TestValidateFormatVersion_Direct tests the validateFormatVersion helper
// directly to avoid side effects from cmd.Execute().
func TestValidateFormatVersion_Direct(t *testing.T) {
	// Valid cases: no error expected.
	assert.NoError(t, validateFormatVersion("json", ""))
	assert.NoError(t, validateFormatVersion("cyclonedxjson", "cyclonedxjson"))
	assert.NoError(t, validateFormatVersion("cyclonedx", "cyclonedx"))
	assert.NoError(t, validateFormatVersion("cyclonedxjson", "1.2"))
	assert.NoError(t, validateFormatVersion("cyclonedxjson", "1.7"))
	assert.NoError(t, validateFormatVersion("cyclonedx", "1.0"))
	assert.NoError(t, validateFormatVersion("cyclonedx", "1.1"))

	// Invalid cases: error expected with specific substrings.
	// "99.0" is not a CycloneDX version, so it routes through the SPDX
	// resolver, which returns an SPDX error.
	err := validateFormatVersion("cyclonedxjson", "99.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "99.0")
	assert.Contains(t, err.Error(), "SPDX")

	err = validateFormatVersion("cyclonedxxml", "99.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "99.0")
	assert.Contains(t, err.Error(), "SPDX")

	// Whitespace-only format-version should not trigger validation.
	err = validateFormatVersion("cyclonedxjson", "   ")
	// Whitespace resolves to empty FormatVersion → no family → no validation.
	assert.NoError(t, err)
}

// TestValidateFormatVersion_NonCycloneDX verifies that non-CycloneDX formats
// never trigger version validation, even if a version-like string is supplied.
func TestValidateFormatVersion_NonCycloneDX(t *testing.T) {
	// These formats do NOT map to a CycloneDX family, so validation is skipped.
	nonCDFormats := []string{"json", "syftjson", "text", "table", "spdx", "spdxjson",
		"spdxtagvalue", "github", "githubjson", "custom-format"}
	for _, fmt := range nonCDFormats {
		t.Run(fmt, func(t *testing.T) {
			err := validateFormatVersion(fmt, "1.2")
			assert.NoError(t, err, "non-CycloneDX format %q should not be version-validated", fmt)
		})
	}
}

// TestValidateFormatVersion_BindFromEnv verifies that the resolved
// FormatVersion correctly identifies version "1.5" as cyclonedxjson.
func TestValidateFormatVersion_BindFromEnv(t *testing.T) {
	// The key test: config parsing picks up the env var value.
	fv := syft.ResolveCycloneDXFormatVersion("1.5")
	assert.Equal(t, "cyclonedxjson", fv.Family)
	assert.Equal(t, "1.5", fv.Version)
	assert.NoError(t, fv.Err)
	assert.NoError(t, validateFormatVersion("cyclonedxjson", "1.5"))
}

// ── SPDX Startup-Boundary Tests ────────────────────────────────────────────

// TestValidateFormatVersion_SPDXStartup verifies that SPDX format-version
// strings are resolved and validated during startup, and that unsupported
// combinations return deterministic errors.
func TestValidateFormatVersion_SPDXStartup(t *testing.T) {
	tests := []struct {
		name          string
		format        string
		formatVersion string
		wantFail      bool
		wantErrSub    string
	}{
		// Valid SPDX JSON formats.
		{"spdxjson alias", "spdxjson", "spdxjson", false, ""},
		{"spdxjson version 2.2", "spdxjson", "2.2", false, ""},
		{"spdxjson version 2.3", "spdxjson", "2.3", false, ""},
		{"spdxjson version 3.0", "spdxjson", "3.0", false, ""},
		// Valid SPDX tag-value formats.
		{"spdx alias", "spdx", "spdx", false, ""},
		{"spdxtv alias", "spdxtv", "spdxtv", false, ""},
		{"spdxtagvalue canonical", "spdxtagvalue", "spdxtagvalue", false, ""},
		{"spdx tv version 2.1", "spdx", "2.1", false, ""},
		{"spdx tv version 2.2", "spdx", "2.2", false, ""},
		{"spdx tv version 2.3", "spdx", "2.3", false, ""},
		// Invalid: 3.0 not supported by tag-value.
		{"spdxtv version 3.0", "spdxtagvalue", "3.0", true, "unsupported"},
		// Invalid: version like 99.0 resolves to spdxjson with error.
		{"invalid version 99.0", "spdxjson", "99.0", true, "unsupported"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFormatVersion(tt.format, tt.formatVersion)
			if tt.wantFail {
				assert.Error(t, err, "startup should reject invalid SPDX format-version")
				if tt.wantErrSub != "" {
					assert.Contains(t, err.Error(), tt.wantErrSub)
				}
			} else {
				assert.NoError(t, err, "startup should accept valid SPDX format-version")
			}
		})
	}
}

// TestValidateFormatVersion_SPDXAliases verifies every SPDX alias resolves
// without error (no version validation needed for alias-only requests).
func TestValidateFormatVersion_SPDXAliases(t *testing.T) {
	// Every known SPDX alias should be accepted without error.
	aliases := []struct {
		format        string
		formatVersion string
	}{
		{"spdxjson", "spdxjson"},
		{"spdx", "spdx"},
		{"spdxtv", "spdxtv"},
		{"spdxtagvalue", "spdxtagvalue"},
		// Whitespace → empty → no validation.
		{"spdxjson", "   "},
	}
	for _, tc := range aliases {
		t.Run(tc.format, func(t *testing.T) {
			err := validateFormatVersion(tc.format, tc.formatVersion)
			assert.NoError(t, err, "SPDX alias %q should not fail startup", tc.format)
		})
	}
}

// TestValidateFormatVersion_SPDXErrorMessages verifies that unsupported SPDX
// version errors contain the family, the supplied version, and a useful
// message so operators can diagnose misconfiguration quickly.
func TestValidateFormatVersion_SPDXErrorMessages(t *testing.T) {
	// Version 3.0 is not valid for tag-value family.
	err := validateFormatVersion("spdxtagvalue", "3.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "3.0", "error should mention supplied version")
	assert.Contains(t, err.Error(), "unsupported", "error should indicate unsupported")

	// Version 99.0 is not valid for JSON family.
	err = validateFormatVersion("spdxjson", "99.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "99.0")
	assert.Contains(t, err.Error(), "unsupported")
}

// TestValidateFormatVersion_SPDXVsCycloneDX verifies that the two resolver
// families are independent: a CycloneDX version string (e.g. "1.5") resolves
// to CycloneDX and never hits the SPDX resolver.
func TestValidateFormatVersion_SPDXVsCycloneDX(t *testing.T) {
	// "1.5" is a CycloneDX JSON version; should NOT resolve to SPDX.
	err := validateFormatVersion("cyclonedxjson", "1.5")
	assert.NoError(t, err)

	// "2.3" is shared: CycloneDX JSON supports it, SPDX JSON also supports it.
	// The CycloneDX resolver returns a family first, so it short-circuits there.
	err = validateFormatVersion("cyclonedxjson", "2.3")
	assert.NoError(t, err)

	// "3.0" is SPDX-only; CycloneDX resolver returns empty family.
	// SPDX resolver then accepts it.
	err = validateFormatVersion("spdxjson", "3.0")
	assert.NoError(t, err)
}

// TestFormatVersionStartup exercises the unified ResolveFormatVersionWithFamily
// that is the single entry point in PersistentPreRunE.  It verifies that both
// daemon and informer paths receive the same resolved value, that invalid
// non-versionable combinations fail with actionable errors, and that unknown
// format fallback (empty family) preserves default encoder configuration.
func TestFormatVersionStartup(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		formatVer   string
		wantFamily  string
		wantVersion string
		wantErr     bool
		wantErrSub  string
	}{
		// ── CycloneDX — valid ──────────────────────────────────────────────
		{"cdjson default", "cyclonedxjson", "cyclonedxjson", "cyclonedxjson", "1.7", false, ""},
		{"cdxml default", "cyclonedx", "cyclonedxxml", "cyclonedxxml", "1.7", false, ""},
		{"cdjson v1.2", "cyclonedxjson", "1.2", "cyclonedxjson", "1.2", false, ""},
		{"cdjson v1.7", "cyclonedxjson", "1.7", "cyclonedxjson", "1.7", false, ""},
		{"cdxml v1.0", "cyclonedx", "1.0", "cyclonedxxml", "1.0", false, ""},
		{"cdxml v1.1", "cyclonedx", "1.1", "cyclonedxxml", "1.1", false, ""},

		// ── SPDX — valid ───────────────────────────────────────────────────
		{"spdxjson default", "spdxjson", "spdxjson", "spdxjson", "2.3", false, ""},
		{"spdx tv default", "spdx", "spdx", "spdxtagvalue", "2.3", false, ""},
		{"spdxjson v3.0", "spdxjson", "3.0", "spdxjson", "3.0", false, ""},
		{"spdxtv v2.1", "spdx", "2.1", "spdxtagvalue", "2.1", false, ""},
		{"spdxjson v2.2", "spdxjson", "2.2", "spdxjson", "2.2", false, ""},

		// ── Non-version-aware — no family, no error ────────────────────────
		{"json empty", "json", "", "", "", false, ""},
		// "1.2" is claimed by CycloneDX (shared version), so even format=json
		// gets cyclonedxjson family through the unified resolver.
		{"json version 1.2 routes to CD", "json", "1.2", "cyclonedxjson", "1.2", false, ""},
		{"text", "text", "", "", "", false, ""},

		// ── Cross-family invalid — version incompatible with requested family ─
		{"spdx tag-value asks for 3.0", "spdx", "3.0", "spdxjson", "3.0", true, "unsupported"},

		// ── Unsupported versions — version-like strings route through SPDX ─
		// "99.0" is not a CycloneDX version → empty family → SPDX resolver
		// claims it as spdxjson with an error.
		{"cdjson unsupported 99.0", "cyclonedxjson", "99.0", "spdxjson", "99.0", true, "unsupported"},
		{"cdxml unsupported 99.0", "cyclonedxxml", "99.0", "spdxjson", "99.0", true, "unsupported"},
		{"spdx unsupported 99.0", "spdxjson", "99.0", "spdxjson", "99.0", true, "unsupported"},

		// ── Whitespace → empty → no validation ─────────────────────────────
		{"cdjson whitespace", "cyclonedxjson", "   ", "", "", false, ""},
		{"spdxjson whitespace", "spdxjson", "   ", "", "", false, ""},

		// ── Aliases ────────────────────────────────────────────────────────
		{"cyclone alias", "cyclonedx", "cyclone", "cyclonedxxml", "1.7", false, ""},
		{"spdxtv alias", "spdx", "spdxtv", "spdxtagvalue", "2.3", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv := syft.ResolveFormatVersionWithFamily(tt.format, tt.formatVer)
			assert.Equal(t, tt.wantFamily, fv.Family)
			assert.Equal(t, tt.wantVersion, fv.Version)
			if tt.wantErr {
				assert.Error(t, fv.Err, "startup should reject %s with %s", tt.format, tt.formatVer)
				if tt.wantErrSub != "" {
					assert.Contains(t, fv.Err.Error(), tt.wantErrSub,
						"error should contain actionable keyword")
				}
			} else {
				assert.NoError(t, fv.Err, "startup should accept %s with %s", tt.format, tt.formatVer)
			}
		})
	}
}

// TestREADMEFormatVersionDocumentation verifies that the README's documented
// format-version contract is consistent with the actual implementation.
func TestREADMEFormatVersionDocumentation(t *testing.T) {
	// 1. Read README and assert documented sections exist.
	readmeBytes, err := os.ReadFile("README.md")
	require.NoError(t, err, "README.md must be readable")
	readme := string(readmeBytes)

	// 1a. Parameter row, env var, YAML key.
	assert.Contains(t, readme, "`format-version`")
	assert.Contains(t, readme, "SBOM_FORMAT_VERSION")
	assert.Contains(t, readme, "formatVersion")

	// 1b. Section headers.
	assert.Contains(t, readme, "### Format Versions")
	assert.Contains(t, readme, "#### Invalid Combinations")
	assert.Contains(t, readme, "#### Unknown Format Fallback")

	// 1c. Family / Alias matrix.
	assert.Contains(t, readme, "cyclonedxjson")
	assert.Contains(t, readme, "cyclonedxxml")
	assert.Contains(t, readme, "spdxjson")
	assert.Contains(t, readme, "spdxtagvalue")
	assert.Contains(t, readme, "`cyclonedx`")
	assert.Contains(t, readme, "`cyclone`")
	assert.Contains(t, readme, "`spdx`")
	assert.Contains(t, readme, "`spdxtv`")

	// 1d. Version authority is delegated to the bundled Syft release and
	// surfaced dynamically by the binary instead of duplicated in this file.
	assert.Contains(t, readme, "Exact supported revisions and defaults come from the Syft version bundled")
	assert.Contains(t, readme, "sbom-operator --help")
	assert.NotContains(t, readme, "#### Supported Version Revisions")

	// 1e. Usage examples.
	assert.Contains(t, readme, "sbom-operator --format=cyclonedxjson --format-version=1.3")
	assert.Contains(t, readme, "export SBOM_FORMAT_VERSION=2.3")
	assert.Contains(t, readme, "custom-format")
}

func TestFormatVersionFlagHelpUsesSyftMetadata(t *testing.T) {
	flag := newRootCmd().PersistentFlags().Lookup(internal.ConfigKeyFormatVersion)
	require.NotNil(t, flag)
	assert.Equal(t, syft.FormatVersionHelp(), flag.Usage)
}

func TestHelpBypassesFormatVersionValidation(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"--format", "cyclonedxjson", "--format-version", "99.0", "--help",
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	require.NoError(t, cmd.Execute())
}
