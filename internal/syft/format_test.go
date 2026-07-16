package syft_test

import (
	"testing"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/stretchr/testify/assert"
)

func TestResolveCycloneDXFormatVersion(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		wantFamily  string
		wantVersion string
	}{
		// Empty / whitespace → no family (not a CycloneDX format)
		{"empty", "", "", ""},
		{"whitespace", "   ", "", ""},

		// CycloneDX JSON canonical name
		{"cyclonedxjson default", "cyclonedxjson", "cyclonedxjson", cyclonedxjson.DefaultEncoderConfig().Version},

		// CycloneDX XML aliases
		{"cyclonedx alias", "cyclonedx", "cyclonedxxml", cyclonedxxml.DefaultEncoderConfig().Version},
		{"cyclone alias", "cyclone", "cyclonedxxml", cyclonedxxml.DefaultEncoderConfig().Version},
		{"cyclonedxxml canonical", "cyclonedxxml", "cyclonedxxml", cyclonedxxml.DefaultEncoderConfig().Version},

		// Bare shared versions prefer JSON; XML-only versions select XML.
		// The full supported-version matrix is exercised dynamically elsewhere.
		{"shared version prefers JSON", "1.2", "cyclonedxjson", "1.2"},
		{"XML-only version", "1.0", "cyclonedxxml", "1.0"},

		// Non-CycloneDX formats → no family
		{"json format", "json", "", ""},
		{"spdxjson", "spdxjson", "", ""},
		{"text", "text", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv := syft.ResolveCycloneDXFormatVersion(tt.format)
			assert.Equal(t, tt.wantFamily, fv.Family)
			assert.Equal(t, tt.wantVersion, fv.Version)
		})
	}
}

func TestResolveCycloneDXFormatVersionUnsupported(t *testing.T) {
	// Unknown version-like strings return empty family so that the SPDX
	// resolver can attempt resolution.  The upstream CycloneDX resolver
	// does NOT claim ownership of arbitrary version strings.
	fv := syft.ResolveCycloneDXFormatVersion("99.0")
	assert.Equal(t, "", fv.Family, "unknown version string should not map to CycloneDX")
	assert.Equal(t, "", fv.Version)
	assert.NoError(t, fv.Err)

	// Alias with no explicit version → no error, default version
	fv2 := syft.ResolveCycloneDXFormatVersion("cyclonedxxml")
	assert.NoError(t, fv2.Err)
	assert.Equal(t, "cyclonedxxml", fv2.Family)
	assert.Equal(t, cyclonedxxml.DefaultEncoderConfig().Version, fv2.Version)
}

func TestValidateFormatVersion(t *testing.T) {
	families := map[string][]string{
		"cyclonedxjson": cyclonedxjson.SupportedVersions(),
		"cyclonedxxml":  cyclonedxxml.SupportedVersions(),
	}
	for family, versions := range families {
		for _, version := range versions {
			assert.NoError(t, syft.ValidateFormatVersion(family, version))
		}
		assert.Error(t, syft.ValidateFormatVersion(family, "99.0"))
	}
	assert.NoError(t, syft.ValidateFormatVersion("json", "99.0"))
}

func TestGetEncoderWithVersion(t *testing.T) {
	tests := []struct {
		name       string
		fv         syft.FormatVersion
		sbomFormat string
		wantErr    bool
	}{
		{
			name:       "cyclonedxjson with supported version",
			fv:         syft.FormatVersion{Family: "cyclonedxjson", Version: "1.7", EncoderConfig: cyclonedxjson.DefaultEncoderConfig()},
			sbomFormat: "cyclonedxjson",
			wantErr:    false,
		},
		{
			name:       "cyclonedxxml with supported version",
			fv:         syft.FormatVersion{Family: "cyclonedxxml", Version: "1.7", EncoderConfig: cyclonedxxml.DefaultEncoderConfig()},
			sbomFormat: "cyclonedx",
			wantErr:    false,
		},
		{
			name: "pointer config is accepted",
			fv: syft.FormatVersion{
				Family:  "cyclonedxjson",
				Version: "1.7",
				EncoderConfig: func() *cyclonedxjson.EncoderConfig {
					cfg := cyclonedxjson.DefaultEncoderConfig()
					return &cfg
				}(),
			},
			sbomFormat: "cyclonedxjson",
			wantErr:    false,
		},
		{
			name:       "non-cyclonedx delegates to GetEncoder",
			fv:         syft.FormatVersion{}, // empty family — not a CD format
			sbomFormat: "json",
			wantErr:    false,
		},
		{
			name:       "non-cyclonedx delegates spdxjson",
			fv:         syft.FormatVersion{},
			sbomFormat: "spdxjson",
			wantErr:    false,
		},
		{
			name:       "unsupported version returns error",
			fv:         syft.FormatVersion{Family: "cyclonedxjson", Version: "99.0", Err: assert.AnError},
			sbomFormat: "cyclonedxjson",
			wantErr:    true,
		},
		{
			name:       "spdxjson with supported version",
			fv:         syft.FormatVersion{Family: "spdxjson", Version: "2.3", EncoderConfig: spdxjson.DefaultEncoderConfig()},
			sbomFormat: "spdxjson",
			wantErr:    false,
		},
		{
			name:       "spdxtagvalue with supported version",
			fv:         syft.FormatVersion{Family: "spdxtagvalue", Version: "2.3", EncoderConfig: spdxtagvalue.DefaultEncoderConfig()},
			sbomFormat: "spdx",
			wantErr:    false,
		},
		{
			name:       "wrong config type returns error",
			fv:         syft.FormatVersion{Family: "cyclonedxjson", Version: "1.7", EncoderConfig: cyclonedxxml.DefaultEncoderConfig()},
			sbomFormat: "cyclonedxjson",
			wantErr:    true,
		},
		{
			name:       "nil config returns error",
			fv:         syft.FormatVersion{Family: "spdxjson", Version: "2.3"},
			sbomFormat: "spdxjson",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder, err := syft.GetEncoderWithVersion(tt.fv, tt.sbomFormat)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.fv.Err == nil {
					assert.ErrorContains(t, err, "invalid encoder config")
					assert.ErrorContains(t, err, tt.fv.Family)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, encoder)
			}
		})
	}
}

// SPDX Format Version Tests

func TestResolveSPDXFormatVersion(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		wantFamily  string
		wantVersion string
	}{
		// Empty / whitespace → no family (not an SPDX format)
		{"empty", "", "", ""},
		{"whitespace", "   ", "", ""},

		// SPDX JSON canonical name
		{"spdxjson default", "spdxjson", "spdxjson", spdxjson.DefaultEncoderConfig().Version},

		// SPDX tag-value aliases
		{"spdx alias", "spdx", "spdxtagvalue", spdxtagvalue.DefaultEncoderConfig().Version},
		{"spdxtv alias", "spdxtv", "spdxtagvalue", spdxtagvalue.DefaultEncoderConfig().Version},
		{"spdxtagvalue canonical", "spdxtagvalue", "spdxtagvalue", spdxtagvalue.DefaultEncoderConfig().Version},

		// Supported SPDX tag-value versions (2.1 is TV-only)
		{"spdx tv 2.1", "2.1", "spdxtagvalue", "2.1"},
		// Supported SPDX JSON versions (shared 2.2, 2.3 default to JSON)
		{"spdx json 2.2", "2.2", "spdxjson", "2.2"},
		{"spdx json 2.3", "2.3", "spdxjson", "2.3"},
		{"spdx json 3.0", "3.0", "spdxjson", "3.0"},

		// Non-SPDX formats → no family
		{"json format", "json", "", ""},
		{"text", "text", "", ""},
		{"cyclonedx", "cyclonedx", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv := syft.ResolveSPDXFormatVersion(tt.format)
			assert.Equal(t, tt.wantFamily, fv.Family)
			assert.Equal(t, tt.wantVersion, fv.Version)
		})
	}
}

func TestResolveSPDXFormatVersionUnsupported(t *testing.T) {
	// Unsupported version for SPDX JSON
	fv := syft.ResolveSPDXFormatVersion("99.0")
	assert.Equal(t, "spdxjson", fv.Family)
	assert.Equal(t, "99.0", fv.Version)
	assert.Error(t, fv.Err)
	assert.Contains(t, fv.Err.Error(), "unsupported")
	assert.Contains(t, fv.Err.Error(), "99.0")

	// Alias with no explicit version → no error, default version
	fv2 := syft.ResolveSPDXFormatVersion("spdxjson")
	assert.NoError(t, fv2.Err)
	assert.Equal(t, "spdxjson", fv2.Family)
	assert.Equal(t, spdxtagvalue.DefaultEncoderConfig().Version, fv2.Version)
}

func TestValidateSPDXFormatVersion(t *testing.T) {
	families := map[string][]string{
		"spdxjson":     spdxjson.SupportedVersions(),
		"spdxtagvalue": spdxtagvalue.SupportedVersions(),
	}
	for family, versions := range families {
		for _, version := range versions {
			assert.NoError(t, syft.ValidateSPDXFormatVersion(family, version))
		}
		err := syft.ValidateSPDXFormatVersion(family, "99.0")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "99.0")
		assert.ErrorContains(t, err, "unsupported")
	}
	assert.NoError(t, syft.ValidateSPDXFormatVersion("json", "99.0"))
}

func TestSPDXGetEncoderWithVersion(t *testing.T) {
	tests := []struct {
		name       string
		fv         syft.FormatVersion
		sbomFormat string
		wantErr    bool
	}{
		{
			name:       "spdxjson with default version",
			fv:         syft.ResolveSPDXFormatVersion("spdxjson"),
			sbomFormat: "spdxjson",
			wantErr:    false,
		},
		{
			name:       "spdxjson with version 2.2",
			fv:         syft.ResolveSPDXFormatVersion("2.2"),
			sbomFormat: "spdxjson",
			wantErr:    false,
		},
		{
			name:       "spdxjson with version 3.0",
			fv:         syft.ResolveSPDXFormatVersion("3.0"),
			sbomFormat: "spdxjson",
			wantErr:    false,
		},
		{
			name:       "spdxtagvalue with default version",
			fv:         syft.ResolveSPDXFormatVersion("spdx"),
			sbomFormat: "spdx",
			wantErr:    false,
		},
		{
			name:       "spdxtagvalue with version 2.1",
			fv:         syft.ResolveSPDXFormatVersion("2.1"),
			sbomFormat: "spdxtv",
			wantErr:    false,
		},
		{
			name:       "spdx alias resolves to tagvalue",
			fv:         syft.ResolveSPDXFormatVersion("spdx"),
			sbomFormat: "spdx",
			wantErr:    false,
		},
		{
			name:       "spdxtv alias resolves to tagvalue",
			fv:         syft.ResolveSPDXFormatVersion("spdxtv"),
			sbomFormat: "spdxtv",
			wantErr:    false,
		},
		{
			name:       "spdxtagvalue canonical resolves",
			fv:         syft.ResolveSPDXFormatVersion("spdxtagvalue"),
			sbomFormat: "spdxtagvalue",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder, err := syft.GetEncoderWithVersion(tt.fv, tt.sbomFormat)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, encoder)
			}
		})
	}
}

// ── Unified ResolveFormatVersion tests ─────────────────────────────────────

// TestResolveFormatVersion exercises the single unified entry point that
// tries the CycloneDX resolver first, then falls back to SPDX.
func TestResolveFormatVersion(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		wantFamily  string
		wantVersion string
		wantErr     bool
	}{
		// Empty / whitespace → no family.
		{"empty", "", "", "", false},
		{"whitespace", "   ", "", "", false},

		// CycloneDX paths (CycloneDX resolver wins).
		{"cdjson alias", "cyclonedxjson", "cyclonedxjson", cyclonedxjson.DefaultEncoderConfig().Version, false},
		{"cdxml alias", "cyclonedx", "cyclonedxxml", cyclonedxxml.DefaultEncoderConfig().Version, false},
		{"cdxml canonical", "cyclonedxxml", "cyclonedxxml", cyclonedxxml.DefaultEncoderConfig().Version, false},
		{"cdjson v1.2", "1.2", "cyclonedxjson", "1.2", false},
		{"cdjson v1.7", "1.7", "cyclonedxjson", "1.7", false},

		// SPDX paths (CycloneDX resolver returns empty → SPDX takes over).
		{"spdxjson alias", "spdxjson", "spdxjson", spdxjson.DefaultEncoderConfig().Version, false},
		{"spdx alias", "spdx", "spdxtagvalue", spdxtagvalue.DefaultEncoderConfig().Version, false},
		{"spdxtv alias", "spdxtv", "spdxtagvalue", spdxtagvalue.DefaultEncoderConfig().Version, false},
		{"spdxjson v3.0", "3.0", "spdxjson", "3.0", false},
		{"spdxtv v2.1", "2.1", "spdxtagvalue", "2.1", false},

		// Non-version-aware formats → no family.
		{"json", "json", "", "", false},
		{"text", "text", "", "", false},

		// Unsupported version → SPDX resolver returns error.
		{"unsupported 99.0", "99.0", "spdxjson", "99.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv := syft.ResolveFormatVersion(tt.format)
			assert.Equal(t, tt.wantFamily, fv.Family)
			assert.Equal(t, tt.wantVersion, fv.Version)
			if tt.wantErr {
				assert.Error(t, fv.Err)
			} else {
				assert.NoError(t, fv.Err)
			}
		})
	}
}

// TestResolveFormatVersionWithFamily verifies cross-family validation.
func TestResolveFormatVersionWithFamily(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		formatVer   string
		wantFamily  string
		wantVersion string
		wantErr     bool
	}{
		// Valid: CycloneDX family matches.
		{"cdjson alias", "cyclonedxjson", "cyclonedxjson", "cyclonedxjson", cyclonedxjson.DefaultEncoderConfig().Version, false},
		{"cdjson v1.5", "cyclonedxjson", "1.5", "cyclonedxjson", "1.5", false},
		{"cdxml shared v1.7", "cyclonedxxml", "1.7", "cyclonedxxml", "1.7", false},

		// Valid: SPDX family matches.
		{"spdxjson alias", "spdxjson", "spdxjson", "spdxjson", spdxjson.DefaultEncoderConfig().Version, false},
		{"spdxjson v3.0", "spdxjson", "3.0", "spdxjson", "3.0", false},
		{"spdxtv shared v2.3", "spdxtagvalue", "2.3", "spdxtagvalue", "2.3", false},
		// Invalid: "spdx" → tag-value family, but 3.0 is JSON-only.
		// The cross-family validator catches this incompatibility.
		{"spdx tag-value 3.0 (invalid)", "spdx", "3.0", "spdxjson", "3.0", true},

		// Invalid: version incompatible with requested format.
		// "3.0" resolves to spdxjson family, but user asked for "spdx" (tag-value).
		// The cross-family validator catches this incompatibility.
		{"spdx tag-value 3.0", "spdx", "3.0", "spdxjson", "3.0", true}, // 3.0 not valid for spdxtagvalue

		// Non-version-aware format → no family, no error.
		{"json empty", "json", "", "", "", false},
		{"text empty", "text", "", "", "", false},
		// Valid: spdxtagvalue versions (2.1) match tag-value user family.
		{"spdx tv v2.1", "spdx", "2.1", "spdxtagvalue", "2.1", false},

		// Whitespace → empty → no validation.
		{"cdjson whitespace", "cyclonedxjson", "   ", "", "", false},

		// Unsupported version → error.
		{"unsupported", "spdxjson", "99.0", "spdxjson", "99.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv := syft.ResolveFormatVersionWithFamily(tt.format, tt.formatVer)
			assert.Equal(t, tt.wantFamily, fv.Family)
			assert.Equal(t, tt.wantVersion, fv.Version)
			if tt.wantErr {
				assert.Error(t, fv.Err)
				// Error should mention both the original family issue and the requested format.
				if len(fv.Err.Error()) > 0 {
					assert.Contains(t, fv.Err.Error(), tt.formatVer, "error should mention supplied version")
				}
			} else {
				assert.NoError(t, fv.Err)
				switch tt.wantFamily {
				case "cyclonedxjson":
					assert.IsType(t, cyclonedxjson.EncoderConfig{}, fv.EncoderConfig)
				case "cyclonedxxml":
					assert.IsType(t, cyclonedxxml.EncoderConfig{}, fv.EncoderConfig)
				case "spdxjson":
					assert.IsType(t, spdxjson.EncoderConfig{}, fv.EncoderConfig)
				case "spdxtagvalue":
					assert.IsType(t, spdxtagvalue.EncoderConfig{}, fv.EncoderConfig)
				}
			}
		})
	}
}

// Verify that empty-format resolution returns default version metadata.
func TestSPDXFormatVersionEmpty(t *testing.T) {
	fv := syft.ResolveSPDXFormatVersion("")
	assert.Equal(t, "", fv.Family)
	assert.Equal(t, "", fv.Version)
	assert.Nil(t, fv.EncoderConfig)
	assert.NoError(t, fv.Err)
}

// Verify that error messages include format, version, and supported versions.
func TestSPDXFormatVersionErrorMessages(t *testing.T) {
	// Test ResolveSPDXFormatVersion error
	fv := syft.ResolveSPDXFormatVersion("99.0")
	assert.Error(t, fv.Err)
	errStr := fv.Err.Error()
	assert.Contains(t, errStr, "SPDX", "error should mention family")
	assert.Contains(t, errStr, "99.0", "error should mention supplied version")
	assert.Contains(t, errStr, "supported versions", "error should list supported versions")

	// Test ValidateSPDXFormatVersion error
	err := syft.ValidateSPDXFormatVersion("spdxtagvalue", "3.0")
	assert.Error(t, err)
	errStr = err.Error()
	assert.Contains(t, errStr, "spdxtagvalue", "error should mention family")
	assert.Contains(t, errStr, "3.0", "error should mention supplied version")
	assert.Contains(t, errStr, "must be one of", "error should list supported versions")
}
