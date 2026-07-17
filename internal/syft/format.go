package syft

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/sbom"
)

// FormatVersion holds the resolved CycloneDX or SPDX family and concrete
// encoder configuration for a format string.  An empty Version leaves
// encoder configuration at Syft defaults.
type FormatVersion struct {
	// Family is the canonical format name: "cyclonedxjson", "cyclonedxxml",
	// "spdxjson", or "spdxtagvalue".  It is empty when the format does not
	// map to a version-aware family (e.g. "json", "text").
	Family string
	// Version is the effective CycloneDX or SPDX spec version selected or the
	// concrete Syft default version when the request was omitted/empty.
	Version string
	// EncoderConfig carries the Syft encoder config (Version + Pretty).
	EncoderConfig interface{}
	// Err is non-nil when the requested version is unsupported.
	Err error
}

// formatToCycloneX maps a user-facing format mnemonic to the canonical
// Syft CycloneDX encoder family.  Known aliases:
//
//	cyclonedxjson  → cyclonedxjson  (no alias)
//	cyclonedxxml   → cyclonedxxml
//	cyclonedx      → cyclonedxxml
//	cyclone        → cyclonedxxml
func formatToCycloneX(format string) string {
	switch format {
	case "cyclonedxjson":
		return "cyclonedxjson"
	case "cyclonedxxml", "cyclonedx", "cyclone":
		return "cyclonedxxml"
	default:
		return ""
	}
}

// supportedVersionsForFamily returns the Syft-supported CycloneDX versions
// for a given family name.
func supportedVersionsForFamily(family string) []string {
	switch family {
	case "cyclonedxjson":
		return cyclonedxjson.SupportedVersions()
	case "cyclonedxxml":
		return cyclonedxxml.SupportedVersions()
	default:
		return nil
	}
}

// getCycloneDXEncoderConfig returns the default CycloneDX encoder config for a family.
func getCycloneDXEncoderConfig(family string) interface{} {
	switch family {
	case "cyclonedxjson":
		return cyclonedxjson.DefaultEncoderConfig()
	case "cyclonedxxml":
		return cyclonedxxml.DefaultEncoderConfig()
	default:
		return nil
	}
}

// getEncoderConfigDefaultVersion returns the default CycloneDX version for a family.
func getEncoderConfigDefaultVersion(family string) string {
	switch family {
	case "cyclonedxjson":
		return cyclonedxjson.DefaultEncoderConfig().Version
	case "cyclonedxxml":
		return cyclonedxxml.DefaultEncoderConfig().Version
	default:
		return ""
	}
}

// FormatVersionHelp renders the supported versions and defaults directly from
// the pinned Syft encoder packages so CLI help changes with dependency upgrades.
func FormatVersionHelp() string {
	return fmt.Sprintf(
		"SBOM spec version supported by bundled Syft. CycloneDX JSON: %s (default %s); CycloneDX XML: %s (default %s); SPDX JSON: %s (default %s); SPDX tag-value: %s (default %s). Format aliases are accepted; omitted uses Syft defaults.",
		strings.Join(cyclonedxjson.SupportedVersions(), ", "),
		cyclonedxjson.DefaultEncoderConfig().Version,
		strings.Join(cyclonedxxml.SupportedVersions(), ", "),
		cyclonedxxml.DefaultEncoderConfig().Version,
		strings.Join(spdxjson.SupportedVersions(), ", "),
		spdxjson.DefaultEncoderConfig().Version,
		strings.Join(spdxtagvalue.SupportedVersions(), ", "),
		spdxtagvalue.DefaultEncoderConfig().Version,
	)
}

// newFormatVersionForFamily creates a resolved version using the encoder config
// for the requested family. The caller must validate that the family supports
// the version before calling this function.
func newFormatVersionForFamily(family, version string) FormatVersion {
	var config interface{}

	switch family {
	case "cyclonedxjson":
		cfg := cyclonedxjson.DefaultEncoderConfig()
		cfg.Version = version
		config = cfg
	case "cyclonedxxml":
		cfg := cyclonedxxml.DefaultEncoderConfig()
		cfg.Version = version
		config = cfg
	case "spdxjson":
		cfg := spdxjson.DefaultEncoderConfig()
		cfg.Version = version
		config = cfg
	case "spdxtagvalue":
		cfg := spdxtagvalue.DefaultEncoderConfig()
		cfg.Version = version
		config = cfg
	}

	return FormatVersion{
		Family:        family,
		Version:       version,
		EncoderConfig: config,
	}
}

// IsVersionLike reports whether the string looks like a version number
// (starts with a digit and contains a dot).
func IsVersionLike(s string) bool {
	return isVersionLike(s)
}

// isVersionLike reports whether the string looks like a version number
// (starts with a digit and contains a dot).
func isVersionLike(s string) bool {
	if len(s) == 0 {
		return false
	}
	return (s[0] >= '0' && s[0] <= '9') && strings.Contains(s, ".")
}

// ResolveFormatVersion maps a format string to its family and derives the
// supported/default version from the pinned Syft library.  It tries the
// CycloneDX resolver first, then falls back to the SPDX resolver.
// Returns an error for unsupported revisions.
//
// Canonical names and operator aliases select their family and use its Syft
// default. Bare versions are matched against the pinned Syft support lists in
// CycloneDX JSON, CycloneDX XML, SPDX JSON, then SPDX tag-value order.
//
// Empty or whitespace-only input maps to Syft defaults (empty FormatVersion).
func ResolveFormatVersion(format string) FormatVersion {
	fv := ResolveCycloneDXFormatVersion(format)
	if fv.Family != "" {
		return fv
	}
	return ResolveSPDXFormatVersion(format)
}

// ResolveFormatVersionWithFamily resolves a format string and also checks
// that the resolved family is compatible with the user's requested format.
// It is the single entry point used by Cobra PersistentPreRunE so that
// daemon and informer paths both receive the same resolved value.
//
// Returns FormatVersion containing Family, Version, EncoderConfig and
// optionally Err when the requested version is unsupported or
// incompatible with the requested format family.
func ResolveFormatVersionWithFamily(format, formatVersion string) FormatVersion {
	fv := ResolveFormatVersion(formatVersion)
	if fv.Family == "" {
		// Not a version-aware format — fall back to Syft defaults.
		return FormatVersion{}
	}
	// Cross-family validation: when an explicit version string was provided,
	// check that it is compatible with the user's requested format family.
	// E.g. "3.0" resolves to spdxjson; if the user asked for "spdx" (tag-value),
	// ValidateSPDXFormatVersion catches that 3.0 is not supported by tag-value.
	if IsVersionLike(formatVersion) && fv.Family != "" {
		// Determine the user's requested family from their format string.
		userFamily := ResolveCycloneDXFormatVersion(format).Family
		if userFamily == "" {
			userFamily = ResolveSPDXFormatVersion(format).Family
		}
		if userFamily != "" && userFamily != fv.Family {
			// Version belongs to a different family than requested — validate.
			var err error
			switch userFamily {
			case "cyclonedxjson", "cyclonedxxml":
				err = ValidateFormatVersion(userFamily, fv.Version)
			default:
				err = ValidateSPDXFormatVersion(userFamily, fv.Version)
			}
			if err != nil {
				return FormatVersion{
					Family:        fv.Family,
					Version:       fv.Version,
					EncoderConfig: fv.EncoderConfig,
					Err:           fmt.Errorf("%w (requested format %q, resolved family %q)", err, format, fv.Family),
				}
			}

			// A version shared by multiple encoder families must retain the
			// family selected by --format, not whichever global resolver matched first.
			return newFormatVersionForFamily(userFamily, fv.Version)
		}
	}
	return fv
}

// ResolveCycloneDXFormatVersion maps a CycloneDX format string (alias or
// canonical) to its family and derives the supported/default version from
// the pinned Syft API.  Returns an error for unsupported revisions.
//
// Canonical names and aliases use the selected family's Syft default. Bare
// versions supported by both CycloneDX encoders prefer JSON; XML-only versions
// select XML. Unknown versions are left unresolved for the SPDX resolver.
//
// Empty or whitespace-only input maps to Syft defaults (empty FormatVersion).
func ResolveCycloneDXFormatVersion(format string) FormatVersion {
	format = strings.TrimSpace(format)
	if format == "" {
		return FormatVersion{}
	}

	// Check if format is a known CycloneDX format name (canonical or alias).
	// These use the Syft encoder default version.
	family := formatToCycloneX(format)
	if family != "" {
		return FormatVersion{
			Family:        family,
			Version:       getEncoderConfigDefaultVersion(family),
			EncoderConfig: getCycloneDXEncoderConfig(family),
		}
	}

	// Check Syft's current version lists. Versions shared by both families
	// default to CycloneDX JSON because it is checked first.
	jsonVersions := cyclonedxjson.SupportedVersions()
	xmlVersions := cyclonedxxml.SupportedVersions()

	for _, v := range jsonVersions {
		if v == format {
			cfg := cyclonedxjson.DefaultEncoderConfig()
			cfg.Version = format
			return FormatVersion{
				Family:        "cyclonedxjson",
				Version:       format,
				EncoderConfig: cfg,
			}
		}
	}

	for _, v := range xmlVersions {
		if v == format {
			cfg := cyclonedxxml.DefaultEncoderConfig()
			cfg.Version = format
			return FormatVersion{
				Family:        "cyclonedxxml",
				Version:       format,
				EncoderConfig: cfg,
			}
		}
	}

	// Not a CycloneDX format name or version — check if it looks like a version.
	// Version-like strings (e.g. "99.0") could belong to the SPDX family
	// (spdxjson: 2.2, 2.3, 3.0; spdxtagvalue: 2.1, 2.2, 2.3).
	// Return an empty family so downstream resolvers (e.g. SPDX) can attempt
	// resolution.  The error is deferred to the SPDX resolver or to an
	// explicit ValidateFormatVersion call when a non-version-aware format
	// (json, text …) is used.
	if isVersionLike(format) {
		return FormatVersion{}
	}

	// Not a CycloneDX format at all (e.g. "json", "spdxjson", "text").
	return FormatVersion{}
}

// formatToSPDX maps a user-facing SPDX format mnemonic to the canonical
// Syft SPDX encoder family.  Known aliases:
//
//	spdxjson        → spdxjson (canonical name, uses Syft default version)
//	spdx            → spdxtagvalue (default Syft alias → tag-value)
//	spdxtv          → spdxtagvalue
//	spdxtagvalue    → spdxtagvalue
func formatToSPDX(format string) string {
	switch format {
	case "spdxjson":
		return "spdxjson"
	case "spdx", "spdxtv", "spdxtagvalue":
		return "spdxtagvalue"
	default:
		return ""
	}
}

// supportedVersionsForSPDXFamily returns the Syft-supported SPDX versions
// for a given family name.
func supportedVersionsForSPDXFamily(family string) []string {
	switch family {
	case "spdxjson":
		return spdxjson.SupportedVersions()
	case "spdxtagvalue":
		return spdxtagvalue.SupportedVersions()
	default:
		return nil
	}
}

// ResolveSPDXFormatVersion maps an SPDX format string (alias or canonical)
// to its family and derives the supported/default version from the pinned
// Syft API.  Returns an error for unsupported revisions.
//
// Canonical names and aliases use the selected family's Syft default. Bare
// versions supported by both SPDX encoders prefer JSON. Unsupported
// version-like values resolve to SPDX JSON with an actionable error.
//
// Empty or whitespace-only input maps to Syft defaults (empty FormatVersion).
func ResolveSPDXFormatVersion(format string) FormatVersion {
	format = strings.TrimSpace(format)
	if format == "" {
		return FormatVersion{}
	}

	// Check if format is a known SPDX format name (canonical or alias).
	// These use the Syft encoder default version.
	family := formatToSPDX(format)
	if family != "" {
		switch family {
		case "spdxjson":
			cfg := spdxjson.DefaultEncoderConfig()
			return FormatVersion{
				Family:        family,
				Version:       cfg.Version,
				EncoderConfig: cfg,
			}
		case "spdxtagvalue":
			cfg := spdxtagvalue.DefaultEncoderConfig()
			return FormatVersion{
				Family:        family,
				Version:       cfg.Version,
				EncoderConfig: cfg,
			}
		}
	}

	// Check Syft's current version lists. Versions shared by both families
	// default to SPDX JSON because it is checked first.
	jsonVersions := spdxjson.SupportedVersions()
	tvVersions := spdxtagvalue.SupportedVersions()

	for _, v := range jsonVersions {
		if v == format {
			cfg := spdxjson.DefaultEncoderConfig()
			cfg.Version = format
			return FormatVersion{
				Family:        "spdxjson",
				Version:       format,
				EncoderConfig: cfg,
			}
		}
	}

	for _, v := range tvVersions {
		if v == format {
			cfg := spdxtagvalue.DefaultEncoderConfig()
			cfg.Version = format
			return FormatVersion{
				Family:        "spdxtagvalue",
				Version:       format,
				EncoderConfig: cfg,
			}
		}
	}

	// Not an SPDX format name or version — check if it looks like a version.
	if isVersionLike(format) {
		return FormatVersion{
			Family:        "spdxjson",
			Version:       format,
			EncoderConfig: spdxjson.DefaultEncoderConfig(),
			Err:           fmt.Errorf("unsupported SPDX JSON version %q: supported versions are %v", format, jsonVersions),
		}
	}

	// Not an SPDX format at all.
	return FormatVersion{}
}

// ValidateSPDXFormatVersion checks whether the requested SPDX version is
// supported by the pinned Syft library.  It is called by Cobra
// PersistentPreRunE to enforce a hard startup boundary.
func ValidateSPDXFormatVersion(family, version string) error {
	supported := supportedVersionsForSPDXFamily(family)
	if len(supported) == 0 {
		return nil // not an SPDX family — no validation needed
	}
	for _, v := range supported {
		if v == version {
			return nil
		}
	}
	return fmt.Errorf("unsupported SPDX %s version %q: must be one of %v", family, version, supported)
}

// ValidateFormatVersion checks whether the requested CycloneDX version is
// supported by the pinned Syft library.  It is called by Cobra
// PersistentPreRunE to enforce a hard startup boundary.
func ValidateFormatVersion(family, version string) error {
	supported := supportedVersionsForFamily(family)
	if len(supported) == 0 {
		return nil // not a CycloneDX family — no validation needed
	}
	for _, v := range supported {
		if v == version {
			return nil
		}
	}
	return fmt.Errorf("unsupported CycloneDX %s version %q: must be one of %v", family, version, supported)
}

// requireEncoderConfig accepts the value and pointer forms returned by the
// resolver and rejects missing or mismatched family configs explicitly.
func requireEncoderConfig[T any](family string, value any) (T, error) {
	if cfg, ok := value.(T); ok {
		return cfg, nil
	}
	if cfg, ok := value.(*T); ok && cfg != nil {
		return *cfg, nil
	}

	var zero T
	return zero, fmt.Errorf("invalid encoder config for family %q: got %T", family, value)
}

// GetEncoderWithVersion resolves the correct Syft encoder for a resolved
// FormatVersion. When the resolved format is not version-aware, it falls back
// to GetEncoder. Invalid or mismatched encoder configs return an explicit error.
func GetEncoderWithVersion(fv FormatVersion, sbomFormat string) (sbom.FormatEncoder, error) {
	if fv.Err != nil {
		return nil, fv.Err
	}

	switch fv.Family {
	case "cyclonedxjson":
		cfg, err := requireEncoderConfig[cyclonedxjson.EncoderConfig](fv.Family, fv.EncoderConfig)
		if err != nil {
			return nil, err
		}
		return cyclonedxjson.NewFormatEncoderWithConfig(cfg)
	case "cyclonedxxml":
		cfg, err := requireEncoderConfig[cyclonedxxml.EncoderConfig](fv.Family, fv.EncoderConfig)
		if err != nil {
			return nil, err
		}
		return cyclonedxxml.NewFormatEncoderWithConfig(cfg)
	case "spdxjson":
		cfg, err := requireEncoderConfig[spdxjson.EncoderConfig](fv.Family, fv.EncoderConfig)
		if err != nil {
			return nil, err
		}
		return spdxjson.NewFormatEncoderWithConfig(cfg)
	case "spdxtagvalue":
		cfg, err := requireEncoderConfig[spdxtagvalue.EncoderConfig](fv.Family, fv.EncoderConfig)
		if err != nil {
			return nil, err
		}
		return spdxtagvalue.NewFormatEncoderWithConfig(cfg)
	default:
		// Non-version-aware format — delegate to the existing resolver.
		return GetEncoder(sbomFormat)
	}
}
