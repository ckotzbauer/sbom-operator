package syft

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/stretchr/testify/assert"
)

func TestStripCPEs(t *testing.T) {
	withCPE := pkg.Package{
		Name:    "busybox",
		Version: "1.36.0",
		Type:    pkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:busybox:busybox:1.36.0:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
	}
	withoutCPE := pkg.Package{Name: "libc", Version: "0.7", Type: pkg.ApkPkg}

	document := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(withCPE, withoutCPE),
		},
	}

	var pkgs []pkg.Package
	for p := range document.Artifacts.Packages.Enumerate() {
		pkgs = append(pkgs, p)
	}
	document.Relationships = []artifact.Relationship{{
		From: pkgs[0],
		To:   pkgs[1],
		Type: artifact.DependencyOfRelationship,
	}}

	before := map[artifact.ID]struct{}{}
	for p := range document.Artifacts.Packages.Enumerate() {
		before[p.ID()] = struct{}{}
	}

	stripCPEs(document)

	for _, r := range document.Relationships {
		assert.NotNilf(t, document.Artifacts.Packages.Package(r.From.ID()), "relationship From ID %q must resolve after stripping", r.From.ID())
		assert.NotNilf(t, document.Artifacts.Packages.Package(r.To.ID()), "relationship To ID %q must resolve after stripping", r.To.ID())
	}

	after := map[artifact.ID]struct{}{}
	for p := range document.Artifacts.Packages.Enumerate() {
		assert.Emptyf(t, p.CPEs, "package %q should have no CPEs", p.Name)
		after[p.ID()] = struct{}{}
	}

	assert.Equal(t, 2, document.Artifacts.Packages.PackageCount())
	assert.Equal(t, before, after, "package IDs must be preserved")
}

func TestStripCPEsNilSafety(t *testing.T) {
	assert.NotPanics(t, func() {
		stripCPEs(nil)
		stripCPEs(&sbom.SBOM{})
	})
}
