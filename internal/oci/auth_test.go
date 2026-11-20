package oci

import (
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/assert"
)

func TestGCPRegistryHost(t *testing.T) {
	tests := []struct {
		name     string
		imageID  string
		expected string
		expectOK bool
	}{
		{
			name:     "valid artifact registry",
			imageID:  "europe-west3-docker.pkg.dev/project/repo/image:tag",
			expected: "europe-west3-docker.pkg.dev",
			expectOK: true,
		},
		{
			name:     "attacker host before marker in path",
			imageID:  "attacker.example/foo-docker.pkg.dev/bar",
			expected: "",
			expectOK: false,
		},
		{
			name:     "plain host",
			imageID:  "ghcr.io/org/img:latest",
			expected: "",
			expectOK: false,
		},
		{
			name:     "ecr host",
			imageID:  "123.dkr.ecr.eu-west-1.amazonaws.com/app:1",
			expected: "",
			expectOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, ok := gcpRegistryHost(tt.imageID)
			assert.Equal(t, tt.expectOK, ok)
			assert.Equal(t, tt.expected, host)
		})
	}
}

func TestRegistryMatches(t *testing.T) {
	assert.True(t, registryMatches("docker.io", "index.docker.io"))
	assert.True(t, registryMatches("index.docker.io", "registry-1.docker.io"))
	assert.True(t, registryMatches("europe-west3-docker.pkg.dev", "europe-west3-docker.pkg.dev"))
	assert.False(t, registryMatches("attacker.example", "attacker.example2"))
	assert.False(t, registryMatches("europe-west3-docker.pkg.dev", "attacker.example"))
}

func TestCredKeychainResolve(t *testing.T) {
	gcpCred := image.RegistryCredentials{
		Authority: "europe-west3-docker.pkg.dev",
		Username:  "oauth2accesstoken",
		Password:  "ya29-secret",
	}
	kc := &credKeychain{creds: []image.RegistryCredentials{gcpCred}}

	t.Run("gcp token only for verified host", func(t *testing.T) {
		auth, err := kc.Resolve(fakeResource("europe-west3-docker.pkg.dev"))
		assert.NoError(t, err)
		assert.NotEqual(t, authn.Anonymous, auth)
	})

	t.Run("attacker registry never gets gcp token", func(t *testing.T) {
		auth, err := kc.Resolve(fakeResource("attacker.example"))
		assert.NoError(t, err)
		// Fallback may be Anonymous or a host docker-config entry, but never
		// the GCP access token: oauth2accesstoken/ya29-secret must stay local.
		cfg, authErr := auth.Authorization()
		if authErr != nil {
			return // Anonymous
		}
		assert.NotEqual(t, "ya29-secret", cfg.Password, "gcp token leaked to attacker registry")
		assert.NotEqual(t, "oauth2accesstoken", cfg.Username, "gcp token leaked to attacker registry")
	})

	anonCred := image.RegistryCredentials{Username: "user", Password: "pass"} // empty Authority
	anonKC := &credKeychain{creds: []image.RegistryCredentials{anonCred}}

	t.Run("empty-authority pull secret still matches every registry", func(t *testing.T) {
		auth, err := anonKC.Resolve(fakeResource("ghcr.io"))
		assert.NoError(t, err)
		cfg, err := auth.Authorization()
		assert.NoError(t, err)
		assert.Equal(t, "user", cfg.Username)
		assert.Equal(t, "pass", cfg.Password)
	})

	t.Run("docker.io alias matches index.docker.io target", func(t *testing.T) {
		dockerCred := image.RegistryCredentials{Authority: "docker.io", Username: "user", Password: "pass"}
		kc := &credKeychain{creds: []image.RegistryCredentials{dockerCred}}
		auth, err := kc.Resolve(fakeResource("index.docker.io"))
		assert.NoError(t, err)
		cfg, err := auth.Authorization()
		assert.NoError(t, err)
		assert.Equal(t, "user", cfg.Username)
		assert.Equal(t, "pass", cfg.Password)
	})

	t.Run("scoped credential never matches unrelated host", func(t *testing.T) {
		scopedCred := image.RegistryCredentials{Authority: "registry.example.com", Username: "user", Password: "pass"}
		kc := &credKeychain{creds: []image.RegistryCredentials{scopedCred}}
		auth, err := kc.Resolve(fakeResource("ghcr.io"))
		assert.NoError(t, err)
		cfg, authErr := auth.Authorization()
		if authErr != nil {
			// Anonymous/auth from host docker config: no username to compare.
			return
		}
		assert.NotEqual(t, "user", cfg.Username, "scoped credential leaked to unrelated host")
	})
}

type fakeResource string

func (f fakeResource) String() string          { return string(f) }
func (f fakeResource) RegistryStr() string     { return string(f) }
func (f fakeResource) RepositoryStr() string   { return string(f) }
func (f fakeResource) Scope(str string) string { return string(f) }
func (f fakeResource) Name() string            { return string(f) }
