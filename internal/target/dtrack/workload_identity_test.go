package dtrack

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testJwtHeader = "x-workload-token"

// testJwt is a structurally valid (unsigned) JWT with iat=1700000000.
var testJwt = "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(`{"iat":1700000000}`)) + ".sig"

type exchangeRecorder struct {
	mu            sync.Mutex
	hits          int
	subjectTokens []string
	paths         []string
	// jwtHeaders records the x-workload-token header of every request, by path.
	jwtHeaders map[string][]string
}

func (r *exchangeRecorder) recordJwtHeader(path, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.jwtHeaders == nil {
		r.jwtHeaders = map[string][]string{}
	}
	r.jwtHeaders[path] = append(r.jwtHeaders[path], value)
}

func (r *exchangeRecorder) record(path, subjectToken string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits++
	r.paths = append(r.paths, path)
	r.subjectTokens = append(r.subjectTokens, subjectToken)
}

// newExchangeServer serves the token exchange endpoint and records each call.
// /api/version (used by client-go's version check) is answered without auth;
// any other path is handed to next (if set).
func newExchangeServer(t *testing.T, rec *exchangeRecorder, next http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.recordJwtHeader(r.URL.Path, r.Header.Get(testJwtHeader))
		if r.URL.Path == "/api/v2/oauth/token" || r.URL.Path == "//api/v2/oauth/token" {
			require.NoError(t, r.ParseForm())
			rec.record(r.URL.Path, r.PostForm.Get("subject_token"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"dt-session","token_type":"Bearer"}`))
			return
		}
		if r.URL.Path == "/api/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"5.2.1"}`))
			return
		}
		if next != nil {
			next(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(p, []byte(content), 0600))
	return p
}

func TestExchangeSendsForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v2/oauth/token", r.URL.Path)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		assert.Empty(t, r.Header.Get("X-Api-Key"))
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.PostForm.Get("grant_type"))
		assert.Equal(t, "urn:ietf:params:oauth:token-type:jwt", r.PostForm.Get("subject_token_type"))
		assert.Equal(t, testJwt, r.PostForm.Get("subject_token"))
		assert.Equal(t, "kubernetes", r.PostForm.Get("workload_identity_provider"))
		assert.Equal(t, "sbom-operator", r.PostForm.Get("service_account"))
		_, _ = w.Write([]byte(`{"access_token":"dt-session","token_type":"Bearer"}`))
	}))
	defer srv.Close()

	e := newTokenExchanger(srv.URL, writeTokenFile(t, testJwt), "kubernetes", "sbom-operator")
	token, err := e.Exchange(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "dt-session", token)
}

func TestExchangeReadsFileEachCall(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, nil)
	file := writeTokenFile(t, "a.b.c")
	e := newTokenExchanger(srv.URL, file, "kubernetes", "sbom-operator")

	_, err := e.Exchange(context.Background())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, []byte("d.e.f"), 0600))
	_, err = e.Exchange(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"a.b.c", "d.e.f"}, rec.subjectTokens)
}

func TestExchangeTrimsToken(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, nil)
	e := newTokenExchanger(srv.URL, writeTokenFile(t, "tok\n"), "kubernetes", "sbom-operator")

	_, err := e.Exchange(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"tok"}, rec.subjectTokens)
}

func TestExchangeMissingOrEmptyFile(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, nil)

	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := newTokenExchanger(srv.URL, missing, "kubernetes", "sbom-operator").Exchange(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), missing)

	empty := writeTokenFile(t, "  \n")
	_, err = newTokenExchanger(srv.URL, empty, "kubernetes", "sbom-operator").Exchange(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), empty)

	assert.Equal(t, 0, rec.hits)
}

func TestExchangeErrors(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		wantContains []string
	}{
		{name: "non-2xx", status: http.StatusBadRequest, body: `{"error":"invalid_request"}`, wantContains: []string{"400", "invalid_request"}},
		{name: "missing access_token", status: http.StatusOK, body: `{}`},
		{name: "invalid json", status: http.StatusOK, body: `not json`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			token, err := newTokenExchanger(srv.URL, writeTokenFile(t, testJwt), "kubernetes", "sbom-operator").Exchange(context.Background())
			require.Error(t, err)
			assert.Empty(t, token)
			for _, s := range tt.wantContains {
				assert.Contains(t, err.Error(), s)
			}
		})
	}
}

func TestExchangeBaseUrlTrailingSlash(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, nil)

	_, err := newTokenExchanger(srv.URL+"/", writeTokenFile(t, testJwt), "kubernetes", "sbom-operator").Exchange(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"/api/v2/oauth/token"}, rec.paths)
}

func TestExchangeTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte(`{"access_token":"dt-session"}`))
	}))
	defer srv.Close()

	e := newTokenExchanger(srv.URL, writeTokenFile(t, testJwt), "kubernetes", "sbom-operator")
	e.httpClient.Timeout = 50 * time.Millisecond
	_, err := e.Exchange(context.Background())
	require.Error(t, err)
}

func TestNewClientBearerPerCall(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/user/self", r.URL.Path)
		assert.Equal(t, "Bearer dt-session", r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("X-Api-Key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"username":"svc:sbom-operator"}`))
	})

	g := NewDependencyTrackTarget(srv.URL, "", "", "", "", "", "", "tag", "", "", "", false, false, "", false).
		WithWorkloadIdentity(writeTokenFile(t, testJwt), "kubernetes", "sbom-operator")
	require.NoError(t, g.Initialize())

	for i := 0; i < 2; i++ {
		client, err := g.newClient(context.Background())
		require.NoError(t, err)
		_, err = client.User.GetSelf(context.Background())
		require.NoError(t, err)
	}
	assert.Equal(t, 2, rec.hits)
}

func TestNewClientApiKeyUnchanged(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "apikey", r.Header.Get("X-Api-Key"))
		assert.Empty(t, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"username":"svc:sbom-operator"}`))
	})

	g := NewDependencyTrackTarget(srv.URL, "apikey", "", "", "", "", "", "tag", "", "", "", false, false, "", false)
	require.NoError(t, g.Initialize())

	client, err := g.newClient(context.Background())
	require.NoError(t, err)
	_, err = client.User.GetSelf(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, rec.hits)
}

func TestSubjectIssuedAt(t *testing.T) {
	assert.Equal(t, int64(1700000000), subjectIssuedAt(testJwt))
	assert.Equal(t, int64(0), subjectIssuedAt("not-a-jwt"))
}

func TestExchangeBaseUrlPathPrefix(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(`{"access_token":"dt-session"}`))
	}))
	defer srv.Close()

	_, err := newTokenExchanger(srv.URL+"/dtrack/", writeTokenFile(t, testJwt), "kubernetes", "sbom-operator").Exchange(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "/dtrack/api/v2/oauth/token", path)
}

func TestExchangeErrorsDoNotLeakTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		// A proxy answering with plain text that echoes the request.
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("RBAC: access denied " + r.PostForm.Get("subject_token")))
	}))
	defer srv.Close()

	_, err := newTokenExchanger(srv.URL, writeTokenFile(t, testJwt), "kubernetes", "sbom-operator").Exchange(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.NotContains(t, err.Error(), testJwt)
}

func TestNewClientConcurrent(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, nil)

	g := NewDependencyTrackTarget(srv.URL, "", "", "", "", "", "", "tag", "", "", "", false, false, "", false).
		WithWorkloadIdentity(writeTokenFile(t, testJwt), "kubernetes", "sbom-operator")
	require.NoError(t, g.Initialize())

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := g.newClient(context.Background())
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Equal(t, 10, rec.hits)
}

func TestNewClientDoesNotStoreSession(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, nil)

	g := NewDependencyTrackTarget(srv.URL, "", "", "", "", "", "", "tag", "", "", "", false, false, "", false).
		WithWorkloadIdentity(writeTokenFile(t, testJwt), "kubernetes", "sbom-operator")
	require.NoError(t, g.Initialize())

	_, err := g.newClient(context.Background())
	require.NoError(t, err)
	assert.Len(t, g.clientOptions, 0)
	// ProcessSbom logs the target with %v at debug verbosity.
	assert.NotContains(t, fmt.Sprintf("%v", g), "dt-session")
	assert.NotContains(t, fmt.Sprintf("%v", g), testJwt)
}

func TestJwtHeaderTransportClonesRequest(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("x-workload-token"))
	}))
	defer srv.Close()

	file := writeTokenFile(t, "first")
	srvUrl, err := url.Parse(srv.URL)
	require.NoError(t, err)
	transport := &jwtHeaderTransport{header: "x-workload-token", tokenFile: file, host: srvUrl.Host, base: http.DefaultTransport}

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	res, err := transport.RoundTrip(req)
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Empty(t, req.Header.Get("x-workload-token"))

	// The kubelet rotates the token between requests.
	require.NoError(t, os.WriteFile(file, []byte("second"), 0600))
	req, err = http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	res, err = transport.RoundTrip(req)
	require.NoError(t, err)
	_ = res.Body.Close()

	assert.Equal(t, []string{"first", "second"}, got)
}

func TestExchangeSendsJwtHeader(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, nil)
	e := newTokenExchanger(srv.URL, writeTokenFile(t, testJwt), "kubernetes", "sbom-operator")
	e.jwtHeader = testJwtHeader

	_, err := e.Exchange(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{testJwt}, rec.jwtHeaders["/api/v2/oauth/token"])
	assert.Equal(t, []string{testJwt}, rec.subjectTokens)
}

func TestExchangeNoJwtHeaderByDefault(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, nil)

	_, err := newTokenExchanger(srv.URL, writeTokenFile(t, testJwt), "kubernetes", "sbom-operator").Exchange(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{""}, rec.jwtHeaders["/api/v2/oauth/token"])
}

type countingTransport struct{ calls int }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls++
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

func TestJwtHeaderTransportMissingOrEmptyFile(t *testing.T) {
	for _, file := range []string{filepath.Join(t.TempDir(), "does-not-exist"), writeTokenFile(t, " \n")} {
		base := &countingTransport{}
		tr := &jwtHeaderTransport{header: testJwtHeader, tokenFile: file, host: "dtrack.invalid", base: base}
		req, err := http.NewRequest(http.MethodGet, "http://dtrack.invalid/api/version", nil)
		require.NoError(t, err)

		_, err = tr.RoundTrip(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), file)
		assert.Equal(t, 0, base.calls)
	}
}

func TestNewClientJwtHeaderPerRequest(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer dt-session", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"username":"svc:sbom-operator"}`))
	})
	file := writeTokenFile(t, testJwt)
	g := NewDependencyTrackTarget(srv.URL, "", "", "", "", "", "", "tag", "", "", "", false, false, "", false).
		WithWorkloadIdentity(file, "kubernetes", "sbom-operator").
		WithWorkloadIdentityJwtHeader(testJwtHeader)
	require.NoError(t, g.Initialize())

	client, err := g.newClient(context.Background())
	require.NoError(t, err)
	_, err = client.User.GetSelf(context.Background())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, []byte("d.e.f"), 0600))
	_, err = client.User.GetSelf(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{testJwt}, rec.jwtHeaders["/api/v2/oauth/token"])
	assert.NotEmpty(t, rec.jwtHeaders["/api/version"])
	for _, v := range rec.jwtHeaders["/api/version"] {
		assert.NotEmpty(t, v)
	}
	assert.Equal(t, []string{testJwt, "d.e.f"}, rec.jwtHeaders["/api/v1/user/self"])
}

func TestNewClientNoJwtHeaderByDefault(t *testing.T) {
	rec := &exchangeRecorder{}
	srv := newExchangeServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"username":"svc:sbom-operator"}`))
	})
	g := NewDependencyTrackTarget(srv.URL, "", "", "", "", "", "", "tag", "", "", "", false, false, "", false).
		WithWorkloadIdentity(writeTokenFile(t, testJwt), "kubernetes", "sbom-operator")
	require.NoError(t, g.Initialize())

	client, err := g.newClient(context.Background())
	require.NoError(t, err)
	_, err = client.User.GetSelf(context.Background())
	require.NoError(t, err)

	for path, values := range rec.jwtHeaders {
		for _, v := range values {
			assert.Empty(t, v, path)
		}
	}
}

func TestExchangeErrorFieldNotEchoed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"denied ` + r.PostForm.Get("subject_token") + `"}`))
	}))
	defer srv.Close()

	_, err := newTokenExchanger(srv.URL, writeTokenFile(t, testJwt), "kubernetes", "sbom-operator").Exchange(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.NotContains(t, err.Error(), testJwt)
}

func TestExchangeDoesNotFollowRedirects(t *testing.T) {
	rec := &exchangeRecorder{}
	other := newExchangeServer(t, rec, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	_, err := newTokenExchanger(srv.URL, writeTokenFile(t, testJwt), "kubernetes", "sbom-operator").Exchange(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "307")
	assert.Equal(t, 0, rec.hits)
}

func TestJwtHeaderTransportOnlyForBaseHost(t *testing.T) {
	var got []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get(testJwtHeader))
	})
	own := httptest.NewServer(handler)
	defer own.Close()
	other := httptest.NewServer(handler)
	defer other.Close()

	ownUrl, err := url.Parse(own.URL)
	require.NoError(t, err)
	tr := &jwtHeaderTransport{header: testJwtHeader, tokenFile: writeTokenFile(t, testJwt), host: ownUrl.Host, base: http.DefaultTransport}
	for _, target := range []string{own.URL, other.URL} {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		require.NoError(t, err)
		res, err := tr.RoundTrip(req)
		require.NoError(t, err)
		_ = res.Body.Close()
	}
	assert.Equal(t, []string{testJwt, ""}, got)
}
