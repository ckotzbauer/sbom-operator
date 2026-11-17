package dtrack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

/* #nosec */
const (
	tokenExchangePath       = "/api/v2/oauth/token"
	tokenExchangeGrantType  = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenExchangeJwtType    = "urn:ietf:params:oauth:token-type:jwt"
	tokenExchangeMaxBodyLen = 64 * 1024
)

// oauthErrorCodePattern matches RFC 6749 error codes (e.g. invalid_request). Anything else in the
// response's error field is dropped: a proxy may echo the request, including the subject token.
var oauthErrorCodePattern = regexp.MustCompile(`^[a-z_]{1,64}$`)

// tokenExchanger exchanges a workload's platform token (e.g. a projected
// Kubernetes service account token) for a Dependency-Track session token
// using workload identity federation (RFC 8693 token exchange).
type tokenExchanger struct {
	baseUrl        string
	tokenFile      string
	provider       string
	serviceAccount string
	// jwtHeader, if set, also sends the subject token in this request header
	// (e.g. for a proxy in front of Dependency-Track that validates it).
	jwtHeader  string
	httpClient *http.Client
}

type tokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
}

func newTokenExchanger(baseUrl, tokenFile, provider, serviceAccount string) *tokenExchanger {
	return &tokenExchanger{
		baseUrl:        baseUrl,
		tokenFile:      tokenFile,
		provider:       provider,
		serviceAccount: serviceAccount,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			// A redirect would re-send the subject token, possibly to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Exchange reads the token file (it is rotated by the kubelet, so it is read
// on every call) and returns a fresh Dependency-Track session token and its
// lifetime (0 if the response has no expires_in).
func (e *tokenExchanger) Exchange(ctx context.Context) (string, time.Duration, error) {
	subjectToken, err := readTokenFile(e.tokenFile)
	if err != nil {
		return "", 0, err
	}

	form := url.Values{}
	form.Set("grant_type", tokenExchangeGrantType)
	form.Set("subject_token_type", tokenExchangeJwtType)
	form.Set("subject_token", subjectToken)
	form.Set("workload_identity_provider", e.provider)
	form.Set("service_account", e.serviceAccount)

	endpoint := strings.TrimRight(e.baseUrl, "/") + tokenExchangePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if e.jwtHeader != "" {
		req.Header.Set(e.jwtHeader, subjectToken)
	}

	res, err := e.httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(res.Body, tokenExchangeMaxBodyLen))
	if err != nil {
		return "", 0, err
	}

	// The response body is never included in errors: a proxy may echo the request.
	var parsed tokenExchangeResponse
	jsonErr := json.Unmarshal(body, &parsed)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		if oauthErrorCodePattern.MatchString(parsed.Error) {
			return "", 0, fmt.Errorf("token exchange returned status %d (error=%q)", res.StatusCode, parsed.Error)
		}
		return "", 0, fmt.Errorf("token exchange returned status %d", res.StatusCode)
	}
	if jsonErr != nil {
		return "", 0, fmt.Errorf("token exchange returned invalid JSON: %w", jsonErr)
	}
	if parsed.AccessToken == "" {
		return "", 0, fmt.Errorf("token exchange response contains no access_token")
	}

	logrus.Infof("Exchanged workload identity token (provider=%s, service-account=%s, subject-iat=%d, expires-in=%d)",
		e.provider, e.serviceAccount, subjectIssuedAt(subjectToken), parsed.ExpiresIn)
	return parsed.AccessToken, time.Duration(parsed.ExpiresIn) * time.Second, nil
}

func readTokenFile(tokenFile string) (string, error) {
	/* #nosec */
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read workload identity token file %s: %w", tokenFile, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("workload identity token file %s is empty", tokenFile)
	}
	return token, nil
}

// hostPort returns the lower-cased host of u with its port, defaulting to the scheme's port, so
// that https://h and https://h:443 compare equal. For another scheme without a port it is the
// hostname alone.
func hostPort(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return host
		}
	}
	return net.JoinHostPort(host, port)
}

// jwtHeaderTransport sets the current content of the token file as a request
// header. The file is read per request, because the kubelet rotates it. The header
// is only set for requests to host (Dependency-Track's), not on redirects elsewhere.
type jwtHeaderTransport struct {
	header    string
	tokenFile string
	host      string
	base      http.RoundTripper
}

func (t *jwtHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if hostPort(req.URL) != t.host {
		return t.base.RoundTrip(req)
	}
	token, err := readTokenFile(t.tokenFile)
	if err != nil {
		return nil, err
	}
	reqCopy := req.Clone(req.Context())
	reqCopy.Header.Set(t.header, token)
	return t.base.RoundTrip(reqCopy)
}

// sessionCache holds the current Dependency-Track session token, so that it is
// reused until shortly before it expires instead of exchanged per operation.
type sessionCache struct {
	mu        sync.Mutex
	token     string
	expiresAt time.Time
	now       func() time.Time
}

var warnNoExpiresIn sync.Once

// get returns the cached session token or exchanges a new one. The lock is held
// across the exchange, so concurrent callers wait for a single exchange.
// A failed exchange leaves the cache empty.
func (c *sessionCache) get(ctx context.Context, exchange func(context.Context) (string, time.Duration, error)) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.expiresAt) {
		return c.token, nil
	}
	c.token = ""
	// DT starts the session lifetime when it issues the token, so count from before the exchange.
	start := c.now()
	token, lifetime, err := exchange(ctx)
	if err != nil {
		return "", err
	}
	if lifetime <= 0 {
		warnNoExpiresIn.Do(func() {
			logrus.Warn("Dependency-Track sent no expires_in with the session token; exchanging a new one per operation")
		})
		return token, nil
	}
	c.token = token
	c.expiresAt = start.Add(lifetime - sessionMargin(lifetime))
	return token, nil
}

// invalidate drops the cached session, but only if token is still the cached one: a 401 for
// a session that was already replaced must not drop the newer one.
func (c *sessionCache) invalidate(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if token != "" && token == c.token {
		c.token = ""
	}
}

// sessionMargin is how long before its expiry a session is replaced, so that it
// does not expire during an operation.
func sessionMargin(lifetime time.Duration) time.Duration {
	return min(30*time.Second, lifetime/2)
}

// sessionInvalidatingTransport drops the cached session when Dependency-Track
// (host) rejects it with 401, e.g. because the DT service account was suspended,
// so that the next operation exchanges a new one. It sits below client-go's bearer
// transport, so it sees the request's Authorization header.
type sessionInvalidatingTransport struct {
	cache *sessionCache
	host  string
	base  http.RoundTripper
}

func (t *sessionInvalidatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.base.RoundTrip(req)
	if err == nil && res.StatusCode == http.StatusUnauthorized && hostPort(req.URL) == t.host {
		if token, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer "); ok {
			t.cache.invalidate(token)
		}
	}
	return res, err
}

// subjectIssuedAt returns the unverified "iat" claim of a JWT, or 0. Only used for logging.
func subjectIssuedAt(jwt string) int64 {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var claims struct {
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0
	}
	return claims.Iat
}
