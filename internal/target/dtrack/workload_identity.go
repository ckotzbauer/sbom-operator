package dtrack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
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
// on every call) and returns a fresh Dependency-Track session token.
func (e *tokenExchanger) Exchange(ctx context.Context) (string, error) {
	subjectToken, err := readTokenFile(e.tokenFile)
	if err != nil {
		return "", err
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
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if e.jwtHeader != "" {
		req.Header.Set(e.jwtHeader, subjectToken)
	}

	res, err := e.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(res.Body, tokenExchangeMaxBodyLen))
	if err != nil {
		return "", err
	}

	// The response body is never included in errors: a proxy may echo the request.
	var parsed tokenExchangeResponse
	jsonErr := json.Unmarshal(body, &parsed)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		if oauthErrorCodePattern.MatchString(parsed.Error) {
			return "", fmt.Errorf("token exchange returned status %d (error=%q)", res.StatusCode, parsed.Error)
		}
		return "", fmt.Errorf("token exchange returned status %d", res.StatusCode)
	}
	if jsonErr != nil {
		return "", fmt.Errorf("token exchange returned invalid JSON: %w", jsonErr)
	}
	if parsed.AccessToken == "" {
		return "", fmt.Errorf("token exchange response contains no access_token")
	}

	logrus.Infof("Exchanged workload identity token (provider=%s, service-account=%s, subject-iat=%d)",
		e.provider, e.serviceAccount, subjectIssuedAt(subjectToken))
	return parsed.AccessToken, nil
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
	if req.URL.Host != t.host {
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
