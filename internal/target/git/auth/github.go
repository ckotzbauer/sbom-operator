package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/golang-jwt/jwt"
)

var (
	githubURL = "https://api.github.com/app/installations"
)

type gitHubToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type GitHubAuthenticator struct {
	AppID             string
	AppInstallationID string
	PrivateKey        string
	currentToken      *gitHubToken
}

func (g *GitHubAuthenticator) IsAvailable() bool {
	return g.AppID != "" && g.AppInstallationID != "" && g.PrivateKey != ""
}

func (g *GitHubAuthenticator) ResolveAuth() (*githttp.BasicAuth, error) {
	if g.currentToken == nil || g.currentToken.ExpiresAt.Before(time.Now().Add(1*time.Minute)) {
		token, err := getGitHubToken(g.PrivateKey, g.AppID, g.AppInstallationID)
		if err != nil {
			return nil, err
		}

		g.currentToken = token
	}

	return &githttp.BasicAuth{Username: "<token>", Password: g.currentToken.Token}, nil
}

func issueJWTFromPEM(key *rsa.PrivateKey, appID string) (string, error) {
	claims := &jwt.StandardClaims{
		IssuedAt:  time.Now().Add(-1 * time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Minute * 5).Unix(),
		Issuer:    appID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("cannot retrieve signed string: %w", err)
	}

	return ss, nil
}

func getInstallationToken(jwtToken, appInstallationID string) (*gitHubToken, error) {
	url := strings.Join([]string{githubURL, appInstallationID, "access_tokens"}, "/")
	responseBody := gitHubToken{}
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create new request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwtToken))
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request execution failed: %w", err)
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if res.StatusCode < 200 || res.StatusCode > 300 {
		return nil, fmt.Errorf("unexpected http-status %v: %s", res.StatusCode, string(b))
	}

	if err := json.Unmarshal(b, &responseBody); err != nil {
		return nil, fmt.Errorf("cannot unmarshal response: %w", err)
	}

	return &responseBody, nil
}

func loadPEMFromBytes(key []byte) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode(key)
	if b != nil {
		key = b.Bytes
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key: %w", err)
	}

	return parsedKey, nil
}

func getGitHubToken(privateKey, appID, appInstallationID string) (*gitHubToken, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private-key from base64: %w", err)
	}

	key, err := loadPEMFromBytes(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load PEM: %w", err)
	}

	jwtToken, err := issueJWTFromPEM(key, appID)
	if err != nil {
		return nil, fmt.Errorf("failed issue a jwt from PEM: %w", err)
	}

	token, err := getInstallationToken(jwtToken, appInstallationID)
	if err != nil {
		return nil, fmt.Errorf("unable to get installation-token: %w", err)
	}

	return token, nil
}
