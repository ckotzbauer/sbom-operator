package auth

import "github.com/go-git/go-git/v5/plumbing/transport/http"

type GitAuthenticator interface {
	IsAvailable() bool
	ResolveAuth() (*http.BasicAuth, error)
}
