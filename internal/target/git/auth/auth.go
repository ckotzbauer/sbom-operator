package auth

import "github.com/go-git/go-git/v5/plumbing/transport"

type GitAuthenticator interface {
	IsAvailable() bool
	ResolveAuth() (transport.AuthMethod, error)
}
