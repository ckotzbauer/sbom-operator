package auth

import (
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

type TokenGitAuthenticator struct {
	Token string
}

func (t *TokenGitAuthenticator) IsAvailable() bool {
	return t.Token != ""
}

func (t *TokenGitAuthenticator) ResolveAuth() (transport.AuthMethod, error) {
	return &http.BasicAuth{
		Username: "<token>", // this can be anything except an empty string
		Password: t.Token,
	}, nil
}
