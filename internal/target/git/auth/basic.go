package auth

import (
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

type BasicGitAuthenticator struct {
	UserName string
	Password string
}

func (t *BasicGitAuthenticator) IsAvailable() bool {
	return t.UserName != "" && t.Password != ""
}

func (t *BasicGitAuthenticator) ResolveAuth() (*http.BasicAuth, error) {
	return &http.BasicAuth{
		Username: t.UserName,
		Password: t.Password,
	}, nil
}
