package git

import (
	"os"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/sirupsen/logrus"
)

type GitAccount struct {
	Token string
	Name  string
	Email string
}

func New(token, name, email string) GitAccount {
	return GitAccount{Token: token, Name: name, Email: email}
}

func (g *GitAccount) Clone(repo, path, branch string) {
	// TODO: Detect if repo is already cloned and skip it in that case.

	r, err := git.PlainClone(path, false, &git.CloneOptions{
		URL:      repo,
		Depth:    1,
		Progress: os.Stdout,
		Auth:     g.tokenAuth(),
	})

	if err != nil {
		logrus.WithError(err).Error("Clone failed")
		return
	}

	w, err := r.Worktree()

	if err != nil {
		logrus.WithError(err).Error("Worktree failed")
		return
	}

	err = w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName(branch),
	})

	if err != nil {
		logrus.WithError(err).Error("Checkout failed")
		return
	}

	// TODO: msg="Pull failed" error="empty git-upload-pack given"
	err = w.Pull(&git.PullOptions{
		Auth: g.tokenAuth(),
	})

	if err != nil {
		logrus.WithError(err).Error("Pull failed")
	}

	logrus.Info("Git-Repository is prepared!")
}

func (g *GitAccount) CommitAll(path, message string) {
	r, err := git.PlainOpen(path)

	if err != nil {
		logrus.WithError(err).Error("Open failed")
		return
	}

	w, err := r.Worktree()

	if err != nil {
		logrus.WithError(err).Error("Worktree failed")
		return
	}

	status, err := w.Status()

	if err != nil {
		logrus.WithError(err).Error("Status failed")
		return
	}

	if status.IsClean() {
		logrus.Info("Git-Worktree is clean")
		return
	}

	_, err = w.Add(".")

	if err != nil {
		logrus.WithError(err).Error("Add failed")
		return
	}

	commit, err := w.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  g.Name,
			Email: g.Email,
			When:  time.Now(),
		},
	})

	logrus.Infof("Created commit %s", commit.String())

	if err != nil {
		logrus.WithError(err).Error("Commit failed")
		return
	}

	err = r.Push(&git.PushOptions{
		Auth: g.tokenAuth(),
	})

	if err != nil {
		logrus.WithError(err).Error("Push failed")
	}

	logrus.Info("Push was successful")
}

func (g *GitAccount) tokenAuth() transport.AuthMethod {
	return &http.BasicAuth{
		Username: "<token>", // this can be anything except an empty string
		Password: g.Token,
	}
}
