package git

import (
	"errors"
	"os"
	"time"

	"github.com/ckotzbauer/sbom-operator/internal/target/git/auth"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/sirupsen/logrus"
)

var authenticators []auth.GitAuthenticator

type GitAccount struct {
	Token                   string
	GitHubAppID             string
	GitHubAppInstallationID string
	GitHubAppPrivateKey     string
	Name                    string
	Email                   string
}

func New(token, name, email, githubAppID, githubAppInstallationID, githubAppPrivateKey string) GitAccount {
	authenticators = []auth.GitAuthenticator{
		&auth.TokenGitAuthenticator{Token: token},
		&auth.GitHubAuthenticator{AppID: githubAppID, AppInstallationID: githubAppInstallationID, PrivateKey: githubAppPrivateKey},
	}

	return GitAccount{Token: token, Name: name, Email: email}
}

func (g *GitAccount) alreadyCloned(path string) (*git.Repository, error) {
	r, err := git.PlainOpen(path)

	if err == git.ErrRepositoryNotExists {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return r, nil
}

func (g *GitAccount) PrepareRepository(repo, path, branch string) {
	r, err := g.alreadyCloned(path)
	cloned := false

	if r == nil && err == nil {
		cloned = true
		auth, err := g.resolveAuth()
		if err != nil {
			logrus.WithError(err).Error("Auth failed")
			return
		}

		r, err = git.PlainClone(path, false, &git.CloneOptions{URL: repo, Progress: os.Stdout, Auth: auth})
		if err != nil {
			logrus.WithError(err).Error("Clone failed")
			return
		}
	} else if err != nil {
		logrus.WithError(err).Error("Open failed")
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

	if !cloned {
		auth, err := g.resolveAuth()
		if err != nil {
			logrus.WithError(err).Error("Auth failed")
			return
		}

		err = w.Pull(&git.PullOptions{ReferenceName: plumbing.NewBranchReferenceName(branch), Auth: auth})
		if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
			logrus.WithError(err).Error("Pull failed")
			return
		}
	}

	logrus.Debug("Git-Repository is prepared!")
}

func (g *GitAccount) openExistingRepo(path string) (*git.Repository, *git.Worktree) {
	r, err := git.PlainOpen(path)

	if err != nil {
		logrus.WithError(err).Error("Open failed")
		return nil, nil
	}

	w, err := r.Worktree()

	if err != nil {
		logrus.WithError(err).Error("Worktree failed")
		return nil, nil
	}

	return r, w
}

func (g *GitAccount) CommitAll(path, message string) error {
	r, w := g.openExistingRepo(path)

	if r == nil && w == nil {
		return nil
	}

	status, err := w.Status()

	if err != nil {
		logrus.WithError(err).Error("Status failed")
		return err
	}

	if status.IsClean() {
		logrus.Debug("Git-Worktree is clean, skip commit")
		return nil
	}

	_, err = w.Add(".")

	if err != nil {
		logrus.WithError(err).Error("Add failed")
		return err
	}

	return g.commitAndPush(w, r, message)
}

func (g *GitAccount) Remove(workTree, path string) error {
	r, w := g.openExistingRepo(workTree)

	if r == nil && w == nil {
		return nil
	}

	_, err := w.Remove(path)
	return err
}

func (g *GitAccount) CommitAndPush(path, message string) error {
	r, w := g.openExistingRepo(path)

	if r == nil && w == nil {
		return nil
	}

	status, err := w.Status()

	if err != nil {
		logrus.WithError(err).Error("Status failed")
		return err
	}

	if status.IsClean() {
		logrus.Debug("Git-Worktree is clean, skip commit")
		return nil
	}

	return g.commitAndPush(w, r, message)
}

func (g *GitAccount) commitAndPush(w *git.Worktree, r *git.Repository, message string) error {
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
		return err
	}

	auth, err := g.resolveAuth()
	if err != nil {
		logrus.WithError(err).Error("Auth failed")
		return err
	}

	err = r.Push(&git.PushOptions{Auth: auth})
	if err != nil {
		logrus.WithError(err).Error("Push failed")
		return err
	}

	logrus.Info("Push was successful")
	return nil
}

func (g *GitAccount) resolveAuth() (transport.AuthMethod, error) {
	for _, authenticator := range authenticators {
		if authenticator.IsAvailable() {
			resolved, err := authenticator.ResolveAuth()
			if err != nil {
				return nil, err
			}

			return resolved, nil
		}
	}

	return nil, nil
}
