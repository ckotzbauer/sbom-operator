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

func (g *GitAccount) alreadyCloned(path string) (*git.Repository, error) {
	r, err := git.PlainOpen(path)

	if err == git.ErrRepositoryNotExists {
		return nil, nil
	}

	return r, nil
}

func (g *GitAccount) PrepareRepository(repo, path, branch string) {
	r, err := g.alreadyCloned(path)
	cloned := false

	if r == nil && err == nil {
		cloned = true
		r, err = git.PlainClone(path, false, &git.CloneOptions{
			URL:      repo,
			Depth:    1,
			Progress: os.Stdout,
			Auth:     g.tokenAuth(),
		})
	}

	if err != nil {
		logrus.WithError(err).Error("Open or clone failed")
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
		// TODO: msg="Pull failed" error="empty git-upload-pack given"
		err = w.Pull(&git.PullOptions{
			Auth: g.tokenAuth(),
		})

		if err != nil {
			logrus.WithError(err).Error("Pull failed")
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

func (g *GitAccount) CommitAll(path, message string) {
	r, w := g.openExistingRepo(path)

	if r == nil && w == nil {
		return
	}

	status, err := w.Status()

	if err != nil {
		logrus.WithError(err).Error("Status failed")
		return
	}

	if status.IsClean() {
		logrus.Debug("Git-Worktree is clean, skip commit")
		return
	}

	_, err = w.Add(".")

	if err != nil {
		logrus.WithError(err).Error("Add failed")
		return
	}

	g.commitAndPush(w, r, message)
}

func (g *GitAccount) Remove(workTree, path string) {
	r, w := g.openExistingRepo(workTree)

	if r == nil && w == nil {
		return
	}

	_, err := w.Remove(path)

	if err != nil {
		logrus.WithError(err).Error("Remove failed")
		return
	}
}

func (g *GitAccount) CommitAndPush(path, message string) {
	r, w := g.openExistingRepo(path)

	if r == nil && w == nil {
		return
	}

	status, err := w.Status()

	if err != nil {
		logrus.WithError(err).Error("Status failed")
		return
	}

	if status.IsClean() {
		logrus.Debug("Git-Worktree is clean, skip commit")
		return
	}

	g.commitAndPush(w, r, message)
}

func (g *GitAccount) commitAndPush(w *git.Worktree, r *git.Repository, message string) {
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
