package internal

import (
	"os"
)

var GitWorkingTree string
var GitRepository string
var GitBranch string
var GitAccessToken string
var GitAuthorName string
var GitAuthorEmail string

func Init() {
	GitWorkingTree = os.Getenv("SGO_GIT_WORKINGTREE")
	GitRepository = os.Getenv("SGO_GIT_REPOSITORY")
	GitBranch = os.Getenv("SGO_GIT_BRANCH")
	GitAccessToken = os.Getenv("SGO_GIT_ACCESS_TOKEN")
	GitAuthorName = os.Getenv("SGO_GIT_AUTHOR_NAME")
	GitAuthorEmail = os.Getenv("SGO_GIT_AUTHOR_EMAIL")
}
