package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"

	config "github.com/ckotzbauer/sbom-git-operator/internal"
	"github.com/ckotzbauer/sbom-git-operator/internal/git"
	"github.com/ckotzbauer/sbom-git-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-git-operator/internal/syft"
	"github.com/sirupsen/logrus"
)

var (
	// Version sets the current Operator version
	Version = "0.0.1"
	Commit  = "main"
	Date    = ""
	BuiltBy = ""
)

func setUpLogs(out io.Writer, level string) error {
	logrus.SetOutput(out)
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}

	logrus.SetLevel(lvl)
	return nil
}

func printVersion() {
	logrus.Info(fmt.Sprintf("Version: %s", Version))
	logrus.Info(fmt.Sprintf("Commit: %s", Commit))
	logrus.Info(fmt.Sprintf("Buit at: %s", Date))
	logrus.Info(fmt.Sprintf("Buit by: %s", BuiltBy))
	logrus.Info(fmt.Sprintf("Go Version: %s", runtime.Version()))
}

func health(w http.ResponseWriter, req *http.Request) {
	fmt.Fprint(w, "Running!")
	w.WriteHeader(200)
}

func main() {
	setUpLogs(os.Stdout, logrus.DebugLevel.String())
	printVersion()

	config.Init()

	gitAccount := git.New(config.GitAccessToken, config.GitAuthorName, config.GitAuthorEmail)
	gitAccount.Clone(config.GitRepository, config.GitWorkingTree, config.GitBranch)

	client := kubernetes.NewClient()
	pods := client.ListPods("monitoring")
	logrus.Debugf("Discovered %v pods", len(pods))
	digests := client.GetContainerDigests(pods)

	for _, d := range digests {
		syft.ExecuteSyft(d, config.GitWorkingTree)
	}

	gitAccount.CommitAll(config.GitWorkingTree, "Created new SBOMs")

	logrus.Info("Webserver is running at port 8080")
	http.HandleFunc("/health", health)
	http.Handle("/", http.FileServer(http.Dir(config.GitWorkingTree)))
	logrus.WithError(http.ListenAndServe(":8080", nil)).Fatal("Starting webserver failed!")
}
