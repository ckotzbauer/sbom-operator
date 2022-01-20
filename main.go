package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime"

	"github.com/ckotzbauer/sbom-git-operator/internal"
	"github.com/ckotzbauer/sbom-git-operator/internal/daemon"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Version sets the current Operator version
	Version = "0.0.1"
	Commit  = "main"
	Date    = ""
	BuiltBy = ""

	verbosity  string
	daemonCron string

	rootCmd = &cobra.Command{
		Use:              "sbom-git-operator",
		Short:            "An operator for cataloguing all k8s-cluster-images to git.",
		PersistentPreRun: internal.BindFlags,
		Run: func(cmd *cobra.Command, args []string) {
			internal.SetUpLogs(os.Stdout, verbosity)
			printVersion()

			daemon.Start(viper.GetString("cron"))

			logrus.Info("Webserver is running at port 8080")
			http.HandleFunc("/health", health)
			logrus.WithError(http.ListenAndServe(":8080", nil)).Fatal("Starting webserver failed!")
		},
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&verbosity, "verbosity", "v", logrus.InfoLevel.String(), "Log-level (debug, info, warn, error, fatal, panic)")
	rootCmd.PersistentFlags().StringVarP(&daemonCron, "cron", "c", "@hourly", "Backround-Service interval (CRON)")
	rootCmd.PersistentFlags().String("git-workingtree", "/work", "Directory to place the git-repo.")
	rootCmd.PersistentFlags().String("git-repository", "", "Git-Repository-URL (HTTPS).")
	rootCmd.PersistentFlags().String("git-branch", "main", "Git-Branch to checkout.")
	rootCmd.PersistentFlags().String("git-path", "", "Folder-Path inside the Git-Repository.")
	rootCmd.PersistentFlags().String("git-access-token", "", "Git-Access-Token.")
	rootCmd.PersistentFlags().String("git-author-name", "", "Author name to use for Git-Commits.")
	rootCmd.PersistentFlags().String("git-author-email", "", "Author email to use for Git-Commits.")
	rootCmd.PersistentFlags().String("pod-label-selector", "", "Kubernetes Label-Selector for pods.")
	rootCmd.PersistentFlags().String("namespace-label-selector", "", "Kubernetes Label-Selector for namespaces.")
}

func initConfig() {
	viper.SetEnvPrefix("SGO")
	viper.AutomaticEnv()
}

func printVersion() {
	logrus.Info(fmt.Sprintf("Version: %s", Version))
	logrus.Info(fmt.Sprintf("Commit: %s", Commit))
	logrus.Info(fmt.Sprintf("Buit at: %s", Date))
	logrus.Info(fmt.Sprintf("Buit by: %s", BuiltBy))
	logrus.Info(fmt.Sprintf("Go Version: %s", runtime.Version()))
}

func health(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)
	fmt.Fprint(w, "Running!")
}

func main() {
	rootCmd.Execute()
}
