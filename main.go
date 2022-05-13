package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime"

	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/daemon"
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
		Use:              "sbom-operator",
		Short:            "An operator for cataloguing all k8s-cluster-images to multiple targets.",
		PersistentPreRun: internal.BindFlags,
		Run: func(cmd *cobra.Command, args []string) {
			internal.SetUpLogs(os.Stdout, verbosity)
			printVersion()

			daemon.Start(viper.GetString(internal.ConfigKeyCron))

			logrus.Info("Webserver is running at port 8080")
			http.HandleFunc("/health", health)
			logrus.WithError(http.ListenAndServe(":8080", nil)).Fatal("Starting webserver failed!")
		},
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&verbosity, internal.ConfigKeyVerbosity, "v", logrus.InfoLevel.String(), "Log-level (debug, info, warn, error, fatal, panic)")
	rootCmd.PersistentFlags().StringVarP(&daemonCron, internal.ConfigKeyCron, "c", "@hourly", "Backround-Service interval (CRON)")
	rootCmd.PersistentFlags().String(internal.ConfigKeyFormat, "json", "SBOM-Format.")
	rootCmd.PersistentFlags().StringSlice(internal.ConfigKeyTargets, []string{"git"}, "Targets for created SBOMs (git, dtrack).")
	rootCmd.PersistentFlags().Bool(internal.ConfigKeyIgnoreAnnotations, false, "Force analyzing of all images, including those from annotated pods.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitWorkingTree, "/work", "Directory to place the git-repo.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitRepository, "", "Git-Repository-URL (HTTPS).")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitBranch, "main", "Git-Branch to checkout.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitPath, "", "Folder-Path inside the Git-Repository.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitAccessToken, "", "Git-Access-Token.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitAuthorName, "", "Author name to use for Git-Commits.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitAuthorEmail, "", "Author email to use for Git-Commits.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyPodLabelSelector, "", "Kubernetes Label-Selector for pods.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyNamespaceLabelSelector, "", "Kubernetes Label-Selector for namespaces.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackBaseUrl, "", "Dependency-Track base URL, e.g. 'https://dtrack.example.com'")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackApiKey, "", "Dependency-Track API key")
	rootCmd.PersistentFlags().String(internal.ConfigKeyKubernetesClusterId, "default", "Kubernetes Cluster ID")
	rootCmd.PersistentFlags().String(internal.ConfigKeyJobImage, "", "Custom Job-Image")
	rootCmd.PersistentFlags().String(internal.ConfigKeyJobImagePullSecret, "", "Custom Job-Image-Pull-Secret")
	rootCmd.PersistentFlags().String(internal.ConfigKeyFallbackPullSecret, "", "Custom Global-Pull-Secret")
	rootCmd.PersistentFlags().Int64(internal.ConfigKeyJobTimeout, 60*60, "Job-Timeout")
}

func initConfig() {
	viper.SetEnvPrefix("SBOM")
	viper.AutomaticEnv()
}

func printVersion() {
	logrus.Info(fmt.Sprintf("Version: %s", Version))
	logrus.Info(fmt.Sprintf("Commit: %s", Commit))
	logrus.Info(fmt.Sprintf("Built at: %s", Date))
	logrus.Info(fmt.Sprintf("Built by: %s", BuiltBy))
	logrus.Info(fmt.Sprintf("Go Version: %s", runtime.Version()))
}

func health(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)
	fmt.Fprint(w, "Running!")
}

func main() {
	rootCmd.Execute()
}
