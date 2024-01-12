package main

import (
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/ckotzbauer/libstandard"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/daemon"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/processor"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// Version sets the current Operator version
	Version = "0.0.1"
	Commit  = "main"
	Date    = ""
	BuiltBy = ""
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "sbom-operator",
		Short: "An operator for cataloguing all k8s-cluster-images to multiple targets.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			internal.OperatorConfig = &internal.Config{}
			return libstandard.DefaultInitializer(internal.OperatorConfig, cmd, "sbom-operator")
		},
		Run: func(cmd *cobra.Command, args []string) {
			printVersion()

			if internal.OperatorConfig.Cron != "" {
				daemon.Start(internal.OperatorConfig.Cron)
			} else {
				k8s := kubernetes.NewClient(internal.OperatorConfig.IgnoreAnnotations, internal.OperatorConfig.FallbackPullSecret)
				sy := syft.New(internal.OperatorConfig.Format, libstandard.ToMap(internal.OperatorConfig.RegistryProxies))
				p := processor.New(k8s, sy)
				p.ListenForPods()
			}

			logrus.Info("Webserver is running at port 8080")
			http.HandleFunc("/health", health)

			server := &http.Server{
				Addr:              ":8080",
				ReadHeaderTimeout: 3 * time.Second,
			}

			logrus.WithError(server.ListenAndServe()).Fatal("Starting webserver failed!")
		},
	}

	libstandard.AddConfigFlag(rootCmd)
	libstandard.AddVerbosityFlag(rootCmd)
	rootCmd.PersistentFlags().String(internal.ConfigKeyCron, "", "Backround-Service interval (CRON)")
	rootCmd.PersistentFlags().String(internal.ConfigKeyFormat, "json", "SBOM-Format.")
	rootCmd.PersistentFlags().StringSlice(internal.ConfigKeyTargets, []string{"git"}, "Targets for created SBOMs (git, dtrack, oci, configmap).")
	rootCmd.PersistentFlags().Bool(internal.ConfigKeyIgnoreAnnotations, false, "Force analyzing of all images, including those from annotated pods.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitWorkingTree, "/work", "Directory to place the git-repo.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitRepository, "", "Git-Repository-URL (HTTPS).")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitBranch, "main", "Git-Branch to checkout.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitPath, "", "Folder-Path inside the Git-Repository.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitAccessToken, "", "Git-Access-Token.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitUserName, "", "Git-Username.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitPassword, "", "Git-Password.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitAuthorName, "", "Author name to use for Git-Commits.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitAuthorEmail, "", "Author email to use for Git-Commits.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitHubAppId, "", "GitHub App ID (for authentication).")
	rootCmd.PersistentFlags().String(internal.ConfigKeyGitHubAppInstallationId, "", "GitHub App Installation ID (for authentication).")
	rootCmd.PersistentFlags().String(internal.ConfigKeyPodLabelSelector, "", "Kubernetes Label-Selector for pods.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyNamespaceLabelSelector, "", "Kubernetes Label-Selector for namespaces.")
	rootCmd.PersistentFlags().Bool(internal.ConfigKeyDeleteOrphanProjects, true, "Set to false to disable automatic removal of orphan projects")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackBaseUrl, "", "Dependency-Track base URL, e.g. 'https://dtrack.example.com'")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackApiKey, "", "Dependency-Track API key")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackLabelTagMatcher, "", "Dependency-Track Pod-Label-Tag matcher regex")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackDtrackParentProjectAnnotationKey, "", "Dependency-Track: kubernetes annotation-key for setting parent project")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackDtrackProjectNameAnnotationKey, "", "Dependency-Track: kubernetes annotation-key for setting custom project name")
	rootCmd.PersistentFlags().String(internal.ConfigKeyKubernetesClusterId, "default", "Kubernetes Cluster ID")
	rootCmd.PersistentFlags().String(internal.ConfigKeyJobImage, "", "Custom Job-Image")
	rootCmd.PersistentFlags().String(internal.ConfigKeyJobImagePullSecret, "", "Custom Job-Image-Pull-Secret")
	rootCmd.PersistentFlags().String(internal.ConfigKeyFallbackPullSecret, "", "Fallback-Pull-Secret")
	rootCmd.PersistentFlags().StringSlice(internal.ConfigKeyRegistryProxy, []string{}, "Registry-Proxy")
	rootCmd.PersistentFlags().Int64(internal.ConfigKeyJobTimeout, 60*60, "Job-Timeout")
	rootCmd.PersistentFlags().String(internal.ConfigKeyOciRegistry, "", "OCI-Registry")
	rootCmd.PersistentFlags().String(internal.ConfigKeyOciUser, "", "OCI-User")
	rootCmd.PersistentFlags().String(internal.ConfigKeyOciToken, "", "OCI-Token")

	return rootCmd
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
	rootCmd := newRootCmd()
	err := rootCmd.Execute()
	if err != nil {
		panic(err)
	}
}
