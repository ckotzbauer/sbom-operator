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
	_ "modernc.org/sqlite" // Required for RPM database cataloging in Syft
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
			if err := libstandard.DefaultInitializer(internal.OperatorConfig, cmd, "sbom-operator"); err != nil {
				return err
			}
			// Resolve format-version through the single unified entry point.
			// Both daemon and informer paths receive the same resolved value.
			fv := syft.ResolveFormatVersionWithFamily(
				internal.OperatorConfig.Format,
				internal.OperatorConfig.FormatVersion,
			)
			if fv.Err != nil {
				logrus.WithFields(logrus.Fields{
					"format":         internal.OperatorConfig.Format,
					"format_version": internal.OperatorConfig.FormatVersion,
				}).WithError(fv.Err).Fatal("Invalid format-version configuration")
			}
			// Store resolved value in config for daemon/informer use.
			// Log effective format version for version-aware formats.
			if fv.Family != "" {
				logrus.WithFields(logrus.Fields{
					"sbom_format":  internal.OperatorConfig.Format,
					"sbom_family":  fv.Family,
					"sbom_version": fv.Version,
				}).Info("Resolved SBOM format version")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			printVersion()

			// Use the unified resolver (same result as PersistentPreRunE).
			fv := syft.ResolveFormatVersionWithFamily(
				internal.OperatorConfig.Format,
				internal.OperatorConfig.FormatVersion,
			)

			if internal.OperatorConfig.Cron != "" {
				daemon.Start(internal.OperatorConfig.Cron, Version, &fv)
			} else {
				k8s := kubernetes.NewClient(internal.OperatorConfig.IgnoreAnnotations, internal.OperatorConfig.FallbackPullSecret)
				sy := syft.New(internal.OperatorConfig.Format, libstandard.ToMap(internal.OperatorConfig.RegistryProxies), Version, &fv)
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
	rootCmd.PersistentFlags().Bool(internal.ConfigKeyDeleteOrphanImages, true, "Set to false to disable automatic removal of orphan images")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackBaseUrl, "", "Dependency-Track base URL, e.g. 'https://dtrack.example.com'")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackApiKey, "", "Dependency-Track API key")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackLabelTagMatcher, "", "Dependency-Track Pod-Label-Tag matcher regex")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDefaultParentProject, "", "Dependency-Track: Dependency-Track: Default parent project UUID")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackDtrackKubernetesClusterIdMode, "tag", "Dependency-Track: Kubernetes Cluster ID mode (tag|prefix)")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackDtrackParentProjectAnnotationKey, "", "Dependency-Track: kubernetes annotation-key for setting parent project")
	rootCmd.PersistentFlags().String(internal.ConfigKeyDependencyTrackDtrackProjectNameAnnotationKey, "", "Dependency-Track: kubernetes annotation-key for setting custom project name")
	rootCmd.PersistentFlags().Bool(internal.ConfigKeyDependencyTrackUseShortName, false, "Dependency-Track: use short image name (without registry) for project names")
	rootCmd.PersistentFlags().String(internal.ConfigKeyKubernetesClusterId, "default", "Kubernetes Cluster ID")
	rootCmd.PersistentFlags().String(internal.ConfigKeyJobImage, "", "Custom Job-Image")
	rootCmd.PersistentFlags().String(internal.ConfigKeyJobImagePullSecret, "", "Custom Job-Image-Pull-Secret")
	rootCmd.PersistentFlags().String(internal.ConfigKeyFallbackPullSecret, "", "Fallback-Pull-Secret")
	rootCmd.PersistentFlags().StringSlice(internal.ConfigKeyRegistryProxy, []string{}, "Registry-Proxy")
	rootCmd.PersistentFlags().Int64(internal.ConfigKeyJobTimeout, 60*60, "Job-Timeout")
	rootCmd.PersistentFlags().String(internal.ConfigKeyOciRegistry, "", "OCI-Registry")
	rootCmd.PersistentFlags().String(internal.ConfigKeyOciUser, "", "OCI-User")
	rootCmd.PersistentFlags().String(internal.ConfigKeyOciToken, "", "OCI-Token")
	rootCmd.PersistentFlags().String(internal.ConfigKeyFormatVersion, "", syft.FormatVersionHelp())

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
	_, err := fmt.Fprint(w, "Running!")
	if err != nil {
		logrus.WithError(err).Error("Failed to write response for health check")
	}
}

// validateFormatVersion resolves the format-version and validates it against
// the pinned Syft library.  It returns a deterministic actionable error when
// the version is unsupported.  Non-version-aware formats (json, text …)
// are accepted without error since versioning is only a CycloneDX / SPDX concern.
func validateFormatVersion(format, formatVersion string) error {
	// First check for CycloneDX family.
	fv := syft.ResolveCycloneDXFormatVersion(formatVersion)
	if fv.Family != "" {
		if fv.Err != nil {
			return fv.Err // unsupported CycloneDX version
		}
		return nil // valid CycloneDX alias or version
	}

	// Then check for SPDX family.
	spdxFv := syft.ResolveSPDXFormatVersion(formatVersion)
	if spdxFv.Family != "" {
		if spdxFv.Err != nil {
			return spdxFv.Err // unsupported SPDX version
		}
		// When a version-like string was explicitly provided (not an alias),
		// validate it against the user's requested format family.
		// E.g. "3.0" resolves to spdxjson; if the user asked for "spdx"
		// (tag-value), ValidateSPDXFormatVersion catches that 3.0 is not
		// supported by tag-value.  Shared versions (2.2, 2.3) pass because
		// they belong to both families.  Alias-only requests (no explicit
		// version string) pass through without per-family validation.
		if syft.IsVersionLike(formatVersion) {
			if userFamily := syft.ResolveSPDXFormatVersion(format).Family; userFamily != "" {
				if err := syft.ValidateSPDXFormatVersion(userFamily, spdxFv.Version); err != nil {
					return err
				}
			}
		}
		return nil // valid SPDX alias or version
	}

	return nil // not a version-aware format — no validation needed
}

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
