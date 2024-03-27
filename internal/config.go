package internal

type Config struct {
	Cron                             string   `yaml:"cron" env:"SBOM_CRON" flag:"cron"`
	Format                           string   `yaml:"format" env:"SBOM_FORMAT" flag:"format"`
	Targets                          []string `yaml:"targets" env:"SBOM_TARGETS" flag:"targets"`
	IgnoreAnnotations                bool     `yaml:"ignoreAnnotations" env:"SBOM_IGNORE_ANNOTATIONS" flag:"ignore-annotations"`
	GitWorkingTree                   string   `yaml:"gitWorkingTree" env:"SBOM_GIT_WORKINGTREE" flag:"git-workingtree"`
	GitRepository                    string   `yaml:"gitRepository" env:"SBOM_GIT_REPOSITORY" flag:"git-repository"`
	GitBranch                        string   `yaml:"gitBranch" env:"SBOM_GIT_BRANCH" flag:"git-branch"`
	GitPath                          string   `yaml:"gitPath" env:"SBOM_GIT_PATH" flag:"git-path"`
	GitAccessToken                   string   `yaml:"gitAccessToken" env:"SBOM_GIT_ACCESS_TOKEN" flag:"git-access-token"`
	GitUserName                      string   `yaml:"gitUserName" env:"SBOM_GIT_USERNAME" flag:"git-username"`
	GitPassword                      string   `yaml:"gitPassword" env:"SBOM_GIT_PASSWORD" flag:"git-password"`
	GitAuthorName                    string   `yaml:"gitAuthorName" env:"SBOM_GIT_AUTHOR_NAME" flag:"git-author-name"`
	GitAuthorEmail                   string   `yaml:"gitAuthorEmail" env:"SBOM_GIT_AUTHOR_EMAIL" flag:"git-author-email"`
	GitHubAppId                      string   `yaml:"githubAppId" env:"SBOM_GITHUB_APP_ID" flag:"github-app-id"`
	GitHubAppInstallationId          string   `yaml:"githubAppInstallationId" env:"SBOM_GITHUB_APP_INSTALLATION_ID" flag:"github-app-installation-id"`
	GitHubPrivateKey                 string   `yaml:"githubAppPrivateKey" env:"SBOM_GITHUB_APP_PRIVATE_KEY"`
	PodLabelSelector                 string   `yaml:"podLabelSelector" env:"SBOM_POD_LABEL_SELECTOR" flag:"pod-label-selector"`
	NamespaceLabelSelector           string   `yaml:"namespaceLabelSelector" env:"SBOM_NAMESPACE_LABEL_SELECTOR" flag:"namespace-label-selector"`
	DeleteOrphanProjects             bool     `yaml:"deleteOrphanProjects" env:"SBOM_DELETRE_ORPHAN_PROJECTS" flag:"delete-orphan-projects"`
	DtrackBaseUrl                    string   `yaml:"dtrackBaseUrl" env:"SBOM_DTRACK_BASE_URL" flag:"dtrack-base-url"`
	DtrackApiKey                     string   `yaml:"dtrackApiKey" env:"SBOM_DTRACK_API_KEY" flag:"dtrack-api-key"`
	DtrackLabelTagMatcher            string   `yaml:"dtrackLabelTagMatcher" env:"SBOM_DTRACK_LABEL_TAG_MATCHER" flag:"dtrack-label-tag-matcher"`
	DtrackCaCertFile                 string   `yaml:"dtrackCaCertFile" env:"SBOM_DTRACK_CA_CERT_FILE" flag:"dtrack-ca-cert-file"`
	DtrackClientCertFile             string   `yaml:"dtrackClientCertFile" env:"SBOM_DTRACK_CLIENT_CERT_FILE" flag:"dtrack-client-cert-file"`
	DtrackClientKeyFile              string   `yaml:"dtrackClientKeyFile" env:"SBOM_DTRACK_CLIENT_KEY_FILE" flag:"dtrack-client-key-file"`
	DtrackParentProjectAnnotationKey string   `yaml:"dtrackParentProjectAnnotationKey" env:"SBOM_DTRACK_PARENT_PROJECT_ANNOTATION_KEY" flag:"dtrack-parent-project-annotation-key"`
	DtrackProjectNameAnnotationKey   string   `yaml:"dtrackProjectNameAnnotationKey" env:"SBOM_DTRACK_PROJECT_NAME_ANNOTATION_KEY" flag:"dtrack-project-name-annotation-key"`
	KubernetesClusterId              string   `yaml:"kubernetesClusterId" env:"SBOM_KUBERNETES_CLUSTER_ID" flag:"kubernetes-cluster-id"`
	JobImage                         string   `yaml:"jobImage" env:"SBOM_JOB_IMAGE" flag:"job-image"`
	JobImagePullSecret               string   `yaml:"jobImagePullSecret" env:"SBOM_JOB_IMAGE_PULL_SECRET" flag:"job-image-pull-secret"`
	JobTimeout                       int64    `yaml:"jobTimeout" env:"SBOM_JOB_TIMEOUT" flag:"job-timeout"`
	OciRegistry                      string   `yaml:"ociRegistry" env:"SBOM_OCI_REGISTRY" flag:"oci-registry"`
	OciUser                          string   `yaml:"ociUser" env:"SBOM_OCI_USER" flag:"oci-user"`
	OciToken                         string   `yaml:"ociToken" env:"SBOM_OCI_TOKEN" flag:"oci-token"`
	FallbackPullSecret               string   `yaml:"fallbackPullSecret" env:"SBOM_FALLBACK_PULL_SECRET" flag:"fallback-pull-secret"`
	RegistryProxies                  []string `yaml:"registryProxy" env:"SBOM_REGISTRY_PROXY" flag:"registry-proxy"`
	Verbosity                        string   `env:"SBOM_VERBOSITY" flag:"verbosity"`
}

var (
	ConfigKeyCron                    = "cron"
	ConfigKeyFormat                  = "format"
	ConfigKeyTargets                 = "targets"
	ConfigKeyIgnoreAnnotations       = "ignore-annotations"
	ConfigKeyGitWorkingTree          = "git-workingtree"
	ConfigKeyGitRepository           = "git-repository"
	ConfigKeyGitBranch               = "git-branch"
	ConfigKeyGitPath                 = "git-path"
	ConfigKeyGitAccessToken          = "git-access-token"
	ConfigKeyGitUserName             = "git-username"
	ConfigKeyGitPassword             = "git-password"
	ConfigKeyGitAuthorName           = "git-author-name"
	ConfigKeyGitAuthorEmail          = "git-author-email"
	ConfigKeyGitHubAppId             = "github-app-id"
	ConfigKeyGitHubAppInstallationId = "github-app-installation-id"
	ConfigKeyPodLabelSelector        = "pod-label-selector"
	ConfigKeyNamespaceLabelSelector  = "namespace-label-selector"
	ConfigKeyDeleteOrphanProjects    = "delete-orphan-projects"
	ConfigKeyDependencyTrackBaseUrl  = "dtrack-base-url"
	/* #nosec */
	ConfigKeyDependencyTrackApiKey                           = "dtrack-api-key"
	ConfigKeyDependencyTrackLabelTagMatcher                  = "dtrack-label-tag-matcher"
	ConfigKeyDependencyTrackCaCertFile                       = "dtrack-ca-cert-file"
	ConfigKeyDependencyTrackClientCertFile                   = "dtrack-client-cert-file"
	ConfigKeyDependencyTrackClientKeyFile                    = "dtrack-client-key-file"
	ConfigKeyDependencyTrackDtrackParentProjectAnnotationKey = "dtrack-parent-project-annotation-key"
	ConfigKeyDependencyTrackDtrackProjectNameAnnotationKey   = "dtrack-project-name-annotation-key"
	ConfigKeyKubernetesClusterId                             = "kubernetes-cluster-id"
	ConfigKeyJobImage                                        = "job-image"
	/* #nosec */
	ConfigKeyJobImagePullSecret = "job-image-pull-secret"
	ConfigKeyJobTimeout         = "job-timeout"
	ConfigKeyOciRegistry        = "oci-registry"
	ConfigKeyOciUser            = "oci-user"
	ConfigKeyOciToken           = "oci-token"
	ConfigKeyFallbackPullSecret = "fallback-pull-secret"
	ConfigKeyRegistryProxy      = "registry-proxy"

	OperatorConfig *Config
)
