package internal

var (
	ConfigKeyVerbosity              = "verbosity"
	ConfigKeyCron                   = "cron"
	ConfigKeyFormat                 = "format"
	ConfigKeyTargets                = "targets"
	ConfigKeyIgnoreAnnotations      = "ignore-annotations"
	ConfigKeyGitWorkingTree         = "git-workingtree"
	ConfigKeyGitRepository          = "git-repository"
	ConfigKeyGitBranch              = "git-branch"
	ConfigKeyGitPath                = "git-path"
	ConfigKeyGitAccessToken         = "git-access-token"
	ConfigKeyGitAuthorName          = "git-author-name"
	ConfigKeyGitAuthorEmail         = "git-author-email"
	ConfigKeyPodLabelSelector       = "pod-label-selector"
	ConfigKeyNamespaceLabelSelector = "namespace-label-selector"
	ConfigKeyDependencyTrackBaseUrl = "dtrack-base-url"
	/* #nosec */
	ConfigKeyDependencyTrackApiKey = "dtrack-api-key"
	ConfigKeyKubernetesClusterId   = "kubernetes-cluster-id"
	ConfigKeyJobImage              = "job-image"
	/* #nosec */
	ConfigKeyJobImagePullSecret = "job-image-pull-secret"
	ConfigKeyJobTimeout         = "job-timeout"
	ConfigKeyOciRegistry        = "oci-registry"
	ConfigKeyOciUser            = "oci-user"
	ConfigKeyOciToken           = "oci-token"
	ConfigKeyFallbackPullSecret = "fallback-pull-secret"
)
