package main

type Config struct {
	Cron string `yaml:"cron" env:"SBOM_CRON" flag:"cron"`

	IgnoreAnnotations      bool   `yaml:"ignoreAnnotations" env:"SBOM_IGNORE_ANNOTATIONS" flag:"ignoreAnnotations"`
	PodLabelSelector       string `yaml:"podLabelSelector" env:"SBOM_POD_LABEL_SELECTOR" flag:"podLabelSelector"`
	NamespaceLabelSelector string `yaml:"namespaceLabelSelector" env:"SBOM_NAMESPACE_LABEL_SELECTOR" flag:"namespaceLabelSelector"`

	JobTimeout         int64    `yaml:"jobTimeout" env:"SBOM_JOB_TIMEOUT" flag:"jobTimeout"`
	FallbackPullSecret string   `yaml:"fallbackPullSecret" env:"SBOM_FALLBACK_PULL_SECRET" flag:"fallbackPullSecret"`
	RegistryProxies    []string `yaml:"registryProxy" env:"SBOM_REGISTRY_PROXY" flag:"registryProxy"`
	Verbosity          string   `env:"SBOM_VERBOSITY" flag:"verbosity"`

	DevGuardToken  string `yaml:"devGuardToken" env:"DEVGUARD_TOKEN" flag:"token"`
	DevGuardApiURL string `yaml:"devGuardApiURL" env:"DEVGUARD_API_URL" flag:"apiUrl"`
}

var (
	ConfigKeyCron = "cron"

	ConfigKeyIgnoreAnnotations      = "ignoreAnnotations"
	ConfigKeyPodLabelSelector       = "podLabelSelector"
	ConfigKeyNamespaceLabelSelector = "namespaceLabelSelector"

	ConfigKeyJobTimeout         = "jobTimeout"
	ConfigKeyFallbackPullSecret = "fallbackPullSecret"
	ConfigKeyRegistryProxy      = "registryProxy"

	ConfigDevGuardToken  = "token"
	ConfigDevGuardApiURL = "apiUrl"

	OperatorConfig *Config
)
