package target

type Target interface {
	Initialize()
	ValidateConfig() error
	ProcessSboms(sbomFiles []string, namespace string)
	Cleanup()
}
