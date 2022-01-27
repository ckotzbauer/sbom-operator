package target

type Target interface {
	Initialize()
	ValidateConfig() error
	ProcessSboms(namespace string)
	Cleanup(allImages []string)
}
