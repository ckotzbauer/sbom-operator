package target

type Target interface {
	Initialize()
	ValidateConfig() error
	ProcessSboms(imageID string)
	Cleanup(allImages []string)
}
