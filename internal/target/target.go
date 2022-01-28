package target

type Target interface {
	Initialize()
	ValidateConfig() error
	ProcessSbom(imageID, sbom string)
	Cleanup(allImages []string)
}
