package target

type Target interface {
	ProcessSboms(sbomFiles []string, namespace string)
	Cleanup()
}
