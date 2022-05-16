REGISTRY_USER=""
REGISTRY_TOKEN=""

all: build

build: fmt vet
	goreleaser build --rm-dist --single-target --snapshot

# Run against the configured Kubernetes cluster in ~/.kube/config
run: fmt vet
	go run ./main.go

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

test:
	go test $(shell go list ./... | grep -v sbom-operator/internal/registry | grep -v sbom-operator/internal/target) -coverprofile cover.out

test-integration:
	bash internal/target/oci/fixtures/oci-test.sh $(REGISTRY_USER) $(REGISTRY_TOKEN)
	go test github.com/ckotzbauer/sbom-operator/internal/registry -coverprofile cover-registry.out
