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

test-registries:
	go test github.com/ckotzbauer/sbom-operator/internal/registry -coverprofile cover-registries.out

test:
	go test $(shell go list ./... | grep -v sbom-operator/internal/registry) -coverprofile cover.out
