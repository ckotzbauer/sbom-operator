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
	go test $(shell go list ./... | grep -v sbom-operator/internal/target/oci) -coverprofile cover.out

lintsec: gosec
	$(GOSEC) ./...

# find or download gosec
# download gosec if necessary
gosec:
ifeq (, $(shell which gosec))
	@{ \
	set -e ;\
	GOSEC_TMP_DIR=$$(mktemp -d) ;\
	cd $$GOSEC_TMP_DIR ;\
	go mod init tmp ;\
	go install github.com/securego/gosec/v2/cmd/gosec@v2.12.0 ;\
	rm -rf $$GOSEC_TMP_DIR ;\
	}
GOSEC=$(GOBIN)/gosec
else
GOSEC=$(shell which gosec)
endif

curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.46.2
