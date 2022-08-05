TEMPDIR = ./.tmp
LINTCMD = $(TEMPDIR)/golangci-lint run --timeout 5m
GOSECCMD = $(TEMPDIR)/gosec ./...

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

lint:
	$(LINTCMD)

lintsec:
	$(GOSECCMD)

$(TEMPDIR):
	mkdir -p $(TEMPDIR)

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMPDIR)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ v1.48.0
	curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b $(TEMPDIR)/ v2.12.0
