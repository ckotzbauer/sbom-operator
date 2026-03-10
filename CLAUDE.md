# CLAUDE.md

## Project Overview

`sbom-operator` is a Kubernetes operator that catalogues all container images running in a Kubernetes cluster by generating Software Bills of Materials (SBOMs) using [Anchore Syft](https://github.com/anchore/syft). Generated SBOMs are stored to one or more configurable targets: Git repository, Dependency Track, OCI registry, or Kubernetes ConfigMaps.

The operator watches for pod changes via Kubernetes informers (real-time mode) or runs on a configurable CRON schedule (daemon mode). Already-processed images are tracked via pod annotations (`ckotzbauer.sbom-operator.io/<container-name>`) to avoid redundant scans. Orphan images (no longer running in the cluster) are automatically cleaned up from targets.

- **Module**: `github.com/ckotzbauer/sbom-operator`
- **Container image**: `ghcr.io/ckotzbauer/sbom-operator`
- **License**: (see `/home/christian/Dokumente/dev/github/sbom-git-operator/LICENSE`)

## Tech Stack

| Component                    | Details                                                                            |
| ---------------------------- | ---------------------------------------------------------------------------------- |
| Language                     | Go 1.26.1                                                                          |
| CLI framework                | `github.com/spf13/cobra` v1.10.2                                                   |
| Configuration                | `github.com/ckotzbauer/libstandard` (struct tags: `yaml`, `env`, `flag`)           |
| Kubernetes client            | `k8s.io/client-go` v0.35.0, `k8s.io/api` v0.35.0, `k8s.io/apimachinery` v0.35.0    |
| Kubernetes helpers           | `github.com/ckotzbauer/libk8soci` (pod/image extraction, git operations, OCI auth) |
| SBOM generation              | `github.com/anchore/syft` v1.42.1, `github.com/anchore/stereoscope` v0.1.20        |
| Dependency Track client      | `github.com/DependencyTrack/client-go` v0.18.0                                     |
| OCI registry                 | `github.com/google/go-containerregistry` v0.21.2                                   |
| Docker image parsing         | `github.com/novln/docker-parser` v1.0.0                                            |
| CRON scheduling              | `github.com/robfig/cron` v1.2.0                                                    |
| Logging                      | `github.com/sirupsen/logrus` v1.9.4                                                |
| Testing                      | `github.com/stretchr/testify` v1.11.1                                              |
| SQLite (Syft RPM cataloging) | `modernc.org/sqlite` v1.44.3                                                       |
| GCP auth                     | `golang.org/x/oauth2/google`                                                       |
| Build                        | GoReleaser v2 (`.goreleaser.yml`)                                                  |
| Linting                      | golangci-lint v2.5.0, gosec v2.22.9                                                |
| Signing                      | cosign (release artifacts and container images)                                    |
| Dependency management        | Renovate (extends `ckotzbauer/renovate-config`)                                    |

## Project Structure

```
sbom-git-operator/
├── main.go                          # Entrypoint, CLI flag definitions, health endpoint (:8080)
├── internal/
│   ├── config.go                    # Config struct with yaml/env/flag tags, config key constants
│   ├── daemon/
│   │   └── daemon.go                # CRON-based background service (mutex-protected re-entrance guard)
│   ├── job/
│   │   └── job.go                   # Kubernetes Job creation for delegated SBOM generation
│   ├── kubernetes/
│   │   ├── kubernetes.go            # KubeClient: pod/namespace informers, annotations, jobs, configmaps
│   │   ├── image.go                 # Registry proxy logic (ApplyProxyRegistry)
│   │   └── image_test.go            # Tests for proxy registry mapping
│   ├── processor/
│   │   └── processor.go             # Core orchestration: pod watching, SBOM scanning, target dispatch
│   ├── syft/
│   │   ├── syft.go                  # Syft integration: SBOM creation, format encoding, GCP Workload Identity
│   │   └── syft_test.go             # Integration tests against real container images (alpine, redis, node, fedora)
│   └── target/
│       ├── target.go                # Target interface definition (Initialize, ValidateConfig, ProcessSbom, LoadImages, Remove)
│       ├── git/
│       │   ├── git_target.go        # Git target: stores SBOMs as files in a git repository
│       │   └── git_target_test.go   # Tests for ImageIDToFilePath
│       ├── dtrack/
│       │   └── dtrack_target.go     # Dependency Track target: uploads BOMs via API, manages project tags
│       ├── oci/
│       │   ├── oci_target.go        # OCI registry target: pushes SBOMs as OCI artifacts
│       │   ├── oci.go               # OCI image/layer construction, media type mapping
│       │   └── oci_target_test.go   # Integration test using ttl.sh ephemeral registry
│       └── configmap/
│           └── configmap_target.go  # ConfigMap target: stores compressed SBOMs in K8s ConfigMaps
├── deploy/
│   ├── standard/                    # Standard deployment manifests (Deployment + RBAC)
│   └── job-image/                   # Job-image mode deployment manifests
├── job-images/
│   └── vcn/                         # VCN (CodeNotary) job image for notarization
│       ├── Dockerfile
│       └── entrypoint.sh
├── hack/
│   └── run-tests.sh                 # Test runner: builds ephemeral OCI image, runs go test with coverage
├── auth/                            # Sample registry auth configs (gcr, ghcr, ecr, acr, gar, hub)
├── .github/workflows/               # CI/CD workflows
├── Makefile                         # Build, lint, test targets
├── Dockerfile                       # Multi-stage: alpine (certs/tz) -> scratch
├── .goreleaser.yml                  # GoReleaser v2 config
└── renovate.json                    # Renovate config (K8s deps grouped)
```

## Architecture & Patterns

### Two Operating Modes

1. **Informer mode** (default, no `--cron`): Uses Kubernetes `SharedIndexInformer` to watch pod update/delete events in real-time. Processes new images immediately on pod changes. Also watches namespace changes when `--namespace-label-selector` is set.

2. **CRON/Daemon mode** (`--cron` set): Uses `robfig/cron` to run periodic full-cluster scans. Mutex-protected to prevent concurrent runs. Iterates all namespaces and pods per schedule.

### Target Interface

All SBOM storage backends implement `target.Target` (defined in `internal/target/target.go`):

```go
type Target interface {
    Initialize() error
    ValidateConfig() error
    ProcessSbom(ctx *TargetContext) error
    LoadImages() ([]*oci.RegistryImage, error)
    Remove(images []*oci.RegistryImage) error
}
```

Four implementations: `git`, `dtrack`, `oci`, `configmap`. Selected via `--targets` flag (comma-separated list).

### Job Image Mode

When `--job-image` is set, the operator delegates SBOM generation to a Kubernetes Job instead of running Syft in-process. The operator creates a Secret with image configuration and a Job that mounts it. The VCN job image (`job-images/vcn/`) notarizes images using CodeNotary. Environment variables prefixed with `SBOM_JOB_` are forwarded to the job container.

### Pod Annotation Tracking

After processing, pods are annotated with `ckotzbauer.sbom-operator.io/<container-name>=<imageID>` to skip already-scanned images. Annotation updates retry up to 3 times.

### Namespace Filtering

When `--namespace-label-selector` is configured, the processor maintains a thread-safe map of allowed namespaces (`sync.RWMutex`). A separate namespace informer dynamically tracks label changes.

### Registry Proxy Support

The `--registry-proxy` flag maps source registries to proxy registries (e.g., `docker.io=my-proxy.com:5000`). Applied before Syft pulls images, then reverted for storage.

### GCP Workload Identity

For GCP Artifact Registry images (`*-docker.pkg.dev/*`), the operator automatically attempts Google Application Default Credentials when no pull secrets are available.

### Configuration

Configuration is loaded via `github.com/ckotzbauer/libstandard` with three binding layers:

- CLI flags (highest priority)
- Environment variables (prefixed `SBOM_`)
- YAML config file

Key environment variables: `POD_NAMESPACE`, `POD_NAME`, `POD_UID` (used for Job owner references).

## Build & Development

### Prerequisites

- Go 1.26.1+
- GoReleaser v2
- Docker (for test runner and container builds)
- cosign, syft CLI (for release workflow)

### Build Commands

```bash
# Build single-target binary (uses goreleaser)
make build

# Build for all platforms (linux/amd64, linux/arm64)
make build-all

# Run locally against ~/.kube/config
make run
```

### GoReleaser Configuration

- `CGO_ENABLED=0` (static binary)
- Platforms: `linux/amd64`, `linux/arm64`
- ldflags inject: `Version`, `Commit`, `Date`, `BuiltBy`
- Flags: `-trimpath`
- Release signing with cosign
- SBOM generation for release artifacts

### Docker Image

Multi-stage build (`Dockerfile`):

1. `alpine:latest` stage: installs `ca-certificates` and `tzdata`
2. `scratch` final stage: copies certs, timezone data, and the built binary
3. Entrypoint: `/usr/local/bin/sbom-operator`

Health endpoint: `GET :8080/health`

## Testing

### Test Framework

- `github.com/stretchr/testify` (assert package)
- Table-driven tests throughout

### Running Tests

```bash
# Full test suite (builds ephemeral OCI image on ttl.sh, runs all tests with coverage)
make test
# Equivalent to: bash hack/run-tests.sh
```

The `hack/run-tests.sh` script:

1. Builds a timestamped Docker image and pushes to `ttl.sh` (ephemeral registry, 1h TTL)
2. Generates an SBOM fixture using `syft`
3. Runs `go test ./... -coverprofile cover.out`
4. Verifies cosign SBOM download from the ephemeral registry

### Test Files

| Test file                                | What it tests                                                                                                                                              |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal/kubernetes/image_test.go`      | Registry proxy mapping (`ApplyProxyRegistry`)                                                                                                              |
| `internal/syft/syft_test.go`             | End-to-end SBOM generation against real images (alpine, redis, node, fedora) in JSON, CycloneDX XML, SPDX JSON formats. Uses fixture files for comparison. |
| `internal/target/git/git_target_test.go` | `ImageIDToFilePath` conversion logic                                                                                                                       |
| `internal/target/oci/oci_target_test.go` | OCI target integration test (requires `TEST_DIGEST` and `DATE` env vars)                                                                                   |

### SBOM Format Test Coverage

Tests validate output against fixtures for multiple formats:

- Syft JSON (`json`)
- CycloneDX XML (`cyclonedx`)
- SPDX JSON (`spdxjson`)

Fixtures are stored in `internal/syft/fixtures/` and `internal/target/oci/fixtures/`.

## Linting & Code Style

### Linters

```bash
# Install linting tools
make bootstrap-tools

# Run golangci-lint (5 minute timeout)
make lint

# Run gosec security scanner
make lintsec
```

- **golangci-lint** v2.5.0 (installed to `.tmp/golangci-lint`)
- **gosec** v2.22.9 (installed to `.tmp/gosec`)

### Code Conventions

- `go fmt ./...` and `go vet ./...` run as prerequisites to `build`
- `/* #nosec */` comments suppress gosec warnings on intentional patterns (e.g., `os.MkdirAll(dir, 0777)`, secret variable names)
- `// nolint QF1003` used to suppress if-else chain warnings where switch is not preferred

### Style Patterns

- All packages under `internal/` (not exported)
- Logrus for all logging with structured error fields (`logrus.WithError(err)`)
- Error handling: log and return, or log and fatal for critical init failures
- Constructor pattern: `New*()` functions for all major types
- Config keys defined as package-level `var` strings in `internal/config.go`

## CI/CD

All workflows use reusable workflows from `ckotzbauer/actions-toolkit`.

### Workflows

| Workflow                | Trigger                      | Purpose                                                                                          |
| ----------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------ |
| `test.yml`              | push, PR                     | Build (`make build`), test (`make test`), coverage report, Docker image build                    |
| `code-checks.yml`       | push, PR                     | golangci-lint (`make lint`) and gosec (`make lintsec`)                                           |
| `create-release.yml`    | manual (`workflow_dispatch`) | GoReleaser release, multi-arch Docker image (amd64/arm64), cosign signing, VCN job image release |
| `release-job-image.yml` | called by `create-release`   | Build/push/sign job images, generate and attest SBOMs                                            |
| `stale.yml`             | daily cron (`0 0 * * *`)     | Mark stale issues/PRs                                                                            |
| `update-snyk.yml`       | weekly Monday (`0 12 * * 1`) | Snyk monitoring scan                                                                             |
| `label-issues.yml`      | issue comment                | Label management via commands                                                                    |
| `size-label.yml`        | PR                           | Automatic PR size labeling                                                                       |

### Release Process

1. Triggered manually via `workflow_dispatch` with a version input
2. GoReleaser builds binaries for linux/amd64 and linux/arm64
3. Docker images pushed to `ghcr.io/ckotzbauer/sbom-operator:{version}` and `:latest`
4. All artifacts signed with cosign (signatures stored in `ghcr.io/ckotzbauer/sbom-operator-metadata`)
5. VCN job image released separately to `ghcr.io/ckotzbauer/sbom-operator/vcn:{version}`

## Key Commands

```bash
# Build
make build              # Single-target build via goreleaser
make build-all          # All platforms
make run                # Run locally with go run

# Test
make test               # Full test suite with coverage (needs Docker)

# Lint
make bootstrap-tools    # Download golangci-lint and gosec
make lint               # Run golangci-lint
make lintsec            # Run gosec

# Format
make fmt                # go fmt ./...
make vet                # go vet ./...

# Deploy (standard mode)
kubectl apply -f deploy/standard/

# Deploy (job-image mode)
kubectl apply -f deploy/job-image/
```

## Important Conventions

- **No CRDs**: This operator does not use Custom Resource Definitions. It watches native Pod resources and uses annotations for state tracking.
- **Annotation format**: `ckotzbauer.sbom-operator.io/<container-name>` stores the imageID of the processed image.
- **ConfigMap label**: ConfigMaps created by the operator are labeled `ckotzbauer.sbom-operator.io=true`.
- **SBOM file naming**: Files are named `sbom.json`, `sbom.xml`, `sbom.spdx`, or `sbom.txt` depending on format (see `syft.GetFileName()`).
- **Git path structure**: Image IDs are converted to file paths by replacing `@` with `/` and `:` with `_` (e.g., `alpine@sha256:abc...` becomes `alpine/sha256_abc.../sbom.json`).
- **Dependency Track tags**: Projects are tagged with `kubernetes-cluster=<id>`, `sbom-operator`, `raw-image-id=<id>`, and `namespace=<ns>`. Multi-cluster awareness is built in -- cluster tags are managed per cluster ID.
- **Security context**: The container runs as non-root (UID 101), read-only root filesystem, all capabilities dropped, seccomp RuntimeDefault profile.
- **Health endpoint**: `GET :8080/health` returns 200 with body "Running!".
- **Scratch-based image**: Final container image is built FROM scratch with only the static binary, CA certs, and timezone data.
- **Version injection**: Build version, commit, date, and builder are injected via ldflags at build time.
- **Supported SBOM formats**: `json` (syft), `cyclonedx`/`cyclonedxxml`, `cyclonedxjson`, `spdx`/`spdxtv`/`spdxtagvalue`, `spdxjson`, `github`/`githubjson`, `text`, `table`.
- **Informer transforms**: Pod and namespace informers use `SetTransform` to strip unnecessary fields, reducing memory usage.
