
# sbom-operator

> Catalogue all images of a Kubernetes cluster to multiple targets with Syft.

[![test](https://github.com/ckotzbauer/sbom-operator/actions/workflows/test.yml/badge.svg)](https://github.com/ckotzbauer/sbom-operator/actions/workflows/test.yml)

## Motivation

This operator maintains a central place to track all packages and software used in all those images in a Kubernetes cluster. For this a Software Bill of 
Materials (SBOM) is generated from each image with Syft. They are all stored in one or more targets. Currently only Git is supported. With this it is 
possible to do further analysis, vulnerability scans and much more in a single place.

## Kubernetes Compatibility

The image contains versions of `k8s.io/client-go`. Kubernetes aims to provide forwards & backwards compatibility of one minor version between client and server:

| access-manager  | k8s.io/{api,apimachinery,client-go} | expected kubernetes compatibility |
|-----------------|-------------------------------------|-----------------------------------|
| 0.2.0           | v0.23.2                             | 1.22.x, 1.23.x, 1.24.x            |
| 0.1.0           | v0.23.2                             | 1.22.x, 1.23.x, 1.24.x            |
| main            | v0.23.2                             | 1.22.x, 1.23.x, 1.24.x            |

However, the operator will work with more versions of Kubernetes in general.

## Container Registry Support

The operator relies on the [go-containeregistry](https://github.com/google/go-containerregistry) library to download images. It should work with most registries. 
These are officially tested (with authentication):
- ACR (Azure Container Registry)
- ECR (Amazon Elastic Container Registry)
- GAR (Google Artifact Registry)
- GCR (Google Container Registry)
- GHCR (GitHub Container Registry)
- DockerHub


## Installation

#### Manifests

```
kubectl apply -f deploy/
```

#### Helm-Chart

Create a YAML file first with the required configurations or use helm-flags instead.

```
helm repo add ckotzbauer https://ckotzbauer.github.io/helm-charts
helm install ckotzbauer/sbom-operator -f your-values.yaml
```


## Configuration

All parameters are cli-flags.

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `verbosity` | `false` | `info` | Log-level (debug, info, warn, error, fatal, panic) |
| `cron` | `false` | `@hourly` | Backround-Service interval (CRON). All options from [github.com/robfig/cron](https://github.com/robfig/cron) are allowed |
| `ignore-annotations` | `false` | `false` | Force analyzing of all images, including those from annotated pods. |
| `format` | `false` | `json` | SBOM-Format. |
| `targets` | `false` | `git` | Comma-delimited list of targets to sent the generated SBOMs to. Possible targets `git` |
| `git-workingtree` | `false` | `/work` | Directory to place the git-repo. |
| `git-repository` | `true` when `git` target is used. | `""` | Git-Repository-URL (HTTPS). |
| `git-branch` | `false` | `main` | Git-Branch to checkout. |
| `git-path` | `false` | `""` | Folder-Path inside the Git-Repository. |
| `git-access-token` | `true` when `git` target is used. | `""` | Git-Personal-Access-Token with write-permissions. |
| `git-author-name` | `true` when `git` target is used. | `""` | Author name to use for Git-Commits. |
| `git-author-email` | `true` when `git` target is used. | `""` | Author email to use for Git-Commits. |
| `pod-label-selector` | `false` | `""` | Kubernetes Label-Selector for pods. |
| `namespace-label-selector` | `false` | `""` | Kubernetes Label-Selector for namespaces. |

The flags can be configured as args or as environment-variables prefixed with `SGO_` to inject sensitive configs as secret values.

#### Example Helm-Config

```yaml
args:
  targets: git
  git-author-email: XXX
  git-author-name: XXX
  git-repository: https://github.com/XXX/XXX
  git-path: dev-cluster/sboms
  verbosity: debug
  cron: "0 30 * * * *"

envVars:
  - name: SGO_GIT_ACCESS_TOKEN
    valueFrom:
      secretKeyRef:
        name: "sbom-operator"
        key: "accessToken"

```


## Targets

It is possible to store the generated SBOMs to different targets (even multple at once). Currently the only available target is Git, but this will change soon.

#### Git

The operator will save all files with a specific folder structure as described below. When a `git-path` is configured, all folders above this path are not touched
from the application. Assuming that `git-path` is set to `dev-cluster/sboms`. When no `git-path` is given, the structure below is directly in the repository-root. 
The structure is basically `<git-path>/<registry-server>/<image-path>/<image-digest>/sbom.json`. The file-extension may differ when another output-format is configured. A token-based authentication to the git-repository is used.

```
dev-cluster
│
└───sboms
    │
    └───docker.io
    |   │
    |   └───library
    |       │
    |       └───busybox
    |           │
    |           └───sha256_ae39a6f5...
    |               │   sbom.json
    |
    └───ghcr.io
        │
        └───kyverno
            │
            └───kyverno
            |   │
            |   └───sha256_9e3f14e5...
            |       │   sbom.json
            |
            └───kyvernopre
                │
                └───sha256_e48f87fd...
                    │   sbom.json
            |
            └───policy-reporter
                │
                └───sha256_b70caa7a...
                    │   sbom.json
```


## Security

The docker-image is based on `scratch` to reduce the attack-surface and keep the image small. Furthermore the image and release-artifacts are signed 
with [cosign](https://github.com/sigstore/cosign) and attested with provenance-files. The release-process satisfies SLSA Level 2. All of those "metadata files" are 
also stored in a dedicated repository `ghcr.io/ckotzbauer/sbom-operator-metadata`.
Both, SLSA and the signatures are still experimental for this project.



[Contributing](https://github.com/ckotzbauer/sbom-operator/blob/master/CONTRIBUTING.md)
--------
[License](https://github.com/ckotzbauer/sbom-operator/blob/master/LICENSE)
--------
[Changelog](https://github.com/ckotzbauer/sbom-operator/blob/master/CHANGELOG.md)
--------

