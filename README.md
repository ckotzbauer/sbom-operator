
# sbom-operator

> Catalogue all images of a Kubernetes cluster to multiple targets with Syft.

[![test](https://github.com/ckotzbauer/sbom-operator/actions/workflows/test.yml/badge.svg)](https://github.com/ckotzbauer/sbom-operator/actions/workflows/test.yml)

## Overview

This operator maintains a central place to track all packages and software used in all those images in a Kubernetes cluster. For this a Software Bill of 
Materials (SBOM) is generated from each image with Syft. They are all stored in one or more targets. Currently Git, Dependency Track, OCI-Registry and ConfigMaps are supported. 
With this it is possible to do further analysis, [vulnerability scans](https://github.com/ckotzbauer/vulnerability-operator) and much more in a single place. 
To prevent scans of images that have already been analyzed pods are annotated with the imageID of the already processed image.

## Kubernetes Compatibility

The image contains versions of `k8s.io/client-go`. Kubernetes aims to provide forwards & backwards compatibility of one minor version between client and server:

| sbom-operator   | k8s.io/{api,apimachinery,client-go} | expected kubernetes compatibility |
|-----------------|-------------------------------------|-----------------------------------|
| main            | v0.26.2                             | 1.25.x, 1.26.x, 1.27.x            |
| 0.25.0          | v0.26.2                             | 1.25.x, 1.26.x, 1.27.x            |
| 0.24.0          | v0.26.0                             | 1.25.x, 1.26.x, 1.27.x            |
| 0.23.0          | v0.26.0                             | 1.25.x, 1.26.x, 1.27.x            |
| 0.22.0          | v0.25.4                             | 1.24.x, 1.25.x, 1.26.x            |
| 0.21.0          | v0.25.3                             | 1.24.x, 1.25.x, 1.26.x            |
| 0.20.0          | v0.25.2                             | 1.24.x, 1.25.x, 1.26.x            |
| 0.19.0          | v0.25.2                             | 1.24.x, 1.25.x, 1.26.x            |
| 0.18.0          | v0.25.2                             | 1.24.x, 1.25.x, 1.26.x            |
| 0.17.0          | v0.25.1                             | 1.24.x, 1.25.x, 1.26.x            |
| 0.16.0          | v0.25.0                             | 1.24.x, 1.25.x, 1.26.x            |
| 0.15.0          | v0.24.4                             | 1.23.x, 1.24.x, 1.25.x            |
| 0.14.0          | v0.24.3                             | 1.23.x, 1.24.x, 1.25.x            |
| 0.13.0          | v0.24.2                             | 1.23.x, 1.24.x, 1.25.x            |
| 0.12.0          | v0.24.1                             | 1.23.x, 1.24.x, 1.25.x            |
| 0.11.0          | v0.24.0                             | 1.23.x, 1.24.x, 1.25.x            |
| 0.10.0          | v0.23.6                             | 1.22.x, 1.23.x, 1.24.x            |
| 0.9.0           | v0.23.5                             | 1.22.x, 1.23.x, 1.24.x            |
| 0.8.0           | v0.23.5                             | 1.22.x, 1.23.x, 1.24.x            |
| 0.7.0           | v0.23.4                             | 1.22.x, 1.23.x, 1.24.x            |
| 0.6.0           | v0.23.4                             | 1.22.x, 1.23.x, 1.24.x            |
| 0.5.0           | v0.23.4                             | 1.22.x, 1.23.x, 1.24.x            |
| 0.4.1           | v0.23.3                             | 1.22.x, 1.23.x, 1.24.x            |
| 0.3.1           | v0.23.3                             | 1.22.x, 1.23.x, 1.24.x            |
| 0.2.0           | v0.23.2                             | 1.22.x, 1.23.x, 1.24.x            |
| 0.1.0           | v0.23.2                             | 1.22.x, 1.23.x, 1.24.x            |

However, the operator will work with more versions of Kubernetes in general.

## Container Registry Support

The operator relies on the syft-internal mechanism to download images from OCI-compliant registries.

## Installation

#### Manifests

```
kubectl apply -f deploy/standard/
```

#### Helm-Chart

Create a YAML file first with the required configurations or use helm-flags instead.

```
helm repo add ckotzbauer https://ckotzbauer.github.io/helm-charts
helm install ckotzbauer/sbom-operator -f your-values.yaml
```


## Configuration

All parameters are cli-flags. The flags can be configured as args or as environment-variables prefixed with `SBOM_` to inject sensitive configs as secret values.

### Common parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `verbosity` | `false` | `info` | Log-level (debug, info, warn, error, fatal, panic) |
| `cron` | `false` | `""` | Backround-Service interval (CRON). See [Trigger](#analysis-trigger) for details. |
| `ignore-annotations` | `false` | `false` | Force analyzing of all images, including those from annotated pods. |
| `format` | `false` | `json` | SBOM-Format. (One of `json`, `syftjson`, `cyclonedxjson`, `spdxjson`, `github`, `githubjson`, `cyclonedx`, `cyclone`, `cyclonedxxml`, `spdx`, `spdxtv`, `spdxtagvalue`, `text`, `table`) |
| `targets` | `false` | `git` | Comma-delimited list of targets to sent the generated SBOMs to. Possible targets `git`, `dtrack`, `oci`, `configmap`. Ignored with a `job-image` |
| `pod-label-selector` | `false` | `""` | Kubernetes Label-Selector for pods. |
| `namespace-label-selector` | `false` | `""` | Kubernetes Label-Selector for namespaces. |
| `fallback-image-pull-secret` | `false` | `""` | Kubernetes Pull-Secret Name to load as a fallback when all others fail (must be in the same namespace as the sbom-operator) |
| `registry-proxy` | `false` | `[]` | Proxy-Registry-Hosts to use. Flag can be used multiple times. Value-Mapping e.g. `docker.io=ghcr.io` |
| `delete-orphan-projects` | `false` | `true` | Delete orphan projects automatically |


### Example Helm-Config

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
  - name: SBOM_GIT_ACCESS_TOKEN
    valueFrom:
      secretKeyRef:
        name: "sbom-operator"
        key: "accessToken"
```

## Analysis-Trigger

### Cron

With the `cron` flag set, the operator runs with a specified interval and checks for changed images in your cluster.
All options from [github.com/robfig/cron](https://github.com/robfig/cron) are allowed as cron-syntax.

### Real-Time

When you omit the `cron` flag, the operator uses a Cache-Informer to process changed pods immediately. In this mode there's also
a one-time analysis at startup to sync the targets with the actual cluster-state. If you configured a job-image there's no initial
startup sync.


## Targets

It is possible to store the generated SBOMs to different targets (even multple at once). All targets are using Syft as analyzer.
If you want to use another tool to analyze your images, then have a look at the [Job image](#job-images) section. Images which are
not present in the cluster anymore are removed from the configured targets (except for the OCI-Target).

### Dependency Track

#### Dependency Track Parameter

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `dtrack-base-url` | `true` when `dtrack` target is used | `""` | Dependency-Track base URL, e.g. 'https://dtrack.example.com' |
| `dtrack-api-key` | `true` when `dtrack` target is used | `""` | Dependency-Track API key |
| `dtrack-label-tag-matcher` | `false` | `""` | Dependency-Track Pod-Label-Tag matcher regex |
| `dtrack-ca-cert-file` | `false` | `""` | CA-Certificate filepath when using mTLS to connect to dtrack |
| `dtrack-client-cert-file` | `true` when `dtrack-ca-cert-file` is provided | `""` | Client-Certificate filepath when using mTLS to connect to dtrack |
| `dtrack-client-key-file` | `true` when `dtrack-ca-cert-file` is provided | `""` | Client-Key filepath when using mTLS to connect to dtrack |
| `dtrack-parent-project-annotation-key` | `false` | `""` | Kubernetes pod annotation key to set parent project automatically, e.g. "my.pod.annotation" |
| `dtrack-project-name-annotation-key` | `false` | `""` | Kubernetes pod annotation key to set custom dtrack project name automatically, e.g. "my.pod.annotation" |
| `kubernetes-cluster-id` | `false` | `"default"` | Kubernetes Cluster ID (to be used in Dependency-Track or Job-Images) |

Each image in the cluster is created as project with the full-image name (registry and image-path without tag) and the image-tag as project-version.
When there's no image-tag, but a digest, the digest is used as project-version.
The `autoCreate` option of DT is used. You have to set the `--format` flag to `cyclonedx` with this target.

---
#### Custom dtrack project name:

The key at kubernetes has to be suffixed with the container name the project is for. e.g. `my.project.name/my-nginx`.
> [!IMPORTANT]
> The suffix regarding container name must not be added to the config value and must not include `/`. e.g. `my.project.name`

The value for a custom project name in dtrack by annotation at the specific Pod is written in the format of `project:version` or just `project` where version defaults to `latest`. E.g. `MyParentProject` or `MyParentProject:1.0`

---

#### Setting parent project at Dependency Track automatically:

The key at kubernetes has to be suffixed with the container name the parent project is for. e.g. `my.parent.project/my-nginx`.
The value for the parent project annotation at the specific Pod is written in the format of `project:version` or just `project` where version defaults to `latest`. E.g. `MyParentProject` or `MyParentProject:1.0`

> [!IMPORTANT]
> The suffix regarding container name must not be added to the config value and must not include `/`. e.g. `my.parent.project`

---

#### Example Pod Annotation:
```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    my.parent.project/my-nginx: MyParentProject
    my.project.name/my-nginx: MyNginxProject:1.0
    my.parent.project/my-sidecar: MyOtherParentProject
    my.project.name/my-sidecar: MySidecarProject:1.0.1
spec:
  containers:
    - image: nginx:latest
      name: my-nginx
    ...
    - image: some-other-image:latest
      name: my-sidecar
    ...
...
```
---

#### sbom-operator config:
```bash
--dtrack-parent-project-annotation-key=my.parent.project
--dtrack-project-name-annotation-key=my.project.name
```
---

### Git

#### Git Parameter

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `git-workingtree` | `false` | `/work` | Directory to place the git-repo. |
| `git-repository` | `true` when `git` target is used. | `""` | Git-Repository-URL (HTTPS). |
| `git-branch` | `false` | `main` | Git-Branch to checkout. |
| `git-path` | `false` | `""` | Folder-Path inside the Git-Repository. |
| `git-author-name` | `true` when `git` target is used. | `""` | Author name to use for Git-Commits. |
| `git-author-email` | `true` when `git` target is used. | `""` | Author email to use for Git-Commits. |
| `git-access-token` | `false` | `""` | Git-Personal-Access-Token with write-permissions. |
| `git-username` | `false` | `""` | Git-Username |
| `git-password` | `false` | `""` | Git-Password |
| `github-app-id` | `false` | `""` | GitHub App-ID. |
| `github-app-installation-id` | `false` | `""` | GitHub App-Installation-ID. |

The operator will save all files with a specific folder structure as described below. When a `git-path` is configured, all folders above this path are not touched
from the application. Assuming that `git-path` is set to `dev-cluster/sboms`. When no `git-path` is given, the structure below is directly in the repository-root. 
The structure is basically `<git-path>/<registry-server>/<image-path>/<image-digest>/sbom.json` (see example below).
The file-extension may differ when another output-format is configured. 
You can use a token-based authentication (e.g. a PAT for GitHub) with `--git-access-token`, BasicAuth with username and password (`--git-username`, `--git-password`) or
Github App Authentication (`--github-app-id`, `--github-app-installation-id`, env: `SBOM_GITHUB_APP_PRIVATE_KEY`) The private-key has to be Base64 encoded. 

**Note**: It is required, that the specified branch of the repo is fully initialized. There's no logic which creates a non-existent branch. Just commit a `README.md`
or something similar, to make things work.

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

### OCI-Registry

#### OCI-Registry Parameter

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `oci-registry` | `true` when `oci` target is used | `""` | OCI-Registry |
| `oci-user` | `true` when `oci` target is used | `""` | OCI-User |
| `oci-token` | `true` when `oci` target is used | `""` | OCI-Token |

In this mode the operator will generate a SBOM and store it into an OCI-Registry. The SBOM then can be processed by cosign, Kyverno
or any other tool. E.g.:
```bash
COSIGN_REPOSITORY=<yourregistry> cosign download sbom <your full image digest>
```

The operator needs the Registry-URL, a user and a token as password to authenticate to the registry. Write-permissions are needed.


### ConfigMap

This target stores the SBOM as Kubernetes-ConfigMap. They are placed in the same namespace as the corresponding pod and the name
consists of the pod- and container-name. The configmap is labeled with `ckotzbauer.sbom-operator.io=true` and 
annotated with `ckotzbauer.sbom-operator.io/image-id=<full-image-repo-with-digest>`.
The content is stored as broli-compressed binary-data with the configmap-key `sbom`.


## Job-Images

#### Job-Image Parameter

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `job-image` | `false` | `""` | Job-Image to process images with instead of Syft |
| `job-image-pull-secret` | `false` | `""` | Pre-existing pull-secret-name for private job-images |
| `job-timeout` | `false` | `3600` | Job-Timeout in seconds (`activeDeadlineSeconds`) |
| `kubernetes-cluster-id` | `false` | `"default"` | Kubernetes Cluster ID (to be used in Dependency-Track or Job-Images) |

If you don't want to use Syft to analyze your images, you can give the Job-Image feature a try. The operator creates a Kubernetes-Job
which does the analysis with any possible tool inside. There's no target-handling done by the operator, the tool from the job has to process
the SBOMs on its own. Currently there are two possible integrations:

| Tool | Description |
| ---- | ----------- |
| [Codenotary VCN](job-images/vcn/README.md) | The VCN-Tool from Codenotary can notarize your images in the Codenotary Cloud. (chargeable) |

This feature is built as generic approach. Any image which follows [these specs](job-images/SPEC.md) can be used as job-image.

e.g. Manifest (`deploy/job-image`):
```yaml
--job-image=ghcr.io/ckotzbauer/sbom-operator/vcn:<TAG>
```

e.g. Helm:
```yaml
jobImageMode: true

envVars:
  - name: SBOM_JOB_VCN_LC_API_KEY
    value: "<KEY>"
```

All operator-environment variables prefixed with `SBOM_JOB_` are passed to the Kubernetes job.


## Security

The docker-image is based on a [distroless git-image](https://github.com/ckotzbauer/distroless-git-slim) to reduce the attack-surface and keep the image small.
Furthermore the image and release-artifacts are signed with [cosign](https://github.com/sigstore/cosign) and attested with provenance-files.
The release-process satisfies SLSA Level 2. All of those "metadata files" are  also stored in a dedicated repository `ghcr.io/ckotzbauer/sbom-operator-metadata`.
When discovering security issues please refer to the [Security process](https://github.com/ckotzbauer/.github/blob/main/SECURITY.md).

### Signature verification

```bash
COSIGN_EXPERIMENTAL=1 COSIGN_REPOSITORY=ghcr.io/ckotzbauer/sbom-operator-metadata cosign verify ghcr.io/ckotzbauer/sbom-operator:<tag-to-verify> --certificate-github-workflow-name create-release --certificate-github-workflow-repository ckotzbauer/sbom-operator
```

### Attestation verification

```bash
COSIGN_EXPERIMENTAL=1 COSIGN_REPOSITORY=ghcr.io/ckotzbauer/sbom-operator-metadata cosign verify-attestation ghcr.io/ckotzbauer/sbom-operator:<tag-to-verify> --certificate-github-workflow-name create-release --certificate-github-workflow-repository ckotzbauer/sbom-operator
```

### Download attestation

```bash
COSIGN_REPOSITORY=ghcr.io/ckotzbauer/sbom-operator-metadata cosign download attestation ghcr.io/ckotzbauer/sbom-operator:<tag-to-verify> | jq -r '.payload' | base64 -d
```

### Download SBOM

```bash
COSIGN_REPOSITORY=ghcr.io/ckotzbauer/sbom-operator-metadata cosign download sbom ghcr.io/ckotzbauer/sbom-operator:<tag-to-verify> | jq -r '.payload' | base64 -d
```


[License](https://github.com/ckotzbauer/sbom-operator/blob/master/LICENSE)
--------
[Changelog](https://github.com/ckotzbauer/sbom-operator/blob/master/CHANGELOG.md)
--------


## Contributing

Please refer to the [Contribution guildelines](https://github.com/ckotzbauer/.github/blob/main/CONTRIBUTING.md).

## Code of conduct

Please refer to the [Conduct guildelines](https://github.com/ckotzbauer/.github/blob/main/CODE_OF_CONDUCT.md).

