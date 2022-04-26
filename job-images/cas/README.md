
# Codenotary Community Attestation Service

> Integrates Codenotary's "Community Attestation Service" (CAS) with the SBOM-Operator.

This Job-Image notarizes your images with CAS.

## Usage

1. Visit [cas.codenotary.com](https://cas.codenotary.com/) and create an API-Key.
2. Add the following flag to the operator-installation.

Manifest:
```yaml
--job-image=ghcr.io/ckotzbauer/sbom-operator/cas:<TAG>
```

Helm:
```yaml
args:
  job-image: ghcr.io/ckotzbauer/sbom-operator/cas:<TAG>
```

3. Add the API-Key as environment variable.

Manifest:
```yaml
env:
  - name: SBOM_JOB_CAS_API_KEY
    value: "<KEY>"
```

Helm:
```yaml
jobImageMode: true

envVars:
  - name: SBOM_JOB_CAS_API_KEY
    value: "<KEY>"
```


The job-images are always tagged with the same versions as the operator itself.
The flag instructs the operator to not analyze the container-images with Syft, but create a Kubernetes Job instead with the given job-image.
The job will notarize all images which are selected by the operator with CAS. When the job has finished it will be in state "Completed"
when there were no errors during notarization. All pods from the analyzed images are annotated then. There's no target-handling from the operator
for the analyze-result, as the Codenotary Attestation Service is doing this for us.

## Notes

- The Pod-Name, Pod-Namespace and the cluster-name are stored as notarization-attributes.
- Environment variables from on the operator prefixed with `SBOM_JOB_` are passed to the job without the prefix.
- Use the `SBOM_JOB_CAS_EXTRA_ARGS` env to pass custom flags to the `cas notarize` command.
- The job-container needs to be privileged, as CAS needs the Docker-Daemon to read the images from.
- CAS currently does not support distroless images and images where no package-manager is installed.
- There's a bug in CAS, that some images could not be notarized (error-messages like `stream copy error: reading from a closed fifo` are appearing)
- All bugs or behaviours from CAS which could not be handled by the operator or the `entrypoint.sh` are out-of-scope of this repo.

## Verifying an notarized image (manually)

```
docker pull alpine:3.15
cas authenticate --bom docker://alpine:3.15
```

See the official Codenotary docs for more infos.
