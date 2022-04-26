
# External Job-Image Specification

> SBOM-Operator can delegate the generation and storage of SBOMs to a thirdparty tool.


## Assumptions

### The CLI-Tool

- The thirdparty tool has a CLI interface
- Credentials needed by the CLI tool can be provided with environment variables or CLI-Flags (non-interactive)
- The tool has a solid exit-code handling and only exits with a non-zero code on unexpected errors.
- The tool can pull the images to catalogue by itself or can consume images from a container-runtime-daemon or file (the entrypoint-script has to handle prepulls).

### The Job-Image and its entrypoint-script

- There is a container image available which consists of the CLI-Tool and an entrypoint-script.
- The entrypoint-script satisfies the following requirements:
    - Takes a JSON-file at `/sbom/image-config.json` with the details of the images to catalogue. (see the [example](example-image-config.json))
    - Prepares anything at start which is needed to process.
    - Processes all images defined in `/sbom/image-config.json` in a loop with the CLI-Tool.
    - Cleans up all images downloaded and stops possible daemons (the container should die gracefully at the end)
    - Exits with a zero-code on success.
    - Exits with a non-zero-code when there where unexpected errors.
- Command-Line arguments to the entrypoint-script are not supported.
- Environment variables can be used.

## Integration with the SBOM-Operator

- The operator will skip SBOM generation with Syft and target-handling when there's a job-image specified.
- The `image-config.json` will be generated from the images detected for scanning.
- The config will be created as Kubernetes-Secret with a specific name.
- The operator creates a Kubernetes-Job with the secret mounted at `/sbom/image-config.json`.
- The operator will pass all environment variables starting with `SBOM_JOB_` to the job.
- The Job-Image can be private, an existing Image-Pull-Secret has to be configured as CLI-Flag to the operator.
- The operator blocks new execution-cycles as long as the job is running.
- The operator configures the job with a configurable `activeDeadlineSeconds` duration.
- When the job has ended successfully the operator will annotate all Pods with processed images.
- When the job errored or is killed no Pods will be annotated.
