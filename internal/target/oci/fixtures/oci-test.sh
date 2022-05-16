#!/bin/bash
set -eu

DATE="$(date +%Y%m%d%H%M%S)"

docker build --build-arg date=${DATE} -t ghcr.io/ckotzbauer/sbom-operator/oci-test:${DATE} internal/target/oci/fixtures
docker push ghcr.io/ckotzbauer/sbom-operator/oci-test:${DATE}
DIGEST=$(docker inspect ghcr.io/ckotzbauer/sbom-operator/oci-test:${DATE} --format='{{index .RepoDigests 0}}')

syft registry:${DIGEST} -o json > internal/target/oci/fixtures/sbom.json
TEST_DIGEST="${DIGEST}" REGISTRY_USER="${1}" REGISTRY_TOKEN="${2}" go test github.com/ckotzbauer/sbom-operator/internal/target -coverprofile cover-integration.out

COSIGN_REPOSITORY="ghcr.io/ckotzbauer/sbom-operator/oci-test" cosign download sbom ${DIGEST}
