#!/bin/bash

DATE="$(date +%Y%m%d%H%M%S)"
docker build --build-arg date=${DATE} -t ttl.sh/sbom-operator-oci-test-${DATE}:1h internal/target/oci/fixtures
docker push ttl.sh/sbom-operator-oci-test-${DATE}:1h
DIGEST=$(docker inspect ttl.sh/sbom-operator-oci-test-${DATE}:1h --format='{{index .RepoDigests 0}}')
syft registry:${DIGEST} -o json > internal/target/oci/fixtures/sbom.json

TEST_DIGEST="${DIGEST}" DATE="${DATE}" go test $(go list ./...) -coverprofile cover.out
COSIGN_REPOSITORY="ttl.sh/sbom-operator-oci-test-${DATE}" cosign download sbom ${DIGEST}
