#!/bin/bash

/mnt/win-dev/github/syft/snapshot/linux-build_linux_amd64_v1/syft registry:alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300 -o json > alpine.json
/mnt/win-dev/github/syft/snapshot/linux-build_linux_amd64_v1/syft registry:alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300 -o cyclonedx > alpine.cyclonedx
/mnt/win-dev/github/syft/snapshot/linux-build_linux_amd64_v1/syft registry:alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300 -o spdx-json > alpine.spdxjson

/mnt/win-dev/github/syft/snapshot/linux-build_linux_amd64_v1/syft registry:nginx@sha256:2834dc507516af02784808c5f48b7cbe38b8ed5d0f4837f16e78d00deb7e7767 -o json > nginx.json
/mnt/win-dev/github/syft/snapshot/linux-build_linux_amd64_v1/syft registry:nginx@sha256:2834dc507516af02784808c5f48b7cbe38b8ed5d0f4837f16e78d00deb7e7767 -o cyclonedx > nginx.cyclonedx
/mnt/win-dev/github/syft/snapshot/linux-build_linux_amd64_v1/syft registry:nginx@sha256:2834dc507516af02784808c5f48b7cbe38b8ed5d0f4837f16e78d00deb7e7767 -o spdx-json > nginx.spdxjson

/mnt/win-dev/github/syft/snapshot/linux-build_linux_amd64_v1/syft registry:node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec -o json > node.json
/mnt/win-dev/github/syft/snapshot/linux-build_linux_amd64_v1/syft registry:node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec -o cyclonedx > node.cyclonedx
/mnt/win-dev/github/syft/snapshot/linux-build_linux_amd64_v1/syft registry:node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec -o spdx-json > node.spdxjson
