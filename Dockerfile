FROM ghcr.io/ckotzbauer/distroless-git-slim

ARG TARGETOS
ARG TARGETARCH

COPY dist/sbom-operator_${TARGETOS}_${TARGETARCH}*/sbom-operator /usr/local/bin/sbom-operator
COPY hack/git-ask-pass.sh /usr/local/bin/git-ask-pass.sh

ENTRYPOINT ["/usr/local/bin/sbom-operator"]
