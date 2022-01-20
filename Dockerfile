ARG SYFT_VERSION=v0.36.0
FROM anchore/syft:${SYFT_VERSION}@sha256:305e1777f6e105bfd4cc9a06faceefabb0a5c6c59d854013b4068c7ee7b310ba as syft

FROM alpine:3.15 as alpine

ARG TARGETARCH

RUN set -eux; \
    apk add -U --no-cache ca-certificates


FROM scratch

ARG TARGETOS
ARG TARGETARCH

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=syft /syft /usr/bin/syft
COPY dist/sbom-operator_${TARGETOS}_${TARGETARCH}/sbom-operator /usr/local/bin/sbom-operator

ENTRYPOINT ["/usr/local/bin/sbom-operator"]
