FROM alpine:3.15 as alpine

ENV SYFT_VERSION 0.35.0
ARG TARGETARCH

RUN set -eux; \
    apk add -U --no-cache ca-certificates && \
    case "${TARGETARCH}" in \
      amd64) CHECKSUM="5eddcf20dc3d19dd2a23ec5fd1c29dd74a9589dd3a799708a881b9cd6205fccc" ;; \
      arm64) CHECKSUM="5912abf7a5b8bfa30f1bd00ec4f8715734adbab10f413c7bbef9b1cea47e55d0" ;; \
      *) ;; \
    esac && \
    wget -O syft.tar.gz https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz && \
    echo "$CHECKSUM  syft.tar.gz" | sha256sum -c - && \
    mkdir -p /usr/share/syft && \
    tar -C /usr/share/syft -oxzf syft.tar.gz && \
    rm syft.tar.gz


FROM scratch

ARG TARGETOS
ARG TARGETARCH

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=alpine /usr/share/syft/syft /usr/bin/syft
COPY dist/sbom-git-operator_${TARGETOS}_${TARGETARCH}/sbom-git-operator /usr/local/bin/sbom-git-operator

ENTRYPOINT ["/usr/local/bin/sbom-git-operator"]
