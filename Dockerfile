FROM alpine:3.15 as alpine

ENV SYFT_VERSION 0.35.0
ARG TARGETARCH

RUN set -eux; \
    apk add -U --no-cache ca-certificates


FROM scratch

ARG TARGETOS
ARG TARGETARCH

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=anchore/syft:v0.35.1@sha256:fd2da1424585680f220ed61db13096f7abcd0c0073b52616bbce397a8e708a96 /syft /usr/bin/syft
COPY dist/sbom-operator_${TARGETOS}_${TARGETARCH}/sbom-operator /usr/local/bin/sbom-operator

ENTRYPOINT ["/usr/local/bin/sbom-operator"]
