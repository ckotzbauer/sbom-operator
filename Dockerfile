FROM alpine:3.18@sha256:7144f7bab3d4c2648d7e59409f15ec52a18006a128c733fcff20d3a4a54ba44a as alpine

ARG TARGETARCH

RUN set -eux; \
    apk add -U --no-cache ca-certificates


FROM scratch

ARG TARGETOS
ARG TARGETARCH

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY dist/sbom-operator_${TARGETOS}_${TARGETARCH}*/sbom-operator /usr/local/bin/sbom-operator

ENTRYPOINT ["/usr/local/bin/sbom-operator"]
