FROM alpine:latest AS alpine

ARG TARGETARCH

RUN set -eux; \
    apk add -U --no-cache ca-certificates; \
    apk add -U --no-cache tzdata


FROM scratch

ARG TARGETOS
ARG TARGETARCH

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=alpine /usr/share/zoneinfo /usr/share/zoneinfo
COPY dist/sbom-operator_${TARGETOS}_${TARGETARCH}*/sbom-operator /usr/local/bin/sbom-operator

ENTRYPOINT ["/usr/local/bin/sbom-operator"]
