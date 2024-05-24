FROM alpine:3.20@sha256:77726ef6b57ddf65bb551896826ec38bc3e53f75cdde31354fbffb4f25238ebd as alpine

ARG TARGETARCH

RUN set -eux; \
    apk add -U --no-cache ca-certificates


FROM scratch

ARG TARGETOS
ARG TARGETARCH

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY dist/sbom-operator_${TARGETOS}_${TARGETARCH}*/sbom-operator /usr/local/bin/sbom-operator

ENTRYPOINT ["/usr/local/bin/sbom-operator"]
