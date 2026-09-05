FROM codenotary/vcn:v1.1.1@sha256:f228a89ccdb70349ecb24c39d803fa5e341027c3b7ec266d4b927963446a441e as vcn
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

COPY --from=vcn /bin/vcn /bin/vcn
COPY entrypoint.sh /

RUN mkdir .vcn && \
    apk add --no-cache jq bash && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
