FROM codenotary/vcn:v1.1.1@sha256:f228a89ccdb70349ecb24c39d803fa5e341027c3b7ec266d4b927963446a441e as vcn
FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

COPY --from=vcn /bin/vcn /bin/vcn
COPY entrypoint.sh /

RUN mkdir .vcn && \
    apk add --no-cache jq bash && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
