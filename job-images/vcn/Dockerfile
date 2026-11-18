FROM codenotary/vcn:v1.1.1@sha256:f228a89ccdb70349ecb24c39d803fa5e341027c3b7ec266d4b927963446a441e as vcn
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

COPY --from=vcn /bin/vcn /bin/vcn
COPY entrypoint.sh /

RUN mkdir .vcn && \
    apk add --no-cache jq bash && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
