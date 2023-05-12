FROM codenotary/vcn:v1.0.4 as vcn
FROM alpine:3.18

COPY --from=vcn /bin/vcn /bin/vcn
COPY entrypoint.sh /

RUN mkdir .vcn && \
    apk add --no-cache jq bash && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
