FROM codenotary/vcn:0.9.13 as vcn
FROM docker:20.10.14-dind

COPY --from=vcn /bin/vcn /bin/vcn
COPY entrypoint.sh /

RUN mkdir .vcn && \
    apk add --no-cache jq bash && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
