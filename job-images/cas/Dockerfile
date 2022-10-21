FROM codenotary/cas:1.0.3 as cas
FROM docker:20.10.20-dind

COPY --from=cas /bin/cas /bin/cas
COPY entrypoint.sh /

RUN mkdir .cas && \
    apk add --no-cache jq bash && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
