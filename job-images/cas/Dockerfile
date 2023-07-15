FROM codenotary/cas:1.0.3 as cas
FROM docker:24.0.4-dind

COPY --from=cas /bin/cas /bin/cas
COPY entrypoint.sh /

RUN mkdir .cas && \
    apk add --no-cache jq bash && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
