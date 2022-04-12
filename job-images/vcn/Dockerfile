FROM docker:20.10.14-dind

COPY vcn-v0.9.14-linux-amd64 /usr/local/bin/vcn
COPY entrypoint.sh /

RUN mkdir .vcn && \
    apk add --no-cache jq bash

ENTRYPOINT ["/entrypoint.sh"]
