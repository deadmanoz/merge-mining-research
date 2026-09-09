# RSKj Vetiver 9.0.1 runtime from the preserved native JAR.
FROM --platform=linux/amd64 ubuntu:24.04

ARG RSK_JAR_SHA256=ffa9ada4e58ede93b342171ce635392f99315b744efbf251bda2fb2cd18da3bb
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless=17.0.20+8-1~24.04 \
        ca-certificates curl jq \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 binaries/rskj-core-9.0.1-VETIVER-all.jar \
    /opt/rsk/rskj-core-9.0.1-VETIVER-all.jar
COPY --chmod=0755 rsk-rpc.sh /usr/local/bin/rsk-rpc

RUN printf '%s  %s\n' "$RSK_JAR_SHA256" \
        /opt/rsk/rskj-core-9.0.1-VETIVER-all.jar | sha256sum -c - \
    && if ! getent group 1000 >/dev/null; then groupadd --gid 1000 rsk; fi \
    && if ! getent passwd 1000 >/dev/null; then \
        useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin rsk; \
    fi

USER 1000:1000
WORKDIR /data
ENTRYPOINT ["java"]
CMD ["-version"]
