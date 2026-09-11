FROM ubuntu:24.04 AS build
ARG QBIT_SOURCE_SHA256=d948db28fdf5d27dc155dddab2eb3770ac4d2059b392553accdfdaaae1352ad2
ARG BUILD_JOBS=4
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkgconf python3 python3-venv libevent-dev libboost-dev \
    ca-certificates && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/build-venv
ENV VIRTUAL_ENV=/opt/build-venv PATH="/opt/build-venv/bin:${PATH}"
WORKDIR /src
COPY source.tar /tmp/source.tar
RUN echo "${QBIT_SOURCE_SHA256}  /tmp/source.tar" | sha256sum --check \
    && tar -xf /tmp/source.tar -C /src && rm /tmp/source.tar
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_WALLET=OFF \
    -DENABLE_IPC=OFF -DBUILD_GUI=OFF -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF \
    -DBUILD_BITCOIN_BIN=OFF -DINSTALL_MAN=OFF \
    && cmake --build build --target qbitd qbit-cli -j"${BUILD_JOBS}" \
    && strip build/bin/qbitd build/bin/qbit-cli

FROM ubuntu:24.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libevent-2.1-7t64 libevent-core-2.1-7t64 libevent-extra-2.1-7t64 \
    libevent-pthreads-2.1-7t64 ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/bin/qbitd /usr/local/bin/qbitd
COPY --from=build /src/build/bin/qbit-cli /usr/local/bin/qbit-cli
LABEL org.opencontainers.image.source="https://github.com/Qbit-Org/qbit" \
    org.opencontainers.image.revision="70fea84f5becfb57463247af09790df5ddd424f8"
USER 1000:1000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "test -f /config/qbit.conf && exec qbitd -datadir=/data -conf=/config/qbit.conf -prune=0 -prunewitnesses=0 -assumevalid=0 -txindex=1 -printtoconsole"]
