FROM ubuntu:22.04 AS build
ARG ROD_SOURCE_SHA256=789cfd4ccdd924c4b879aaf993f5ef6f30294d917f88cfe342298048e738d449
ARG BUILD_JOBS=6
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libtool autotools-dev automake pkg-config bsdmainutils \
    python3 python3-venv ca-certificates libevent-dev libboost-dev \
    libboost-system-dev libboost-filesystem-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/build-venv
ENV VIRTUAL_ENV=/opt/build-venv PATH="/opt/build-venv/bin:${PATH}"
WORKDIR /src
COPY source.tar /tmp/source.tar
RUN echo "${ROD_SOURCE_SHA256}  /tmp/source.tar" | sha256sum --check \
    && tar -xf /tmp/source.tar -C /src && rm /tmp/source.tar
COPY download-window.patch /tmp/download-window.patch
RUN patch --batch --fuzz=0 -p1 < /tmp/download-window.patch
RUN ./autogen.sh \
    && ./configure --without-gui --disable-wallet --disable-tests --disable-bench \
        --disable-zmq --disable-man --without-miniupnpc --without-natpmp \
        CFLAGS="-O2 -fno-strict-aliasing" CXXFLAGS="-O2" \
    && make -j"${BUILD_JOBS}" \
    && strip src/spacexpansed src/spacexpanse-cli
COPY test-neoscrypt.c /tmp/test-neoscrypt.c
# Link the actual daemon crypto object, not a separately rebuilt implementation.
RUN cc /tmp/test-neoscrypt.c src/crypto/libbitcoin_crypto_base_a-neoscrypt.o \
    -o /tmp/test-neoscrypt && /tmp/test-neoscrypt

FROM ubuntu:22.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libevent-2.1-7 libevent-core-2.1-7 libevent-extra-2.1-7 libevent-pthreads-2.1-7 \
    libboost-system1.74.0 libboost-filesystem1.74.0 libboost-thread1.74.0 \
    ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 rod && useradd -u 1000 -g rod -m rod
RUN mkdir -p /data /config && chown rod:rod /data
COPY --from=build /src/src/spacexpansed /usr/local/bin/spacexpansed
COPY --from=build /src/src/spacexpanse-cli /usr/local/bin/spacexpanse-cli
LABEL org.opencontainers.image.source="https://github.com/SpaceXpanse/rod-core-wallet" \
      org.opencontainers.image.revision="248f1af050579a369af527288f5773a021ae8492"
USER rod
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "test -f /config/spacexpanse.conf && exec spacexpansed -datadir=/data -conf=/config/spacexpanse.conf -printtoconsole"]
