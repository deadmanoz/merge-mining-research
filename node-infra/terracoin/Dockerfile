# Terracoin Core v0.12.2.5 in a container.
#
# Base: ubuntu:20.04 (focal). Ships Boost 1.71 and GCC 9, which matches the
# era the v0.12.2.5 source was written against (March 2020). Boost 1.73+ moved
# `_1` / `_2` / `_3` out of the global namespace, which breaks the AuxPoW
# validation interface in this version of the source. Sticking to 1.71 is
# simpler than patching six call sites.
# Wallet is disabled because AuxPoW extraction only reads blocks.

# --- build stage --------------------------------------------------------------
FROM ubuntu:20.04 AS build

ARG TERRACOIN_REF=v0.12.2.5
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 ca-certificates git \
        libssl-dev libevent-dev libzmq3-dev libcurl4-openssl-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-test-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${TERRACOIN_REF}" \
        https://github.com/terracoin/terracoin.git .

RUN ./autogen.sh \
    && ./configure \
        --without-gui \
        --disable-wallet \
        --disable-tests \
        --disable-bench \
        --disable-zmq \
    && make -j"$(nproc)" \
    && strip src/terracoind src/terracoin-cli src/terracoin-tx

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:20.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl1.1 libevent-2.1-7 libevent-pthreads-2.1-7 libcurl4 \
        libboost-system1.71.0 libboost-filesystem1.71.0 libboost-chrono1.71.0 \
        libboost-program-options1.71.0 libboost-thread1.71.0 \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 terracoin \
    && useradd -u 1000 -g terracoin -d /home/terracoin -m terracoin

COPY --from=build /src/src/terracoind     /usr/local/bin/terracoind
COPY --from=build /src/src/terracoin-cli  /usr/local/bin/terracoin-cli
COPY --from=build /src/src/terracoin-tx   /usr/local/bin/terracoin-tx

USER terracoin
WORKDIR /home/terracoin
RUN mkdir -p /home/terracoin/.terracoincore
VOLUME ["/home/terracoin/.terracoincore"]

EXPOSE 13332 13333

ENTRYPOINT ["/usr/bin/tini", "--", "terracoind", "-printtoconsole"]
