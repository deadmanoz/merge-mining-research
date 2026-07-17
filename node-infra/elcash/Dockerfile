# Electric Cash (ELCASH) headless node: Bitcoin Core 0.20.2 + Namecoin-style AuxPoW.
# Built for AuxPoW parent-header extraction + Bitcoin Core classification
# (mirrors the other node-infra/ recipes).
# Two-stage: fat autotools build -> slim runtime. Wallet/GUI/ZMQ disabled
# (extraction only reads blocks), so no BerkeleyDB needed.

# --- build stage ------------------------------------------------------------
FROM ubuntu:20.04 AS build
ARG DEBIAN_FRONTEND=noninteractive
ARG ELCASH_REF=master
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 git ca-certificates \
        libssl-dev libevent-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-test-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "${ELCASH_REF}" \
        https://github.com/electric-cash/electric-cash.git . \
    && git log -1 --oneline
RUN ./autogen.sh \
    && ./configure --without-gui --disable-wallet --disable-tests \
                   --disable-bench --disable-zmq \
    && make -j"$(nproc)" \
    && strip src/elcashd src/elcash-cli

# --- runtime stage ----------------------------------------------------------
FROM ubuntu:20.04 AS runtime
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl1.1 libevent-2.1-7 libevent-pthreads-2.1-7 \
        libboost-system1.71.0 libboost-filesystem1.71.0 libboost-chrono1.71.0 \
        libboost-program-options1.71.0 libboost-thread1.71.0 \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 elcash && useradd -u 1000 -g elcash -d /data -m elcash
COPY --from=build /src/src/elcashd    /usr/local/bin/elcashd
COPY --from=build /src/src/elcash-cli /usr/local/bin/elcash-cli
USER elcash
WORKDIR /data
VOLUME ["/data"]
# Mainnet P2P 8333 (remapped at publish time off the host's Core), RPC remapped off 8332.
EXPOSE 8433 18432
ENTRYPOINT ["/usr/bin/tini", "--", "elcashd", "-printtoconsole", "-datadir=/data"]
