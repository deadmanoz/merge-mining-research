# Myriadcoin Core in a container.
#
# Base: ubuntu:20.04 (focal). Myriadcoin's last upstream commit is 2021-12-10
# on a Bitcoin Core ~0.17 lineage (autotools, ADD_SERIALIZE_METHODS-era).
# Focal's Boost 1.71 + OpenSSL 1.1 match the era cleanly; no patches needed
# unlike the older ixcoin/unobtanium 0.11 forks.
#
# Multi-algo PoW (SHA-256d / Scrypt / Groestl / Yescrypt / Argon2d, with
# Skein/Qubit deprecated in the ~2019 hard fork). Only the SHA-256d branch
# carries Bitcoin-parent AuxPoW commitments; per-block algo filtering happens
# at the extractor, not at the node (myriadcoind validates all 5 algos).
#
# Wallet/GUI/tests/bench/zmq all disabled because AuxPoW extraction only
# reads blocks.

# --- build stage --------------------------------------------------------------
FROM ubuntu:20.04 AS build

ARG MYRIADCOIN_REF=master
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 ca-certificates git \
        libssl-dev libevent-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-test-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${MYRIADCOIN_REF}" \
        https://github.com/myriadcoin/myriadcoin.git . \
    && git log -1 --oneline

RUN ./autogen.sh \
    && ./configure \
        --without-gui \
        --disable-wallet \
        --disable-tests \
        --disable-bench \
        --disable-zmq \
    && make -j"$(nproc)" \
    && strip src/myriadcoind src/myriadcoin-cli src/myriadcoin-tx

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:20.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl1.1 libevent-2.1-7 libevent-pthreads-2.1-7 \
        libboost-system1.71.0 libboost-filesystem1.71.0 libboost-chrono1.71.0 \
        libboost-program-options1.71.0 libboost-thread1.71.0 \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 myriadcoin \
    && useradd -u 1000 -g myriadcoin -d /home/myriadcoin -m myriadcoin

COPY --from=build /src/src/myriadcoind     /usr/local/bin/myriadcoind
COPY --from=build /src/src/myriadcoin-cli  /usr/local/bin/myriadcoin-cli
COPY --from=build /src/src/myriadcoin-tx   /usr/local/bin/myriadcoin-tx

USER myriadcoin
WORKDIR /home/myriadcoin
RUN mkdir -p /home/myriadcoin/.myriadcoin
VOLUME ["/home/myriadcoin/.myriadcoin"]

EXPOSE 10888 10889

ENTRYPOINT ["/usr/bin/tini", "--", "myriadcoind", "-printtoconsole"]
