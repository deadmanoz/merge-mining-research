# Bitmark Core (project-bitmark/bitmark) in a container.
#
# Base: ubuntu:20.04 (focal). Bitmark's master HEAD is ffd840e (2023-06-15),
# a Bitcoin Core ~0.9/0.10 lineage (pchMessageStart[] API) with Equihash and
# multi-algo + AuxPoW grafted on. The default ref here is the upstream
# `fix/ubuntu-2204-build` branch (cb75935 -- single commit on top of master)
# because focal's Boost 1.71 requires the boost::placeholders fixes that
# branch ships (std::placeholders cannot be used with boost::bind on Boost
# 1.66+). The same branch also fixes blake2 alignment. For ubuntu:24.04
# (GCC 13 + OpenSSL 3) additionally cherry-pick fix/gcc13-blake2-alignment,
# fix/gcc13-bmw256-optimization, and fix/openssl3-signature-verification.
#
# Multi-algo PoW (SHA-256d / Scrypt / Yescrypt / Argon2d / X17 / LYRA2REv2 /
# Equihash / CryptoNight, all eight merge-mineable since the 2018-06-07
# Fork 1 activation at height ~450,950). Only the SHA-256d branch carries
# Bitcoin-parent AuxPoW commitments; per-block algo filtering happens at
# the extractor by decoding child block `nVersion` bits before parsing the
# AuxPoW tail.
#
# Wallet/GUI/tests/bench all disabled because AuxPoW extraction only reads
# blocks.

# --- build stage --------------------------------------------------------------
FROM ubuntu:20.04 AS build

ARG BITMARK_REF=fix/ubuntu-2204-build
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 ca-certificates git \
        libssl-dev libevent-dev libsodium-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-test-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${BITMARK_REF}" \
        https://github.com/project-bitmark/bitmark.git . \
    && git log -1 --oneline

RUN ./autogen.sh \
    && ./configure \
        --without-gui \
        --disable-wallet \
        --disable-tests \
        --disable-bench \
    && make -j"$(nproc)" \
    && strip src/bitmarkd src/bitmark-cli
# Note: bitmark-tx is not built when --disable-wallet is set (wallet-adjacent tool).

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:20.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl1.1 libevent-2.1-7 libevent-pthreads-2.1-7 libsodium23 \
        libboost-system1.71.0 libboost-filesystem1.71.0 libboost-chrono1.71.0 \
        libboost-program-options1.71.0 libboost-thread1.71.0 \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 bitmark \
    && useradd -u 1000 -g bitmark -d /home/bitmark -m bitmark

COPY --from=build /src/src/bitmarkd     /usr/local/bin/bitmarkd
COPY --from=build /src/src/bitmark-cli  /usr/local/bin/bitmark-cli

USER bitmark
WORKDIR /home/bitmark
RUN mkdir -p /home/bitmark/.bitmark
VOLUME ["/home/bitmark/.bitmark"]

EXPOSE 9265 9266

ENTRYPOINT ["/usr/bin/tini", "--", "bitmarkd", "-printtoconsole"]
