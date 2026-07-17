# Xaya Core v1.13 in a container.
#
# Base: ubuntu:24.04. Xaya v1.13 (Apr 2025) is built on `namecoin-29.x`, i.e.
# Bitcoin Core 29.x lineage with CMake. Modern toolchain — no libssl1.1 /
# Boost 1.71 patches needed. Multi-algo PoW (NEOSCRYPT + SHA256D-AuxPoW) —
# only SHA256D blocks carry BTC parent commitments.
#
# Wallet/GUI/tests/bench/zmq all disabled because AuxPoW extraction only
# reads blocks.

# --- build stage --------------------------------------------------------------
FROM ubuntu:24.04 AS build

ARG XAYA_REF=v1.13
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake pkgconf python3 ca-certificates git \
        libevent-dev libboost-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${XAYA_REF}" \
        https://github.com/xaya/xaya.git . \
    && git log -1 --oneline

RUN cmake -B build \
        -DBUILD_BITCOIN_BIN=OFF \
        -DBUILD_DAEMON=ON \
        -DBUILD_CLI=ON \
        -DBUILD_GUI=OFF \
        -DBUILD_TESTS=OFF \
        -DBUILD_TX=OFF \
        -DBUILD_UTIL=OFF \
        -DENABLE_WALLET=OFF \
        -DWITH_ZMQ=OFF \
    && cmake --build build -j"$(nproc)" \
    && strip build/bin/xayad build/bin/xaya-cli

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libevent-core-2.1-7t64 libevent-extra-2.1-7t64 libevent-pthreads-2.1-7t64 \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && (userdel -r ubuntu 2>/dev/null || true) \
    && groupadd -g 1000 xaya \
    && useradd -u 1000 -g xaya -d /home/xaya -m xaya

COPY --from=build /src/build/bin/xayad    /usr/local/bin/xayad
COPY --from=build /src/build/bin/xaya-cli /usr/local/bin/xaya-cli

USER xaya
WORKDIR /home/xaya
RUN mkdir -p /home/xaya/.xaya
VOLUME ["/home/xaya/.xaya"]

EXPOSE 8394 8396

ENTRYPOINT ["/usr/bin/tini", "--", "xayad", "-printtoconsole"]
