# Devcoin Core (devcoin/core @ 301c1ae) in a container.
#
# Base: ubuntu:24.04 (noble). GCC 13.3 / Boost 1.83 — the host toolchain
# <archival-host> used. The patch below adds standard-library include directives
# (`<cstdint>`, `<stdexcept>`, `<map>`, `<string>`) that GCC 13 stopped
# pulling in transitively. 82 header files touched, 1011 lines, but the
# changes are mechanical — no semantics change.
# Wallet, BDB, GUI, tests, and bench are all disabled because AuxPoW
# extraction only reads blocks.

# --- build stage --------------------------------------------------------------
FROM ubuntu:24.04 AS build

ARG DEVCOIN_REF=301c1ae8c2a59c1bfa160a2dce3286b036989ba2
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 ca-certificates git \
        libssl-dev libevent-dev libcurl4-openssl-dev \
        libboost-system-dev libboost-filesystem-dev libboost-thread-dev \
        libboost-test-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone https://github.com/devcoin/core.git . \
    && git checkout "${DEVCOIN_REF}" \
    && git log -1 --oneline

# Modern-toolchain header-include patches. See README.
COPY patches/0001-modern-toolchain.patch /tmp/
RUN git apply --check /tmp/0001-modern-toolchain.patch \
    && git apply /tmp/0001-modern-toolchain.patch

RUN ./autogen.sh \
    && ./configure \
        --without-gui \
        --without-bdb \
        --disable-wallet \
        --disable-tests \
        --disable-bench \
    && make -j"$(nproc)" \
    && strip src/devcoind src/devcoin-cli src/devcoin-tx

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libevent-2.1-7t64 libevent-pthreads-2.1-7t64 libcurl4t64 \
        libboost-system1.83.0 libboost-filesystem1.83.0 libboost-thread1.83.0 \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && (userdel -r ubuntu 2>/dev/null || true) \
    && (groupdel ubuntu 2>/dev/null || true) \
    && groupadd -g 1000 devcoin \
    && useradd -u 1000 -g devcoin -d /home/devcoin -m devcoin

COPY --from=build /src/src/devcoind     /usr/local/bin/devcoind
COPY --from=build /src/src/devcoin-cli  /usr/local/bin/devcoin-cli
COPY --from=build /src/src/devcoin-tx   /usr/local/bin/devcoin-tx

USER devcoin
WORKDIR /home/devcoin
RUN mkdir -p /home/devcoin/.devcoin
VOLUME ["/home/devcoin/.devcoin"]

EXPOSE 52333 52332

ENTRYPOINT ["/usr/bin/tini", "--", "devcoind", "-printtoconsole"]
