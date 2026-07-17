# ixcoin (IXCore @ 8207734) in a container.
#
# Base: ubuntu:24.04 (noble). GCC 13.3 / Boost 1.83 / OpenSSL 3 — exactly
# what was used to build the daemon on <archival-host>. The patches below are
# the minimum set needed to make the 0.14-era IXCore source compile against
# this modern toolchain (Boost 1.66+ requires `const` on functor `operator()`,
# Boost 1.74+ moved `boost::placeholders::_N` out of global scope, and GCC
# 13's stricter parsing exposes a missing `<deque>` include).
# Wallet is disabled because AuxPoW extraction only reads blocks.

# --- build stage --------------------------------------------------------------
FROM ubuntu:24.04 AS build

ARG IXCOIN_REF=8207734f4106b5154ac8596f0ac9a725e3b406d8
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 ca-certificates git \
        libssl-dev libevent-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-thread-dev libboost-test-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone https://github.com/IXCore/IXCoin.git . \
    && git checkout "${IXCOIN_REF}" \
    && git log -1 --oneline

# Modern-toolchain patches: missing <deque>, scoped Boost signals2 connection,
# const on functor operator(), boost::placeholders import. See README.
COPY patches/0001-modern-toolchain.patch /tmp/
RUN git apply --check /tmp/0001-modern-toolchain.patch \
    && git apply /tmp/0001-modern-toolchain.patch

RUN ./autogen.sh \
    && ./configure \
        --without-gui \
        --disable-wallet \
        --disable-tests \
        --disable-bench \
    && make -j"$(nproc)" \
    && strip src/ixcoind src/ixcoin-cli src/ixcoin-tx

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libevent-2.1-7t64 libevent-pthreads-2.1-7t64 \
        libboost-system1.83.0 libboost-filesystem1.83.0 libboost-chrono1.83.0 \
        libboost-program-options1.83.0 libboost-thread1.83.0 \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && (userdel -r ubuntu 2>/dev/null || true) \
    && (groupdel ubuntu 2>/dev/null || true) \
    && groupadd -g 1000 ixcoin \
    && useradd -u 1000 -g ixcoin -d /home/ixcoin -m ixcoin

COPY --from=build /src/src/ixcoind     /usr/local/bin/ixcoind
COPY --from=build /src/src/ixcoin-cli  /usr/local/bin/ixcoin-cli
COPY --from=build /src/src/ixcoin-tx   /usr/local/bin/ixcoin-tx

USER ixcoin
WORKDIR /home/ixcoin
RUN mkdir -p /home/ixcoin/.ixcoin
VOLUME ["/home/ixcoin/.ixcoin"]

EXPOSE 8338 8337

ENTRYPOINT ["/usr/bin/tini", "--", "ixcoind", "-printtoconsole"]
