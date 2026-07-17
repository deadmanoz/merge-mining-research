# Crown Core v0.14.0.4 in a container.
#
# Base: ubuntu:18.04 (bionic). Crown's RPC server still uses pre-1.66 Boost
# ASIO APIs that were removed in Boost 1.66+: the two-arg `ssl::context`
# constructor, `acceptor::get_io_service()`, and `ssl::context::impl()`.
# Ubuntu 18.04 ships Boost 1.65, which still has these. Ubuntu 20.04 (Boost
# 1.71) and later require source patches to rpcserver.cpp. Crown also needs
# libcurl at configure time (AuxPoW mining helpers — harmless on a read-only
# node) and libdb++-dev because db_cxx.h leaks into main.cpp/init.cpp even
# with --disable-wallet.
# Wallet is disabled because AuxPoW extraction only reads blocks.

# --- build stage --------------------------------------------------------------
FROM ubuntu:18.04 AS build

ARG CROWN_REF=v0.14.0.4
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake autoconf pkg-config bsdmainutils \
        python3 ca-certificates git \
        libssl-dev libevent-dev libcurl4-openssl-dev libdb++-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-test-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${CROWN_REF}" \
        https://github.com/Crowndev/crowncoin.git .

# OpenSSL: `--with-unsupported-ssl` bypasses the RAND_egd sentinel check that
# Crown uses to detect SSL <= 1.0.x. Safe for read-only nodes (no signing/mining).
#
# Wallet stays enabled: Crown 0.14.x masternode/governance/spork/auxpow code
# unconditionally references wallet-only symbols (mnodeman, legacySigner,
# budget, InstantSend::GetSignaturesCount, CSystemnodeBroadcast, etc.), so
# `--disable-wallet` fails at link time with dozens of undefined references.
# `--with-incompatible-bdb` accepts whatever BDB version bionic ships (5.3.x);
# we never create a wallet so binary compatibility doesn't matter.
RUN ./autogen.sh \
    && ./configure \
        --without-gui \
        --disable-tests \
        --without-miniupnpc \
        --with-unsupported-ssl \
        --with-incompatible-bdb \
    && make -j"$(nproc)" \
    && strip src/crownd src/crown-cli src/crown-tx

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:18.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# `tini` is in bionic-universe, which the minimal ubuntu:18.04 image leaves
# disabled. Rather than enable universe just for an init wrapper, we omit it
# and rely on crownd's own SIGTERM handler (inherited from Bitcoin Core);
# docker compose can supply `init: true` if zombie reaping ever becomes an
# issue.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl1.1 libevent-2.1-6 libevent-pthreads-2.1-6 libcurl4 libdb5.3++ \
        libboost-system1.65.1 libboost-filesystem1.65.1 libboost-chrono1.65.1 \
        libboost-program-options1.65.1 libboost-thread1.65.1 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 crown \
    && useradd -u 1000 -g crown -d /home/crown -m crown

COPY --from=build /src/src/crownd     /usr/local/bin/crownd
COPY --from=build /src/src/crown-cli  /usr/local/bin/crown-cli
COPY --from=build /src/src/crown-tx   /usr/local/bin/crown-tx

USER crown
WORKDIR /home/crown
RUN mkdir -p /home/crown/.crown
VOLUME ["/home/crown/.crown"]

# 9340 = P2P, 9341 = RPC (mainnet, per src/chainparamsbase.cpp + src/chainparams.cpp)
EXPOSE 9340 9341

ENTRYPOINT ["crownd", "-printtoconsole"]
