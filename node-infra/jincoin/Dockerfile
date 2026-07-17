# Jincoin Core (jincoin/jincoin-core @ master, v2.0.2.1) in a container.
#
# Base: ubuntu:22.04 (jammy). Boost 1.74 / OpenSSL 3 / GCC 11. We attempted
# focal first (closer-era toolchain for this 2018 Bitcoin Core 0.13.x fork),
# but <archival-host>'s focal apt repositories fail GPG signature validation as of
# 2026-05 — Ubuntu 20.04 standard support ended 2025-04-30 and the focal-
# updates/backports signing keys are no longer accepted by the host. Jammy is
# the next-newest LTS still in active support. Modern toolchain may require
# small patches (Boost 1.66+ placeholder removal, OpenSSL 3 deprecation
# warnings) similar to the ixcoin 0.14 case, but JIN v2 is closer to modern
# Bitcoin Core than ixcoin, so expect a cleaner build.
#
# Wallet/GUI/tests/bench/zmq disabled because (a) AuxPoW extraction only reads
# blocks, and (b) --disable-wallet avoids the BITCOIN_FIND_BDB48 configure path
# entirely, sidestepping the BDB-4.8 dependency. init.cpp guards wallet.h with
# #ifdef ENABLE_WALLET so --disable-wallet works cleanly here.
#
# Network reality (verified 2026-05-16): all six DNS seeds are NXDOMAIN, and
# the single hardcoded mainnet peer 192.52.166.125:23099 is unreachable from
# multiple vantage points. The daemon will start but is not expected to find
# any peers without an addnode= from a private archive.

# --- build stage --------------------------------------------------------------
FROM ubuntu:22.04 AS build

ARG JINCOIN_REF=master
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 ca-certificates git \
        libssl-dev libevent-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-test-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${JINCOIN_REF}" \
        https://github.com/jincoin/jincoin-core.git . \
    && git log -1 --oneline

# Modern-toolchain patches lifted from node-infra/ixcoin/patches/. The four
# applicable hunks (httpserver.cpp <deque>, init.cpp scoped signals2,
# main.cpp const-on-IteratorComparator, validationinterface.cpp boost
# placeholders) are required for jammy's GCC 11 / Boost 1.74 to compile JIN
# v2's source. The miner.h and txmempool.h hunks fail to apply because JIN
# already has the const-on-functor fixes — we use git apply --reject and
# discard the .rej files for those two.
COPY patches/0001-modern-toolchain-from-ixcoin.patch /tmp/
RUN git apply --reject /tmp/0001-modern-toolchain-from-ixcoin.patch || true \
    && find src -name '*.rej' -print -delete \
    && grep -l "boost::placeholders" src/validationinterface.cpp \
    && grep -l "<deque>" src/httpserver.cpp \
    && grep -l "conn_genesis_wait" src/init.cpp \
    && grep -l "bool operator()(const I& a, const I& b) const" src/main.cpp

# CMerkleTx is moved into src/auxpow.h in the Syscoin-1.x / Daniel-Kraft-2014
# lineage (so AuxPoW can reuse it), but its static `ABANDON_HASH` constant is
# defined only in src/wallet/wallet.cpp. With --disable-wallet that
# translation unit isn't compiled, so jincoind fails to link with "undefined
# reference to CMerkleTx::ABANDON_HASH". Add the definition to auxpow.cpp
# (always compiled) so the non-wallet build links cleanly. Value matches
# wallet.cpp:59.
RUN grep -q "CMerkleTx::ABANDON_HASH" src/auxpow.cpp \
    || printf '\n// Definition relocated from wallet.cpp so --disable-wallet builds link.\nconst uint256 CMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));\n' \
        >> src/auxpow.cpp \
    && tail -5 src/auxpow.cpp

RUN ./autogen.sh \
    && ./configure \
        --without-gui \
        --disable-wallet \
        --disable-tests \
        --disable-bench \
        --disable-zmq \
    && make -j"$(nproc)" \
    && strip src/jincoind src/jincoin-cli src/jincoin-tx

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libevent-2.1-7 libevent-pthreads-2.1-7 \
        libboost-system1.74.0 libboost-filesystem1.74.0 libboost-chrono1.74.0 \
        libboost-program-options1.74.0 libboost-thread1.74.0 \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 jincoin \
    && useradd -u 1000 -g jincoin -d /home/jincoin -m jincoin

COPY --from=build /src/src/jincoind     /usr/local/bin/jincoind
COPY --from=build /src/src/jincoin-cli  /usr/local/bin/jincoin-cli
COPY --from=build /src/src/jincoin-tx   /usr/local/bin/jincoin-tx

USER jincoin
WORKDIR /home/jincoin
RUN mkdir -p /home/jincoin/.jincoin
VOLUME ["/home/jincoin/.jincoin"]

EXPOSE 23098 23099

ENTRYPOINT ["/usr/bin/tini", "--", "jincoind", "-printtoconsole"]
