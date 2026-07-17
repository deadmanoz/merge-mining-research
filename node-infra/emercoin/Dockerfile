# Emercoin Core in a container.
#
# Base: ubuntu:20.04 (focal). Emercoin's `src/primitives/block.h` /
# `src/auxpow.h` lineage is Bitcoin Core 0.19 (configure.ac declares
# 0.19.2; autotools, READWRITEAS, std::shared_ptr<CAuxPow>). Focal's Boost 1.71 + OpenSSL
# 1.1 + libevent 2.1 match cleanly; no patches needed unlike the older
# ixcoin/unobtanium 0.11 forks.
#
# Hybrid PoW/PoS chain (Peercoin lineage). Only PoW blocks carry the
# Namecoin-style AuxPoW commitment (AUXPOW_CHAIN_ID = 666, MMHeight =
# 219809). The PoS branch is filtered out at the extractor via
# `nFlags & BLOCK_PROOF_OF_STAKE` (bit 0) - the node accepts both.
#
# GUI/tests/bench/zmq disabled. `--disable-wallet` cannot be used: Emercoin's
# `src/init.cpp:70` includes `<wallet/wallet.h>` unconditionally (outside any
# ENABLE_WALLET guard), so wallet code must compile and BDB 4.8 must be on
# the include path. We build BDB 4.8 statically via the upstream
# `contrib/install_db4.sh`, then disable the wallet at *runtime* via
# `disablewallet=1` in `emercoin.conf` (rendered by init.sh).

# --- build stage --------------------------------------------------------------
FROM ubuntu:20.04 AS build

ARG EMERCOIN_REF=master
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 ca-certificates git curl \
        libssl-dev libevent-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-test-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${EMERCOIN_REF}" \
        https://github.com/emercoin/emercoin.git . \
    && git log -1 --oneline

# BDB 4.8 (Oracle download, statically linked into emercoind via BDB_PREFIX).
#
# `contrib/install_db4.sh` downloads `config.guess` / `config.sub` from
# `git.savannah.gnu.org/gitweb`, which is currently down (timeouts even
# from local host as of 2026-05-16). Replace those `http_get` calls
# with `cp` from the modern files shipped by `autotools-dev` in focal -
# they're 2018-vintage and recognise x86_64-linux-gnu fine, which is
# all BDB 4.8's stale 2010 dist/ dir actually needs.
RUN sed -i \
        -e 's|^http_get "\${CONFIG_GUESS_URL}".*|cp /usr/share/misc/config.guess dist/config.guess|' \
        -e 's|^http_get "\${CONFIG_SUB_URL}".*|cp /usr/share/misc/config.sub dist/config.sub|' \
        ./contrib/install_db4.sh \
    && grep -E "cp /usr/share/misc/config\.(guess|sub)" ./contrib/install_db4.sh \
    && ./contrib/install_db4.sh /src \
    && ls /src/db4/lib/libdb_cxx-4.8.a

RUN ./autogen.sh \
    && export BDB_PREFIX=/src/db4 \
    && ./configure \
        --without-gui \
        --disable-tests \
        --disable-bench \
        --disable-zmq \
        BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" \
        BDB_CFLAGS="-I${BDB_PREFIX}/include" \
    && make -j"$(nproc)" -C src emercoind emercoin-cli \
    && strip src/emercoind src/emercoin-cli

# Note: we deliberately skip `emercoin-tx` and `emercoin-wallet` targets.
# Both fail to link with `undefined reference to GetMinFee(unsigned long)`.
# The free function lives in `src/policy/feerate.cpp`, which Makefile.am
# compiles into `libbitcoin_common.a`; `primitives/transaction.cpp` in
# `libbitcoin_consensus.a` calls it, and both tools' LDADD lists the
# consensus lib AFTER common, so a single-pass static linker cannot
# resolve the consensus-to-common back-reference. Emercoin source defect.
# We don't need either binary for IBD or AuxPoW extraction -
# emercoind + emercoin-cli are sufficient.

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:20.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl1.1 libevent-2.1-7 libevent-pthreads-2.1-7 \
        libboost-system1.71.0 libboost-filesystem1.71.0 libboost-chrono1.71.0 \
        libboost-program-options1.71.0 libboost-thread1.71.0 \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 emercoin \
    && useradd -u 1000 -g emercoin -d /home/emercoin -m emercoin

COPY --from=build /src/src/emercoind     /usr/local/bin/emercoind
COPY --from=build /src/src/emercoin-cli  /usr/local/bin/emercoin-cli

USER emercoin
WORKDIR /home/emercoin
RUN mkdir -p /home/emercoin/.emercoin
VOLUME ["/home/emercoin/.emercoin"]

EXPOSE 6661 6662

ENTRYPOINT ["/usr/bin/tini", "--", "emercoind", "-printtoconsole"]
