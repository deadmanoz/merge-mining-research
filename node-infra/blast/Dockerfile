# BLAST Core (blastdev/blast-core-v2 @ master, last commit 2019-10-15) in a container.
#
# Base: ubuntu:22.04 (jammy). Boost 1.74 / OpenSSL 3 / GCC 11. This is the
# same base used by node-infra/jincoin/ and for the same reasons: jammy is
# the next-newest LTS still in active support after focal (20.04) signing
# keys started failing GPG validation on <archival-host> in 2026-05.
#
# Lineage note: BLAST is a Ravencoin-lineage Bitcoin Core ~0.15.x fork. The
# AuxPoW subsystem (src/auxpow/) follows the Namecoin Daniel-Kraft 2014
# pattern (CAuxPow : public CMerkleTx, pchMergedMiningHeader = fa be 6d 6d).
# Two BLAST-specific consensus quirks the extractor must respect:
#
#   1. Chain-ID rotation. consensus.nAuxpowChainId = 0x1940 (6464) at launch
#      and consensus.nAlternateChainId = 0x00A4 (164) post-rotation.
#      consensus.nChainIdUpgradeHeight = 796000 controls only the miner
#      (src/miner.cpp:148-149). The consensus rule at src/pow.cpp:273
#      accepts EITHER id at ANY height — height is not part of the
#      validation predicate. So extractors should mirror the consensus rule
#      (two-value whitelist, no height check) and additionally record which
#      id was observed per block for the methodologically-interesting
#      rotation distribution.
#
#   2. No fStrictChainId. Zero hits anywhere in src/. The Namecoin/i0coin
#      strict-vs-lax toggle does not exist here. The 2019-09-10 commit
#      "Fixes 2 bugs related to AUX POW blocks" removed the flag upstream
#      and the v2 fork's tip reflects that.
#
# Wallet kept enabled (vs jincoin's --disable-wallet) because the
# --disable-wallet trap is worse here than in jincoin: BLAST's
# src/auxpow/auxpow.h:10 unconditionally `#include`s wallet/wallet.h, which
# transitively pulls in wallet/walletdb.h -> wallet/db.h -> db_cxx.h (BDB).
# Disabling the wallet therefore fails at compile time on every translation
# unit that includes primitives/block.h -> auxpow.h. The least-invasive
# fix is to build *with* the wallet against the system BDB 5.3 (vs
# upstream Bitcoin Core's required-by-convention BDB 4.8), using
# --with-incompatible-bdb. The wallet won't be runtime-compatible with
# pre-existing 4.8 wallets, but we never load one — init.sh sets
# disablewallet=1 in blast.conf — so it's irrelevant for AuxPoW extraction.
#
# Network reality (verified 2026-05-16): all six DNS-seed names declared in
# chainparams.cpp + their bare-domain / www counterparts resolve to the
# SAME single IP 35.220.144.141 (GCP wildcard A-record on a single
# instance, not a populated seeder). TCP 64640 on that IP is closed. The
# daemon will start but is not expected to find peers without an addnode=
# from a private archive.

# --- build stage --------------------------------------------------------------
FROM ubuntu:22.04 AS build

ARG BLAST_REF=master
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 ca-certificates git \
        libssl-dev libevent-dev libdb5.3-dev libdb5.3++-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-test-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${BLAST_REF}" \
        https://github.com/blastdev/blast-core-v2.git . \
    && git log -1 --oneline

# Modern-toolchain patches (Boost 1.66+ / GCC 11+ on Ubuntu 22.04). Three trips:
#
# 1. src/httpserver.cpp uses std::deque and std::queue without including
#    <deque> / <queue>. Older libstdc++ pulled them in transitively via
#    <event2/util.h>; GCC 11's libstdc++ does not.
#
# 2. src/validationinterface.cpp and src/validation.cpp use bare _1/_2/_3
#    Boost placeholders. Boost 1.66+ moved these from the global namespace
#    into boost::placeholders. Add a using-declaration after the first
#    #include line. (Same fix the jincoin/ixcoin patch applies, extended
#    here to also cover validation.cpp.)
RUN grep -q '#include <deque>' src/httpserver.cpp \
    || sed -i 's|#include <event2/util.h>|#include <event2/util.h>\n#include <deque>\n#include <queue>|' src/httpserver.cpp \
    && grep -nE '<deque>|<queue>' src/httpserver.cpp

RUN for f in src/validationinterface.cpp src/validation.cpp; do \
        grep -q 'boost::placeholders' "$f" \
        || sed -i '0,/^#include/{s|^#include\(.*\)$|#include\1\n#include <boost/bind/bind.hpp>\nusing namespace boost::placeholders;|}' "$f"; \
        grep -n 'boost::placeholders' "$f" || { echo "patch failed on $f" >&2; exit 1; }; \
    done

RUN ./autogen.sh \
    && ./configure \
        --without-gui \
        --with-incompatible-bdb \
        --disable-tests \
        --disable-bench \
        --disable-zmq \
    && make -j"$(nproc)" \
    && strip src/blastd src/blast-cli
# Note: blast-tx is intentionally NOT built — BLAST's configure.ac sets
# "build bitcoin-tx = no" as the default. We don't need it for AuxPoW
# extraction (blastd + blast-cli for RPC are sufficient), so we don't
# override the configure default.

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libevent-2.1-7 libevent-pthreads-2.1-7 \
        libdb5.3 libdb5.3++ \
        libboost-system1.74.0 libboost-filesystem1.74.0 libboost-chrono1.74.0 \
        libboost-program-options1.74.0 libboost-thread1.74.0 \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 blast \
    && useradd -u 1000 -g blast -d /home/blast -m blast

COPY --from=build /src/src/blastd    /usr/local/bin/blastd
COPY --from=build /src/src/blast-cli /usr/local/bin/blast-cli

USER blast
WORKDIR /home/blast
RUN mkdir -p /home/blast/.blast
VOLUME ["/home/blast/.blast"]

EXPOSE 64639 64640

ENTRYPOINT ["/usr/bin/tini", "--", "blastd", "-printtoconsole"]
