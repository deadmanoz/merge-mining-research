# Argentum Core in a container.
#
# Base: debian:stretch (9). Argentum's active fork (dbkeys/argentum,
# last commit 2024-02-07) is a Bitcoin Core ~0.13/0.14 lineage that
# retains the legacy CBigNum class (src/bignum.h, removed upstream in
# 2015) for the multi-algo nth-root work calculation in src/chain.cpp.
# CBigNum inherits directly from OpenSSL's BIGNUM struct, which became
# opaque in OpenSSL 1.1 — so a Focal build fails with "invalid use of
# incomplete type 'BIGNUM'" when compiling miner.cpp. Stretch pins
# Boost 1.62 + GCC 6 (matching the ARG-era native build environment),
# but its DEFAULT libssl-dev is OpenSSL 1.1.0 — which fails the same way.
# Stretch also ships libssl1.0-dev (OpenSSL 1.0.2) as a parallel legacy
# package for projects still on the pre-1.1 API; we install that instead.
#
# Stretch is past EOL but the Docker base image remains available on
# Docker Hub and archive.debian.org continues to serve apt indexes
# cleanly (unlike Ubuntu's old-releases archive which returns 404s on
# xenial binary-amd64/Packages after EOL).
#
# Multi-algo PoW (Scrypt / SHA-256d / Lyra2REv2 / Myriad-Groestl /
# Argon2d / Yescrypt, the four native algos activated at the 2018-03
# nBIP146Height fork; pre-fork the chain had only Scrypt + SHA-256d).
# Only the SHA-256d branch carries Bitcoin-parent AuxPoW commitments
# (Scrypt branch merge-mines with Litecoin/Dogecoin — out of scope;
# only Bitcoin-parent AuxPoW is in scope here). Per-block algo
# filtering happens at the extractor, not at the node.
#
# Wallet/GUI/tests/bench/zmq all disabled because AuxPoW extraction only
# reads blocks. src/init.cpp guards wallet headers with #ifdef
# ENABLE_WALLET so --disable-wallet is reliable here (unlike some older
# forks where --disable-wallet is unreliable).

# --- build stage --------------------------------------------------------------
FROM debian:stretch AS build

ARG ARGENTUM_REF=master
ENV DEBIAN_FRONTEND=noninteractive

# Repoint apt at archive.debian.org (stretch moved there after EOL
# in June 2022; the regular deb.debian.org mirrors return 404).
# `check-valid-until=no` disables the Release file expiry check (the
# frozen indexes are well past their original valid-until date).
# We need both `stretch` (main) AND `stretch/updates` (security) to
# resolve git's libcurl3-gnutls dependency.
RUN printf '%s\n' \
        'deb [check-valid-until=no] http://archive.debian.org/debian stretch main' \
        'deb [check-valid-until=no] http://archive.debian.org/debian-security stretch/updates main' \
        > /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid-until \
    && apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 ca-certificates git libcurl3-gnutls \
        libssl1.0-dev libevent-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-test-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${ARGENTUM_REF}" \
        https://github.com/dbkeys/argentum.git . \
    && git log -1 --oneline

RUN ./autogen.sh \
    && ./configure \
        --without-gui \
        --disable-wallet \
        --disable-tests \
        --disable-bench \
        --disable-zmq \
    && make -j"$(nproc)" \
    && strip src/argentumd src/argentum-cli src/argentum-tx

# --- runtime stage ------------------------------------------------------------
FROM debian:stretch AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN printf '%s\n' \
        'deb [check-valid-until=no] http://archive.debian.org/debian stretch main' \
        'deb [check-valid-until=no] http://archive.debian.org/debian-security stretch/updates main' \
        > /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid-until \
    && apt-get update && apt-get install -y --no-install-recommends \
        libssl1.0.2 libevent-2.0-5 libevent-pthreads-2.0-5 \
        libboost-system1.62.0 libboost-filesystem1.62.0 libboost-chrono1.62.0 \
        libboost-program-options1.62.0 libboost-thread1.62.0 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 argentum \
    && useradd -u 1000 -g argentum -d /home/argentum -m argentum

COPY --from=build /src/src/argentumd    /usr/local/bin/argentumd
COPY --from=build /src/src/argentum-cli /usr/local/bin/argentum-cli
COPY --from=build /src/src/argentum-tx  /usr/local/bin/argentum-tx

USER argentum
WORKDIR /home/argentum
RUN mkdir -p /home/argentum/.argentum
VOLUME ["/home/argentum/.argentum"]

EXPOSE 13580 13581

# tini is not in stretch main; docker-compose.yml sets `init: true` to
# get the same PID-1 reaping behaviour from Docker's built-in init.
ENTRYPOINT ["argentumd", "-printtoconsole"]
