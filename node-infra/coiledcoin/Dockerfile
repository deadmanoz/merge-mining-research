# CoiledCoin (mmpool/coiledcoin @ 0aa503c) in a container.
#
# The chain has been dead since Luke-Jr / Eligius merge-mined its hashrate to
# obliteration in early 2012. We run the original 2012 codebase to read the
# pre-existing Berkeley DB block files for cross-confirmation against ixcoin
# and devcoin AuxPoW recovery.
#
# Base: ubuntu:16.04 (xenial) — ships GCC 5.4 / Boost 1.58 / OpenSSL 1.0.2,
# matching the Bitcoin 0.6-era codebase. Wallet support requires libdb 4.8;
# Xenial doesn't package it, so we build it from the Oracle source tarball.
# The tarball is fetched at build time with a pinned SHA-256 from the Bitcoin
# Core "depends" mirror (a stable, long-lived source for this exact file)
# rather than vendored, to keep large binaries out of the repository.

# --- build stage --------------------------------------------------------------
FROM ubuntu:16.04 AS build

ARG COILEDCOIN_REF=0aa503c9343bb84b06ccd79bf0219fe267a3bac2
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libboost-all-dev \
        libminiupnpc-dev \
        ca-certificates \
        pkg-config \
        patch \
        git \
    && rm -rf /var/lib/apt/lists/*

# Build libdb 4.8.30 from source (not packaged on Xenial).
# bdb-atomic.patch fixes an __atomic_compare_exchange clash with newer libc;
# fresh config.guess/config.sub teach BDB's autotools about modern arches.
# The BDB source tarball is fetched (checksum-pinned) instead of vendored; the
# Bitcoin Core depends mirror has hosted this exact file for years. Override
# BDB_URL to point at your own mirror if needed.
ARG BDB_URL=https://bitcoincore.org/depends-sources/db-4.8.30.NC.tar.gz
ARG BDB_SHA256=12edc0df75bf9abd7f82f821795bcee50f42cb2e5f76a6a281b85732798364ef
WORKDIR /bdb-build
ADD ${BDB_URL} /bdb-build/db-4.8.30.NC.tar.gz
COPY bdb-atomic.patch config.guess config.sub /bdb-build/
RUN echo "${BDB_SHA256}  db-4.8.30.NC.tar.gz" | sha256sum -c - \
    && tar xzf db-4.8.30.NC.tar.gz \
    && cd db-4.8.30.NC \
    && patch -p1 < /bdb-build/bdb-atomic.patch \
    && cp /bdb-build/config.guess /bdb-build/config.sub dist/ \
    && chmod +x dist/config.guess dist/config.sub \
    && cd build_unix \
    && ../dist/configure \
        --enable-cxx \
        --disable-shared \
        --disable-replication \
        --with-pic \
        --prefix=/opt/bdb4 \
    && make -j$(nproc) \
    && make install

# Clone CoiledCoin pinned to a known-good revision.
WORKDIR /build
RUN git clone https://github.com/mmpool/coiledcoin.git . \
    && git checkout "${COILEDCOIN_REF}" \
    && git log -1 --oneline

WORKDIR /build/src
RUN mkdir -p obj/nogui \
    && make -f makefile.unix USE_UPNP=- \
        BDB_INCLUDE_PATH=/opt/bdb4/include \
        BDB_LIB_PATH=/opt/bdb4/lib \
        BDB_LIB_SUFFIX=-4.8 \
        LDFLAGS="-L/opt/bdb4/lib" \
        CXXFLAGS="-O2 -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-but-set-variable" \
    && strip coiledcoind

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:16.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl1.0.0 \
        libboost-system1.58.0 libboost-filesystem1.58.0 \
        libboost-program-options1.58.0 libboost-thread1.58.0 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r coiled \
    && useradd -r -g coiled -d /data -s /bin/false coiled

COPY --from=build /build/src/coiledcoind /usr/local/bin/coiledcoind

USER coiled
WORKDIR /data
VOLUME ["/data"]

EXPOSE 8368

ENTRYPOINT ["coiledcoind", "-datadir=/data", "-printtoconsole"]
