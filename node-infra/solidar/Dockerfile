# Solidar (formerly WorldLeadCurrency, WLC) daemon in a container.
#
# Base: debian:stretch (9), following the Argentum precedent. The pinned
# wincev/SOLIDAR lineage (0.8.9.0) is a 2014-era Bitcoin 0.8/0.9-family
# codebase that retains CBigNum (src/bignum.h), which inherits directly
# from OpenSSL's BIGNUM struct — opaque since OpenSSL 1.1, so a modern
# distro fails with "invalid use of incomplete type 'BIGNUM'". Stretch
# ships libssl1.0-dev (OpenSSL 1.0.2) as a parallel legacy package and
# pairs it with Boost 1.62 + GCC 6, close to the chain's native era.
# Stretch is past EOL, but its Docker base image and the
# archive.debian.org apt indexes remain available (unlike Ubuntu xenial,
# whose old-releases mirror 404s and failed GPG validation on the
# archival host in 2026-05).
#
# Source: public upstream wincev/SOLIDAR, pinned by full-commit ARG. The
# WLC-era sibling WorldLeadCurrency/WLC (f07b4a0d...) is selectable via
# SOLIDAR_REPO/SOLIDAR_REF for era-comparison builds; do not assume the
# newest branch validates every historical era. The daemon (solidard,
# 0.8.9.0) builds with its own src/makefile.unix, which also builds the
# bundled leveldb — the CoiledCoin build mechanics plus leveldb.
#
# Berkeley DB 4.8.30 is built from the checksum-pinned bitcoincore.org
# tarball (Sleepycat license, pre-AGPL relicensing), with the CoiledCoin
# workspace's bdb-atomic.patch and refreshed config.guess/config.sub for
# modern libc and arches.
#
# The wallet stays enabled (makefile.unix has no disable switch); the GUI
# is not built. The daemon binary doubles as the RPC CLI client.

# --- build stage --------------------------------------------------------------
FROM debian:stretch AS build

ARG SOLIDAR_REPO=https://github.com/wincev/SOLIDAR.git
ARG SOLIDAR_REF=a1ab9063f338666f602f0e056960061026ffb0d7
ENV DEBIAN_FRONTEND=noninteractive

# Repoint apt at archive.debian.org (stretch moved there after EOL in
# June 2022; the regular deb.debian.org mirrors return 404).
RUN printf '%s\n' \
        'deb [check-valid-until=no] http://archive.debian.org/debian stretch main' \
        'deb [check-valid-until=no] http://archive.debian.org/debian-security stretch/updates main' \
        > /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl1.0-dev libboost-all-dev libgmp-dev libmpfr-dev \
        zlib1g-dev \
        ca-certificates pkg-config patch git \
    && rm -rf /var/lib/apt/lists/*

# Build libdb 4.8.30 from source (not packaged on stretch).
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
    && ../dist/configure --enable-cxx --disable-shared \
        --disable-replication --with-pic --prefix=/opt/bdb4 \
    && make -j$(nproc) && make install

WORKDIR /build
RUN git clone "${SOLIDAR_REPO}" . \
    && git checkout "${SOLIDAR_REF}" && git log -1 --oneline

WORKDIR /build/src
RUN mkdir -p obj/nogui \
    && make -f makefile.unix USE_UPNP=- \
        BDB_INCLUDE_PATH=/opt/bdb4/include \
        BDB_LIB_PATH=/opt/bdb4/lib \
        BDB_LIB_SUFFIX=-4.8 \
        LDFLAGS="-L/opt/bdb4/lib" \
        CXXFLAGS="-O2 -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-but-set-variable" \
    && strip solidard

# --- runtime stage ------------------------------------------------------------
FROM debian:stretch AS runtime
# Redeclare so the label sees the same pin as the build stage. An ARG does
# not cross FROM boundaries.
ARG SOLIDAR_REF=a1ab9063f338666f602f0e056960061026ffb0d7
LABEL org.opencontainers.image.source="https://github.com/deadmanoz/merge-mining-research" \
      org.opencontainers.image.revision="${SOLIDAR_REF}"
ENV DEBIAN_FRONTEND=noninteractive
RUN printf '%s\n' \
        'deb [check-valid-until=no] http://archive.debian.org/debian stretch main' \
        'deb [check-valid-until=no] http://archive.debian.org/debian-security stretch/updates main' \
        > /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        libssl1.0.2 libgmp10 libgmpxx4ldbl libmpfr4 \
        libboost-system1.62.0 libboost-filesystem1.62.0 \
        libboost-program-options1.62.0 libboost-thread1.62.0 \
        libboost-chrono1.62.0 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 solidar && useradd -u 1000 -g solidar -d /data -s /bin/false solidar
COPY --from=build /build/src/solidard /usr/local/bin/solidard
USER solidar
WORKDIR /data
VOLUME ["/data"]
EXPOSE 55888 55889
ENTRYPOINT ["solidard", "-datadir=/data", "-printtoconsole"]
