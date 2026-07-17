# Unobtanium Core (master @ 54d68b08) in a container.
#
# Base: ubuntu:20.04 (focal). Ships Boost 1.71 and GCC 9, matching the Bitcoin
# Core 0.11 era this fork was written against. Master branch carries 2024-era
# patches ('Add missing boost build flags', 'Fix qt5 byte array for gcc11+')
# that make the build portable across modern toolchains.
# Wallet, tests, and bench are disabled because AuxPoW extraction only reads blocks.

# --- build stage --------------------------------------------------------------
FROM ubuntu:20.04 AS build

ARG UNO_REF=54d68b08cdda
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 ca-certificates git \
        libssl-dev libevent-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-thread-dev libboost-test-dev \
        libdb++-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone https://github.com/unobtanium-official/Unobtanium.git . \
    && git checkout "${UNO_REF}" \
    && git log -1 --oneline

# OpenSSL 1.1+ made EVP_CIPHER_CTX opaque; wallet/crypter.cpp still uses the
# legacy stack-allocated API. Patch in-place before configure.
COPY crypter-openssl11.sed /tmp/crypter-openssl11.sed
RUN sed -i -f /tmp/crypter-openssl11.sed src/wallet/crypter.cpp \
    && head -80 src/wallet/crypter.cpp | tail -30

RUN ./autogen.sh \
    && ./configure \
        --without-gui \
        --with-incompatible-bdb \
        --disable-tests \
        --disable-bench \
    && make -j"$(nproc)" \
    && strip src/unobtaniumd src/unobtanium-cli src/unobtanium-tx

# --- runtime stage ------------------------------------------------------------
FROM ubuntu:20.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl1.1 libevent-2.1-7 libevent-pthreads-2.1-7 \
        libboost-system1.71.0 libboost-filesystem1.71.0 libboost-chrono1.71.0 \
        libboost-program-options1.71.0 libboost-thread1.71.0 libdb5.3++ \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 uno \
    && useradd -u 1000 -g uno -d /home/uno -m uno

COPY --from=build /src/src/unobtaniumd     /usr/local/bin/unobtaniumd
COPY --from=build /src/src/unobtanium-cli  /usr/local/bin/unobtanium-cli
COPY --from=build /src/src/unobtanium-tx   /usr/local/bin/unobtanium-tx

USER uno
WORKDIR /home/uno
RUN mkdir -p /home/uno/.unobtanium
VOLUME ["/home/uno/.unobtanium"]

EXPOSE 65534 65535

ENTRYPOINT ["/usr/bin/tini", "--", "unobtaniumd", "-printtoconsole"]
