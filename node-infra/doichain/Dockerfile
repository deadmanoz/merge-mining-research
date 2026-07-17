# Doichain Core pinned to the source revision used for the completed survey.
FROM ubuntu:22.04 AS build

ARG DOICHAIN_REF=7eb68ae902f8329c80dc38e464f80d8bda2ed514
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libtool autotools-dev automake pkg-config bsdmainutils \
        python3 ca-certificates git libssl-dev libevent-dev \
        libboost-system-dev libboost-filesystem-dev libboost-chrono-dev \
        libboost-program-options-dev libboost-test-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone https://github.com/Doichain/doichain-core.git . \
    && git checkout "${DOICHAIN_REF}" \
    && git log -1 --oneline

RUN ./autogen.sh \
    && ./configure --without-gui --disable-wallet --disable-tests \
        --disable-bench --disable-zmq \
    && make -j"$(nproc)" \
    && strip src/doichaind src/doichain-cli src/doichain-tx

FROM ubuntu:22.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libevent-2.1-7 libevent-pthreads-2.1-7 \
        libboost-system1.74.0 libboost-filesystem1.74.0 libboost-chrono1.74.0 \
        libboost-program-options1.74.0 libboost-thread1.74.0 ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 doichain \
    && useradd -u 1000 -g doichain -d /home/doichain -m doichain

COPY --from=build /src/src/doichaind /usr/local/bin/doichaind
COPY --from=build /src/src/doichain-cli /usr/local/bin/doichain-cli
COPY --from=build /src/src/doichain-tx /usr/local/bin/doichain-tx

USER doichain
WORKDIR /home/doichain
RUN mkdir -p /home/doichain/.doichain
VOLUME ["/home/doichain/.doichain"]
EXPOSE 8338 8339
ENTRYPOINT ["/usr/bin/tini", "--", "doichaind", "-printtoconsole"]
