# Fractal Bitcoin (fractald v0.3.0) in a container.
#
# Fractal is an unbranded Bitcoin Core fork; upstream ships pre-built x86_64
# Linux tarballs, so this image just downloads the official release artifact
# and lays it out under /usr/local. The bitcoind binary is statically linked
# for Bitcoin Core deps (Boost / OpenSSL / libevent / libdb baked in); only
# libc/libpthread/libm are dynamic, so ubuntu:20.04 base is plenty.
#
# Datadir is /home/fractal/.fractal (bind-mounted from the host via
# docker-compose; point it at a large disk — archival mode needs ~2 TB).

FROM ubuntu:20.04 AS download

ARG FRACTAL_VERSION=0.3.0
ARG FRACTAL_TARBALL=fractald-${FRACTAL_VERSION}-x86_64-linux-gnu-ubuntu-20.04.tar.gz
ARG FRACTAL_URL=https://github.com/fractal-bitcoin/fractald-release/releases/download/v${FRACTAL_VERSION}/${FRACTAL_TARBALL}
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends         ca-certificates wget     && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN wget -q "${FRACTAL_URL}" \
    && tar xzf "${FRACTAL_TARBALL}" \
    && mv fractald-${FRACTAL_VERSION}-x86_64-linux-gnu fractald \
    && rm "${FRACTAL_TARBALL}"

# --- runtime stage ----------------------------------------------------------
FROM ubuntu:20.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends         ca-certificates tini     && rm -rf /var/lib/apt/lists/*     && groupadd -g 1000 fractal     && useradd -u 1000 -g fractal -d /home/fractal -m fractal

COPY --from=download /opt/fractald/bin/bitcoind        /usr/local/bin/fractald
COPY --from=download /opt/fractald/bin/bitcoin-cli     /usr/local/bin/fractal-cli
COPY --from=download /opt/fractald/bin/bitcoin-tx      /usr/local/bin/fractal-tx
COPY --from=download /opt/fractald/bin/bitcoin-wallet  /usr/local/bin/fractal-wallet
COPY --from=download /opt/fractald/bin/bitcoin-util    /usr/local/bin/fractal-util

USER fractal
WORKDIR /home/fractal
RUN mkdir -p /home/fractal/.fractal
VOLUME ["/home/fractal/.fractal"]

# Fractal defaults are 8332/8333 (collide with Bitcoin Core); we publish a
# remapped pair in docker-compose and pin them in bitcoin.conf via init.sh.
EXPOSE 18332 18333

ENTRYPOINT ["/usr/bin/tini", "--", "fractald", "-printtoconsole"]
