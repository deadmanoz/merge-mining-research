# Lyncoin Core v4.0.0 official Linux x64 release in a container.
#
# The release archive is pinned by version and SHA-256. Lyncoin v4 follows
# modern Bitcoin Core storage conventions, including optional blk*.dat XOR
# obfuscation. The shared offline extractor detects blocks/xor.dat.

FROM debian:bookworm-slim AS download

ARG LYNCOIN_VERSION=4.0.0
ARG LYNCOIN_SHA256=048d3ac9268b68c598d49e94f6d93a475ade3cd75e4818a8d3e0367bf66f4e6f
ARG LYNCOIN_URL=https://github.com/lyncoin/lyncoin/releases/download/v4.0.0/lyncoin-4.0.0-linux-x64.tar.gz

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /download
RUN curl -fsSLo lyncoin.tar.gz "${LYNCOIN_URL}" \
    && echo "${LYNCOIN_SHA256}  lyncoin.tar.gz" | sha256sum -c - \
    && mkdir /out \
    && tar -xzf lyncoin.tar.gz -C /out \
    && test -x /out/lyncoind \
    && test -x /out/lyncoin-cli \
    && test -x /out/lyncoin-tx

FROM debian:bookworm-slim AS runtime

ARG LYNCOIN_VERSION=4.0.0
LABEL org.opencontainers.image.version="${LYNCOIN_VERSION}" \
      org.opencontainers.image.source="https://github.com/lyncoin/lyncoin"

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 lyncoin \
    && useradd -u 1000 -g lyncoin -d /home/lyncoin -m lyncoin

COPY --from=download /out/lyncoind /usr/local/bin/lyncoind
COPY --from=download /out/lyncoin-cli /usr/local/bin/lyncoin-cli
COPY --from=download /out/lyncoin-tx /usr/local/bin/lyncoin-tx
RUN lyncoind --version \
    && lyncoin-cli --version \
    && lyncoin-tx --version

USER lyncoin
WORKDIR /home/lyncoin
RUN mkdir -p /home/lyncoin/.lyncoin
VOLUME ["/home/lyncoin/.lyncoin"]

EXPOSE 5053 5054

ENTRYPOINT ["/usr/bin/tini", "--", "lyncoind", "-printtoconsole"]
