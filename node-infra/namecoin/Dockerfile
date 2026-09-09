# Namecoin Core v28.0.0 runtime using the preserved native Linux binaries.
#
# This image deliberately does not compile or upgrade Namecoin. The binaries
# are supplied from the reviewed private archive and their hashes are checked
# during the image build.
FROM debian:bookworm-slim

ARG NAMECOIND_SHA256=dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7
ARG NAMECOIN_CLI_SHA256=318b6c881c8071abbafd984550172369c3498b4c65c389797350f2d458f085b1

RUN groupadd --gid 1000 namecoin \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/namecoin namecoin

COPY binaries/namecoind /usr/local/bin/namecoind
COPY binaries/namecoin-cli /usr/local/bin/namecoin-cli

RUN printf '%s  %s\n' \
        "${NAMECOIND_SHA256}" /usr/local/bin/namecoind \
        "${NAMECOIN_CLI_SHA256}" /usr/local/bin/namecoin-cli \
    | sha256sum --check --strict - \
    && chmod 0755 /usr/local/bin/namecoind /usr/local/bin/namecoin-cli \
    && mkdir -p /data /config \
    && chown namecoin:namecoin /data /config

USER namecoin:namecoin
WORKDIR /data

ENTRYPOINT ["namecoind"]
CMD ["--version"]
