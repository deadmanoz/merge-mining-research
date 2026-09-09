# Syscoin Core v5.1.0 runtime using the preserved native Linux binaries.
#
# This image deliberately does not compile or upgrade Syscoin. The binaries
# are supplied from the reviewed private archive and their hashes are checked
# during the image build.
FROM debian:bookworm-slim

ARG SYSCOIND_SHA256=b181090eaaa8761270ec9da05743da1f1dc4d9c765975723fd68181faa73cdad
ARG SYSCOIN_CLI_SHA256=a93a0b4e1b625172f074eabe303aff441489ebd055c7b90b2ce8e64b5dba584f

RUN groupadd --gid 1000 syscoin \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/syscoin syscoin

COPY binaries/syscoind /usr/local/bin/syscoind
COPY binaries/syscoin-cli /usr/local/bin/syscoin-cli

RUN printf '%s  %s\n' \
        "${SYSCOIND_SHA256}" /usr/local/bin/syscoind \
        "${SYSCOIN_CLI_SHA256}" /usr/local/bin/syscoin-cli \
    | sha256sum --check --strict - \
    && chmod 0755 /usr/local/bin/syscoind /usr/local/bin/syscoin-cli \
    && mkdir -p /data /config \
    && chown syscoin:syscoin /data /config

USER syscoin:syscoin
WORKDIR /data

ENTRYPOINT ["syscoind"]
CMD ["--version"]
