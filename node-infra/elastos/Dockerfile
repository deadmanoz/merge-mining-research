# Elastos v1.0.2 runtime using the two preserved native Linux binaries.
#
# This image deliberately does not compile or upgrade Elastos. The binaries
# are supplied from the reviewed private archive and their hashes are checked
# during the image build.
FROM debian:bookworm-slim

ARG ELA_SHA256=b1e2f3e43b772ac50e67db235b1c0df1110622db3b6d039370114dcbf1da4f2e
ARG ELA_CLI_SHA256=de429a77685793864c9b510fb2917e080786ebd46b262a0785b096a0ad00d544

RUN groupadd --gid 1000 ela \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/ela \
        --shell /usr/sbin/nologin ela

COPY --chmod=0755 ela /usr/local/bin/ela
COPY --chmod=0755 ela-cli /usr/local/bin/ela-cli
RUN printf '%s  %s\n' \
        "${ELA_SHA256}" /usr/local/bin/ela \
        "${ELA_CLI_SHA256}" /usr/local/bin/ela-cli \
    | sha256sum --check --strict - \
    && mkdir -p /data /config \
    && chown ela:ela /data /config

USER 1000:1000
WORKDIR /data

CMD ["/usr/local/bin/ela-cli", "--version"]
