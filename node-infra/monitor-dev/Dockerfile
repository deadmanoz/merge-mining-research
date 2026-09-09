# MMR-owned development image for merge-mining-monitor. The build context is
# the explicit local monitor checkout supplied by compose.yaml.
ARG RUST_IMAGE=rust:1.88-bookworm
FROM ${RUST_IMAGE} AS build

ARG MMM_SOURCE_REVISION=working-tree
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY README.md LICENSE RELEASE_NOTES.md ./
COPY crates ./crates
COPY data/consensus/error_blocks.csv ./data/consensus/error_blocks.csv
COPY data/historical/historical-source-manifest.json ./data/historical/historical-source-manifest.json
COPY data/pools/current.json ./data/pools/current.json
COPY data/pools/child-identities/elastos_minerinfo_registry.json ./data/pools/child-identities/elastos_minerinfo_registry.json
COPY data/pools/child-identities/elastos_reward_address_registry.json ./data/pools/child-identities/elastos_reward_address_registry.json
COPY data/pools/child-identities/fractal_reward_address_registry.json ./data/pools/child-identities/fractal_reward_address_registry.json
COPY data/pools/child-identities/hathor_reward_registry.json ./data/pools/child-identities/hathor_reward_registry.json
COPY data/pools/child-identities/namecoin_payout_address_registry.json ./data/pools/child-identities/namecoin_payout_address_registry.json
COPY data/pools/child-identities/rsk_miner_registry.json ./data/pools/child-identities/rsk_miner_registry.json
COPY data/pools/child-identities/syscoin_payout_address_registry.json ./data/pools/child-identities/syscoin_payout_address_registry.json
COPY data/sources/chain_profiles.json ./data/sources/chain_profiles.json

RUN cargo build --release --locked --bin merge-mining-monitor

FROM debian:bookworm-slim AS runtime

ARG MMM_SOURCE_REVISION=working-tree
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --user-group monitor

COPY --from=build /src/target/release/merge-mining-monitor /usr/local/bin/merge-mining-monitor
COPY www /app/www

LABEL org.opencontainers.image.title="Merge Mining Monitor development" \
      org.opencontainers.image.source-revision="${MMM_SOURCE_REVISION}"

ENV SERVE_WWW_DIR=/app/www \
    RUST_LOG=info
USER monitor

# The read-only API is the only default operation. Database migration, import,
# capture and polling commands are supplied explicitly by the operator.
ENTRYPOINT ["/usr/local/bin/merge-mining-monitor"]
CMD ["serve"]
