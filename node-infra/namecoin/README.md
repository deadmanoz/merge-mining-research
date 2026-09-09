# Namecoin Core (preserved native runtime)

This workspace runs the reviewed Linux `namecoind` and `namecoin-cli` v28.0.0
binaries preserved from the original native node. It preserves
that runtime; it does not compile a new Namecoin release. The Dockerfile checks
the exact binary hashes during the image build and runs as UID/GID `1000:1000`
on `linux/amd64`.

The build context allowlist contains only `Dockerfile` and the two files under
the ignored `binaries/` directory. Populate that directory from the private
archive before building. Never put a datadir, config, wallet, cookie, or `.env`
in the build context.

Archived inputs may share storage through hardlinks. Treat them as immutable:
do not edit an archived payload or preserved binary in place. When preparing
a different binary version, remove and recreate the disposable build inputs
so the archived version remains unchanged. Read-only binaries still build and
run normally.

## Private selections

Copy `.env.example` to a private `.env` and set `NAMECOIN_IMAGE`,
`NAMECOIN_CONTAINER_NAME`, `NAMECOIN_DATA_DIR`, and
`NAMECOIN_CONFIG_FILE` to the reviewed target selections. The data and config
bind sources must already exist. Compose uses `create_host_path: false`, so a
missing or misspelled source fails instead of creating an empty node path.

The default `NAMECOIN_RESTART_POLICY=no` keeps the historical container parked
between explicit runs. Change it to `unless-stopped` only after live-cutover
acceptance. The Compose file uses Linux host networking, daemon foreground
mode, `/data` as the datadir, and the read-only `/config/namecoin.conf` bind.

Before any startup, review the private config for the copied state. Remove
source-only `datadir`, `conf`, P2P bind/listen, and RPC bind/allow settings that
refer to the old host or ports. The offline overlay supplies no-peer and
loopback RPC flags, but multi-valued config entries can remain effective unless
the old entries are removed from the reviewed config. Do not use `just init`,
`-reindex`, `-prune`, or import commands on the preserved datadir.

## Build and retained operation

After the exact image is loaded or built and the populated datadir plus
reviewed config are in place, render first:

```sh
just config
docker compose up -d --no-build --pull never
just status
just rpc getblockcount
# Verify recorded block anchors before parking the node.
just stop
```

For offline historical reads, set
`COMPOSE_FILE=docker-compose.yml:compose.offline.yml` in the private `.env`,
rerun `just config`, and use the same start/read/stop sequence. The initial
`docker compose up -d --no-build --pull never` creates the retained container;
later runs use `just start`. `just stop` uses an unlimited Compose stop timeout
and preserves the container and datadir. No node is started by `just config`,
`just build`, or the harmless direct image probe `docker run --rm --network
none <image> --version`.

The historical Namecoin extraction uses the existing block-file workflow and
the same mounted config/datadir for any later RPC identity checks. Keep raw
extracts and derived outputs in the private archive; this workspace only
defines the reproducible runtime.
