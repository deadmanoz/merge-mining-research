# Fractal Bitcoin node (Dockerised)

Runs `fractald` v0.3.0 in a container for AuxPoW parent-header extraction.
This is the node behind the Fractal integration documented in
`docs/chains/fractal.md`.

## Why the pre-built release (no source build)

Fractal upstream publishes x86_64 Linux tarballs at
`github.com/fractal-bitcoin/fractald-release`. The v0.3.0 binary is
statically linked for all Bitcoin Core dependencies (Boost, OpenSSL,
libevent, libdb); only glibc/libpthread/libm are dynamic, so an
`ubuntu:20.04` base matches the upstream build environment and nothing
needs compiling. The Dockerfile pins the release version but does not pin an
asset checksum or verify a signature, so a rebuild still relies on the
upstream release asset remaining unchanged.

## Datadir

The datadir is bind-mounted from `FRACTAL_DATA_DIR` (default `./data`)
to `/home/fractal/.fractal` in the container. Archival mode needs multiple
terabytes, so point it at a disk with headroom:

```sh
export FRACTAL_DATA_DIR=<chain-data-dir>/fractal
just init
```

## Port remap

Fractal defaults to 8332/8333, colliding with Bitcoin Core. The compose
file publishes `127.0.0.1:18332` (RPC, loopback only) and `18333` (P2P,
public), and `init.sh` pins those in `bitcoin.conf`, so the node can
share a host with a Bitcoin Core instance on the defaults.

## Adopting an existing disk

Select the existing image and populated datadir in a private `.env`, using
`.env.example` as the template. Do not run `just init`, rebuild the image,
reindex, or create a replacement datadir during adoption. The data bind
rejects a missing host path. Both the daemon and health check explicitly
select the retained `bitcoin.conf`.

Use `COMPOSE_FILE=docker-compose.yml:compose.offline.yml` for initial reads.
This profile has no network interface or published ports; query RPC through
`just height` and the container CLI. Verify the disk identity and historical
blocks, then stop it with `just stop`. Both `just stop` and `just down` wait
without a forced shutdown timeout.

After live acceptance, select only the base Compose file, set
`FRACTAL_RPC_BIND` to the intended private host address and
`FRACTAL_RESTART_POLICY=unless-stopped`, and apply that configuration.
The default restart policy is `no` while adoption is in progress. Persistent
mount identity checks belong in the host runtime configuration; an existing
directory alone does not establish that the correct disk is mounted.

## Usage

```sh
just init       # render bitcoin.conf in the datadir
just build      # build merge-mining-research/fractald:0.3.0
just up         # start the container
just logs       # watch IBD progress
just height     # current block height
just peers      # connection count
just status     # full blockchain + peer snapshot
just sync-status  # one-line IBD status with deltas
```

`wait-build.sh` polls a `just build > build.log 2>&1 &` run and reports
success or failure; useful because the image build downloads a large
release tarball.

## Extraction

After IBD, extraction runs over RPC on the same host with
`scripts/extract/extract_fractal_auxpow.py` (compact
`getblockheader <hash> false true` reads; see `docs/chains/fractal.md`
for the version-gate details and stage counts).
