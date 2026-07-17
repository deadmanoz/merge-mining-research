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
to `/home/fractal/.fractal` in the container. Archival mode needs about
2 TB, so point it at a disk with headroom:

```sh
export FRACTAL_DATA_DIR=<chain-data-dir>/fractal
just init
```

## Port remap

Fractal defaults to 8332/8333, colliding with Bitcoin Core. The compose
file publishes `127.0.0.1:18332` (RPC, loopback only) and `18333` (P2P,
public), and `init.sh` pins those in `bitcoin.conf`, so the node can
share a host with a Bitcoin Core instance on the defaults.

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
