# devcoind (Docker)

Build `devcoind` from `devcoin/core` at commit `301c1ae` (the upstream tip
at extraction time) in a container for AuxPoW stale-block extraction.
Recovered 484 stale-labelled candidates from DVC 25,000 to tip (468 pass the
publication gate and are published; see `docs/chains/devcoin.md`).

## Why patches are needed

Devcoin's recent merge from upstream Bitcoin Core (22.x era) is intermingled
with the original AuxPoW codebase, but the source still trips over GCC 13's
stricter parsing: 82 header files are missing transitive includes for
`<cstdint>`, `<stdexcept>`, `<map>`, `<string>` that older GCC versions
pulled in implicitly via other headers. The fix is mechanical - every
patched file just gains one or two `#include` lines at the top.

`patches/0001-modern-toolchain.patch` is the captured diff from the working
build on `<archival-host>` (Ubuntu 24.04, GCC 13.3, Boost 1.83). 82 files,
1011 lines, but no semantic changes - purely missing-header additions.

## AuxPoW extraction quirk

This codebase does not surface the AuxPoW header in the JSON RPC response
for `getblock` / `getblockheader`. Stale-block recovery instead pulls the
raw hex (`getblock <hash> 0`) and parses the AuxPoW fields binary-wise.
See `scripts/extract/extract_devcoin_auxpow.py` and the `getblockhex`
just target in this directory.

## One-time setup

```sh
cd /opt/merge-mining-research/node-infra/devcoin   # wherever you clone
just build
# For a new sync only: create the deliberate default bind source, then add
# devcoin.conf (rpcuser, rpcpassword, addnode=...) before first up.
mkdir -p data
just up
just logs
```

Wallet is disabled in the build (`--disable-wallet --without-bdb`) - the
daemon only reads blocks, no libdb dependency at runtime.

## Build from preserved local source

The same Dockerfile supports a local Git bundle with BuildKit. From this
workspace, create `source.bundle` from a local checkout whose `HEAD` history
contains the pinned revision, then select the bundle build:

```sh
git -C /path/to/devcoin-source bundle create "$PWD/source.bundle" HEAD
DEVCOIN_SOURCE=bundle just build
```

The Dockerfile checks out the same pinned commit and applies the same patch
in either mode. The bundle contains committed history; the checked-in patch
supplies the build fixes. `source.bundle` is ignored by Git and retained with
the private archive. The default `DEVCOIN_SOURCE=upstream` needs no bundle.

## On-demand archival operation

Apply the [copied-config preparation](../README.md) before using this host-network
offline profile, including removal of explicit peer entries from the runtime copy.

Devcoin is a historical Monitor source. Leave its container stopped between
research runs; the Compose definition disables automatic restart and forces
the daemon to remain in the foreground inside the container.

After the initial `just up`, use `just stop` to wait for graceful shutdown
while retaining the container, then `just start` when RPC access is needed.
`just down` removes the container and is not the normal parking command.
The `.dockerignore` permits only the Dockerfile, patches and optional source
bundle into the build context, excluding node data and RPC credentials.

For a Linux archival node that should stay offline, select the repo's
`compose.offline.yml` overlay. It preserves loopback-only RPC on port 52332
using host networking, disables P2P listening and connections, and removes
the default published ports using Compose's `!reset` merge tag. An ignored
`.env` in the deployed workspace can select the supported build/runtime
options and the existing, populated datadir:

```dotenv
COMPOSE_FILE=docker-compose.yml:compose.offline.yml
DEVCOIN_SOURCE=bundle
DEVCOIN_CONTAINER_NAME=regen-devcoind
DEVCOIN_DATA_DIR=/path/to/existing/devcoin-data
```

The bind uses `create_host_path: false`, so a missing or misspelled
`DEVCOIN_DATA_DIR` fails instead of creating an empty node directory. The
default `./data` remains available for the deliberate new-sync setup above;
archival operation must set `DEVCOIN_DATA_DIR` to the copied populated path.
Copy the repo's Dockerfile, Compose files, patches, `.dockerignore` and
`justfile` unchanged to that workspace. Keep host paths in `.env`; no private
Dockerfile or Compose variant is needed. `just build`, `just up`, `just start`
and `just stop` then use the selected configuration.

When adopting an existing native node, record its exact source revision,
patches, launch arguments, numeric UID/GID and chain tip. Stop it and retain a
cold datadir backup before attaching that datadir to a container. Select the
matching repo runtime profile and keep host-specific values in `.env`, then
verify the same tip and raw `getblock <hash> 0` bytes through the
container's RPC before making the container the normal restart path. Keep the
native executable and invocation as rollback evidence, and never run both
processes against the same datadir.

## Useful commands

```sh
just height
just peers
just status
just getblockhex 250000   # raw hex for AuxPoW parsing
just shell
```

## Files

- `Dockerfile` - multi-stage, ubuntu:24.04, applies the include-header
  patch at `301c1ae` from upstream or a preserved local Git bundle
- `docker-compose.yml` - runtime
- `compose.offline.yml` - Linux offline runtime overlay with loopback RPC
- `patches/0001-modern-toolchain.patch` - 82 file diff; mechanical includes
- `justfile` - common operations, includes raw-hex helper for AuxPoW parsing
