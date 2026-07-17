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
# put devcoin.conf in ./data/ before first up (rpcuser, rpcpassword, addnode=...)
just up
just logs
```

Wallet is disabled in the build (`--disable-wallet --without-bdb`) - the
daemon only reads blocks, no libdb dependency at runtime.

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
  patch to a fresh upstream clone pinned to `301c1ae`
- `docker-compose.yml` - runtime
- `patches/0001-modern-toolchain.patch` - 82 file diff; mechanical includes
- `justfile` - common operations, includes raw-hex helper for AuxPoW parsing
