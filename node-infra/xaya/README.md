# Xaya node scaffold (Docker)

Build `xayad` v1.13 in a container for AuxPoW stale-block extraction. See
[`../../docs/chains/xaya.md`](../../docs/chains/xaya.md) for recovery details.

Status note: Xaya is an integrated stale-output chain (chronological position
19 of 26; 40 accepted direct-stale candidates). It was recovered offline from
Xaya's open `blocks.zip` snapshot rather than from a live node (the legacy P2P network is
dead; see `peers.list`). See
[`../../docs/chains/xaya.md`](../../docs/chains/xaya.md) for the recovery writeup and
provenance. This directory's node scaffold is retained for a future tail
top-up if a live peer or updated dump becomes available.

## Why ubuntu:24.04

Xaya v1.13 (Apr 2025) is built on `namecoin-29.x` - Bitcoin Core 29.x lineage
with a CMake build system. Modern toolchain, no era-specific patches needed,
unlike Unobtanium (libssl1.1 crypter sed) or Terracoin (Boost 1.71 pinning).

## Mining design - important caveat

Xaya is **multi-algo**: blocks are mined either with NEOSCRYPT (CPU/GPU,
solo-mined) or SHA256D-AuxPoW (merge-mined with Bitcoin). The source
enforces "SHA256D must be merge-mined", so every SHA256D Xaya block
carries a BTC parent commitment - but Neoscrypt blocks contribute none.

The block header is also non-standard for this lineage: it appends a
`PowData` wrapper after the usual 80-byte header, encoding `{ algo,
fakeHeader | CAuxPow }`. The embedded `CAuxPow` itself is the standard
Namecoin lineage; only the outer block-header parsing needs custom logic
in the extractor.

The offline recovery measured 1,695,912 SHA256D merge-mined blocks among
6,344,114 scanned blocks, a 26.7% share; the remaining 73.3% were the
non-merge-mined Neoscrypt branch.

## One-time setup

```sh
cd ~/xaya-docker   # or wherever you clone node-infra/xaya
just init       # render data/xaya.conf
just build      # builds image merge-mining-research/xayad:v1.13
just up         # start the container
just logs       # watch IBD progress
```

## Useful commands

```sh
just height          # current block height
just peers           # connection count
just status          # full blockchain + peer snapshot
```

## Ports

- `8394` - P2P (published publicly on the node host)
- `8396` - RPC (bound to 127.0.0.1 on the host; extractor runs on the same host)

## Chain identifiers (recorded from source, Phase 1)

- `nAuxpowChainId = 1829`
- Network magic = `cc be b4 fe`
- DNS seeds = `seed.xaya.io.`, `seed.xaya.domob.eu.`
- Genesis = `e5062d76e5f50c42f493826ac9920b63a8def2626fd70a5cec707ec47a4c4651` (2018-07-13)
- Genesis algo = NEOSCRYPT (the first SHA256D-AuxPoW block will be height ≥ 1)
