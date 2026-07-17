# Lyncoin Core node (Dockerised)

This scaffold packages the official Lyncoin Core v4.0.0 Linux x64 release for
historical Bitcoin-parent AuxPoW recovery. The release archive is pinned to
SHA-256
`048d3ac9268b68c598d49e94f6d93a475ade3cd75e4818a8d3e0367bf66f4e6f`.

This full-node route is a reproducible fallback, not the provenance of the
committed Lyncoin evidence. The completed recovery used
`scripts/extract/download_lyncoin_auxpow_headers.py` against a live peer's raw
P2P `headers` stream. Lyncoin's extended header messages serialize the full
AuxPoW proof, so that capture recovered the complete pre-Flex range without
waiting for block bodies. See
`node-infra/lyncoin/p2p-capture-manifest.json` and
`docs/chains/catalogued-recovery.md`.

Verified network and consensus parameters:

| Parameter | Value |
|---|---|
| P2P magic | `52 03 0e 2f` |
| P2P port | 5054 |
| RPC port | 5053, bound to host loopback |
| AuxPoW chain ID | `0x0b0d` (2829) |
| Recoverable AuxPoW range | child heights 0 through 260,499 |
| Flex activation | height 260,500 |

The node must sync beyond height 260,499 to reach tip, but the generic
`scripts/extract/extract_auxpow_from_blkdat.py` extractor rejects Flex-version
blocks and recovers only the pre-Flex Namecoin-family encoding. The extractor
also detects a modern `blocks/xor.dat` key automatically.

`seed.lyncoin.net` currently resolves, and `peers.list` includes a peer that
advertised Lyncoin Core v4.0.0 at height roughly 1.36 million on 2026-07-10.

## Usage

```bash
just init
just build
just up
just logs
just height
just peers
just status
just down
```

The default data directory is `./data`. Put it on another disk without editing
the compose file:

```bash
export LYNCOIN_DATA_DIR=<chain-data-dir>/lyncoin
just init
just up
```

Provision 5 to 10 GB initially. The chain was described as roughly 1 GB of
blocks plus 1 GB of chainstate in early 2025, and sampled blocks remain small.

For the fallback full-node route, after IBD extract candidate Bitcoin parents from
`$LYNCOIN_DATA_DIR/blocks`. The candidate CSV still requires canonical Bitcoin
classification and normalization before Merge Mining Monitor ingestion. Its
`child_block_hash` column is already serialized in MMM's internal byte order;
`btc_hash` remains conventional display hex. Its `child_height` is only a
blk-file sequence counter, so normalization must replace it with an exact
consensus height before ingestion.
