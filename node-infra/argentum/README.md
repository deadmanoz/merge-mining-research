# Argentum Core node (Dockerised)

Multi-stage build of `dbkeys/argentum` (active fork, last commit
2024-02-07) for the merge-mining-research SHA-256d AuxPoW recovery
pipeline.

## Context

Argentum is a multi-algo PoW chain. Pre-2018-03 fork: Scrypt +
SHA-256d only. Post-fork (height ≥ 2,977,000): Scrypt + SHA-256d +
Lyra2REv2 + Myriad-Groestl + Argon2d + Yescrypt (six algos with a 45 s
overall block-time target, ~270 s per algo).

Only the **SHA-256d** branch is Bitcoin-parent merge-mined. The Scrypt
branch merge-mines with Litecoin/Dogecoin (out of scope per
the BTC-parent scope convention). The four post-fork native-only algos
have no AuxPoW.

The node syncs the full chain across all algos - branch filtering
happens in the extractor (`scripts/extract_argentum_auxpow.py`),
using the `nVersion & 0x0E00 == 0x0200` test (BLOCK_VERSION_SHA256D
= 1 << 9). **Argentum's SHA-256d encoding differs from Myriadcoin's**
- in Argentum SHA-256d is explicit `(1<<9)` (Scrypt is the default
zero), whereas in Myriadcoin SHA-256d is the default zero. The
extractor filter constants therefore differ between the two chains.

Catalogue facts (confirmed in Phase 1 source verification):

| | |
|-|-|
| Chain ID | `nAuxpowChainId = 0x004A3` (= 1187), `fStrictChainId = false` |
| AuxPoW activation | height **1,825,000** (~2016-04, exact date from block time) |
| Multi-algo activation | height **1,930,000** (`nMultiAlgoFork` / `nBlockSequentialAlgoRuleStart1`) |
| BIP146 / 4-new-algo cutover | height **2,977,000** (~2018-03-13 per source comment) |
| Algo encoding | `nVersion` bits 9–11 (`BLOCK_VERSION_ALGO = 7 << 9`); SHA-256d = `1 << 9` (Scrypt is default 0) |
| AuxPoW flag | `nVersion` bit 8 (`VERSION_AUXPOW = 1 << 8`) |
| Block header | Standard Namecoin-style: `CBlockHeader : CPureBlockHeader { CAuxPow auxpow }` (Daniel Kraft 2014-2016 lineage, 231/237-line `src/auxpow.{h,cpp}`) |
| Magic bytes | `0xfbc1b8dc` |
| Default P2P port | 13580 |
| RPC (this deployment) | 13581 (loopback-only on the host) |
| Genesis hash | `0x88c667bc63167685e4e4da058fffdfe8e007e5abffd6855de52ad59df7bb0bb2` |
| Genesis nTime | `1369199888` (2013-05-22 00:38:08 UTC; standalone Scrypt-only at launch) |

## Usage

```bash
just init                  # render data/argentum.conf with addnode= entries
just build                 # multi-stage Docker build (~10–20 min on <archival-host>)
just up                    # start container; IBD begins via addnode= peers
just logs                  # tail container logs
just height                # current block height
just peers                 # active connection count
just status                # full snapshot (blockchain + peers)
just refresh-peers         # attempt to re-pull live IPs from chainetics
just down                  # stop container (data volume persists)
```

## Peer discovery in 2026

**All three DNS seeds in source are dead** (`seed.argentum.cc`,
`dnsseed.argentum.cc`, `dnsseed.argentumcoin.cc` all NXDOMAIN as of
2026-05-16). The chainetics community node-IP service at
`chainetics.com/nodes/arg.php` is **also currently non-functional** -
the page renders with a real-time timestamp but the IP `<pre>` blocks
come back empty (the same problem hits `chainetics.com/nodes/btc.php`,
so the chainetics seeder backend is broken across all chains, not
ARG-specific).

`peers.list` therefore ships pre-populated with the **41 fixed seeds
from `contrib/seeds/nodes_main.txt`** in the active fork - a ~2017
snapshot. Many of those IPs may be unreachable after nine years;
expectations should be tempered. If fewer than a few succeed and the
chain fails to advance through IBD, the realistic outcome is **Path C
(catalogue-only, code-confirmed-not-extracted)** - same pattern as
Crown, BLAST, Jincoin.

`just refresh-peers` is a periodic retry hook for when chainetics
restores their seeder. The mining-pool stratum endpoints
(`pool.openmarks.com`, `pool.chainetics.com`) are not P2P peers and
cannot be used here.

## Sync expectations

- Tip height: unknown (no public explorer reachable -
  `explorer.argentum.cc` from chainetics nav does not resolve either).
  Last source checkpoint is height 3,056,860 (~2018); current tip is
  somewhere higher, discoverable at run time if IBD progresses.
- Block time: 45 s overall post-2018 fork; 270 s per-algo. Pre-fork
  (Scrypt + SHA-256d only) the cadence was 32 s overall
  (`nPowTargetSpacingV1`).
- Disk: single-digit to low-double-digit GB for a fully-indexed
  (`txindex=1`) node - chain is on the order of 13 years old with a
  modest block size, well within Myriadcoin/Terracoin ballpark.

## Phase 2 deployment

This directory is the source of truth for the Argentum node-infra. To
deploy on <archival-host>:

```bash
rsync -av --delete node-infra/argentum/ <archival-host>:~/argentum-docker/
ssh <archival-host> 'cd ~/argentum-docker && just init && just build && just up'
```

After `up`, monitor `just logs` and `just peers`. If `just peers` stays
at 0 for >30 min, the fixed-seed snapshot has fully decayed; mark the
chains.csv recovery_status as `code-confirmed-not-extracted`
and downgrade to Path C. If sync proceeds, monitor `just height` until
tip stabilises, then move to Phase 3 (extraction).
