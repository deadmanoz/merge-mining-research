# Argentum Core node (Dockerised)

Multi-stage build of `dbkeys/argentum` (active fork, last commit
2024-02-07) for the merge-mining-research SHA-256d AuxPoW recovery
pipeline.

Recovery is complete. The node synced through ARG height 7,204,637, extraction
scanned the full AuxPoW era from height 1,825,000, and classification produced
27 canonical Bitcoin parents, 2 accepted direct-stale candidates, and 634,277
unknown parents. The accepted rows are committed at
[`data/validated-stales/argentum_validated_stales.csv`](../../data/validated-stales/argentum_validated_stales.csv);
see
[`../../docs/chains/argentum.md`](../../docs/chains/argentum.md) for the audited
counts and interpretation.

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
happens in the extractor (`scripts/extract/extract_argentum_auxpow.py`),
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

The successful recovery used one live peer found in archived captures of the
chainetics peer page. The endpoint and acquisition provenance are recorded in
the chain note linked above. `peers.list` retains the 41 fixed seeds from
`contrib/seeds/nodes_main.txt` in the active fork as a fallback, but those
roughly 2017 addresses were unreachable during the recovery and should not be
treated as a currently live peer set.

`just refresh-peers` is a periodic retry hook for when chainetics
restores their seeder. The mining-pool stratum endpoints
(`pool.openmarks.com`, `pool.chainetics.com`) are not P2P peers and
cannot be used here.

## Sync expectations

- Recovered tip: height 7,204,637 in May 2026. A later run should confirm the
  current tip with `just height` rather than treating that snapshot as live.
- Block time: 45 s overall post-2018 fork; 270 s per-algo. Pre-fork
  (Scrypt + SHA-256d only) the cadence was 32 s overall
  (`nPowTargetSpacingV1`).
- Disk: single-digit to low-double-digit GB for a fully-indexed
  (`txindex=1`) node - chain is on the order of 13 years old with a
  modest block size, well within Myriadcoin/Terracoin ballpark.

## Reproduction and refresh

This directory is the source of truth for the Argentum node-infra. To
deploy on `<archival-host>`:

```bash
rsync -av --delete node-infra/argentum/ <archival-host>:~/argentum-docker/
ssh <archival-host> 'cd ~/argentum-docker && just init && just build && just up'
```

After `up`, monitor `just logs`, `just peers`, and `just height`. The original
recovery is already integrated, so rerun the extractor and classifier only
when refreshing beyond the documented May 2026 tip. Their current entry points
are `scripts/extract/extract_argentum_auxpow.py` and
`scripts/classify/classify_argentum_stales.py` from the repository root.
