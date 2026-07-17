# Myriadcoin Core node (Dockerised)

Multi-stage build of `myriadcoin/myriadcoin` (master, last commit 2021-12-10) for
the merge-mining-research SHA-256d AuxPoW recovery pipeline.

## Context

Myriadcoin is a multi-algo PoW chain (SHA-256d / Scrypt / Groestl /
Yescrypt / Argon2d; Yescrypt replaced Qubit at height 1,764,000 in 2016
and Argon2d replaced Skein at 2,772,000 in ~2019). Only the **SHA-256d**
branch is Bitcoin-parent merge-mined; the other four algos either merge
with non-Bitcoin parents (Scrypt → Litecoin/Dogecoin) or are native PoW.

The node syncs the full chain across all 5 algos - branch filtering
happens in the extractor (`scripts/extract/extract_myriadcoin_auxpow.py`),
which decodes `nVersion` bits 9-11 from the raw block hex and keeps only
algo 0 (SHA-256d).

Catalogue facts (confirmed in Phase 1 source verification):

| | |
|-|-|
| Chain ID | `nAuxpowChainId = 0x005A` (= 90), `fStrictChainId = false` |
| AuxPoW activation | height **1,402,000** (block timestamp 1443262763 = 2015-09-26 UTC) |
| Algo encoding | `nVersion` bits 9–11 (`BLOCK_VERSION_ALGO = 7 << 9`); SHA-256d = 0 |
| Block header | Standard Namecoin-style: `CBlockHeader : CPureBlockHeader { CAuxPow auxpow }` |
| Default P2P port | 10888 |
| RPC (this deployment) | 10889 (loopback-only on the host) |

## Usage

```bash
just init                  # render data/myriadcoin.conf
just build                 # multi-stage Docker build (~10–20 min on <archival-host>)
just up                    # start container; IBD begins via DNS seeds
just logs                  # tail container logs
just height                # current block height
just status                # full snapshot (blockchain + peers)
just refresh-peers         # repopulate peers.list from chainz.cryptoid.info
just down                  # stop container (data volume persists)
```

## Sync expectations

- Tip height: 3,712,365 as of 2026-05-16 (the `chainz.cryptoid.info/xmy/`
  explorer has since dropped XMY, so there is no live reference tip).
- Combined block time: ~60 s across all 5 algos historically; MIP3
  "longblocks" raised it stepwise to 8 min from height 3,628,800.
- DNS seeds: 8x `*.myriadcoin.org`, `myriadseed1.cryptapus.org`,
  `xmy-seed1.coinid.org`. The 2026-05 IBD reached tip in ~6 h without
  recorded `addnode=` use; `peers.list` is the fallback.
- Disk: ~5 GB observed at the 2026-05 sync.

## Phase 2 deployment

This directory is the source of truth for the Myriadcoin node-infra. To
deploy on <archival-host>:

```bash
rsync -av --delete node-infra/myriadcoin/ <archival-host>:~/myriadcoin-docker/
ssh <archival-host> 'cd ~/myriadcoin-docker && just init && just build && just up'
```

After `up`, monitor `just logs` and `just height` until sync reaches tip
(with the chainz XMY explorer offline, watch for the height plateau and
`initialblockdownload: false`). Then move to Phase 3 (extraction).
