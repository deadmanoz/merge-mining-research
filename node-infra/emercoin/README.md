# Emercoin Core node (Dockerised)

Multi-stage build of `emercoin/emercoin` (master, last commit 2026-05-01)
for the merge-mining-research SHA-256d AuxPoW recovery pipeline.

## Context

Emercoin (2013+) is a hybrid PoW/PoS chain in the Peercoin lineage. PoW
blocks are SHA-256d and carry a Namecoin-style AuxPoW commitment after
the merged-mining activation height. PoS blocks have no AuxPoW
commitment and must be **filtered out at the extractor**, not the node
- `emercoind` validates both branches.

Catalogue facts (confirmed in Phase 1 source verification):

| | |
|-|-|
| Chain ID | `AUXPOW_CHAIN_ID = 666` (`src/primitives/block.h:18`) |
| AuxPoW signaling | `BLOCK_VERSION_AUXPOW = (1 << 8)` bit in `nVersion` |
| AuxPoW activation | mainnet height **219,809** (`MMHeight`, `src/chainparams.cpp:158`) |
| PoS filter | `nFlags & BLOCK_PROOF_OF_STAKE` (bit 0); `IsProofOfWork() = !IsProofOfStake()` |
| Block header | Standard Namecoin-style: `CBlockHeader { ... std::shared_ptr<CAuxPow> auxpow; }` |
| Default P2P port | 6661 |
| Default RPC port | 6662 (loopback-only on the host) |
| Genesis | 2013-12-09 ("Emergence is inevitable!") |

## Liveness check (scaffold time, 2026-05-16)

- Repo: last commit 2026-05-01 (~2 weeks before scaffold).
- DNS seed `seed.emercoin.com`: resolves to 5 IPs.
- TCP probe on 6661: 3/3 sampled IPs accept connections.

Strong contrast with Crown (network dead, deferred). IBD via DNS seed
should work; `peers.list` preseeded with the 5 resolved IPs as fallback.

## Usage

```bash
just init                  # render data/emercoin.conf
just build                 # multi-stage Docker build
just up                    # start container; IBD begins via DNS seeds + peers.list
just logs                  # tail container logs
just height                # current block height
just status                # full snapshot (blockchain + peers)
just refresh-peers         # repopulate peers.list from `dig seed.emercoin.com`
just down                  # stop container (data volume persists)
```

## Sync expectations

- Tip height: unknown at scaffold time - explorer at
  `explorer.emercoin.com` is alive but uses a non-iquidus API
  (`Unknown API call` for standard endpoints). Confirm tip after IBD
  catches up, or via `getblockcount` on the running node.
- Genesis-to-tip span: 2013-12 → present (~12.5 years), but the hybrid
  spacing keeps the chain shorter than a pure 10-min PoW would be.
- Expected stale yield: low, because PoW share is small (~15% per the
  Tier-3 survey note; **to be measured** during extraction - this is
  the unresolved Q1 from the discovery brief).
- DNS seeds healthy: `seed.emercoin.com` (5 IPs at scaffold time).

## Phase 2 deployment

This directory is the source of truth for the Emercoin node-infra. To
deploy on <archival-host>:

```bash
rsync -av --delete node-infra/emercoin/ <archival-host>:~/emercoin-docker/
ssh <archival-host> 'cd ~/emercoin-docker && just init && just build && just up'
```

After `up`, monitor `just logs` and `just height` until sync reaches
tip. Then move to Phase 3 (extraction).
