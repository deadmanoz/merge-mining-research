# Emercoin Core node (Dockerised)

Multi-stage build of `emercoin/emercoin` (master, last commit 2026-05-01)
for the merge-mining-research SHA-256d AuxPoW recovery pipeline.

Recovery is complete. The original node reached EMC height 790,173, extraction
scanned 570,365 post-activation blocks and found 88,201 AuxPoW rows, and the
refreshed publication input contains 96 accepted direct-stale candidates. A
June 2026 tail scan through EMC height 797,184 found 668 additional canonical
Bitcoin parents and no new stales. See
[`../../docs/chains/emercoin.md`](../../docs/chains/emercoin.md) for the audited
stage counts and caveats.

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

IBD via the DNS seed completed successfully during recovery; `peers.list` is
preseeded with the five resolved IPs as a fallback.

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

## Observed sync and recovery

- The cold node reached height 790,173 in approximately five minutes during the
  May 2026 recovery. Confirm the current tip with `just height`; the public
  explorer uses a non-Iquidus API and is not the source of the recorded height.
- Genesis-to-retained-tip span: December 2013 to May 2026 (about 12.4 years),
  but the hybrid spacing keeps the chain shorter than a pure 10-minute PoW
  chain would be.
- Measured post-activation PoW/AuxPoW share: 15.5% (88,201 of 570,365 scanned
  blocks); the other 84.5% were PoS or had no AuxPoW.
- Accepted direct-stale yield: 96 rows after the June 2026 canonical refresh
  and publication gates.
- DNS seeds healthy: `seed.emercoin.com` (5 IPs at scaffold time).

## Reproduction and refresh

This directory is the source of truth for the Emercoin node-infra. To
deploy on `<archival-host>`:

```bash
rsync -av --delete node-infra/emercoin/ <archival-host>:~/emercoin-docker/
ssh <archival-host> 'cd ~/emercoin-docker && just init && just build && just up'
```

After `up`, monitor `just logs` and `just height` until sync reaches
tip. The original recovery is already integrated. For a refresh, run
`scripts/extract/extract_emercoin_auxpow.py` and
`scripts/classify/classify_emercoin_stales.py` from the repository root after
the node is current.
