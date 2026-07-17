# Bitmark Core node (Dockerised)

Multi-stage build of `project-bitmark/bitmark` (master, HEAD `ffd840e`, dated
2023-06-15) for the merge-mining-research SHA-256d AuxPoW recovery pipeline.

## Context

Bitmark is a hybrid 8-algorithm PoW chain (SHA-256d / Scrypt / Yescrypt /
Argon2d / X17 / LYRA2REv2 / Equihash / CryptoNight, all merge-mineable
since the 2018-06-07 Fork 1 activation at height ~450,950). Only the
**SHA-256d** branch is Bitcoin-parent merge-mined; the other seven
branches either merge with non-Bitcoin parents (Scrypt -> Litecoin/Dogecoin,
Equihash -> Zcash, CryptoNight -> Monero family) or are native PoW.

The node syncs the full chain across all 8 algos. Branch filtering happens
in the extractor by decoding the child block `nVersion` bits before parsing
the AuxPoW tail.

Catalogue facts (confirmed Phase 1 source verification):

| | |
|-|-|
| Chain ID | `nAuxpowChainId = 0x005B` (= 91), `fStrictChainId = true` |
| Fork 1 activation | height 450,947 (2018-06-07 04:18:55 UTC) |
| Algo encoding | `nVersion` bits 9-11 (`BLOCK_VERSION_ALGO = 7 << 9`); SHA-256d is enum `1` |
| Block header | Standard Namecoin-style: `CBlockHeader : CPureBlockHeader { CAuxPow auxpow }` (inline in `core.{h,cpp}`, NOT `auxpow.{h,cpp}`) |
| Default P2P port | 9265 |
| RPC (this deployment) | 9266 (loopback-only on the host) |
| Network magic | `0xf9 0xbe 0xb4 0xd9` -- identical to Bitcoin mainnet (cross-chain tooling collision risk) |

## Usage

```bash
just init                  # render data/bitmark.conf
just build                 # multi-stage Docker build
just up                    # start container; IBD begins via DNS seeds
just logs                  # tail container logs
just height                # current block height
just status                # full snapshot (blockchain + peers)
just refresh-peers         # repopulate peers.list from chainz.cryptoid.info
just down                  # stop container (data volume persists)
```

## Sync expectations

- Tip height: ~2.38M blocks (verify at run time via `chainz.cryptoid.info/btmk/`).
- Combined block time: short; the chain's all-8-algos design means high
  block production rate.
- DNS seed health: 12 seeds listed in source as of 2021-03-08; status today
  uncertain. `peers.list` ships with all 6 hardcoded `pnSeed[]` IPs first,
  then the 12 DNS-seed hostnames as fallback.
- Disk: estimate low-double-digit GB; verify on first sync.

## Build-fix branch escalation (if master + ubuntu:20.04 fails)

If the default `BITMARK_REF=master` + ubuntu:20.04 build fails, the
upstream maintains four single-commit fix branches that can be
cherry-picked onto a newer base image:

| Base image | Fix branches to apply |
|------------|----------------------|
| ubuntu:22.04 (GCC 11) | `origin/fix/ubuntu-2204-build` (cb75935) |
| ubuntu:24.04 (GCC 13 + OpenSSL 3) | all four: `fix/ubuntu-2204-build`, `fix/gcc13-blake2-alignment` (07b5307), `fix/gcc13-bmw256-optimization` (880294e), `fix/openssl3-signature-verification` (eab6d2a) |

Alternative fork sources (per discovery brief):
- `bitmarkcc/bitmark@master2024` -- downstream fork pushed 2026-05-02 with
  modern-toolchain work.
- `akrmn2021/bitmark@master2024` -- fork endorsed by the
  `bitmarkcc/btm-equihash-auxpow` README as the working baseline.

## Deployment

This directory is the source of truth for the Bitmark node-infra. Copy it to
the target host, run `just init`, then `just build` and `just up`. After
startup, monitor `just logs` and `just height` until sync reaches tip.
