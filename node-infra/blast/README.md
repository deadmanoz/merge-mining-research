# BLAST Core node (Dockerised)

Multi-stage build of `blastdev/blast-core-v2` (master, last commit
2019-10-15) for the merge-mining-research SHA-256d AuxPoW recovery
pipeline.

Status note: BLAST is a surveyed infrastructure artifact, not an integrated
stale-output chain. See
[`docs/chains/surveyed-infra.md`](../../docs/chains/surveyed-infra.md) for
the public status treatment shared by surveyed and deferred chains.

## Context

BLAST (ticker `BLAST`) is a 2017-12 SHA-256d AuxPoW chain on a
Ravencoin-lineage Bitcoin Core fork. It carries the standard Namecoin
Daniel-Kraft 2014 AuxPoW subsystem (`src/auxpow/`) - `CAuxPow : public
CMerkleTx`, `pchMergedMiningHeader = { 0xfa, 0xbe, 'm', 'm' }`, chain ID
in block-version high bits - with one project-specific quirk: a
**post-launch chain-ID rotation** from `0x1940 (6464)` to `0x00A4 (164)`
at mainnet height 796,000. BLAST is the second observed post-launch
chain-ID change in the catalogue after Syscoin's `4096 → 16`.

Catalogue facts (independently verified against
`raw.githubusercontent.com/blastdev/blast-core-v2/master/` 2026-05-16):

| | |
|-|-|
| Chain ID (launch) | `nAuxpowChainId = 0x1940` (6464) |
| Chain ID (post-rotation) | `nAlternateChainId = 0x00A4` (164) |
| Rotation height (miner-only) | `nChainIdUpgradeHeight = 796000` |
| Consensus rule for chain-ID | `pow.cpp:273` - accepts **either** id at **any** height |
| Miner switch | `miner.cpp:148-149` - picks id by height; consumer of `nChainIdUpgradeHeight` |
| Strict-chain-id semantics | **none** - no `fStrictChainId` anywhere in `src/` |
| AuxPoW activation | from block 1 (`AuxPow::START_MAINNET = 1`, `consensus.h:10`); validation reject at `validation.cpp:3966` |
| Coinbase magic | `pchMergedMiningHeader = { 0xfa, 0xbe, 'm', 'm' }` (`auxpow/check.h:9`) |
| Genesis hash | `00000000a6a47e28b4fea2ab47262d9a420bb1600dee375cad30fa54c9f6ec90` |
| Genesis nTime | `1512550966` (2017-12-06 09:02:46 UTC) |
| Block time | 32 s (`consensus.nPowTargetSpacing = 1*32`) |
| Subsidy halving | 640,000 blocks |
| Default P2P port | 64640 (`chainparams.cpp:192`) |
| Default RPC port | 64639 (`chainparamsbase.cpp:36`) |
| Network magic | `b3 c4 fd a2` |
| Base58 prefix (PUBKEY) | 25 → leading `8` (matches `consensus.devWalletAddress` `8XMNXVZvMTcxvp37wQFdjL2PhSPcCsC8kL`) |
| Base58 prefix (SCRIPT) | 18 |
| Base58 prefix (SECRET) | 239 |
| Reward split | miner 80% / masternode 15% / dev 5% (from `nMasternodePaymentsStartBlock = 1710000`) |

## Chain-ID rotation - extractor requirement

The miner-vs-consensus asymmetry matters. `src/miner.cpp:148-149`
selects which id to stamp into newly-mined blocks based on height:

```cpp
const int32_t nChainId  = chainparams.GetConsensus().nAuxpowChainId;
const int32_t nnChainId = (nHeight > chainparams.GetConsensus().nChainIdUpgradeHeight)
                              ? chainparams.GetConsensus().nAlternateChainId : nChainId;
```

But the consensus rule at `src/pow.cpp:273` accepts either id at any
height:

```cpp
if (pblock->GetChainID() != params.nAuxpowChainId &&
    pblock->GetChainID() != params.nAlternateChainId)
    return error("CheckAuxPowValidity() : block does not have our chain ID");
```

A naive height-keyed parser will mostly work in practice (miners
generally follow miner.cpp's height switch) but is **not what the
consensus rule says**. Any future extractor must mirror the consensus
rule (two-value whitelist, no height check) and additionally record
**which id was observed per block** so the height/id distribution is
preserved for later analysis. A `BLAST_LIVE_PARSER_MUST_RECORD_ID_USED`
comment in the extractor entry-point is the cheapest reminder.

## Network reachability - chain is effectively unrecoverable

All standard discovery paths verified dead 2026-05-16:

- **DNS seeds** (`src/chainparams.cpp:202-204`): all three names -
  `seed.blastblastblast.com`, `seed1.blastblastblast.com`,
  `seed2.blastblastblast.com` - plus their `testseed.*`, `www.*` and
  bare-domain siblings wildcard-resolve to the **same single IP**
  `35.220.144.141` (PTR `141.144.220.35.bc.googleusercontent.com.`).
  This is a wildcard A-record on one GCP instance, not a populated
  peer-discovery resolver - the strongest single signal that the chain
  is dead.
- **TCP 64640 on the seed IP** is closed. Only TCP 80 responds; HTTPS
  on `www.blastblastblast.com` and the bare domain both fail.
- **Repo** (`blastdev/blast-core-v2`): last commit 2019-10-15
  ("Disconnect from v1 peers (pre-asset/masternode proto version)"),
  silent for 6+ years.
- **Block explorers**: `chainz.cryptoid.info` does not host BLAST. No
  Wayback snapshot of a retired chainz entry has been surfaced.
- **Community signal**: the project's ANN at Bitcointalk topic
  `2547036` was observed locked by a Bitcointalk moderator with 162+
  posts deleted during the 2026-05-16 Workstream 3 sweep; the live
  thread state is the source of that observation (the 2023-09-27
  Wayback snapshot returns only the page boilerplate). Consistent with
  the post-2019 silence and the dead infrastructure.

Without a private archive (a 2018-2020 `blk*.dat` from a former pool
operator, a saved peers.dat from a long-running node, etc.) the daemon
will start, sync the empty mempool, and find zero peers. This directory
is preserved as the buildable source-of-truth in case a peer surfaces
or a snapshot is recovered.

Use `just probe-seeds` to re-check periodically - the cost is zero and
the upside (the project domain comes back online, or a community member
re-registers and points the seeders at real nodes) would unblock the
rest of the recovery.

## Usage

```bash
just init                  # render data/blast.conf
just build                 # multi-stage Docker build
just up                    # start container; IBD attempts via wildcard-dead seeds
just logs                  # tail container logs
just height                # current block height (will stay at 0 without peers)
just peers                 # peer count (expect 0)
just status                # full snapshot
just probe-seeds           # re-check DNS seeds + hardcoded peer for life signs
just down                  # stop container (data volume persists)
```

## Build notes

- Toolchain: ubuntu:22.04 (GCC 11, Boost 1.74, OpenSSL 3). Same base as
  `node-infra/jincoin/` for the same reason - focal (20.04) signing
  keys started failing GPG validation on `<archival-host>` in 2026-05.
- **`--disable-wallet` does NOT work here**: `src/auxpow/auxpow.h:10`
  unconditionally `#include`s `wallet/wallet.h`, which transitively
  pulls `wallet/walletdb.h → wallet/db.h → db_cxx.h` (BDB). Every TU
  that includes `primitives/block.h` (i.e. most of `libbitcoin_server`)
  fails to compile without BDB headers on the include path. The
  jincoin trick of relocating `CMerkleTx::ABANDON_HASH` does not help
  because the compile breaks before we even get to the link step. The
  Dockerfile therefore builds **with** the wallet enabled, using
  system BDB 5.3 (`libdb5.3-dev` / `libdb5.3++-dev`) plus
  `--with-incompatible-bdb`. The wallet is never loaded at runtime
  because `init.sh` sets `disablewallet=1` in `blast.conf`, so the
  BDB version mismatch is irrelevant for AuxPoW extraction.
- BLAST is a more modern Bitcoin Core fork than jincoin (Ravencoin
  0.15-0.16 era vs Syscoin 0.13 era) so it needs fewer modern-toolchain
  patches. Re-evaluate the jincoin patch set only if the wallet-enabled
  build itself fails.

## Phase 3 deployment

To deploy on `<archival-host>`:

```bash
rsync -av --delete node-infra/blast/ <archival-host>:~/blast-docker/
ssh <archival-host> 'cd ~/blast-docker && just init && just build && just up'
```

After `up`, monitor `just logs` and `just peers` for any signs of life.
If peers stays at 0 for ~24 h, Phase 4 (live sync) is conclusively
dead. The Dockerfile build itself is the deliverable in that case - it
documents that the source still compiles under a modern Ubuntu 22.04 /
Boost 1.74 / OpenSSL 3 toolchain, useful for any future researcher who
locates a private archive.

## Optional Phase 5 (outreach for peers / archives)

If Phase 4 fails (the realistic case), the next step is contacting
parties most likely to still hold a `blk*.dat` or `peers.dat`:

- BLAST ANN thread on Bitcointalk (`2547036`) - moderator-locked but
  the OP may still be reachable via PM. Lock reason worth quietly
  searching the Reputation / Scam Accusations boards for before
  spending more time.
- Any post-2019 BLAST community channel (Discord / Telegram) - none
  surfaced in the 2026-05-16 W3 sweep but cheap to re-check.
- 2018-2019 SHA-256d merge-mining pool operators that may have offered
  BLAST as a hash-side option.

If a private peer surfaces, drop it into `peers.list` (one per line,
`host[:port]`), re-run `just init`, and restart the container.
