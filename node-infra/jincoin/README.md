# Jincoin Core node (Dockerised)

Multi-stage build of `jincoin/jincoin-core` (master, v2.0.2.1, last commit
2019-06-14) for the merge-mining-research SHA-256d AuxPoW recovery
pipeline.

Status note: Jincoin is a surveyed infrastructure artifact, not an integrated
stale-output chain. See
[`docs/chains/surveyed-infra.md`](../../docs/chains/surveyed-infra.md) for
the public status treatment shared by surveyed and deferred chains.

## Context

Jincoin (JIN, 金 = gold) is a Chinese-branded but Western-distributed
Bitcoin Core ~0.13-era fork of the Syscoin 1.x / Daniel Kraft 2014
lineage. v2.0 (2018-02-12) shipped AuxPoW; v1 (2016-08 launch via
`jincoin/Jin-Coin-source`) had none. The mainnet chain ID is
`nAuxpowChainId = 0x00BA` (= 186), unregistered in Bitcointalk thread
769073. Block time is 79 seconds - a deliberate aesthetic choice tied to
gold's atomic number.

Catalogue facts (confirmed in Phase 1 source verification):

| | |
|-|-|
| Chain ID (mainnet) | `nAuxpowChainId = 0x00BA` (186) |
| Chain ID (testnet) | `nAuxpowChainId = 0x00BA` (same as mainnet; only regtest uses `0x1940`) |
| AuxPoW activation | TBD - no hardcoded height; gated implicitly by `IsLegacy()` returning `nVersion == 1` at `src/primitives/pureheader.h:125` |
| Strict-chain-id semantics | Hardcoded via the `IsLegacy()` gate in `src/main.cpp:1683`; no `fStrictChainId` toggle and no `nLegacyBlocksBefore` constant |
| Coinbase magic | `pchMergedMiningHeader = { 0xfa, 0xbe, 'm', 'm' }` (`src/auxpow.h:23`) - Namecoin lineage |
| Genesis nTime | `1471801377` (2016-08-21 16:22:57 UTC) |
| Block time | 79 s (`consensus.nPowTargetSpacing = 79`) |
| Default P2P port | 23099 |
| RPC port (per ANN) | 23098 |
| Network magic | `d7 c4 ef eb` |

## Network reachability - chain is effectively unrecoverable

All standard discovery paths verified dead 2026-05-16:

- **DNS seeds** (`src/chainparams.cpp`): all six NXDOMAIN
  - `seed1/2/3.jin-coin.com`
  - `seed1/2.jin.exchange`
  - `seed3.jin-coin.info`
- **Project domains**: `jin-coin.com`, `jin-coin.info`, `jin.exchange` -
  all NXDOMAIN. `explorer.jin-coin.com` NXDOMAIN; only late-life Wayback
  snapshot is the "Site Broken!" placeholder.
- **Hardcoded mainnet peer** (`src/chainparamsseeds.h`,
  `contrib/seeds/nodes_main.txt`): single entry `192.52.166.125:23099`,
  unreachable from multiple vantage points (no route to host).
- **Third-party explorers**: CoinGecko 404, Coinpaprika 404, Chainz
  unlisted.
- **Residue signal only**: CMC preview lists market cap $842 / 24h volume
  $2.84 (2026-05-15) - implies non-zero block production through to mid-
  2026 but exposes no height value.

Without a private archive (a 2018-2020 blk*.dat from a former pool
operator, a saved peers.dat, etc.) the daemon will start, sync the
empty mempool, and find zero peers. This directory is preserved as the
buildable-source-of-truth in case a peer surfaces.

Use `just probe-seeds` to re-check periodically - the cost is zero and
the upside (the project domain comes back online, or a JIN holder
re-registers) would unblock the rest of the recovery.

## Usage

```bash
just init                  # render data/jincoin.conf
just build                 # multi-stage Docker build (~10-20 min on <archival-host>)
just up                    # start container; IBD attempts via dead seeds
just logs                  # tail container logs
just height                # current block height (will stay at 0 without peers)
just peers                 # peer count (expect 0)
just status                # full snapshot
just probe-seeds           # re-check DNS seeds + hardcoded peer for life signs
just down                  # stop container (data volume persists)
```

## Phase 3 deployment

To deploy on `<archival-host>`:

```bash
rsync -av --delete node-infra/jincoin/ <archival-host>:~/jincoin-docker/
ssh <archival-host> 'cd ~/jincoin-docker && just init && just build && just up'
```

After `up`, monitor `just logs` and `just peers` for any signs of life. If
peers stays at 0 for ~24 h, Phase 4 (live sync) is conclusively dead.
The Dockerfile build itself is the deliverable in that case - it
documents that the source still compiles cleanly under a modern Ubuntu
20.04 / Boost 1.71 / OpenSSL 1.1 toolchain, which is itself useful for
any future researcher who locates a private archive.

## Optional Phase 5 (outreach for peers)

If Phase 4 fails (the realistic case), the next step is contacting
parties most likely to still hold a peers.dat or blk*.dat:

- JIN ANN thread on Bitcointalk (`1598401`) - still live, last edit
  2018-05-07. Post a one-shot request.
- 2018-2019 mining-pool operators: `blockmasters.co` (US),
  `mineblocks.co.uk` (UK), `suprnova.cc` (Slovenia).
- Existing outreach circle: Stifter, 0xB10C, Decker - anyone who ran a
  JIN node 2018-2020 and could share blockchain data (precedent: i0coin
  MediaFire/Mega 2018 snapshot).

If a private peer surfaces, drop it into `peers.list` (one per line,
`host[:port]`), re-run `just init`, and restart the container.
