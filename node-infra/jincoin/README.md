# Jincoin Core node (Dockerised)

Multi-stage build of `jincoin/jincoin-core` (master, v2.0.2.1, last commit
2019-06-14) for the merge-mining-research SHA-256d AuxPoW recovery
pipeline.

Status note: Jincoin is a surveyed infrastructure artifact, not an integrated
stale-output chain. See
[`docs/chains/surveyed-infra.md`](../../docs/chains/surveyed-infra.md) for
the public status treatment shared by surveyed and deferred chains.

## Context

Jincoin is a Bitcoin Core ~0.13-era fork of the Syscoin 1.x / Daniel Kraft
2014 lineage. v2.0 (2018-02-12) shipped AuxPoW; v1 (2016-08 launch via
`jincoin/Jin-Coin-source`) had none. The mainnet chain ID `0x00BA` (186)
is unregistered in Bitcointalk thread 769073.

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

Without a private archive (a 2018-2020 `blk*.dat` from a former pool
operator, or a saved `peers.dat`) the daemon starts, syncs an empty
mempool, and finds zero peers.

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

## Deployment

To deploy on `<archival-host>`:

```bash
rsync -av --delete node-infra/jincoin/ <archival-host>:~/jincoin-docker/
ssh <archival-host> 'cd ~/jincoin-docker && just init && just build && just up'
```

After `up`, monitor `just logs` and `just peers`. If the peer count stays
at 0 for about 24 hours, no live sync is available. The image builds on
Ubuntu 20.04 with Boost 1.71 and OpenSSL 1.1.

## Outreach for peers

If the peer count stays at zero, the parties most likely to still hold
a `peers.dat` or `blk*.dat` are:

- the JIN ANN thread on Bitcointalk (`1598401`), still live, last edit
  2018-05-07
- 2018-2019 mining-pool operators: `blockmasters.co` (US),
  `mineblocks.co.uk` (UK), `suprnova.cc` (Slovenia)
- operators who ran a JIN node in 2018-2020 (Stifter, 0xB10C, Decker);
  the i0coin recovery used a 2018 MediaFire/Mega snapshot

If a private peer surfaces, drop it into `peers.list` (one per line,
`host[:port]`), re-run `just init`, and restart the container.

## Parked operation

Automatic restart is disabled. Keep this research node stopped between
explicit sessions: `just stop` waits for normal database shutdown and retains
the container; `just start` resumes it. The existing online configuration can
contact peers when started. These lifecycle commands do not establish that a
preserved datadir is complete or that a surveyed chain has recoverable history.
