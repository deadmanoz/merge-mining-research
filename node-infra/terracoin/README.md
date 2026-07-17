# terracoind on `<archival-host>` (Docker)

Build `terracoind` v0.12.2.5 in a container for AuxPoW stale-block extraction.
See `../../docs/chains/terracoin.md` for the recovery details.

## Why Docker

The upstream repo hasn't moved since May 2021 and the source was written
against Boost ≤ 1.71 / GCC 7–9. Building on modern Ubuntu (GCC 13, Boost
1.83) requires patching several source files. The `ubuntu:20.04` base image
ships Boost 1.71 and GCC 9, which matches the era the code was written
against - no patches needed. Ubuntu 22.04 / Boost 1.74 also fails: Boost
1.73 moved `_1` / `_2` / `_3` out of the global namespace, which breaks
`src/validationinterface.cpp` in this version.

## Why this config works without fresh DNS seeds

Both DNS seeds (`seed.terracoin.io`, `dnsseed.southofheaven.ca`) return no A
records, and all 45 IPs pinned in `chainparamsseeds.h` (from the 2020 release)
are unreachable. But the network is alive - ~46 reachable nodes existed at
recovery time. We found them via the Chainz TRC nodes API and pinned them as
`addnode=` entries. The Chainz TRC listing has since expired ("hosting
expired", observed 2026-07), so `peers.list` preserves the last-known-good
set.

We also pre-load `bootstrap.dat.gz` (official, 1.3 GB, 2021-04-30) so the
first ~70% of the AuxPoW range syncs without any peer dependency.

## One-time setup

On `<archival-host>`:

```sh
cd /opt/merge-mining-research/node-infra/terracoin   # wherever you clone
just init           # fetch + verify bootstrap.dat.gz, render terracoin.conf
just build          # builds image merge-mining-research/terracoind:0.12.2.5
just up             # start the container
just logs           # watch the bootstrap import then peer sync
```

Initial import of `bootstrap.dat` typically takes 1–3 hours on a small chain
like TRC. After that, the ~720k-block gap from 2021-05 to present catches up
from the pinned peers.

## Operational

```sh
just status          # blockchain + peer snapshot
just height          # current block count
just peers           # connection count
just refresh-peers   # re-pull peer list from Chainz (defunct as of 2026-07; falls back to the committed peers.list)
just shell           # drop into a shell inside the container
```

RPC is bound to `127.0.0.1:13332` on the host only; P2P is `0.0.0.0:13333`.
Credentials are written to `./data/terracoin.conf` (mode 600) by `just init`.
Override with env vars: `RPCUSER=xxx RPCPASSWORD=yyy just init`.

## Files

- `Dockerfile` - multi-stage build of terracoind from source at `v0.12.2.5`
- `docker-compose.yml` - runtime (volumes, ports, healthcheck)
- `bootstrap.sh` - idempotent data-dir prep (download, verify, render config)
- `peers.list` - verified-reachable peers from the Chainz nodes API; refresh
  with `just refresh-peers` if peers drift
- `justfile` - common operations

`./data/` is the container's data directory (bind-mounted). It holds
`bootstrap.dat`, `terracoin.conf`, `blocks/`, `chainstate/`, and the debug log.
