# unobtaniumd on <archival-host> (Docker)

Build `unobtaniumd` master @ `54d68b08` in a container for AuxPoW stale-block
extraction. See `../../docs/chains/unobtanium.md` for the recovery details.

## Why Docker on ubuntu:20.04

Unobtanium is a Bitcoin Core 0.11 fork. Last release v0.11.5 (Sep 2020) pre-dates
GCC 11 / Boost 1.74+. Master branch landed two portability fixes in Feb 2024
('Add missing boost build flags' and 'Fix qt5 byte array for gcc11+') but no
new tag was cut. Pinning master @ 54d68b08 and building against ubuntu:20.04
(GCC 9, Boost 1.71) keeps us close to the codebase's original toolchain era
and dodges the patch-a-dead-repo fight entirely.

## Why this config works without fresh DNS seeds

Both DNS seeds (`node1.unobtanium.uno`, `node2.unobtanium.uno`) return a
single A record each and neither listens on port 65534 - effectively dead,
consistent with upstream issue #53. The `chainparamsseeds.h` fixed list is
from 2015 and long stale.

The network IS alive: Chainz `q=nodes` API exposes 13 live peers, 8 of which
are reachable on TCP 65534 as of 2026-04-24. Those 8 are pinned in `peers.list`
and rendered into `unobtanium.conf` as `addnode=` entries by `init.sh`.

No official bootstrap.dat exists. IBD proceeds directly from the pinned peers.

## One-time setup

```sh
cd /opt/merge-mining-research/node-infra/unobtanium   # wherever you clone
just init       # render data/unobtanium.conf from peers.list
just build      # builds image merge-mining-research/unobtaniumd:master-54d68b08
just up         # start the container
just logs       # watch IBD progress
```

## Useful commands

```sh
just height          # current block height
just peers           # connection count
just status          # full blockchain + peer snapshot
just refresh-peers   # pull fresh peer list from Chainz API
```

## Ports

- `65534` - P2P (published publicly on <archival-host>)
- `65535` - RPC (bound to 127.0.0.1 on the host; extractor runs on the same host)
