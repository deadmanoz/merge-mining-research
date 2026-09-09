# crownd on `<archival-host>` (Docker)

Build `crownd` v0.14.0.4 in a container for AuxPoW stale-block extraction.
See `../../docs/chains/crown.md` for recovery details.

Crown is an integrated stale-output chain: the recovery yielded 23 validated
BTC stales (5 chronologically novel, 11 new-to-upstream) over the CRW
453,273 → ~2,330,000 PoW merge-mined era. It was previously a deferred
candidate - every DNS seed and the hardcoded bootstrap were unreachable - and
was un-deferred via a Wayback harvest of `monitor.crownplatform.com` that
surfaced a single still-live peer.

## Why Docker

Crown 0.14.x is mid-2010s Bitcoin-Core-derived, and its `rpcserver.cpp`
still uses pre-1.66 Boost ASIO APIs (the two-arg `ssl::context`
constructor, `acceptor::get_io_service()`, `ssl::context::impl()`) that
Boost 1.66+ removed. The `ubuntu:18.04` (bionic) base image ships Boost
1.65, which retains them, so no source patches to `rpcserver.cpp` are
needed. Ubuntu 20.04 (Boost 1.71) and later would require those patches.

Crown's `configure` also requires libcurl (used by the AuxPoW mining
helpers - harmless on a read-only node, but mandatory at configure time).

## AuxPoW parameters

| Field | Value |
|---|---|
| Chain ID | 20 (0x14) |
| Strict chain ID | true |
| AuxPoW activation height | 453,273 (mainnet) |
| PoS-hybrid activation | 2,330,000 (~April 2019; PoW replaced by MN-PoS) |
| Genesis | 2014-10-08 (nTime 1412760826; coinbase "10/Oct/2014") |
| Target spacing | 1 min |

Extraction window: **block 453,273 → tip** (the extractor scans to tip and
gates on the AuxPoW version bit). AuxPoW is present only in the PoW era,
453,273 → ~2,330,000; at the full MN-PoS switch (~April 2019) PoW ends and
PoS blocks carry no AuxPoW, so the effective window closes there.

## One-time setup

On `<archival-host>`:

```sh
cd /opt/merge-mining-research/node-infra/crown
just init           # render crown.conf
just build          # builds image merge-mining-research/crownd:0.14.0.4
just up             # start the container
just logs           # watch DNS seed discovery + peer sync
```

Initial sync from DNS seeds + addnodes. Crown's chain (~6.3M blocks of
1-min slots since 2014) is small in byte volume but long in count; expect
a few hours for IBD. No official `bootstrap.dat` URL exists at the time of
writing - if one surfaces, extend `bootstrap.sh` to fetch/verify it
following the terracoin/ pattern.

## Operational

Apply the [copied-config preparation](../README.md) before using this host-network
offline profile, including removal of explicit peer entries from the runtime copy.

For a preserved-data deployment, copy `.env.example` to a private `.env` and
select the reviewed image, container name, and populated `CROWN_DATA_DIR`.
The bind uses `create_host_path: false`; a missing source fails instead of
creating an empty datadir. Do not run `just init` on copied state. Use `just
init` only when deliberately preparing a new sync with the default `./data`.

The reviewed offline profile uses Linux host networking, foreground daemon mode,
loopback RPC, and disables P2P listening, DNS seeding, and peer connections.
Before startup, remove source-only datadir, bind, and multi-valued RPC entries
from the private `crown.conf`; command-line overrides do not erase every
multi-valued setting. Start a retained container with
`docker compose up -d --no-build --pull never`, then use `just start`, reads,
and `just stop`. Set `COMPOSE_FILE=docker-compose.yml:compose.offline.yml` in
the private `.env` to select the offline overlay.

Crown is a historical source. Keep its retained container stopped between
research runs with `just stop`; `just start` resumes it explicitly. Automatic
restart is disabled, and stopping waits for graceful shutdown without a forced
timeout. `just down` removes the container and is not the normal parking
command. The current online profile can contact peers when started.

```sh
just status          # blockchain + peer snapshot
just height          # current block count
just peers           # connection count
just refresh-peers   # re-pull peer list from Chainz if DNS seeds drift
just shell           # drop into a shell inside the container
```

RPC is bound to `127.0.0.1:9341` on the host only; P2P is `0.0.0.0:9340`.
Credentials are written to `./data/crown.conf` (mode 600) by `just init`.
Override with env vars: `RPCUSER=xxx RPCPASSWORD=yyy just init`.

## Files

- `Dockerfile` - multi-stage build of crownd from source at `v0.14.0.4`
- `docker-compose.yml` - runtime (volumes, ports, healthcheck)
- `bootstrap.sh` - idempotent data-dir prep (renders crown.conf)
- `peers.list` - optional pinned addnodes; refresh with `just refresh-peers`
- `justfile` - common operations

`./data/` is the container's data directory (bind-mounted). It holds
`crown.conf`, `blocks/`, `chainstate/`, and the debug log.
