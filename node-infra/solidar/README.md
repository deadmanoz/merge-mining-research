# Solidar (formerly WorldLeadCurrency, WLC) node workspace

Container build and run workspace for the historical WLC/Solidar daemon
(`solidard`, 0.8.9.0), built from the pinned public upstream
[wincev/SOLIDAR](https://github.com/wincev/SOLIDAR) at
`a1ab9063f338666f602f0e056960061026ffb0d7`. It exists for the
WLC/Solidar recovery strand documented in
[docs/chains/solidar.md](../../docs/chains/solidar.md): native chain
validation and genesis verification now, and the adoption/inspection
vehicle for any recovered datadir, `blk*.dat`, bootstrap, or newly
reachable peer later. Two AuxPoW proof fixtures (WLC children 11,418 and
20,357) are already authenticated offline; the block history itself is
not yet recovered.

## Context

WLC launched 2015-03 as a Freicoin-family Bitcoin 0.8/0.9 fork with
Durham-style AuxPoW merge mining, renamed to Solidar by the same
developer. The 2016-09-03 zpool explorer capture shows the chain live at
child height ~69,250 with every block AuxPoW. A 2020 continuation fork
(`Henne123/SOLIDAR`, +29 commits) carries a commit named "Add
RESTED_BLOCK_HEIGHT to overcome block creation halt" — evidence the
chain had stalled by then.

**Catalogue facts**

| Fact | Value |
|---|---|
| Lineage key | `solidar` (aliases WLC, WorldLeadCurrency, SDR) |
| Built source | `wincev/SOLIDAR @ a1ab9063f338666f602f0e056960061026ffb0d7` (0.8.9.0); WLC-era `WorldLeadCurrency/WLC @ f07b4a0d1a3eb831d116885edc237fb306aa1862` selectable via `SOLIDAR_REPO`/`SOLIDAR_REF` build args |
| Mainnet genesis | `000000004f7ca0e7345a6c29b19a2d555fe922540adfdd74aeaa2cee98d52d85` (genesis coinbase text "MNY Times 13/Mar/2015…") |
| Network magic | `5b6c44a4` |
| P2P port | 55889 (testnet 45889) |
| RPC port | 55888 (testnet 45888) |
| AuxPoW | source-level from child height 1; chain ID packed in the high 16 version bits; observed 2015 chain ID `0x0011`, changed to `0x5588` in Dec 2016 (`f07b4a0d` / `460ab9b0`); the C++ chain-ID guard is a no-op De Morgan bug (`!(id != OLD || id != NEW)`), so either build accepts either historical chain ID |
| Commitment format | old Durham format: `fabe6d6d` + 32-byte chain merkle root (not the child hash); 2^5-slot tree, WLC at slot 27 in the 2015 fixtures |
| Transactions | version 2 with `nRefHeight` appended after `nLockTime`, consensus-bound to the child height (`ConnectBlock` rejects `block.nHeight < tx.nRefHeight`) |
| Hardcoded seeds | 91.108.68.164, 185.38.44.6, 109.73.173.119 (identical in every repo and branch inspected, including the Henne123 fork) |

## Network liveness

**No live peer is known.** On 2026-10-03 a protocol probe of all ten
candidate endpoints (the three source seeds, the 2015 thread peer and
node addresses, the 2020 build host, both `ssdpool.com` DNS seeds — which
resolve but do not answer 55889 — and the current `explorer.solidar.us`
addresses) timed out with zero protocol messages; receipts are in the
private evidence directory (`peer-probes-20261003.json`). A 2026-10-20
connect-only recheck of those routes, plus announcement addnodes, still
found no accepted connection on 55889 (`104.168.155.110` refused the
port). Syncing from
the public network is therefore not currently possible. This workspace
is the acquisition vehicle for when that changes: a newly found peer
needs no rebuild, only `just addnode <ip>` (or `-connect=` on the
command). The outstanding person-held archive lead is tracked in the
chain doc and issue 59.

## Usage

```bash
cp .env.example .env      # then edit selections
just init                 # render solidar.conf with generated RPC credentials (once)
just build                # build the image (native amd64 host)
just config               # render-check the compose files
just up                   # start from the selected image (never builds/pulls)
just logs                 # follow daemon logs
just height               # getblockcount via RPC
just peers                # getconnectioncount
just status               # getinfo (0.8-era RPC; no getblockchaininfo)
just addnode 203.0.113.7  # one-shot peer attempt (online profile)
just stop                 # graceful stop (waits, no forced kill)
just down                 # stop and remove the container (datadir persists)
```

The daemon doubles as the RPC CLI (there is no separate `solidar-cli`).
A first-run smoke test is the genesis check:

```bash
just up
docker compose exec -T solidard solidard -datadir=/data -conf=/data/solidar.conf getblockhash 0
# expect 000000004f7ca0e7345a6c29b19a2d555fe922540adfdd74aeaa2cee98d52d85
```

## Profiles

- **Base (`docker-compose.yml`)** — online acquisition-capable: P2P
  55889 published, RPC 55888 published on `${SOLIDAR_RPC_BIND}`
  (loopback by default), restart disabled by default
  (`SOLIDAR_RESTART_POLICY=no`). With no known live peers this currently
  serves native validation and genesis verification; it is the profile a
  future peer or archive plugs into.
- **Offline (`compose.offline.yml`)** — networkless reads of an adopted
  datadir: `network_mode: none`, no published ports, `-listen=0
  -dnsseed=0 -connect=0`, RPC via `docker compose exec` on container
  loopback. Select with
  `COMPOSE_FILE=docker-compose.yml:compose.offline.yml` in `.env`.
  Adopting preserved data means bind-mounting the existing datadir via
  `SOLIDAR_DATA_DIR` — never run `just init` against copied state (the
  existing `solidar.conf` is preserved; init is idempotent), and do not
  rebuild or reindex the node while adopting a disk.

## Legacy RPC listener behaviour

This 0.8-era daemon ignores `-rpcbind` entirely and binds the RPC socket
to **all interfaces** as soon as any `rpcallowip` entry exists
(`bitcoinrpc.cpp`: loopback only when `-rpcallowip` is absent). The
rendered `solidar.conf` therefore allows loopback plus the Docker
container networks, with exposure bounded by two layers: the container
network namespace and the loopback-only host publish
(`${SOLIDAR_RPC_BIND:-127.0.0.1}:55888:55888`). RPC auth is always
required (generated 48-hex password, `chmod 600`). Verify after every
`just up` that the only host listener for 55888 is loopback
(`lsof -nP -iTCP:55888 -sTCP:LISTEN`), and that inside the container the
socket is unreachable from anything but the docker networks. The
offline profile removes the concern entirely (`network_mode: none`).

## Build notes

- Base image `debian:stretch` + `libssl1.0-dev` (OpenSSL 1.0.2): the
  codebase retains `CBigNum`, which inherits the BIGNUM struct that
  became opaque in OpenSSL 1.1. Stretch's apt indexes are served from
  archive.debian.org (`check-valid-until=no`); see the Dockerfile header
  for the full rationale, mirrored from the Argentum workspace.
- Berkeley DB 4.8.30 builds from the checksum-pinned
  `bitcoincore.org/depends-sources` tarball (SHA-256 pinned in the
  Dockerfile) with `bdb-atomic.patch` and refreshed `config.guess` /
  `config.sub` (copied verbatim from `node-infra/coiledcoin/`). BDB
  4.8.30 is Sleepycat-licensed (pre-AGPL), which is why it is fetched
  rather than vendored.
- The daemon builds via `src/makefile.unix` (`USE_UPNP=-`, BDB paths and
  `-4.8` suffix), which also builds the bundled leveldb. Runtime carries
  only the Boost 1.62 runtime libraries.
- Build host is the Linux/amd64 archival host; `platform: linux/amd64`
  is pinned so an arm64 dev host doesn't silently change the package set.

## Files

- `Dockerfile` — two-stage build (BDB 4.8.30 + leveldb + `makefile.unix`
  → stretch runtime, UID/GID 1000 `solidar`).
- `docker-compose.yml` — base online profile (noncreating datadir bind,
  loopback RPC publish, restart disabled).
- `compose.offline.yml` — networkless overlay for adopted-datadir reads.
- `justfile` — `init`/`build`/`up`/`stop`/`logs`/`height`/`peers`/
  `status`/`addnode`/`shell`; `up`/`start` never build or pull.
- `init.sh` — renders `solidar.conf` with generated RPC credentials
  (idempotent; `chmod 600`; chowns to 1000:1000 when run as root).
- `.env.example` — image/container/datadir/RPC-bind/restart/profile
  selections.
- `.gitignore` / `.dockerignore` — keep the datadir, `.env`, and build
  context clean (the daemon writes `data/`; never commit it).
- `bdb-atomic.patch`, `config.guess`, `config.sub` — BDB 4.8.30 build
  inputs from the CoiledCoin workspace.

## Deployment

Runs on the Linux/amd64 archival host. Deploy the workspace and build
there:

```bash
rsync -av --delete --exclude 'data/' --exclude '.env' node-infra/solidar/ <archival-host>:~/solidar-docker/
ssh <archival-host> 'cd ~/solidar-docker && cp -n .env.example .env && just init && just build && just up'
```

The `--exclude` flags are load-bearing: a plain `rsync --delete` of the
workspace wipes the host-side `data/` directory (and its rendered
`solidar.conf`) on every redeploy — the noncreating datadir bind then
correctly refuses to start. Keep the excludes whenever you redeploy over
a workspace that has live state.

Keep generated datadirs, RPC credentials, logs, and any adopted chain
data out of git; the workspace `.gitignore` covers `data/` and `.env`.
Enable a live restart policy only after acceptance and host-startup
ordering are verified. See the chain doc for the recovery state and the
evidence contracts any extraction must follow.
