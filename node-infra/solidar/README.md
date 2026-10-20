# Solidar (formerly WorldLeadCurrency, WLC) node workspace

`solidard` 0.8.9.0 from [wincev/SOLIDAR](https://github.com/wincev/SOLIDAR) `a1ab9063f338666f602f0e056960061026ffb0d7`. Recovery state is in [docs/chains/solidar.md](../../docs/chains/solidar.md). Build and run this image on the Linux/amd64 archival host.

## Catalogue facts

| Fact | Value |
|---|---|
| Lineage key | `solidar` (aliases WLC, WorldLeadCurrency, SDR) |
| Built source | `wincev/SOLIDAR @ a1ab9063f338666f602f0e056960061026ffb0d7` (0.8.9.0). `SOLIDAR_REF` selects that pin. The image copies `solidard` only |
| Mainnet genesis | `000000004f7ca0e7345a6c29b19a2d555fe922540adfdd74aeaa2cee98d52d85` (genesis coinbase text "MNY Times 13/Mar/2015…") |
| Network magic | `5b6c44a4` |
| P2P port | 55889 (testnet 45889) |
| RPC port | 55888 (testnet 45888) |
| AuxPoW | source-level from child height 1; chain ID packed in the high 16 version bits; observed 2015 chain ID `0x0011`, changed to `0x5588` in Dec 2016 (`f07b4a0d` / `460ab9b0`); the C++ chain-ID guard is a no-op De Morgan bug (`!(id != OLD || id != NEW)`), so either build accepts either historical chain ID |
| Commitment format | old Durham format: `fabe6d6d` + 32-byte chain merkle root (not the child hash); 2^5-slot tree, WLC at slot 27 in the 2015 fixtures |
| Transactions | version 2 with `nRefHeight` after `nLockTime`. `ConnectBlock` rejects `block.nHeight < tx.nRefHeight` for every transaction, and rejects a coinbase whose `nRefHeight` is not the block height |
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
port).

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

- **Base (`docker-compose.yml`).** P2P 55889 published, RPC 55888 published on `${SOLIDAR_RPC_BIND}` (loopback by default), restart `SOLIDAR_RESTART_POLICY=no`.
- **Offline (`compose.offline.yml`).** `network_mode: none`, no published ports, `-listen=0 -dnsseed=0 -connect=0`, RPC via `docker compose exec`. Select with `COMPOSE_FILE=docker-compose.yml:compose.offline.yml`. Bind an existing datadir with `SOLIDAR_DATA_DIR`. Do not run `just init` against copied state, and do not rebuild or reindex while adopting a disk. Init is idempotent and leaves an existing `solidar.conf` in place.

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

- Base image `debian:stretch` with `libssl1.0-dev` (OpenSSL 1.0.2). `CBigNum` needs the pre-1.1 `BIGNUM` layout. Apt indexes come from archive.debian.org (`check-valid-until=no`). The build stage installs `libboost-system-dev`, `libboost-filesystem-dev`, `libboost-program-options-dev`, `libboost-thread-dev`, and `libboost-chrono-dev` (`libboost_thread` links chrono).
- Berkeley DB 4.8.30 builds from the checksum-pinned
  `bitcoincore.org/depends-sources` tarball (SHA-256 pinned in the
  Dockerfile) with `bdb-atomic.patch` and refreshed `config.guess` /
  `config.sub` (copied verbatim from `node-infra/coiledcoin/`). BDB
  4.8.30 is Sleepycat-licensed (pre-AGPL), which is why it is fetched
  rather than vendored.
- The daemon builds via `src/makefile.unix` (`USE_UPNP=-`, BDB paths and
  `-4.8` suffix), which also builds the bundled leveldb. Runtime carries
  only the Boost 1.62 runtime libraries.
- `platform: linux/amd64` is pinned. Build on the archival host.

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
