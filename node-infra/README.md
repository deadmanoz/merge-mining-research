# Node infrastructure

[Qbit](qbit/README.md) is the pinned archival node and acquisition worker.
Its profile is in [node operations](../docs/node-operations.md); recovery
scope is in [the Qbit chain notes](../docs/chains/qbit.md).

Build and run recipes for the merge-mined chains whose recovery needed a
locally operated node. Each directory is its own workspace with a README,
a compose file, and usually a Dockerfile and `justfile`; read the chain's
README before building, and keep generated datadirs out of git (each directory
ignores `data/`). Some workspaces, including SixEleven, pin a published image
directly and therefore do not need a Dockerfile.

Order host runtime startup after required data mounts and private network
interfaces used by RPC bindings. Image ownership and private variants are
in [node operations](../docs/node-operations.md).

The private [archive dashboard](https://github.com/deadmanoz/mmr-archive-dashboard)
provides a view of storage, locations, verified transfers and research gaps.
Its source, Docker image recipe and read-only collector now live in that
repository; `archive-dashboard/` here is only a pointer.

Terracoin also supports `terracoin/compose.live.yml` for continuous operation
of verified retained state, private RPC and bounded resources. Its restart
policy remains disabled until acceptance; follow the Terracoin workspace
README before setting `TERRACOIN_RESTART_POLICY=unless-stopped`.

Argentum, Bitmark, Crown, Devcoin, Doichain, Elcash, Emercoin, IXCoin,
Myriadcoin, Terracoin and Unobtanium have `compose.offline.yml` overlays for reading preserved
datadirs on Linux with peer connections disabled and RPC on loopback. Use
each workspace's README to select the retained image and datadir; the
overlays are opt-in, and the existing online recipes remain available.
Before a host-network offline start, preserve the copied original config
privately and remove its `addnode`, `connect`, `seednode`, `rpcbind` and
`rpcallowip` entries from the runtime copy. The overlay supplies the offline
connection and loopback RPC settings. Explicit peer entries must not survive
merely because automatic peer discovery is disabled. Keep index, network and
database options unchanged, and verify zero peers and loopback-only listeners.
Historical containers, including Crown, have automatic restart disabled.
Keep them stopped between explicit research runs. A retained datadir is not
proof of complete coverage or of a successful restart; record its verified
tip and historical block reads before relying on it.

Use the workspace's actual CLI recipe for readiness checks. RPC error `-28`
while loading or rewinding an existing block index is normal startup work.
Keep the daemon running, inspect its progress, and poll again. A tool-call
timeout or an unhealthy startup probe is not a reason to stop, recreate or
reindex the node. Acceptance needs one successful cold start, authenticated
block reads and graceful stop. Repeat startup only when a runtime correction
needs verification. Use `just start` to resume the retained container for a
later research run.

The historical workspaces allow five minutes for ordinary container shutdown.
Their explicit `just stop` and `just down` recipes wait without a forced
timeout so database flushing can finish. Investigate a stalled shutdown before
considering a forced stop.

CoiledCoin and SixEleven have separate offline overlays with networking
disabled entirely. Their legacy RPC is accessed through the workspace's
`docker compose exec` recipes, without publishing a host port. Their existing
database formats and entrypoints differ from newer Bitcoin-family nodes;
follow their own instructions when adopting preserved data.

The Blast, Jincoin, Lyncoin and Xaya research scaffolds also
default to no automatic restart and provide explicit retained-container
start/stop commands. Their ordinary configurations may contact peers when
started. Keeping a scaffold available does not imply recoverable chain data.

[Namecoin](namecoin/README.md), [Syscoin](syscoin/README.md),
[Elastos](elastos/README.md), [RSK](rsk/README.md) and
[Fractal](fractal/README.md) package preserved binaries or retained disks.
Each keeps noncreating binds and leaves restart disabled until acceptance.
Follow the workspace README and
[node operations](../docs/node-operations.md).

Not every integrated chain has a recipe here, because not every recovery
ran a node:

- **i0coin** was recovered from the complete March 2026 snapshot parsed offline;
  no node ran.
- **Geistgeld and Groupcoin** survive only as complete `getblock`-JSON
  dumps; there is no network left to sync.
- **Huntercoin** uses Daniel Kraft's native dump parsed offline; no node ran.
- **Bitcoin Vault and Hathor** were recovered over public REST APIs
  without running a node.
- **Lyncoin** was ultimately recovered from a live peer's raw P2P extended
  `headers` stream. The `node-infra/lyncoin/` workspace is a reproducible
  full-node fallback, not the provenance of the committed evidence.
- **SixEleven** synced with the pinned official `611project/611coin` image
  and six live peers. `node-infra/sixeleven/` reproduces that node, including
  the digest-pinned image, verified peers, loopback-only RPC, and extraction
  recipe for its legacy numbered block files.
- **Doichain** synced from 16 peers through the active-chain tip observed at
  height 430,684 using the source revision pinned by `node-infra/doichain/`.
  Its block-file survey is documented in `docs/chains/doichain.md`.
- **Blast and Jincoin** are surveyed scaffolds that never reached a
  usable peer or block archive; see `docs/chains/surveyed-infra.md`.
- **Solidar** (`node-infra/solidar/`) builds pinned `wincev/SOLIDAR` 0.8.9.0.
  A 2026-10-03 smoke test checked the native genesis hash. No listener
  accepted port 55889 on 2026-10-03 or 2026-10-20. Recovery scope is in
  `docs/chains/solidar.md`.

The per-chain provenance docs under `docs/chains/` record which path
each recovery took and the resulting stage counts.

The [ROD archival node](rod/README.md) builds from a pinned local source
archive and retains the complete block dataset with pruning off. Its sync and
Bitcoin-parent extraction are separate acceptance steps; the workspace does
not register a source or publish recovery evidence automatically.

The [research worker](research-worker/README.md) runs extraction and
classification commands in a container with an explicit read-only checkout and
archive. Generated output goes to a separate writable directory. It includes
Git and Git LFS so classification can verify its code revision, and it starts
no research job automatically.

## Reaching Bitcoin Core

The classification and recovery scripts speak JSON-RPC to Bitcoin Core over
HTTP. They take a `--rpc-url` (default `http://127.0.0.1:8332`, overridable via
`BTC_RPC_URL`) and resolve auth from `--rpc-user`/`--rpc-pass`, the
`BITCOIN_RPC_USER`/`BITCOIN_RPC_PASSWORD` env vars, the node's `.cookie`, or
`bitcoin.conf` (in that order). The same applies to the child-chain nodes the
extractors reach, each on its own port.

Where the node runs is the operator's concern, not the pipeline's. If Bitcoin
Core is on another host, forward its RPC port to localhost and point `--rpc-url`
at the forward:

```bash
ssh -L 8332:localhost:8332 <archival-host>
# then, in another shell:
# run the relevant classifier with --rpc-url http://127.0.0.1:8332
```

The child-chain extractors follow the same pattern on their own ports (for
example `ssh -L 13332:localhost:13332 <host>` for terracoind).
