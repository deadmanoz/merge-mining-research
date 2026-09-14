# Qbit archival node

Build the headless mainnet daemon and CLI from Qbit revision
`70fea84f5becfb57463247af09790df5ddd424f8`. Export that local revision with
`git archive --format=tar` to the ignored `source.tar`. Its SHA256 must be
`d948db28fdf5d27dc155dddab2eb3770ac4d2059b392553accdfdaaae1352ad2`.
The build verifies the digest before compiling with Ubuntu 24.04 and CMake.
No consensus patches are applied. Wallet, IPC and GUI are disabled.

Create private data and config paths writable/readable by UID 1000 and set
their absolute paths in `.env` using `.env.example`. Both binds must exist;
Compose cannot create replacements. The config must include `server=1`,
`prune=0`, `prunewitnesses=0`, `assumevalid=0`, `txindex=1`, `listen=0` and
`rpcport=8354`, and it binds RPC to the container interface
(`rpcbind=0.0.0.0`) with `rpcallowip` entries for exactly the client classes
that need access: container loopback, the Docker bridge range for containers
on the same host, and the poller's private address when the node serves a
remote consumer. Exposure is governed by the published host address in
`QBIT_RPC_BIND`, loopback by default, never `0.0.0.0`. The image also enforces
all four archival validation options on its command line. Witness pruning is
separate from block pruning and incompatible with transaction indexing. Keep
cookie authentication private inside the datadir for the CLI, the health check
and research use; a remote poller authenticates with one `rpcauth` line.

The workspace follows the same profile model as the other node workspaces.
The base Compose file is the operating shape: RPC published on `QBIT_RPC_BIND`,
automatic restart from `QBIT_RESTART_POLICY` (default `no`), and a
`qbit-cli getblockcount` health check. `compose.offline.yml` is the opt-in
overlay for networkless reads of the retained datadir (no network interface,
no host ports, no restart). Select profiles through `COMPOSE_FILE` in `.env`.

Run `just config`, `just build`, `just test`, then `just up`. `just up` and
`just start` never build or pull; only `just build` builds. Use
`just rpc getblockchaininfo`, `just rpc getindexinfo` and
`just rpc getpeerinfo`; `just status` shows the container and its health.
Outbound mainnet P2P uses port 8355. Keep the restart policy at `no` during
acquisition. Use `just stop` and `just start` to retain and resume the node.
The default image command exits without starting when the separate config is
absent.

Before sealing an acquisition, record the image ID, source revision, validation
settings, genesis, endpoint height/hash, chainwork and index state. Mainnet
genesis is `0000000000004d60aa5d46013991d0a0e2995d89ee98e53068ae196d763e79f2`.
Account for every height and predecessor edge, and both directly mined and
AuxPoW blocks. Native placement and Qbit proof acceptance are separate from
Bitcoin-parent classification. Preserve all lower-work and unresolved proofs.

Keep source bundles, datadir, raw RPC captures, receipts and credentials private.
Starting the node does not run extraction, Research publication or Monitor
imports. Historical acquisition runs on the loopback bind; serving the
Monitor's live capture is the same base profile with a private bind.

## Serving a remote poller

Set `QBIT_RPC_BIND` to the selected private host address and keep
`QBIT_RESTART_POLICY=no` until the endpoint and recovery checks pass:
authenticated requests succeed from each intended client path, unauthenticated
requests are rejected, and other host addresses refuse the connection. Then
set `unless-stopped` and apply it to the existing container without
recreating it: `docker update --restart unless-stopped <container>`, where
`<container>` is the configured `QBIT_CONTAINER_NAME` (default
`mmr-qbit-archive`). `docker stop` and `docker kill` are operator actions that suppress
restart policies, so test recovery by terminating the daemon process inside
the container instead. Host startup must be ordered after the data mount and
the private interface that `QBIT_RPC_BIND` names, as the node-infra README
requires. RPC error `-28` during index load is normal startup work; keep the
daemon running. The published address, allowlist values and credentials are
host-specific and never appear in tracked files.

Rollback at any point: `just stop`, set `QBIT_RPC_BIND` back to loopback and
the restart policy to `no` (`docker update --restart no <container>`), and
`just up`; or select the offline overlay for reads only. The research worker
overlay joins the configured container's network namespace through the same
`QBIT_CONTAINER_NAME` variable. The datadir is
shared by every profile and untouched by the switch.

## Explicit historical acquisition

Use `compose.research.yml` to run the shared research worker in the node's
network namespace. Set `MMR_REPO_DIR` to an isolated source copy,
`MMR_ARCHIVE_ROOT` to the read-only private archive, `MMR_WORK_DIR` to an
existing disposable output directory, and `QBIT_COOKIE_FILE` to the node's
existing cookie. `just research-build` uses its own Qbit worker image tag.
No other research worker image is replaced.

After the archive has synced, choose a settled endpoint from native RPC and
record its height and hash. Run:

```sh
just research python scripts/extract/extract_qbit_auxpow.py \
  --rpc-url http://127.0.0.1:8354 --cookie-file /run/qbit.cookie \
  --end-height <height> --end-hash <hash> --output-dir /work/<new-run>
```

For a long run, replace `research` with `research-background <unique-name>`.
Inspect the named container's logs and exit status before accepting its receipt.
The output directory must be new. Incomplete runs retain their raw captures
but cannot seal; rerun to a fresh directory. Successful runs bind exact RPC
response bytes, every raw block, coverage and standard extraction CSVs, parser
dependencies and both chain endpoints. `qbit_auxpow.csv` is a private complete
proof inventory, including lower-work parents, not a validated-stales input.

For offline regeneration, the root `just acquire-qbit` command accepts
`--from-acquisition <sealed-directory>` instead of RPC credentials. Supply the
original endpoint and batch size and a fresh output directory. The normal
producer authenticates the retained calls and reruns its coverage and proof
checks without starting the node or changing the sealed source. See
[`docs/chains/qbit.md`](../../docs/chains/qbit.md) for classification and
publication provenance.
