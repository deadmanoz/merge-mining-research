# SpaceXpanse ROD archival node

This workspace builds the headless ROD daemon and CLI from source revision
`248f1af050579a369af527288f5773a021ae8492` (0.6.8.10). It supports a complete,
unpruned mainnet sync for historical merge-mining research. The node validates
ROD's dual-algorithm difficulty and proof rules; a separate research pass
classifies the embedded SHA256d parent evidence against Bitcoin.

The upstream build uses Autotools. The Ubuntu 22.04 build disables wallet,
GUI, tests, benchmarks, ZMQ and automatic port mapping. The source input is a
local `git archive` tar, verified by SHA256 before compilation. Do not replace
it with an unpinned web checkout or modify a preserved source directory.

The C build requires `-fno-strict-aliasing`. GCC 11 at `-O2` otherwise
miscompiles the bundled portable NeoScrypt implementation and rejects the
network's genesis proof. This compiler setting restores the expected hash;
it does not change the source or bypass proof verification.
The image build links `test-neoscrypt.c` against the daemon's actual compiled
NeoScrypt object and requires the exact mainnet genesis proof hash to match.

The build applies the tracked `download-window.patch` after source digest
verification. It changes only `MAX_BLOCKS_IN_TRANSIT_PER_PEER` from 16 to 128;
`BLOCK_DOWNLOAD_WINDOW` remains 1024. A measured six-peer sync was limited by
16 outstanding requests per peer and network latency. The larger queue allows
more concurrent downloads while retaining native block, AuxPoW and NeoScrypt
validation. It can increase memory use and let a slow peer hold more requests
until the existing stall timeout. Record the patch digest with the source and
image receipts. The image tag includes `archive128`; set `ROD_IMAGE` to a
retained original image for rollback, then use `just run` without rebuilding.

## Prepare and run

From the pinned local ROD checkout, export `git archive --format=tar
248f1af050579a369af527288f5773a021ae8492` to this workspace's ignored
`source.tar`. Its expected SHA256 is
`789cfd4ccdd924c4b879aaf993f5ef6f30294d917f88cfe342298048e738d449`.

Create a dedicated data directory and separate private config. Set their
absolute paths in `.env` using `.env.example`. Bind sources must exist before
startup, and the data directory must be writable by UID/GID 1000. A missing
config causes the default command to exit without starting
the daemon. The runtime exposes no host ports; use `just rpc` inside the
container. It can make outbound peer connections when explicitly started.

The archival config must include `server=1`, `prune=0`, `txindex=1`,
`assumevalid=0`, `listen=0`, `rpcbind=127.0.0.1`, `rpcallowip=127.0.0.1`,
and an explicit `rpcport=11997` (ROD's source defaults overlap the mainnet
P2P port). Cookie authentication stays in the datadir. Mainnet peers use
port 11998. Add verified peer endpoints only in the private config.

Run `just config`, `just build`, `just test`, then `just run`. Use `just rpc
getblockchaininfo`, `just rpc getpeerinfo`, `just rpc getindexinfo` and
`just logs` to assess progress. Automatic restart is disabled. Use `just stop`
for a clean shutdown and `just start` to resume the retained node.

For batched extraction, `just research <command> <arguments>` reuses the
[research worker](../research-worker/README.md) and joins the running node's
network namespace. Set the worker's `MMR_REPO_DIR`, `MMR_ARCHIVE_ROOT` and
`MMR_WORK_DIR`, plus `ROD_COOKIE_FILE` to the existing datadir cookie. The
cookie mounts read-only at `/run/rod.cookie`; use RPC URL
`http://127.0.0.1:11997`. This explicit command starts only the disposable
worker, not the node. Store outputs under `/work`. The worker image must
already be built through its own canonical workspace.

Use `just research-background <unique-container-name> <command> <arguments>`
for an explicitly launched long job that must survive an SSH disconnect.
Inspect its status and logs with Docker, and remove that named container after
collecting the result. Output files remain in `MMR_WORK_DIR`. This does not
enable automatic jobs on node startup or an automatic restart policy.

Before replacing the node container, stop its research workers. Recreate them
after the new node starts so their network namespace and cookie bind refer to
the new container and cookie. Retain their output directories for resumption.

## Acceptance and data boundary

Sync completion requires the recorded snapshot height/hash to occur on the
node's active chain, no outstanding headers at that boundary, pruning off,
and readable historical full blocks. Record the running image ID, daemon
version, source revision, chainwork and peer observations. Verify genesis
`5d4b20be4fc87d2333aea5235d9de1c685696fc935f806a9ffd71c9f9abf3c57`
and the source checkpoints. Do not treat an IBD flag alone as proof that the
complete dataset is retained.

Keep the complete datadir, logs, RPC cookies, extracts and host configuration
private. Retain every scanned parent observation, including lower-work,
unresolved and rejected proofs. Publication eligibility is a separate verdict;
node availability or successful sync does not imply a Bitcoin canonical or
stale recovery. No Research publication or Monitor import runs at startup.
