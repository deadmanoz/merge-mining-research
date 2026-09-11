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
`prune=0`, `prunewitnesses=0`, `assumevalid=0`, `txindex=1`, `listen=0`,
`rpcbind=127.0.0.1`, `rpcallowip=127.0.0.1`, and `rpcport=8354`.
The image also enforces all four archival validation options on its command
line. Witness pruning is separate from block pruning and incompatible with
transaction indexing. Keep cookie authentication private inside the datadir.

Run `just config`, `just build`, `just test`, then `just run`. RPC has no
published host port; use `just rpc getblockchaininfo`, `just rpc getindexinfo`
and `just rpc getpeerinfo`. Outbound mainnet P2P uses port 8355. Automatic
restart is disabled during acquisition. Use `just stop` and `just start` to
retain and resume the node. The default image command exits without starting
when the separate config is absent.

Before sealing an acquisition, record the image ID, source revision, validation
settings, genesis, endpoint height/hash, chainwork and index state. Mainnet
genesis is `0000000000004d60aa5d46013991d0a0e2995d89ee98e53068ae196d763e79f2`.
Account for every height and predecessor edge, and both directly mined and
AuxPoW blocks. Native placement and Qbit proof acceptance are separate from
Bitcoin-parent classification. Preserve all lower-work and unresolved proofs.

Keep source bundles, datadir, raw RPC captures, receipts and credentials private.
Starting the node does not run extraction, Research publication or Monitor
imports. Historical acquisition is the current scope; no live feed is implied.

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
