# Node infrastructure

Build and run recipes for the merge-mined chains whose recovery needed a
locally operated node. Each directory is its own workspace with a README,
a compose file, and usually a Dockerfile and `justfile`; read the chain's
README before building, and keep generated datadirs out of git (each directory
ignores `data/`). Some workspaces, including SixEleven, pin a published image
directly and therefore do not need a Dockerfile.

Not every integrated chain has a recipe here, because not every recovery
ran a node:

- **Namecoin, RSK, Syscoin, Elastos** ran as natively installed nodes
  (RSK on RSKj, Elastos on its Go implementation); their setup is
  conventional and documented in the per-chain docs.
- **i0coin** was recovered from a 2018 datadir snapshot parsed offline;
  no node ran.
- **Geistgeld and Groupcoin** survive only as complete `getblock`-JSON
  dumps; there is no network left to sync.
- **Huntercoin** was recovered from the Arweave permaweb archive.
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

The per-chain provenance docs under `docs/chains/` record which path
each recovery took and the resulting stage counts.

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
