# Elastos node

This workspace runs the preserved Elastos v1.0.2 native release on Linux. It
is a runtime profile for the exact binaries selected in the private migration
record; it does not build Elastos. The image runs as UID/GID 1000, uses Linux
host networking, has no automatic restart by default, and keeps the node in
the foreground.

The build expects the ignored `ela` and `ela-cli` files in this directory.
Copy those two binaries from the reviewed archive after verifying its
checksums. Do not copy a source checkout, blockchain data, or operator config
into this build context. The Dockerfile allowlist excludes `.git`, `.env`,
configs, data, caches, and every other file.

Copy `.env.example` to `.env` and edit every path before running `just config`
or `just build`. The selected data directory must already exist and contain
the reviewed node root. The config file must already exist and is mounted
read-only. Compose will not create either bind source. Preserve the complete
selected node root under the one `/data` bind so its logs, config-adjacent
files, sponsor files, and database tree retain their relative layout.

The container working directory and data mount are `/data`. The historical
service used a `node` working directory and the release binary's default
datadir was its `elastos` child. The target therefore passes
`--datadir=/data/elastos` while retaining the whole selected node root under
`/data`. The node receives an explicit `--conf=/config/config.json`,
`--enablerpc`, and `--printlevel 3`. The read-only config is also mounted at
`/data/config.json` so the preserved `ela-cli` can use its default
working-directory lookup without exposing credentials in a recipe.

The normal Compose command uses host networking and publishes no Docker ports;
the reviewed config controls the listener. The offline overlay removes
networking entirely and adds the verified `--disabledns` flag:

```sh
COMPOSE_FILE=docker-compose.yml:compose.offline.yml just config
COMPOSE_FILE=docker-compose.yml:compose.offline.yml docker compose run --rm --no-deps node
```

The offline overlay is a diagnostic guard. It does not make a mainnet node
usable and must not be used with a synchronization job.

Build and operate the node explicitly:

```sh
just config
just build
just start
just status
just logs
just rpc
just stop
just down
just clean
```

`just start` uses the existing image only (`--no-build --pull never`).
`just stop` and `just down` use an unlimited graceful stop timeout.
`just rpc` is the read-only `ela-cli info getnodestate` helper. `just clean`
removes only the stopped Compose container and never touches the bound data
directory or global Docker resources. No automatic migration, synchronization,
import, polling, peer change, pruning, or index operation is performed by
this workspace.

The image default is the finite `ela-cli --version` command. Compose sets the
explicit `ela` entrypoint for real node operation. Inspect help and version
behavior in a temporary networkless container before any real config or data
bind. A real node start, data adoption, RPC exposure, and any peer or pruning
choice require the separate private migration review.
