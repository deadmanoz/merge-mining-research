# RSKj Vetiver 9.0.1

This workspace runs the preserved RSKj 9.0.1 native JAR already archived on
the migration VM. It does not download, rebuild, or upgrade RSKj. The image
checks the exact JAR SHA-256 during its build, runs as UID/GID 1000, and uses
`/data` as its working directory so relative logs remain inside the data bind.
The harmless image default is `java -version`; do not invoke `co.rsk.Start` for
help or version probes against a real state directory.

Copy `.env.example` to a private `.env` and select the loaded image, retained
container name, populated `RSK_DATA_DIR`, and loopback RPC settings. The data
bind source must already exist. It uses `create_host_path: false`, so a missing
source cannot create an empty path.
The base profile uses Linux host networking and keeps restart policy
`RSK_RESTART_POLICY` at `no` until a separate live acceptance decision. It
publishes no ports and does not add a proxy or firewall rule.

The command mirrors the observed native unit: Java heap `4g`/`8g`,
`co.rsk.Start --main --sync-mode=full`, base path `/data`, database path
`/data/mainnet/database`, and RPC bind `127.0.0.1` by default. It deliberately
does not select `/etc/rsk/mainnet.conf` or invent a private configuration
layer. The RPC port defaults to 4444 and is passed consistently to the daemon
and helper. Review the copied state and any effective defaults before startup.

The offline overlay selects `network_mode: none`, forces restart `no`, and
keeps the same runtime and database arguments with loopback RPC. Select it in
the private `.env` with:

```dotenv
COMPOSE_FILE=docker-compose.yml:compose.offline.yml
```

The adopted `RSK_DATA_DIR` must contain the complete live datadir, including
the ordinary `mainnet/database/unitrie` directory. It must not contain an
absolute symlink back to the source host. Preserve the original symlink
provenance and older state as archive records, while keeping the active copied
tree self-contained. The target data ownership adjustment is limited to the
copied RSK data needed by UID/GID 1000; never chown the source or the whole VM.

The normal retained-container lifecycle is:

```sh
docker compose up -d --no-build --pull never rsk
just status
just rpc eth_blockNumber
# Verify recorded block anchors before parking the node.
just stop
```

`just rpc METHOD [JSON_PARAM ...]` sends a JSON-RPC request through
the loopback endpoint. Each parameter must be valid JSON, for example
`just rpc eth_getBlockByNumber '"0x1"' false` or
`just rpc debug_method '{"tag":"x value"}' 42`; the recipe preserves each
argument as one JSON value and rejects empty, malformed or multiple values
within an argument. The helper does not restrict RPC methods; choose diagnostic
read methods when checking archived data. RPC errors are printed without
credentials and return failure. `just stop` and `just down` use unlimited graceful shutdown
timeouts. Do not copy a live changing `/logs/rsk.log` as a
frozen receipt; preserve that source log family separately after quiescing the
source during the later migration.

Only the preserved JAR, this Dockerfile, and the RPC helper belong in the
build context. Runtime data, configs, `.env`, source trees, and logs are
ignored. No datadir copy, unitrie replacement, source stop, node start, DB
reset/import/reindex/GC, or production network change is performed by this
workspace preparation.
