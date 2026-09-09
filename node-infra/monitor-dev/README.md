# Merge Mining Monitor development

This MMR-owned workspace runs a separately restored development copy of the
Merge Mining Monitor and PostgreSQL 16. The app image builds from an explicit
local monitor checkout. The database uses an explicit host bind directory so a
logical restore can be verified on the VM without copying the Mac's ARM
PostgreSQL data directory to an amd64 host.

The app publishes its read API on host loopback port `18080` by default (set
`MMM_APP_PORT` to change it). PostgreSQL is reachable by the app over the
private Compose network and is not published to the host. Both services use
`restart: "no"` and are started on demand.

## Setup

```sh
cd node-infra/monitor-dev
cp .env.example .env
# Edit .env with the actual monitor/MMR checkout paths, an existing PGDATA
# bind path, separate development credentials, and source revision.
just config
just build
```

All bind sources must exist before Compose is invoked. For the initial VM
restore, create `MMM_PGDATA_DIR` as a dedicated empty directory with mode
`0755`, then run `just db-up` so PostgreSQL 16 can initialize a fresh cluster.
The outer bind directory must be traversable by the image entrypoint; it will
create and secure its nested `PGDATA` directory. Restore the logical dump into
that cluster with PG16 `pg_restore --exit-on-error` for a custom-format dump
(or `psql -v ON_ERROR_STOP=1` for SQL), then verify the schema
before starting the app. An already restored PGDATA bind can be started
directly. Do not copy the Mac `PGDATA` directory across architectures.

```sh
mkdir -p -m 0755 /path/to/monitor-dev-postgres
```

Retain and verify every selected source database and the complete restored
schema before deleting any source copy. This workspace does not create a dump,
restore a dump, run application migrations, or alter an existing schema
automatically. PostgreSQL's standard entrypoint may initialize an empty
cluster when `MMM_PGDATA_DIR` is first used; it does not apply the monitor's
migrations.

## Operation

Start only the service needed for a check:

```sh
just db-up
just app-up
```

`app-up` waits for PostgreSQL health but does not apply migrations. The app's
default command is the existing `serve` subcommand. It binds inside the
container at `0.0.0.0:8080` so Compose can expose it only on host loopback;
`SERVE_WWW_DIR=/app/www` serves the checkout's static frontend copied at image
build time. The app's pool connects lazily through `PGHOST=db` and the
configured development credentials. The MMR checkout is also mounted at
`/mmr` read-only and exposed as `MERGE_MINING_RESEARCH_DIR`, matching the
monitor's existing import configuration without making imports automatic.

Run other existing monitor commands only when explicitly intended:

```sh
just run import-all --help
just run sync-bitcoin-core --from-height <start> --to-height <end>
```

These one-off commands do not start the database implicitly; run `just db-up`
first when a command needs a connection. They retain the monitor's normal
environment and safety contracts. In particular, imports, Core sync, pollers,
and migrations are not startup actions. Use the monitor repository's
backup-first migration procedure for any future schema work, after confirming
the restored database and backup state.

`import-all` and `sync-bitcoin-core` also require the monitor's configured
Bitcoin Core RPC environment. Compose does not forward arbitrary host
variables automatically; pass selected variables through from an existing
shell when an explicit job needs them (the values are not command-line
password arguments):

```sh
export BITCOIN_RPC_URL BITCOIN_RPC_USER BITCOIN_RPC_PASSWORD
docker compose run --no-deps --rm \
  --env BITCOIN_RPC_URL \
  --env BITCOIN_RPC_USER \
  --env BITCOIN_RPC_PASSWORD \
  app sync-bitcoin-core --from-height 123 --to-height 123
```

The image build uses `cargo build --release --locked --bin
merge-mining-monitor` with Rust 1.88 and copies the resulting binary plus
`www/`. Rebuild after changing the monitor source revision or dependency lock;
the image is the executable source of truth for each run. Build context is
restricted by `Dockerfile.dockerignore` to the Rust/data/static inputs needed
for this image and excludes Git metadata, private environment files, build
outputs, logs, backups, test artifacts, and caches.

Stop the services with `just down`. `just clean` removes only stopped Compose
containers and this workspace's image; it leaves the PGDATA bind directory
untouched. The runbook's logical dump/restore, checksum comparison, migration
version check, API/browser verification, and backup retention remain operator
steps outside this workspace.
