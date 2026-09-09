# Electric Cash node (Dockerised)

Builds `elcashd` from the upstream `electric-cash/electric-cash` source
(a Bitcoin Core 0.20 fork with Namecoin-style AuxPoW) for parent-header
extraction. This is the node behind the ELCASH integration documented in
`docs/chains/elcash.md`.

## Chain facts

| | |
|-|-|
| Codebase | Bitcoin Core 0.20.2 fork |
| AuxPoW | Namecoin-style, chain ID `0x2137` (8503), strict |
| Launch | Fresh genesis, December 2020; merge-mined from launch |
| Footprint | Small (a zombie chain at negligible hashrate) |

## Ports

ELCASH inherits Bitcoin Core's 8332/8333 defaults. The Compose file sets RPC
explicitly to 18432 and publishes it on host loopback; `ELCASH_RPC_PORT`
changes the daemon, healthcheck and `just` CLI commands together. Online
operation also publishes P2P 8433, which `init.sh` sets in `elcash.conf`.

RPC uses cookie auth: the extractor reads `.cookie` from the datadir.

## Usage

```sh
just init       # render elcash.conf in the datadir
just build      # compile elcashd (wallet/GUI/ZMQ disabled)
just up         # start the container
just logs       # watch IBD progress
just height     # current block height
```

The default data directory is `./data`; override with
`ELCASH_DATA_DIR`.

## Historical offline operation

Apply the [copied-config preparation](../README.md) before using this host-network
offline profile, including removal of explicit peer entries from the runtime copy.

Use a populated, verified copy of the selected datadir and its exact loaded
image. Put the private choices in `.env`:

```dotenv
ELCASH_IMAGE=sha256:<verified-image-id>
ELCASH_CONTAINER_NAME=elcashd
ELCASH_DATA_DIR=/path/to/preserved/elcash-data
ELCASH_RPC_PORT=18432
COMPOSE_FILE=docker-compose.yml:compose.offline.yml
```

The Linux offline overlay disables P2P and binds RPC only to loopback. A
preserved datadir without `elcash.conf` is supported: the daemon generates its
cookie at startup and every CLI uses the explicit RPC port. Do not run
`just init` on copied state or print the cookie. Bind sources must already
exist; a misspelled path fails instead of creating an empty node.

```sh
docker compose up -d --no-build --pull never
just height
# Read the recorded historical block anchors, then park the node.
just stop
```

Verify the recorded tip and representative blocks before accepting the copy.
Keep the historical container stopped between jobs; automatic restart is
disabled. `just stop` waits for graceful shutdown without a forced timeout.
For a deliberate new sync, create `./data` and use the setup above. The build
context excludes node data and credentials.

## Extraction

After IBD, `scripts/extract/extract_elcash_auxpow.py` runs on the same
host: it censuses every block version for the AuxPoW bit and chain ID
`0x2137`, parses the embedded Bitcoin parent header and coinbase from
each merge-mined block, and writes the standard raw-candidates CSV.
Classification against Bitcoin Core then goes through
`scripts/classify/classify_elcash_stales.py` (a thin `run_classifier`
wrapper that reproduces the committed `data/validated-stales/elcash_validated_stales.csv`
schema). See `docs/chains/elcash.md` for the stage counts.
