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

ELCASH inherits Bitcoin Core's 8332/8333 defaults. The compose file
publishes `127.0.0.1:18432` (RPC, loopback only) and `8433` (P2P,
public), and `init.sh` pins that pair in `elcash.conf`, so the node can
share a host with a Bitcoin Core instance.

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

## Extraction

After IBD, `scripts/extract/extract_elcash_auxpow.py` runs on the same
host: it censuses every block version for the AuxPoW bit and chain ID
`0x2137`, parses the embedded Bitcoin parent header and coinbase from
each merge-mined block, and writes the standard raw-candidates CSV.
Classification against Bitcoin Core then goes through
`scripts/classify/classify_elcash_stales.py` (a thin `run_classifier`
wrapper that reproduces the committed `data/validated-stales/elcash_validated_stales.csv`
schema). See `docs/chains/elcash.md` for the stage counts.
