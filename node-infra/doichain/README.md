# Doichain node (Dockerised)

This workspace reproduces the Doichain node used for the completed AuxPoW
survey. It builds `Doichain/doichain-core` at source commit
`7eb68ae902f8329c80dc38e464f80d8bda2ed514`, the exact revision used by the
archived run.

| Parameter | Value |
|---|---|
| P2P magic | `f8 b2 b2 ff` |
| P2P port | 8338 |
| RPC port | 8339, bound to host loopback |
| AuxPoW chain ID | 2 |
| AuxPoW activation | child height 1 |
| Strict chain-ID enforcement | false |
| Observed active-chain tip | 430,684 on 2026-06-24 |

## Usage

```bash
just init
just build
just up
just logs
just height
just peers
just status
just down
```

The default datadir is `./data`. Put it on another disk without editing the
compose file:

```bash
export DOICHAIN_DATA_DIR='<chain-data-dir>/doichain'
just init
just up
```

`init.sh` writes a private RPC password and adds 12 public peer hints retained
from the completed sync. They are a subset of the 16 connections observed at
the survey tip. Recheck them before expecting a fresh sync to work; peer
availability is not a permanent property of this legacy network.

## Recovery workflow

Once fully synced, extract every AuxPoW commitment, including shares that do
not meet their claimed Bitcoin target:

```bash
just extract doichain_auxpow_full.csv
```

The generic blkdat extractor records numbered block-file order. For a new run,
resolve exact child heights with `normalize_auxpow_child_heights.py` before
classification. Then classify the Bitcoin parents and run the population
characterization:

```bash
source ../../.venv/bin/activate
python ../../scripts/prep/normalize_auxpow_child_heights.py \
  --chain doichain \
  --input doichain_auxpow_full.csv \
  --output doichain_auxpow_full.heights.csv \
  --rpc-conf "${DOICHAIN_DATA_DIR:-./data}/doichain.conf"

python ../../scripts/classify/classify_doichain_stales.py \
  --input doichain_auxpow_full.heights.csv

python ../../scripts/reports/characterize_doichain_auxpow.py \
  --input doichain_auxpow_full.heights.csv \
  --summary doichain-auxpow-characterization.json
```

Doichain sets `fStrictChainId=false`, so the normalizer verifies the AuxPoW
flag and RPC identity but does not require the child version to carry nominal
chain ID 2. The characterization groups the historical population by compact
target exponent; an exponent of `0x17` is not, by itself, an exact
expected-Bitcoin-`nBits` check. The chain document records the separate
exact-target audit results.

The committed survey result is documented in
[`docs/chains/doichain.md`](../../docs/chains/doichain.md). Generated node data,
raw extracts, and full classifier inventories remain outside git.
