#!/usr/bin/env python3
"""Classify Electric Cash (ELCASH) AuxPoW extracts as canonical, stale, or unknown.

ELCASH extraction (``scripts/extract/extract_elcash_auxpow.py``) writes one row
per merge-mined ELCASH block with the embedded Bitcoin parent header and coinbase
transaction. Its output schema already matches the shared classifier input
(``btc_header_hex`` / ``btc_header_hash`` / ``btc_prev_hash`` / ``btc_bits`` /
``btc_time`` / coinbase columns, plus the ``elc_height`` provenance column), so
no per-chain input adapter is needed -- this is a plain ``run_classifier``
wrapper following the ixcoin template.

1. keep only unique headers that meet the Bitcoin nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

The nBits validation gate is non-skippable: it marks parent headers that share a
BTC ancestor but use an easier (non-BTC) target as REJECTED rather than counting
them as BTC stales.

REPRODUCIBILITY: the committed ``data/validated-stales/elcash_validated_stales.csv`` (3 rows,
BTC 688,349 / 693,118 / 699,616) was produced off-tree before this classifier
existed. ``run_classifier(CHAIN_SPECS['elcash'], ...)`` emits the exact committed
column set/order (``output_columns('elc_height')``), so a re-run against the raw
extract reproduces that schema; the default ``--validated-output`` target is
``CHAIN_SPECS['elcash'].validated_csv`` == ``data/validated-stales/elcash_validated_stales.csv``.
(The committed file carries empty ``coinbase_outputs`` because that extraction
preserved no parent-coinbase outputs; only the schema, not the values, is what
this wrapper is asserted to reproduce.)
"""

from __future__ import annotations

import os
import sys

# Allow direct execution from a checkout without requiring editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from stale_blocks_analysis.classifier_cli import run_standard_classifier_cli  # noqa: E402
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402

_SPEC = CHAIN_SPECS["elcash"]


def main() -> None:
    """Delegate to the shared thin-wrapper classifier CLI."""
    raise SystemExit(run_standard_classifier_cli(sys.argv[1:], _SPEC))


if __name__ == "__main__":
    main()
