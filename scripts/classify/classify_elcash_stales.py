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

import argparse
import os
import sys

# Allow direct execution from a checkout without requiring editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from stale_blocks_analysis.btc_classify import run_classifier
from stale_blocks_analysis.classifier_cli import (
    add_rpc_args,
    add_standard_output_args,
    rpc_from_args,
)
from stale_blocks_analysis.config import CHAIN_SPECS

_SPEC = CHAIN_SPECS["elcash"]


def main() -> None:
    """Run the shared classifier for this chain and print the summary counts."""
    parser = argparse.ArgumentParser(
        description="Classify ELCASH AuxPoW as stale/unknown"
    )
    add_standard_output_args(parser, _SPEC)
    add_rpc_args(parser)
    args = parser.parse_args()

    summary = run_classifier(
        _SPEC,
        input_path=args.input,
        output_path=args.output,
        validated_output_path=args.validated_output,
        all_valid=True,
        all_valid_path=args.all_valid,
        keep_near=args.keep_near,
        rpc=rpc_from_args(args),
    )

    print("ELCASH classification complete")
    for key in (
        "total",
        "btc_valid",
        "stale",
        "unknown",
        "valid",
        "rejected",
        "validation_unknown",
        "output_path",
        "validated_output_path",
    ):
        print(f"  {key}: {summary[key]}")
    if args.keep_near:
        print(f"  near: {summary['near']}")
        print(f"  near_output_path: {summary['near_output_path']}")


if __name__ == "__main__":
    main()
