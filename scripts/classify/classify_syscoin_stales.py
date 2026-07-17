#!/usr/bin/env python3
"""Classify Syscoin AuxPoW extracts as canonical, stale, or unknown.

Syscoin extraction writes one row per merge-mined Syscoin block with the
embedded Bitcoin parent header and coinbase transaction, in the canonical
classifier input schema (``btc_header_hex`` / ``btc_header_hash`` / ``btc_bits``
plus the ``sys_height`` provenance column). This wrapper runs the shared
classifier helpers:

1. keep only unique headers that meet the Bitcoin nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

The nBits validation gate is non-skippable: it marks parent headers that share a
BTC ancestor but use an easier (non-BTC) target as REJECTED rather than counting
them as BTC stales.

Syscoin has no chain-specific input handling -- the raw extract already uses the
shared schema -- so this is a plain ``run_classifier`` wrapper. It exposes
``--validated-output`` so the committed VALID-only loader CSV can be written to
an explicit path, and keeps the historical ``--input`` default of
``data/auxpow_raw.csv``.
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

_SPEC = CHAIN_SPECS["syscoin"]


def main() -> None:
    """Run the shared classifier for this chain and print the summary counts."""
    parser = argparse.ArgumentParser(
        description="Classify Syscoin AuxPoW as stale/unknown"
    )
    # Historical --input default is data/auxpow_raw.csv, not the per-chain
    # data/syscoin_auxpow_raw.csv name the spec would derive; preserved here.
    add_standard_output_args(parser, _SPEC, input_default="data/auxpow_raw.csv")
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

    print("Syscoin classification complete")
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
