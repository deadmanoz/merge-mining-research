#!/usr/bin/env python3
"""Classify Terracoin AuxPoW extracts as canonical, stale, or unknown.

Terracoin extraction (scripts/extract/extract_terracoin_auxpow.py) writes one
row per merge-mined Terracoin block carrying the embedded Bitcoin parent header
and coinbase transaction. This classifier uses the shared classifier helpers:

1. keep only unique headers that meet the Bitcoin nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

Terracoin's only chain-specific quirk is the Dash-Core-0.12.x plural
scriptPubKey ``addresses`` array, but that is handled entirely in the extractor
(``format_outputs``); the classifier passes ``coinbase_outputs`` through
verbatim, so no chain-specific output formatting is needed here. The raw
``btc_bits`` artifact is already 8-char hex, so ``bits_source_is_decimal`` stays
False.
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

_SPEC = CHAIN_SPECS["terracoin"]


def main() -> None:
    """Run the shared classifier for this chain and print the summary counts."""
    parser = argparse.ArgumentParser(
        description="Classify Terracoin AuxPoW as stale/unknown"
    )
    # Historical defaults have no "data/" prefix, unlike every other chain's
    # spec-derived default; preserved here exactly, byte-identical to today.
    add_standard_output_args(
        parser,
        _SPEC,
        input_default="terracoin_auxpow_raw.csv",
        output_default="terracoin_stale_blocks.csv",
    )
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

    print("Terracoin classification complete")
    for key in (
        "total",
        "btc_valid",
        "stale",
        "unknown",
        "valid",
        "rejected",
        "validation_unknown",
        "output_path",
    ):
        print(f"  {key}: {summary[key]}")
    if args.keep_near:
        print(f"  near: {summary['near']}")
        print(f"  near_output_path: {summary['near_output_path']}")


if __name__ == "__main__":
    main()
