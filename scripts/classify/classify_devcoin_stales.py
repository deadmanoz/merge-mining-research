#!/usr/bin/env python3
"""Classify Devcoin AuxPoW extracts as canonical, stale, or unknown.

Devcoin extraction writes one row per merge-mined Devcoin block with the
embedded Bitcoin parent header and coinbase transaction. This classifier uses
the shared classifier helpers:

1. keep only unique headers that meet the Bitcoin nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

With ``--keep-near`` the self-target-PoW-failing headers the standard run drops are
retained to ``data/devcoin_near_blocks.csv`` as sibling evidence for
shared-parent multi-block fork detection. This replaces the former bespoke
``classify_devcoin_all.py`` (which emitted stale + unknown + near into one file);
near rows now live in their own split file on the shared schema.
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

_SPEC = CHAIN_SPECS["devcoin"]


def main() -> None:
    """Run the shared classifier for this chain and print the summary counts."""
    parser = argparse.ArgumentParser(
        description="Classify Devcoin AuxPoW as stale/unknown"
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

    print("Devcoin classification complete")
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
