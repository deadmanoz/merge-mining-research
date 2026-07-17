#!/usr/bin/env python3
"""Classify Argentum SHA-256d AuxPoW extracts as canonical, stale, or unknown.

Argentum is a multi-algo PoW chain (Scrypt + SHA-256d + 4 native algos
post-2018-03 fork). Only the SHA-256d branch is Bitcoin-parent merge-mined;
extract_argentum_auxpow.py has already filtered to SHA-256d-only by the time
we get here, so the algo selection is purely an extractor concern. The
classifier just consumes BTC parent-header rows and runs the shared helpers:

1. keep only unique headers that meet their encoded nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

Argentum's ``fStrictChainId=false`` means the SHA-256d branch technically
accepts AuxPoW from any SHA-256d parent. The self-target PoW filter does not
identify the parent; the RPC classification step decides whether the
header actually belongs to Bitcoin, and the nBits gate defends against post-2017
BCH/BSV-family parent-header contamination.
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

_SPEC = CHAIN_SPECS["argentum"]


def main() -> None:
    """Run the shared classifier for this chain and print the summary counts."""
    parser = argparse.ArgumentParser(
        description="Classify Argentum AuxPoW candidates as stale/unknown",
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

    print("Argentum classification complete")
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
