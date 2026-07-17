#!/usr/bin/env python3
"""Classify Crown SHA-256d AuxPoW extracts as canonical, stale, or unknown.

Crown (CRW) is a 2014 Bitcoin/Dash-derived chain with standard
Namecoin-style AuxPoW (chain ID 20, fStrictChainId true). AuxPoW activates at
Crown height 453,273; the chain went PoS-hybrid at 2,330,000 (PoS blocks carry
no AuxPoW and are skipped by the extractor). extract_crown_auxpow.py has already
filtered to AuxPoW-flagged blocks by the time we get here.

fStrictChainId=true prevents a parent header from using Crown's own chain ID;
it does not establish Bitcoin parent identity. This classifier runs the shared
classifier
helpers:

1. keep only unique headers that meet their encoded nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.
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

_SPEC = CHAIN_SPECS["crown"]


def main() -> None:
    """Run the shared classifier for this chain and print the summary counts."""
    ap = argparse.ArgumentParser(
        description="Classify Crown AuxPoW candidates as stale/unknown"
    )
    add_standard_output_args(ap, _SPEC)
    add_rpc_args(ap)
    args = ap.parse_args()

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

    print("Crown classification complete")
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
