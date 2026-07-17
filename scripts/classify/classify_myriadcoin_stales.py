#!/usr/bin/env python3
"""Classify Myriadcoin SHA-256d AuxPoW extracts as canonical, stale, or unknown.

Myriadcoin extraction (scripts/extract/extract_myriadcoin_auxpow.py) already
selects the SHA-256d branch via the nVersion algo bits (BLOCK_VERSION_ALGO =
7 << 9, SHA-256d encoded as 0) and the AuxPoW flag, writing one row per
merge-mined SHA-256d block with the embedded Bitcoin parent header and coinbase
transaction. That multi-algo branch selection is an EXTRACTOR concern; this
classifier has no per-row algo filter. It uses the shared classifier helpers:

1. keep only unique headers that meet the Bitcoin nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

Myriadcoin's fStrictChainId=false means the SHA-256d branch accepts AuxPoW from
any SHA-256d parent. In practice Bitcoin is the only parent miners use, and the
Phase 1 checks whether the parent header meets its encoded target. Bitcoin
parent linkage is established by the later RPC classification and validation.
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

_SPEC = CHAIN_SPECS["myriadcoin"]


def main() -> None:
    """Run the shared classifier for this chain and print the summary counts."""
    ap = argparse.ArgumentParser(
        description="Classify Myriadcoin AuxPoW candidates as stale/unknown"
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

    print("Myriadcoin classification complete")
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
