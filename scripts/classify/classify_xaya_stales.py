#!/usr/bin/env python3
"""Classify Xaya (CHI) SHA-256d AuxPoW extracts as canonical, stale, or unknown.

Xaya is a multi-algo chain (NEOSCRYPT solo-mined or SHA256D merge-mined). The
source enforces "SHA256D must be merge-mined", so every SHA256D Xaya block
carries a Bitcoin-parent CAuxPow; extract_xaya_auxpow.py has already filtered to
those merge-mined blocks and emitted the canonical classifier input schema
(``btc_header_hash`` / ``btc_bits`` plus the exact BIP34 ``child_height``).
AuxPoW chain ID 1829 (0x0725); Xaya does not expose the Namecoin-family
``fStrictChainId`` flag because its AuxPoW parent carries no chain ID. This
wrapper runs the shared classifier helpers:

1. keep only unique headers that meet their own encoded nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

``--validated-output`` (standard on every thin wrapper) is worth calling out
here specifically: run_classifier writes that path without creating its
parent directory, and config.py does not create ``data/`` at import, so when
running on a node working copy that only carries ``src/`` + ``scripts/`` the
outputs should be directed into an existing archive directory instead of the
(possibly absent) repo ``data/``.
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

_SPEC = CHAIN_SPECS["xaya"]


def main() -> None:
    """Run the shared classifier for this chain and print the summary counts."""
    ap = argparse.ArgumentParser(
        description="Classify Xaya AuxPoW candidates as stale/unknown"
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

    print("Xaya classification complete")
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
