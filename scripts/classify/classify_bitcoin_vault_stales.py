#!/usr/bin/env python3
"""Classify Bitcoin Vault (BTCV) AuxPoW extracts as canonical, stale, or unknown.

BTCV has no node in this workflow; Phase 2.1 pulled all in-scope AuxPoW
commitments via Blockbook REST. This classifier uses the shared classifier
helpers:

1. keep only unique headers that meet the Bitcoin nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

The nBits validation gate is non-skippable: it marks parent headers that share a
BTC ancestor but use an easier (non-BTC) target as REJECTED rather than counting
them as BTC stales.

Two BTCV-specific quirks are handled here:

* ``bits_source_is_decimal=True`` -- the legacy committed
  ``bitcoin-vault_validated_stales.csv`` and the current extractor write
  ``btc_bits`` as a DECIMAL int (e.g. ``386924253``), so the driver normalizes
  it to canonical lowercase 8-char hex before the gate rather than treating the
  raw value as hex. Drop this once the extractor emits hex.
* The historical squashed-spelling RPC flags (which hardcoded a
  ``bitcoin`` / ``bitcoin`` default) are retired as part of the fleet-wide CLI
  cutover; ``--rpc-user`` / ``--rpc-pass`` now default to cookie/conf/env
  auto-discovery like every other classifier. Pass them explicitly for a node
  whose RPC credentials really are ``bitcoin`` / ``bitcoin``.
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

_SPEC = CHAIN_SPECS["bitcoin-vault"]


def main() -> None:
    """Run this chain's classification pipeline end to end."""
    ap = argparse.ArgumentParser(
        description="Classify Bitcoin Vault AuxPoW as stale/unknown"
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
        bits_source_is_decimal=True,  # raw BTCV btc_bits is decimal until the extractor is fixed
        rpc=rpc_from_args(args),
    )

    print("Bitcoin Vault classification complete")
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
