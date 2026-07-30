#!/usr/bin/env python3
"""Classify Doichain AuxPoW parents with the shared Bitcoin classifier.

The generic blkdat extractor uses ``btc_hash`` / ``btc_bits_hex`` and a
``child_height`` provenance column. Historical Doichain extracts use the
classifier-native names and ``doi_height``. This wrapper accepts either form,
normalizes it, and delegates classification and the mandatory nBits gate to
``run_classifier``. Unknown rows remain ``unknown``; strict/weak orphan status
is derived later by ``classify_btc_stale_relevance.py``.
"""

from __future__ import annotations

import argparse
import csv
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from stale_blocks_analysis.btc_classify import run_classifier
from stale_blocks_analysis.classifier_cli import (
    add_rpc_args,
    add_standard_output_args,
    rpc_from_args,
)
from stale_blocks_analysis.config import CHAIN_SPECS

_SPEC = CHAIN_SPECS["doichain"]
NORMALIZED_COLUMNS = [
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_bip34_height",
    "btc_nonce",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "doi_height",
    "child_block_hash",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
    "classification",
]


def standardize_row(row: dict[str, str]) -> dict[str, str]:
    """Map generic and historical Doichain rows to the shared input schema."""
    return {
        "btc_height": row.get("btc_height", ""),
        "btc_header_hash": row.get("btc_header_hash") or row.get("btc_hash", ""),
        "btc_prev_hash": row.get("btc_prev_hash", ""),
        "btc_time": row.get("btc_time", ""),
        "btc_bits": row.get("btc_bits") or row.get("btc_bits_hex", ""),
        "btc_bip34_height": row.get("btc_bip34_height", ""),
        "btc_nonce": row.get("btc_nonce", ""),
        "coinbase_scriptsig_hex": row.get("coinbase_scriptsig_hex", ""),
        "coinbase_outputs": row.get("coinbase_outputs", ""),
        "btc_header_hex": row.get("btc_header_hex", ""),
        "doi_height": row.get("doi_height") or row.get("child_height", ""),
        "child_block_hash": row.get("child_block_hash", ""),
        "child_header_hex": row.get("child_header_hex", ""),
        "child_block_time": row.get("child_block_time", ""),
        "child_nbits": row.get("child_nbits", ""),
        "classification": row.get("classification", ""),
    }


def _write_normalized_input(input_path: Path, dest_path: Path) -> int:
    """Write normalized rows and return the source row count."""
    total = 0
    with input_path.open(newline="") as src, dest_path.open("w", newline="") as dst:
        reader = csv.DictReader(src)
        writer = csv.DictWriter(dst, fieldnames=NORMALIZED_COLUMNS)
        writer.writeheader()
        for row in reader:
            total += 1
            writer.writerow(standardize_row(row))
    return total


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Classify Doichain AuxPoW parents as canonical/stale/unknown"
    )
    add_standard_output_args(parser, _SPEC)
    add_rpc_args(parser)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmpdir:
        normalized = Path(tmpdir) / "doichain-normalized.csv"
        total = _write_normalized_input(Path(args.input), normalized)
        summary = run_classifier(
            _SPEC,
            input_path=str(normalized),
            output_path=args.output,
            validated_output_path=args.validated_output,
            all_valid=True,
            all_valid_path=args.all_valid,
            keep_near=args.keep_near,
            rpc=rpc_from_args(args),
        )

    print("Doichain classification complete")
    print(f"  extracted rows: {total:,}")
    for key in (
        "btc_valid",
        "canonical",
        "stale",
        "unknown",
        "valid",
        "rejected",
        "validation_unknown",
        "output_path",
        "validated_output_path",
    ):
        if key in summary:
            print(f"  {key}: {summary[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
