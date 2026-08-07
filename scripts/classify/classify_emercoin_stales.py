#!/usr/bin/env python3
"""Classify Emercoin AuxPoW parent headers against Bitcoin Core.

Emercoin's extractor (``scripts/extract/extract_emercoin_auxpow.py``) emits the
AuxPoW parent header for every PoW EMC block (the PoS branch is filtered out at
extraction time via the RPC ``flags`` field, since PoS blocks carry no AuxPoW
commitment). Most of those parent headers satisfy only Emercoin's child-chain
target, not Bitcoin's full target. Classification now uses the shared classifier
helpers (``run_classifier``), with a thin per-chain ``main()`` that preserves the
one Emercoin-specific input concern the shared driver does not know about:

  A legacy-schema normalizer (``standardize_row``) that maps the original
  recovery columns (``btc_parent_hash`` / ``btc_timestamp``) onto the shared
  unknown-inventory schema. Current raw extractor output already uses the
  standard names, so this is a backward-compatibility shim for the legacy
  ``emercoin_stale_blocks.csv`` input path.

``main()`` applies that normalizer to the chosen input, writes a normalized temp
CSV, and hands it to ``run_classifier`` for the Phase 1 PoW filter, Phase 2
Bitcoin Core classification, and the non-skippable Phase 3 nBits gate.

The primary output is ``data/emercoin_stale_blocks.csv`` in the shared
unknown-inventory schema. The stale-only loader input
(``data/validated-stales/emercoin_validated_stales.csv``) is written by the same driver.
"""

from __future__ import annotations

import argparse
import csv
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from stale_blocks_analysis.btc_classify import run_classifier
from stale_blocks_analysis.classifier_cli import add_rpc_args, rpc_from_args
from stale_blocks_analysis.config import CHAIN_SPECS

DEFAULT_INPUT = REPO_ROOT / "data" / "emercoin_auxpow_raw.csv"
DEFAULT_LEGACY_INPUT = REPO_ROOT / "data" / "emercoin_stale_blocks.csv"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "emercoin_stale_blocks.csv"
DEFAULT_VALIDATED_OUTPUT = (
    REPO_ROOT / "data" / "validated-stales" / "emercoin_validated_stales.csv"
)

# Columns of the normalized temp CSV handed to ``run_classifier``. These are the
# input columns the shared Phase 1/2 pipeline reads plus the per-chain
# ``emc_height`` carried through to the output; ``run_classifier`` derives the
# output schema itself.
NORMALIZED_COLUMNS = [
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "emc_height",
    "child_block_hash",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
    "classification",
]

# ── input normalization ───────────────────────────────────────────────────


def standardize_row(row: dict[str, str]) -> dict[str, str]:
    """Map legacy extractor rows to the shared unknown-inventory schema."""
    return {
        "btc_height": row.get("btc_height", ""),
        "btc_header_hash": row.get("btc_header_hash") or row.get("btc_parent_hash", ""),
        "btc_prev_hash": row.get("btc_prev_hash", ""),
        "btc_time": row.get("btc_time") or row.get("btc_timestamp", ""),
        "btc_bits": row.get("btc_bits", ""),
        "coinbase_scriptsig_hex": row.get("coinbase_scriptsig_hex", ""),
        "coinbase_outputs": row.get("coinbase_outputs", ""),
        "btc_header_hex": row.get("btc_header_hex", ""),
        "emc_height": row.get("emc_height", ""),
        "child_block_hash": row.get("child_block_hash", ""),
        "child_header_hex": row.get("child_header_hex", ""),
        "child_block_time": row.get("child_block_time", ""),
        "child_nbits": row.get("child_nbits", ""),
        "classification": row.get("classification", ""),
    }


def _write_normalized_input(input_path: Path, dest_path: Path) -> int:
    """Normalize ``input_path`` into ``dest_path`` and return the row count.

    Rewrites every row through ``standardize_row`` so the legacy column names
    (``btc_parent_hash`` / ``btc_timestamp``) are mapped onto the shared schema
    before ``run_classifier`` reads the file. Emercoin's raw extract has no
    ``chain_id`` column (unlike the multi-branch Huntercoin extract), so there
    is no branch pre-filter here.
    """
    total = 0
    with input_path.open(newline="") as src, dest_path.open("w", newline="") as dst:
        reader = csv.DictReader(src)
        writer = csv.DictWriter(
            dst, fieldnames=NORMALIZED_COLUMNS, extrasaction="ignore"
        )
        writer.writeheader()
        for row in reader:
            total += 1
            writer.writerow(standardize_row(row))
    return total


def main() -> int:
    """Run the classifier CLI over the extracted candidate CSV."""
    parser = argparse.ArgumentParser(
        description="Classify Emercoin AuxPoW parent headers as stale / unknown"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT if DEFAULT_INPUT.exists() else DEFAULT_LEGACY_INPUT,
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--validated-output", type=Path, default=DEFAULT_VALIDATED_OUTPUT
    )
    parser.add_argument(
        "--keep-near",
        action="store_true",
        help="Also retain self-target-PoW-failing ('near') headers as sibling "
        "evidence for shared-parent fork detection",
    )
    add_rpc_args(parser)
    args = parser.parse_args()

    rpc = rpc_from_args(args)

    # Pre-process the chosen input with the legacy-schema normalizer, then hand
    # the normalized temp CSV to the shared classifier helpers. The extractor's
    # raw btc_bits is already lowercase 8-char hex, so the input is hex, not
    # decimal.
    print(f"Reading {args.input}…")
    with tempfile.TemporaryDirectory() as tmpdir:
        normalized = Path(tmpdir) / "emercoin_normalized.csv"
        total = _write_normalized_input(args.input, normalized)
        print(f"  Total rows scanned:    {total:,}")

        summary = run_classifier(
            CHAIN_SPECS["emercoin"],
            input_path=str(normalized),
            output_path=str(args.output),
            validated_output_path=str(args.validated_output),
            keep_near=args.keep_near,
            bits_source_is_decimal=False,
            rpc=rpc,
        )

    print("\n=== Summary ===")
    print(f"  BTC headers extracted: {total:,}")
    print(f"  Self-target PoW valid: {summary['btc_valid']:,}")
    print(f"  Stale:                 {summary['stale']:,}")
    print(f"  Unknown:               {summary['unknown']:,}")
    print(f"  Validated (gate VALID): {summary['valid']:,}")
    print(f"  Rejected (gate, total): {summary['rejected']:,}")
    print(f"    still stale:          {summary['rejected_stale']:,}")
    print(f"    error blocks:         {summary['rejected_error_block']:,}")
    print(f"    re-routed to unknown: {summary['rejected_unknown']:,}")
    print(f"  Output: {summary['output_path']}")
    print(f"  Validated stales: {summary['validated_output_path']}")
    if args.keep_near:
        print(f"  Near: {summary['near']}")
        print(f"  Near output: {summary['near_output_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
