#!/usr/bin/env python3
"""Classify Huntercoin AuxPoW parent headers against Bitcoin Core.

Huntercoin's extractor emits all SHA-256d-branch AuxPoW parent headers. Most
of those headers satisfy only Huntercoin's child-chain target, not Bitcoin's
full target. Classification now uses the shared classifier helpers
(``run_classifier``), with a thin per-chain ``main()`` that preserves the one
Huntercoin-specific input concern the shared driver does not know about:

  1. A chain-id pre-filter that keeps only ``chain_id == 6`` (the SHA-256d /
     BTC branch) and drops ``chain_id == 2`` (Scrypt / LTC). The extractor
     already filters to chain_id 6, so this is a defensive validation of the
     refreshed raw input.

``main()`` requires the refreshed raw extraction, writes a normalized/filtered
temp CSV, and hands that to ``run_classifier`` for the Phase 1 PoW filter,
Phase 2 Bitcoin Core classification, and the non-skippable Phase 3 nBits gate.

The primary output is ``data/huntercoin_stale_blocks.csv`` in the shared
unknown-inventory schema. The stale-only loader input
(``data/validated-stales/huntercoin_validated_stales.csv``) is written by the same driver. The
redundant unknown shortcut sidecar was removed once the full inventory's
standard schema landed — the 29 unknown rows live in the full inventory under
``classification == "unknown"``.
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

DEFAULT_INPUT = REPO_ROOT / "data" / "huntercoin_auxpow_raw.csv"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "huntercoin_stale_blocks.csv"
DEFAULT_VALIDATED_OUTPUT = (
    REPO_ROOT / "data" / "validated-stales" / "huntercoin_validated_stales.csv"
)

# Bitcoin Core RPC

BATCH_SIZE = 200

# Columns of the normalized/filtered temp CSV handed to ``run_classifier``.
# These are the input columns the shared Phase 1/2 pipeline reads
# (``btc_header_hex`` / ``btc_header_hash`` / ``btc_prev_hash`` / ``btc_bits`` /
# ``btc_time`` / coinbase fields) plus the per-chain ``huc_height`` carried
# through to the output. ``run_classifier`` derives the output schema itself.
NORMALIZED_COLUMNS = [
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "huc_height",
    "child_block_hash",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
    "classification",
]

# ── input normalization + chain-id filter ─────────────────────────────────


def standardize_row(row: dict[str, str]) -> dict[str, str]:
    """Project refreshed extractor rows onto the shared classifier schema."""
    return {
        "btc_height": row.get("btc_height", ""),
        "btc_header_hash": row.get("btc_header_hash", ""),
        "btc_prev_hash": row.get("btc_prev_hash", ""),
        "btc_time": row.get("btc_time", ""),
        "btc_bits": row.get("btc_bits", ""),
        "coinbase_scriptsig_hex": row.get("coinbase_scriptsig_hex", ""),
        "coinbase_outputs": row.get("coinbase_outputs", ""),
        "btc_header_hex": row.get("btc_header_hex", ""),
        "huc_height": row.get("huc_height", ""),
        "child_block_hash": row.get("child_block_hash", ""),
        "child_header_hex": row.get("child_header_hex", ""),
        "child_block_time": row.get("child_block_time", ""),
        "child_nbits": row.get("child_nbits", ""),
        "classification": row.get("classification", ""),
    }


def _write_normalized_input(input_path: Path, dest_path: Path) -> tuple[int, int]:
    """Normalize + chain-id-filter ``input_path`` into ``dest_path``.

    Drops ``chain_id`` rows that are present but not the SHA-256d branch
    (``chain_id == 6``) and rewrites every surviving row through
    ``standardize_row`` before ``run_classifier`` reads the file. Returns
    ``(total_rows, skipped_chain)``.
    """
    total = 0
    skipped_chain = 0
    with input_path.open(newline="") as src, dest_path.open("w", newline="") as dst:
        reader = csv.DictReader(src)
        writer = csv.DictWriter(
            dst, fieldnames=NORMALIZED_COLUMNS, extrasaction="ignore"
        )
        writer.writeheader()
        for row in reader:
            total += 1
            if row.get("chain_id") and row["chain_id"] != "6":
                skipped_chain += 1
                continue
            writer.writerow(standardize_row(row))
    return total, skipped_chain


def main() -> int:
    """Run the classifier CLI over the extracted candidate CSV."""
    parser = argparse.ArgumentParser(
        description="Classify Huntercoin AuxPoW parent headers as stale / unknown"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
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

    if not args.input.is_file():
        raise SystemExit(
            "missing refreshed Huntercoin extractor input: "
            f"{args.input}; run scripts/extract/extract_huntercoin_auxpow.py"
        )

    rpc = rpc_from_args(args)

    # Pre-process the refreshed input, then hand the normalized temp CSV to the
    # shared classifier helpers. The
    # extractor's raw btc_bits is already lowercase 8-char hex (parent.bits_hex),
    # so the input artifact is hex, not decimal.
    print(f"Reading {args.input}…")
    with tempfile.TemporaryDirectory() as tmpdir:
        normalized = Path(tmpdir) / "huntercoin_normalized.csv"
        total, skipped_chain = _write_normalized_input(args.input, normalized)
        print(f"  Total rows scanned:    {total:,}")
        print(f"  Dropped chain_id != 6:  {skipped_chain:,}")

        summary = run_classifier(
            CHAIN_SPECS["huntercoin"],
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
