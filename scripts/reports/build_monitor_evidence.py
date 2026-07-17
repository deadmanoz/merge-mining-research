#!/usr/bin/env python3
"""Build compact monitor-facing evidence exports.

Filters the normalized evidence to the categories the merge-mining-monitor
ingests as final — canonical rows, VALID direct stales, valid stale
descendants, and strict/weak BTC orphans — and writes per-chain CSVs plus a
counts manifest under results/monitor-evidence/. Strict/weak orphan verdicts
are joined by header hash from the relevance inventory produced by
scripts/analysis/classify_btc_stale_relevance.py.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stale_blocks_analysis.full_evidence import (  # noqa: E402
    DATA_DIR,
    DEFAULT_RELEVANCE_INVENTORY,
    MONITOR_OUTPUT_DIR,
    build_monitor_evidence_exports,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--output-dir", type=Path, default=MONITOR_OUTPUT_DIR)
    parser.add_argument(
        "--relevance-inventory",
        type=Path,
        default=DEFAULT_RELEVANCE_INVENTORY,
        help=(
            "Relevance inventory CSV supplying strict/weak orphan verdicts. "
            "When absent, unknown-classified rows are omitted and flagged in the manifest."
        ),
    )
    parser.add_argument(
        "--chain-archive-dir",
        dest="chain_archive_dirs",
        action="append",
        type=Path,
        default=[],
        help=(
            "Private chain archive root to scan for "
            "*/classified/*_stale_blocks.csv and "
            "*/validated/*_validated_stales.csv. May be repeated."
        ),
    )
    parser.add_argument(
        "--skip-canonical",
        action="store_true",
        help=(
            "Exclude canonical-parent companions so the exports stay "
            "compact (stales, valid descendants, strict/weak orphans "
            "only). This is the committed direct-stale/relevance configuration; "
            "curated canonical artifacts are produced separately."
        ),
    )
    return parser


def main() -> None:
    """Write the monitor-facing exports and print the manifest summary."""
    args = build_parser().parse_args()
    summary = build_monitor_evidence_exports(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        chain_archive_dirs=args.chain_archive_dirs,
        relevance_inventory=args.relevance_inventory,
        include_canonical=not args.skip_canonical,
    )
    print(f"wrote {summary['counts_csv']}")
    print(f"wrote {summary['manifest_json']}")
    print(f"strict/weak verdicts joined: {summary['strict_weak_verdicts_loaded']}")
    if summary["relevance_inventory"] == "missing":
        print(
            "WARNING: relevance inventory missing; unknown-classified rows omitted "
            "(run scripts/analysis/classify_btc_stale_relevance.py first)"
        )


if __name__ == "__main__":
    main()
