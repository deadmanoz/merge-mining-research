#!/usr/bin/env python3
"""Build monitor-facing full-evidence AuxPoW exports."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stale_blocks_analysis.full_evidence import (  # noqa: E402
    DATA_DIR,
    DEFAULT_OUTPUT_DIR,
    build_full_evidence_exports,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--reported-output-dir",
        type=Path,
        help=(
            "Logical final directory to record in manifests when --output-dir "
            "is a staging directory"
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
    return parser


def main() -> None:
    """Write the full-evidence exports and print the manifest summary."""
    args = build_parser().parse_args()
    summary = build_full_evidence_exports(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        reported_output_dir=args.reported_output_dir,
        chain_archive_dirs=args.chain_archive_dirs,
    )
    print(f"wrote {summary['counts_csv']}")
    print(f"wrote {summary['manifest_csv']}")
    print(f"wrote {summary['manifest_json']}")


if __name__ == "__main__":
    main()
