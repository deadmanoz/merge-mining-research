#!/usr/bin/env python3
"""Refresh committed Bitcoin epoch reference data from public Esplora."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from stale_blocks_analysis.bitcoin_epoch_reference import (
    DEFAULT_API_BASE,
    EsploraClient,
    refresh_reference,
)
from stale_blocks_analysis.config import BITCOIN_EPOCH_REFERENCE_DIR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--output-dir", type=Path, default=BITCOIN_EPOCH_REFERENCE_DIR)
    parser.add_argument("--confirmations", type=int, default=6)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument("--retry-delay", type=float, default=1.0)
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Maximum concurrent requests during a full-history bootstrap.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    client = EsploraClient(
        api_base=args.api_base,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
    )
    manifest = refresh_reference(
        client,
        args.output_dir,
        confirmations=args.confirmations,
        workers=args.workers,
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
