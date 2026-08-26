#!/usr/bin/env python3
"""Classify the sealed Hathor acquisition dataset into one fresh output directory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from stale_blocks_analysis.classifier_cli import add_rpc_args, rpc_from_args
from stale_blocks_analysis.hathor_classify import (
    DEFAULT_BATCH_SIZE,
    classify_hathor,
)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument(
        "--input",
        required=True,
        action="append",
        type=Path,
        help="sealed acquisition shard in ascending-range order; repeat per shard",
    )
    argument_parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="new directory for the complete classification output family",
    )
    argument_parser.add_argument(
        "--batch-size",
        type=positive_int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Bitcoin RPC classification batch size (default: {DEFAULT_BATCH_SIZE})",
    )
    add_rpc_args(argument_parser)
    return argument_parser


def main() -> None:
    args = parser().parse_args()
    report = classify_hathor(
        args.input,
        args.output_dir,
        rpc_from_args(args),
        batch_size=args.batch_size,
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
