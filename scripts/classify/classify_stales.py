#!/usr/bin/env python3
"""Classify a thin AuxPoW chain as canonical, stale, or unknown.

Canonical entry for the 13 thin ``run_classifier`` chains. Pass ``--chain``
with a ``CHAIN_SPECS`` key. Huntercoin, emercoin, doichain, RSK, Hathor, and
the bespoke classifiers are not accepted here.

Direct-from-checkout: this script inserts ``<repo>/src`` on ``sys.path``
before importing the package, matching the existing classify wrappers.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from stale_blocks_analysis.classifier_cli import (  # noqa: E402
    THIN_CLASSIFIER_CHAINS,
    add_rpc_args,
    add_standard_output_args,
    cli_path_overrides,
    run_standard_classifier_cli,
)
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402


def _build_parser(chain: str | None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Classify a thin AuxPoW chain as stale/unknown"
    )
    parser.add_argument(
        "--chain",
        required=True,
        choices=sorted(THIN_CLASSIFIER_CHAINS),
        help="CHAIN_SPECS key for a thin run_classifier chain",
    )
    if chain in THIN_CLASSIFIER_CHAINS:
        spec = CHAIN_SPECS[chain]
        add_standard_output_args(parser, spec, **cli_path_overrides(spec.key))
    else:
        parser.add_argument("--input", help="Input CSV from extraction")
        parser.add_argument("--output", help="Output CSV with stale/unknown blocks")
        parser.add_argument(
            "--validated-output",
            help="Output CSV with validated stale blocks only",
        )
        parser.add_argument(
            "--all-valid",
            help="Output CSV with all self-target-PoW-valid headers",
        )
        parser.add_argument(
            "--keep-near",
            action="store_true",
            help="Also retain headers that fail their encoded self-target",
        )
    add_rpc_args(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--chain")
    pre_args, rest = pre.parse_known_args(argv)
    parser = _build_parser(pre_args.chain)
    if "-h" in argv or "--help" in argv:
        parser.parse_args(argv)
        return 0
    if pre_args.chain not in THIN_CLASSIFIER_CHAINS:
        parser.parse_args(argv)
        return 2
    spec = CHAIN_SPECS[pre_args.chain]
    return run_standard_classifier_cli(rest, spec)


if __name__ == "__main__":
    raise SystemExit(main())
