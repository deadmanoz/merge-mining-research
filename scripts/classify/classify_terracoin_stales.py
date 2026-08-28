#!/usr/bin/env python3
"""Classify Terracoin AuxPoW extracts as canonical, stale, or unknown.

Terracoin extraction (scripts/extract/extract_terracoin_auxpow.py) writes one
row per merge-mined Terracoin block carrying the embedded Bitcoin parent header
and coinbase transaction. This classifier uses the shared classifier helpers:

1. keep only unique headers that meet the Bitcoin nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

Terracoin's only chain-specific quirk is the Dash-Core-0.12.x plural
scriptPubKey ``addresses`` array, but that is handled entirely in the extractor
(``format_outputs``); the classifier passes ``coinbase_outputs`` through
verbatim, so no chain-specific output formatting is needed here. The raw
``btc_bits`` artifact is already 8-char hex, so ``bits_source_is_decimal`` stays
False.
"""

from __future__ import annotations

import os
import sys

# Allow direct execution from a checkout without requiring editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from stale_blocks_analysis.classifier_cli import run_standard_classifier_cli  # noqa: E402
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402

_SPEC = CHAIN_SPECS["terracoin"]


def main() -> None:
    """Delegate to the shared thin-wrapper classifier CLI."""
    raise SystemExit(run_standard_classifier_cli(sys.argv[1:], _SPEC))


if __name__ == "__main__":
    main()
