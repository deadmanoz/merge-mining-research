#!/usr/bin/env python3
"""Classify Unobtanium AuxPoW extracts as canonical, stale, or unknown.

Unobtanium extraction writes one row per merge-mined UNO block with the
embedded Bitcoin parent header and coinbase transaction. This classifier uses
the shared classifier helpers:

1. keep only unique headers that meet the Bitcoin nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

The default input/output paths point at the operator's private extraction
archive (``~/uno-extract``) rather than the committed ``data/`` tree, matching
the original Phase 3 driver. ``btc_bits`` in the UNO raw extract is already
emitted as lowercase 8-char hex (``parse_parent_header`` -> ``f"{bits:08x}"``),
so ``bits_source_is_decimal`` stays False.
"""

from __future__ import annotations

import os
import sys

# Allow direct execution from a checkout without requiring editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from stale_blocks_analysis.classifier_cli import run_standard_classifier_cli  # noqa: E402
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402

_SPEC = CHAIN_SPECS["unobtanium"]


def main() -> None:
    """Delegate to the shared thin-wrapper classifier CLI."""
    raise SystemExit(run_standard_classifier_cli(sys.argv[1:], _SPEC))


if __name__ == "__main__":
    main()
