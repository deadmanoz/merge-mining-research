#!/usr/bin/env python3
"""Classify Devcoin AuxPoW extracts as canonical, stale, or unknown.

Devcoin extraction writes one row per merge-mined Devcoin block with the
embedded Bitcoin parent header and coinbase transaction. This classifier uses
the shared classifier helpers:

1. keep only unique headers that meet the Bitcoin nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

With ``--keep-near`` the self-target-PoW-failing headers the standard run drops are
retained to ``data/devcoin_near_blocks.csv`` as sibling evidence for
shared-parent multi-block fork detection. This replaces the former bespoke
``classify_devcoin_all.py`` (which emitted stale + unknown + near into one file);
near rows now live in their own split file on the shared schema.
"""

from __future__ import annotations

import os
import sys

# Allow direct execution from a checkout without requiring editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from stale_blocks_analysis.classifier_cli import run_standard_classifier_cli  # noqa: E402
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402

_SPEC = CHAIN_SPECS["devcoin"]


def main() -> None:
    """Delegate to the shared thin-wrapper classifier CLI."""
    raise SystemExit(run_standard_classifier_cli(sys.argv[1:], _SPEC))


if __name__ == "__main__":
    main()
