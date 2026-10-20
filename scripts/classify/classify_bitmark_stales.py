#!/usr/bin/env python3
"""Classify Bitmark SHA-256d AuxPoW extracts as canonical, stale, or unknown.

SHA-256d is algo 1, not Myriadcoin's 0. ``fStrictChainId`` is true (chain ID 91). ``btc_bits`` is already 8-char hex.
"""

from __future__ import annotations

import os
import sys

# Allow direct execution from a checkout without requiring editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from stale_blocks_analysis.classifier_cli import run_standard_classifier_cli  # noqa: E402
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402

_SPEC = CHAIN_SPECS["bitmark"]


def main() -> None:
    """Delegate to the shared thin-wrapper classifier CLI."""
    raise SystemExit(run_standard_classifier_cli(sys.argv[1:], _SPEC))


if __name__ == "__main__":
    main()
