#!/usr/bin/env python3
"""Classify Crown SHA-256d AuxPoW extracts as canonical, stale, or unknown.

Crown (CRW) is a 2014 Bitcoin/Dash-derived chain with standard
Namecoin-style AuxPoW (chain ID 20, fStrictChainId true). AuxPoW activates at
Crown height 453,273; the chain went PoS-hybrid at 2,330,000 (PoS blocks carry
no AuxPoW and are skipped by the extractor). extract_crown_auxpow.py has already
filtered to AuxPoW-flagged blocks by the time we get here.

fStrictChainId=true prevents a parent header from using Crown's own chain ID;
it does not establish Bitcoin parent identity. This classifier runs the shared
classifier
helpers:

1. keep only unique headers that meet their encoded nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.
"""

from __future__ import annotations

import os
import sys

# Allow direct execution from a checkout without requiring editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from stale_blocks_analysis.classifier_cli import run_standard_classifier_cli  # noqa: E402
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402

_SPEC = CHAIN_SPECS["crown"]


def main() -> None:
    """Delegate to the shared thin-wrapper classifier CLI."""
    raise SystemExit(run_standard_classifier_cli(sys.argv[1:], _SPEC))


if __name__ == "__main__":
    main()
