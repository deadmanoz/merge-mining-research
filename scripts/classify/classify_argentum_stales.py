#!/usr/bin/env python3
"""Classify Argentum SHA-256d AuxPoW extracts as canonical, stale, or unknown.

Argentum is a multi-algo PoW chain (Scrypt + SHA-256d + 4 native algos
post-2018-03 fork). Only the SHA-256d branch is Bitcoin-parent merge-mined;
extract_argentum_auxpow.py has already filtered to SHA-256d-only by the time
we get here, so the algo selection is purely an extractor concern. The
classifier just consumes BTC parent-header rows and runs the shared helpers:

1. keep only unique headers that meet their encoded nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

Argentum's ``fStrictChainId=false`` means the SHA-256d branch technically
accepts AuxPoW from any SHA-256d parent. The self-target PoW filter does not
identify the parent; the RPC classification step decides whether the
header actually belongs to Bitcoin, and the nBits gate defends against post-2017
BCH/BSV-family parent-header contamination.
"""

from __future__ import annotations

import os
import sys

# Allow direct execution from a checkout without requiring editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from stale_blocks_analysis.classifier_cli import run_standard_classifier_cli  # noqa: E402
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402

_SPEC = CHAIN_SPECS["argentum"]


def main() -> None:
    """Delegate to the shared thin-wrapper classifier CLI."""
    raise SystemExit(run_standard_classifier_cli(sys.argv[1:], _SPEC))


if __name__ == "__main__":
    main()
