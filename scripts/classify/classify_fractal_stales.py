#!/usr/bin/env python3
"""Classify Fractal Bitcoin AuxPoW extracts as canonical, stale, or unknown.

Fractal extraction writes one row per merge-mined Fractal block with the
embedded Bitcoin parent header and coinbase transaction. This classifier uses
the shared classifier helpers:

1. keep only unique headers that meet their encoded self-target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. apply the shared available-evidence publication gate to stale candidates.

The first gate does not establish Bitcoin's contemporaneous target. The
publication gate corroborates expected nBits and the other header-context and
coinbase checks available from Fractal's full CAuxPow proof. This matters
because Fractal is post-BCH/BSV and the project treats post-2017 parent-header
contamination defensively.
"""

from __future__ import annotations

import os
import sys

# Allow direct execution from a checkout without requiring editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from stale_blocks_analysis.classifier_cli import run_standard_classifier_cli  # noqa: E402
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402

_SPEC = CHAIN_SPECS["fractal"]


def main() -> None:
    """Delegate to the shared thin-wrapper classifier CLI."""
    raise SystemExit(run_standard_classifier_cli(sys.argv[1:], _SPEC))


if __name__ == "__main__":
    main()
