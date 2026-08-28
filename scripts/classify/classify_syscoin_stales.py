#!/usr/bin/env python3
"""Classify Syscoin AuxPoW extracts as canonical, stale, or unknown.

Syscoin extraction writes one row per merge-mined Syscoin block with the
embedded Bitcoin parent header and coinbase transaction, in the canonical
classifier input schema (``btc_header_hex`` / ``btc_header_hash`` / ``btc_bits``
plus the ``sys_height`` provenance column). This wrapper runs the shared
classifier helpers:

1. keep only unique headers that meet the Bitcoin nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

The nBits validation gate is non-skippable: it marks parent headers that share a
BTC ancestor but use an easier (non-BTC) target as REJECTED rather than counting
them as BTC stales.

Syscoin has no chain-specific input handling -- the raw extract already uses the
shared schema -- so this is a plain ``run_classifier`` wrapper. It exposes
``--validated-output`` so the committed VALID-only loader CSV can be written to
an explicit path, and keeps the historical ``--input`` default of
``data/auxpow_raw.csv``.
"""

from __future__ import annotations

import os
import sys

# Allow direct execution from a checkout without requiring editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from stale_blocks_analysis.classifier_cli import run_standard_classifier_cli  # noqa: E402
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402

_SPEC = CHAIN_SPECS["syscoin"]


def main() -> None:
    """Delegate to the shared thin-wrapper classifier CLI."""
    raise SystemExit(run_standard_classifier_cli(sys.argv[1:], _SPEC))


if __name__ == "__main__":
    main()
