#!/usr/bin/env python3
"""Classify Bitmark SHA-256d AuxPoW extracts as canonical, stale, or unknown.

Bitmark extraction writes one row per merge-mined Bitmark block with the
embedded Bitcoin parent header and coinbase transaction. This classifier uses
the shared classifier helpers:

1. keep only unique headers that meet their encoded nBits target,
2. classify them against Bitcoin Core as canonical / stale / unknown, and
3. validate stale nBits against the canonical Bitcoin epoch target.

Bitmark is multi-algo (only the SHA-256d branch is in this Bitcoin-parent study);
that branch selection is an extractor concern, so the classifier sees only
SHA-256d parent headers. Bitmark's ``fStrictChainId=true`` (chain ID 91) means
a decoded parent contains the BTMK commitment. The Phase 1 self-target PoW
filter does not establish parent identity or Bitcoin's contemporaneous target.

RPC is special for Bitmark: the node lives behind a configurable endpoint, so
``--rpc-url`` defaults from the ``BTC_RPC_URL`` env var (via the shared
``add_rpc_args``/``rpc_from_args`` helpers, which already build a
``requests``-backed client with a 120s timeout -- the same shape this script
used to hand-roll). Auth resolves through the shared ``get_btc_auth``
(cookie/conf, honouring the ``BITCOIN_RPC_USER`` / ``BITCOIN_RPC_PASSWORD``
env override, or explicit ``--rpc-user``/``--rpc-pass``).

``btc_bits`` in the BTMK raw extract is already emitted as lowercase 8-char hex
(``parse_parent_header`` -> ``f"{bits:08x}"``; the committed
``data/validated-stales/bitmark_validated_stales.csv`` carries e.g. ``172e5b50``), so
``bits_source_is_decimal`` stays False.
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
