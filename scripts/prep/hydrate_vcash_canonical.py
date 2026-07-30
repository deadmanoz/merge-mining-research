#!/usr/bin/env python3
"""Hydrate VCash Wayback-confirmed canonical BTC parents from Bitcoin Core.

This writes a partial canonical evidence subset only. Hash-only unknown rows are
not emitted and are not treated as recovered VCash blockchain data.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from stale_blocks_analysis.btc_rpc import BtcRpc, get_btc_auth  # noqa: E402
from stale_blocks_analysis.config import DATA_DIR  # noqa: E402
from stale_blocks_analysis.vcash_canonical import (  # noqa: E402
    build_vcash_canonical_hydration,
)


def main() -> None:
    """Hydrate the confirmed VCash mappings with full Bitcoin header evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wayback-results", type=Path, required=True)
    parser.add_argument("--canonical-classification", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=DATA_DIR / "vcash_canonical_blocks.csv",
        help="Canonical source CSV consumed by the monitor evidence builder.",
    )
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    parser.add_argument("--rpc-user")
    parser.add_argument("--rpc-pass")
    parser.add_argument("--bitcoin-conf")
    parser.add_argument("--rpc-timeout", type=float, default=30.0)
    args = parser.parse_args()

    auth = get_btc_auth(args.rpc_user, args.rpc_pass, args.bitcoin_conf)
    rpc = BtcRpc(url=args.rpc_url, auth=auth, timeout=args.rpc_timeout)
    tip = rpc.call("getblockcount")
    if not isinstance(tip, int):
        raise SystemExit(
            "Bitcoin Core RPC preflight failed: getblockcount returned no height"
        )

    summary = build_vcash_canonical_hydration(
        wayback_results_path=args.wayback_results,
        canonical_classification_path=args.canonical_classification,
        output_path=args.output,
        rpc=rpc,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
