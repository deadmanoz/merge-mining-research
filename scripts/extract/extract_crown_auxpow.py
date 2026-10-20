#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from Crown.

AuxPoW starts at height 453273. PoS blocks have no AuxPoW flag. ``getblock`` does not expose decoded auxpow, so the extractor parses raw block hex.
"""

import os
import sys

from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.config import CHAIN_SPECS

# --- Configuration ---
RPC_URL = os.environ.get("CRW_RPC_URL", "http://127.0.0.1:9341")
RPC_USER = os.environ.get("CRW_RPC_USER", "crw")
RPC_PASS = os.environ.get("CRW_RPC_PASS", "")

VERSION_AUXPOW = 1 << 8

_SPEC = CHAIN_SPECS["crown"]
_STATS_KEYS = (
    "auxpow_blocks",
    "skipped_empty",
    "skipped_short",
    "skipped_no_auxpow_flag",
    "skipped_parse_error",
)

_rpc = None


def rpc() -> RpcClient:
    """The Crown RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        _rpc = RpcClient(RPC_URL, user=RPC_USER, password=RPC_PASS, timeout=120)
    return _rpc


def _gate(version: int, stats: dict) -> bool:
    """Keep only AuxPoW-flagged blocks (skips pre-merge PoW and the PoS era)."""
    if not (version & VERSION_AUXPOW):
        stats["skipped_no_auxpow_flag"] += 1
        return False
    return True


def _require_rpc() -> RpcClient:
    if not RPC_PASS:
        print("CRW_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)
    return rpc()


def main(argv: list[str] | None = None) -> None:
    """Keep the AuxPoW-flag gate and delegate CLI lifecycle."""
    extract_driver.run_standard_extractor_cli(
        argv,
        _SPEC,
        rpc=_require_rpc,
        gate=_gate,
        stats_keys=_STATS_KEYS,
        progress_extra=("no-flag", "skipped_no_auxpow_flag"),
        description="Extract BTC AuxPoW from Crown",
    )


if __name__ == "__main__":
    main()
