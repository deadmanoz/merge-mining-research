#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from Myriadcoin.

SHA-256d is algo 0, the default. AuxPoW starts at height 1402000. ``fStrictChainId`` is false.
"""

import os
import sys

from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.config import CHAIN_SPECS

# --- Configuration ---
RPC_URL = os.environ.get("XMY_RPC_URL", "http://127.0.0.1:10889")
RPC_USER = os.environ.get("XMY_RPC_USER", "myriadcoin")
RPC_PASS = os.environ.get("XMY_RPC_PASS", "")

VERSION_AUXPOW = 1 << 8
BLOCK_VERSION_ALGO = 7 << 9  # 3-bit algo field at nVersion[9:12]
ALGO_SHA256D = 0

_SPEC = CHAIN_SPECS["myriadcoin"]
_STATS_KEYS = (
    "auxpow_blocks",
    "skipped_empty",
    "skipped_short",
    "skipped_non_sha256d",
    "skipped_no_auxpow_flag",
    "skipped_parse_error",
)

_rpc = None


def rpc() -> RpcClient:
    """The Myriadcoin RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        _rpc = RpcClient(RPC_URL, user=RPC_USER, password=RPC_PASS, timeout=120)
    return _rpc


def _gate(version: int, stats: dict) -> bool:
    """Keep only SHA-256d AuxPoW blocks; tally the two skip reasons."""
    algo = (version & BLOCK_VERSION_ALGO) >> 9
    if algo != ALGO_SHA256D:
        stats["skipped_non_sha256d"] += 1
        return False
    if not (version & VERSION_AUXPOW):
        stats["skipped_no_auxpow_flag"] += 1
        return False
    return True


def _require_rpc() -> RpcClient:
    if not RPC_PASS:
        print("XMY_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)
    return rpc()


def main(argv: list[str] | None = None) -> None:
    """Keep the SHA-256d gate and delegate CLI lifecycle."""
    extract_driver.run_standard_extractor_cli(
        argv,
        _SPEC,
        rpc=_require_rpc,
        gate=_gate,
        stats_keys=_STATS_KEYS,
        progress_extra=("non-sha256d", "skipped_non_sha256d"),
        description="Extract BTC AuxPoW from Myriadcoin (SHA-256d branch)",
        scan_prefix="Extracting AuxPoW (SHA-256d only)",
    )


if __name__ == "__main__":
    main()
