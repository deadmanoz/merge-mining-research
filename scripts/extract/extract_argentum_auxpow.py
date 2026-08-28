#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from the Argentum blockchain via RPC.

Argentum is a multi-algo PoW chain:
  - pre-2018-03 fork: Scrypt + SHA-256d only
  - post-fork (height >= 2,977,000): Scrypt + SHA-256d + Lyra2REv2 +
    Myriad-Groestl + Argon2d + Yescrypt

Only the SHA-256d branch is Bitcoin-parent merge-mined; Scrypt
merge-mines with Litecoin/Dogecoin (out of scope; only Bitcoin-parent
AuxPoW is in scope here) and the four post-fork native algos have no
AuxPoW.

Algorithm encoding (src/primitives/pureheader.h, dbkeys/argentum):

    BLOCK_VERSION_ALGO     = (7 << 9)   == 0x0E00
    BLOCK_VERSION_SHA256D  = (1 << 9)   == 0x0200    <- in-scope filter
    BLOCK_VERSION_LYRA2RE2 = (2 << 9)   == 0x0400
    BLOCK_VERSION_GROESTL  = (3 << 9)   == 0x0600
    BLOCK_VERSION_ARGON2D  = (4 << 9)   == 0x0800
    BLOCK_VERSION_YESCRYPT = (5 << 9)   == 0x0A00
    # ALGO_SCRYPT == 0 (no bits set; default case in GetAlgo())

  NOTE: this differs from Myriadcoin, where SHA-256d is the *default*
  (algo == 0). In Argentum SHA-256d is explicit (1<<9) and Scrypt is
  the default. The Argentum filter is therefore
      (nVersion & BLOCK_VERSION_ALGO) == BLOCK_VERSION_SHA256D
  NOT the Myriadcoin-style `algo == 0`.

AuxPoW flag (`VERSION_AUXPOW = 1 << 8`, bit 8 of nVersion) must also
be set. We filter on both fields before attempting Namecoin-style
CAuxPow deserialisation.

AuxPoW activates at Argentum height 1,825,000
(consensus.nStartAuxPow in src/chainparams.cpp; exact wall-clock date
derivable from the block-1825000 timestamp). The extractor iterates
1,825,000 -> tip, skipping blocks whose algo bits indicate a
non-SHA-256d branch OR whose AuxPoW flag is not set.

fStrictChainId is false on Argentum (identical to Myriadcoin) — the
SHA-256d branch will accept AuxPoW from any SHA-256d parent. In
practice Bitcoin is the only economically rational parent (the live
SHA-256d difficulty is ~4.3e10, requiring real BTC-scale hashrate),
but the downstream classify_*_candidates.py step is what enforces
parent-against-BTC-mainchain matching.

Output CSV schema matches the other chain extractors for pipeline
compatibility.
"""

import os
import sys

from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.child_rpc import RpcClient

# --- Configuration ---
RPC_URL = os.environ.get("ARG_RPC_URL", "http://127.0.0.1:13581")
RPC_USER = os.environ.get("ARG_RPC_USER", "argentum")
RPC_PASS = os.environ.get("ARG_RPC_PASS", "")

VERSION_AUXPOW = 1 << 8
BLOCK_VERSION_ALGO = 7 << 9  # 3-bit algo field at nVersion[9:12]
BLOCK_VERSION_SHA256D = 1 << 9  # ARG: SHA-256d == 0x0200 (NOT the default)

# Matches CHAIN_SPECS["argentum"] without importing config (mkdir side effects).
HEIGHT_COLUMN = "arg_height"
ACTIVATION_HEIGHT = 1_825_000
DEFAULT_OUTPUT = "data/argentum_auxpow_raw.csv"
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
    """The Argentum RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        _rpc = RpcClient(RPC_URL, user=RPC_USER, password=RPC_PASS, timeout=120)
    return _rpc


def _gate(version: int, stats: dict) -> bool:
    """Keep only SHA-256d AuxPoW blocks; tally the two skip reasons."""
    if (version & BLOCK_VERSION_ALGO) != BLOCK_VERSION_SHA256D:
        stats["skipped_non_sha256d"] += 1
        return False
    if not (version & VERSION_AUXPOW):
        stats["skipped_no_auxpow_flag"] += 1
        return False
    return True


def _require_rpc() -> RpcClient:
    if not RPC_PASS:
        print("ARG_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)
    return rpc()


def main(argv: list[str] | None = None) -> None:
    """Keep the SHA-256d gate and delegate CLI lifecycle."""
    extract_driver.run_standard_extractor_cli(
        argv,
        height_column=HEIGHT_COLUMN,
        activation_height=ACTIVATION_HEIGHT,
        output_default=DEFAULT_OUTPUT,
        rpc=_require_rpc,
        gate=_gate,
        stats_keys=_STATS_KEYS,
        progress_extra=("non-sha256d", "skipped_non_sha256d"),
        description="Extract BTC AuxPoW from Argentum (SHA-256d branch)",
        scan_prefix="Extracting AuxPoW (SHA-256d only)",
    )


if __name__ == "__main__":
    main()
