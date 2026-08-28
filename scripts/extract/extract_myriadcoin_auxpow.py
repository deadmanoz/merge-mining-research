#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from the Myriadcoin blockchain via RPC.

Myriadcoin is a multi-algo PoW chain (SHA-256d / Scrypt / Groestl /
Yescrypt / Argon2d, with Skein and Qubit deprecated in the ~2019 hard
fork). Only the SHA-256d branch is Bitcoin-parent merge-mined; the other
four algos either merge with non-Bitcoin parents (Scrypt → Litecoin/
Dogecoin) or are native PoW.

The algorithm is encoded in nVersion bits 9-11 (BLOCK_VERSION_ALGO =
7 << 9). SHA-256d is encoded as 0 (no bits set). The AuxPoW flag is
nVersion bit 8 (VERSION_AUXPOW = 1 << 8). We filter on both bit fields
before attempting Namecoin-style CAuxPow deserialisation.

AuxPoW activates at Myriadcoin height 1,402,000 (consensus.nStartAuxPow
in src/chainparams.cpp). The extractor iterates 1,402,000 → tip, skipping
blocks whose algo bits indicate a non-SHA-256d branch OR whose AuxPoW
flag is not set.

fStrictChainId is false on Myriadcoin — the SHA-256d branch will accept
AuxPoW from any SHA-256d parent. In practice Bitcoin is the only parent
miners use, but we leave the downstream classify_auxpow_candidates.py
step to enforce parent-against-BTC-mainchain matching.

Output CSV schema matches the other chain extractors for pipeline
compatibility.
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


def main(argv: list[str] | None = None) -> None:
    """Build child RPC, keep the SHA-256d gate, and delegate CLI lifecycle."""
    if not RPC_PASS:
        print("XMY_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)

    extract_driver.run_standard_extractor_cli(
        argv,
        _SPEC,
        rpc=rpc(),
        gate=_gate,
        stats_keys=_STATS_KEYS,
        progress_extra=("non-sha256d", "skipped_non_sha256d"),
        description="Extract BTC AuxPoW from Myriadcoin (SHA-256d branch)",
        scan_prefix="Extracting AuxPoW (SHA-256d only)",
    )


if __name__ == "__main__":
    main()
