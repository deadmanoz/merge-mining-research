#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from the Bitmark blockchain via RPC.

Bitmark is a hybrid 8-algo PoW chain (SHA-256d / Scrypt / Yescrypt /
Argon2d / X17 / LYRA2REv2 / Equihash / CryptoNight, all merge-mineable
since the 2018-06-07 Fork 1 activation). Only the SHA-256d branch is
considered for Bitcoin-parent recovery; the other seven branches either merge with
non-Bitcoin parents (Scrypt -> Litecoin/Dogecoin, Equihash -> Zcash,
CryptoNight -> Monero family) or are out of project scope.

Algorithm is encoded in nVersion bits 9-11 (BLOCK_VERSION_ALGO = 7 << 9):
ALGO_SCRYPT=0, ALGO_SHA256D=1, ALGO_YESCRYPT=2, ALGO_ARGON2=3, ALGO_X17=4,
ALGO_LYRA2REv2=5, ALGO_EQUIHASH=6, ALGO_CRYPTONIGHT=7 (per src/pureheader.h).
Note the SHA-256d encoding differs from Myriadcoin (where SHA-256d=0); the
ALGO_SHA256D constant below is 1 for Bitmark. The AuxPoW flag is nVersion
bit 8 (VERSION_AUXPOW = 1 << 8). We filter on both bit fields before
attempting Namecoin-style CAuxPow deserialisation.

Fork 1 activation is empirically pinned at Bitmark height 450,947
(2018-06-07 04:18:55 UTC) via boundary walk on the synced node -- the
first block where the algo bits flip from SCRYPT v4 to LYRA2REv2.
Pre-fork blocks are Scrypt-only with no AuxPoW; the extractor iterates
450,947 -> tip, skipping blocks whose algo bits indicate a non-SHA-256d
branch OR whose AuxPoW flag is not set.

fStrictChainId is true on Bitmark (chain ID 0x005B = 91) -- tighter than
Myriadcoin's permissive mode. The classifier's self-target PoW filter is only
an internal header-PoW check; downstream RPC classification establishes
Bitcoin linkage.

CPureBlockHeader serialisation is conditional on algo: Equihash blocks
have extra fields (hashReserved, nNonce256, nSolution vector) per the
Zcash layout, but SHA-256d blocks use the standard 80-byte Bitcoin
layout. Our algo filter guarantees we only parse 80-byte headers.

Output CSV schema matches the other chain extractors for pipeline
compatibility.
"""

import os
import sys

from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.config import CHAIN_SPECS

# --- Configuration ---
RPC_URL = os.environ.get("BTMK_RPC_URL", "http://127.0.0.1:9266")
RPC_USER = os.environ.get("BTMK_RPC_USER", "bitmark")
RPC_PASS = os.environ.get("BTMK_RPC_PASS", "")

VERSION_AUXPOW = 1 << 8
BLOCK_VERSION_ALGO = 7 << 9  # 3-bit algo field at nVersion[9:12]
ALGO_SHA256D = 1  # Bitmark's enum (Myriadcoin uses 0 -- these are NOT compatible)

_SPEC = CHAIN_SPECS["bitmark"]
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
    """The Bitmark RPC client, built lazily so importing this module needs no creds."""
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
        print("BTMK_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)

    extract_driver.run_standard_extractor_cli(
        argv,
        _SPEC,
        rpc=rpc(),
        gate=_gate,
        stats_keys=_STATS_KEYS,
        progress_extra=("non-sha256d", "skipped_non_sha256d"),
        description="Extract BTC AuxPoW from Bitmark (SHA-256d branch)",
        scan_prefix="Extracting AuxPoW (SHA-256d only)",
    )


if __name__ == "__main__":
    main()
