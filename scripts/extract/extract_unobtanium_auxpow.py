#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from the Unobtanium blockchain via RPC.

Unobtanium is a Bitcoin Core 0.11 fork; its JSON-RPC `getblock <hash> 1`
does NOT decode the embedded CAuxPow into JSON the way Syscoin/Elastos do.
So we fetch raw block hex via `getblock <hash> 0` and parse the Namecoin-
style AuxPoW binary in Python, reusing the same primitives as
`extract_auxpow_from_blkdat.py`.

AuxPoW activates at UNO height 600,000 but the first AuxPoW block in
practice is a few hundred higher (miners transitioned gradually).
The extractor iterates 600,000 → tip, skipping blocks whose version
does not have the AuxPoW flag set (bit 0x100).

Output CSV schema matches the other chain extractors for pipeline
compatibility.
"""

import os
import sys

from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.config import CHAIN_SPECS

# --- Configuration ---
RPC_URL = os.environ.get("UNO_RPC_URL", "http://127.0.0.1:65535")
RPC_USER = os.environ.get("UNO_RPC_USER", "uno")
RPC_PASS = os.environ.get("UNO_RPC_PASS", "")

VERSION_AUXPOW = 1 << 8

_SPEC = CHAIN_SPECS["unobtanium"]
_STATS_KEYS = (
    "auxpow_blocks",
    "skipped_empty",
    "skipped_short",
    "skipped_no_auxpow_flag",
    "skipped_parse_error",
)

_rpc = None


def rpc() -> RpcClient:
    """The Unobtanium RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        _rpc = RpcClient(RPC_URL, user=RPC_USER, password=RPC_PASS, timeout=120)
    return _rpc


def _gate(version: int, stats: dict) -> bool:
    """Keep only AuxPoW-flagged blocks."""
    if not (version & VERSION_AUXPOW):
        stats["skipped_no_auxpow_flag"] += 1
        return False
    return True


def main(argv: list[str] | None = None) -> None:
    """Build child RPC, keep the AuxPoW-flag gate, and delegate CLI lifecycle."""
    if not RPC_PASS:
        print("UNO_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)

    extract_driver.run_standard_extractor_cli(
        argv,
        _SPEC,
        rpc=rpc(),
        gate=_gate,
        stats_keys=_STATS_KEYS,
        description="Extract BTC AuxPoW from Unobtanium",
    )


if __name__ == "__main__":
    main()
