#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from the Crown blockchain via RPC.

Crown (CRW) is a 2014 Bitcoin/Dash-derived chain with SHA-256d AuxPoW
(standard Namecoin / Daniel Kraft lineage, chain ID 20, fStrictChainId
true). AuxPoW activates at Crown height 453,273. Crown went PoS-hybrid
at height 2,330,000 — PoS blocks carry no AuxPoW. In the PoS era the
chain-ID field in nVersion also rotated from 20 (0x14) to 22 (0x16),
but that is irrelevant here: PoS blocks never have the AuxPoW flag set.

Crown is single-algo (SHA-256d) so there is no per-algo filter — unlike
Myriadcoin/Argentum. The only gate is the AuxPoW flag.

nVersion layout (Namecoin-style):
    bits 0-7   : base version
    bit  8     : VERSION_AUXPOW (1 << 8) — AuxPoW present
    bits 16+   : chain ID (20 for Crown's PoW era; 22 in the PoS era)

Observed in practice (probed 2026-05-20):
    h 453,273          version 0x00140002  PoW  auxbit 0  (activation block, pre-merge)
    h 460,000-2,330,000 version 0x00140102 PoW  auxbit 1  (merge-mined — in scope)
    h 2,330,001+       version 0x0016xxxx  PoS  auxbit 0  (PoS-hybrid era)

The extractor iterates 453,273 -> tip, skips any block whose AuxPoW flag
is clear (covers both the pre-merge-mining PoW blocks and the entire
PoS era), and parses the Namecoin-style CAuxPow tail for the rest.

getblock does NOT expose a decoded `auxpow` JSON field on Crown's RPC,
so we fetch raw block hex (`getblock <hash> false`) and parse the
CAuxPow binary directly — same approach as Devcoin / Myriadcoin /
Argentum.

Output CSV schema matches the other chain extractors for pipeline
compatibility.
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


def main(argv: list[str] | None = None) -> None:
    """Build child RPC, keep the AuxPoW-flag gate, and delegate CLI lifecycle."""
    if not RPC_PASS:
        print("CRW_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)

    extract_driver.run_standard_extractor_cli(
        argv,
        _SPEC,
        rpc=rpc(),
        gate=_gate,
        stats_keys=_STATS_KEYS,
        progress_extra=("no-flag", "skipped_no_auxpow_flag"),
        description="Extract BTC AuxPoW from Crown",
    )


if __name__ == "__main__":
    main()
