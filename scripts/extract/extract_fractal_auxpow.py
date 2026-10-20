#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from Fractal.

Proof bytes come from ``getblockheader(hash, false, true)``. Chain ID 0x2024 is required; the AuxPoW flag alone is not sufficient.
"""

import os

from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.config import CHAIN_SPECS
from stale_blocks_analysis.rpc_env import load_local_rpc_env, rpc_auth_from_env

load_local_rpc_env()

# --- Configuration ---
# fractald runs with RPC bound to 127.0.0.1:18332 on the archival host
# (defaults remapped from 8332 to avoid colliding with Bitcoin Core on the same
# host). Provide credentials via FRACTAL_RPC_USER/FRACTAL_RPC_PASSWORD or
# FRACTAL_RPC_COOKIEFILE.
RPC_URL = os.environ.get("FRACTAL_RPC_URL", "http://127.0.0.1:18332")

# Fractal's AuxPoW predicate combines the generic 0x100 flag with its 0x2024
# chain ID. The observed mainnet encoding is 0x20240100. Do not test the flag
# alone: the 0x2026 Indexer class also sets it but serializes CIndexerProof,
# not CAuxPow.
AUXPOW_FLAG = 0x100
AUXPOW_CHAIN_ID = 0x2024
CHAIN_ID_SHIFT = 16

_SPEC = CHAIN_SPECS["fractal"]
_STATS_KEYS = (
    "auxpow_blocks",
    "skipped_empty",
    "skipped_short",
    "skipped_no_auxpow_flag",
    "skipped_parse_error",
)

_rpc = None


def rpc() -> RpcClient:
    """The Fractal Bitcoin RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        user, password = rpc_auth_from_env("FRACTAL")
        _rpc = RpcClient(RPC_URL, user=user, password=password, timeout=300)
    return _rpc


def _fetch_params(block_hash: str) -> list:
    """``getblockheader <hash> false true``: compact header + AuxPoW proof,
    without full Fractal transactions."""
    return [block_hash, False, True]


def _gate(version: int, stats: dict) -> bool:
    """Keep only versions carrying Fractal chain ID 0x2024 and AuxPoW flag."""
    if not (version & AUXPOW_FLAG) or version >> CHAIN_ID_SHIFT != AUXPOW_CHAIN_ID:
        stats["skipped_no_auxpow_flag"] += 1
        return False
    return True


def main(argv: list[str] | None = None) -> None:
    """Keep the Fractal gate and delegate CLI lifecycle."""
    extract_driver.run_standard_extractor_cli(
        argv,
        _SPEC,
        rpc=rpc,
        gate=_gate,
        stats_keys=_STATS_KEYS,
        block_fetch_method="getblockheader",
        block_fetch_params=_fetch_params,
        description="Extract BTC AuxPoW from Fractal Bitcoin",
    )


if __name__ == "__main__":
    main()
