#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from the Fractal Bitcoin blockchain via RPC.

Fractal is a Bitcoin Core fork, but unlike Syscoin/Elastos/Terracoin its
`getblock <hash> 1` JSON output does NOT include a decoded `auxpow`
object. The CAuxPow proof is reachable via the `auxpow` boolean third
argument to `getblockheader`: passing `(hash, false, true)` returns
hex-serialised header data with the AuxPoW proof appended after the
80-byte FB header, in the standard Namecoin-style CAuxPow binary layout.

We therefore use the same compact header-hex + binary parse approach as
`extract_unobtanium_auxpow.py`, with two Fractal-specific adjustments:

  1. The RPC call is `getblockheader <hash> false true`
     (non-verbose, auxpow=true).
  2. Fractal Bitcoin's Cadence Mining assigns work across block classes. Only
     chain ID 0x2024 with the 0x100 AuxPoW flag carries CAuxPow. The Indexer
     class encoding 0x20260100 also sets that flag, so the flag is not
     sufficient without the chain ID.

AuxPoW is permitted on the post-genesis chain. The scan starts at FB height 1;
height 1 is non-AuxPoW and height 2 is the first observed AuxPoW block. The
version gate decides the proof format per block.

Output CSV schema matches the other chain extractors for pipeline
compatibility.
"""

import argparse
import os
from pathlib import Path


# Repo `src/` is on sys.path when installed via `pip install -e .`; these
# shared modules are pure-stdlib and safe to import on the archival host.
from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.auxpow_parse import parse_parent_header
from stale_blocks_analysis.bitcoin_binary import format_outputs_pkhex
from stale_blocks_analysis.coinbase_markers import parse_bip34_height
from stale_blocks_analysis.rpc_env import load_local_rpc_env, rpc_auth_from_env

load_local_rpc_env()

# --- Configuration ---
# fractald runs with RPC bound to 127.0.0.1:18332 on the archival host
# (defaults remapped from 8332 to avoid colliding with Bitcoin Core on the same
# host). Provide credentials via FRACTAL_RPC_USER/FRACTAL_RPC_PASSWORD or
# FRACTAL_RPC_COOKIEFILE.
RPC_URL = os.environ.get("FRACTAL_RPC_URL", "http://127.0.0.1:18332")

DEFAULT_SCAN_START_HEIGHT = 1
# Fractal's AuxPoW predicate combines the generic 0x100 flag with its 0x2024
# chain ID. The observed mainnet encoding is 0x20240100. Do not test the flag
# alone: the 0x2026 Indexer class also sets it but serializes CIndexerProof,
# not CAuxPow.
AUXPOW_FLAG = 0x100
AUXPOW_CHAIN_ID = 0x2024
CHAIN_ID_SHIFT = 16
BATCH_SIZE = 100
PROGRESS_INTERVAL = 10_000
DEFAULT_OUTPUT = "data/fractal_auxpow_raw.csv"

CSV_COLUMNS = [
    "fb_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_height",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
]


# ---------------------------------------------------------------------------
# RPC
# ---------------------------------------------------------------------------

_rpc = None


def rpc() -> RpcClient:
    """The Fractal Bitcoin RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        user, password = rpc_auth_from_env("FRACTAL")
        _rpc = RpcClient(RPC_URL, user=user, password=password, timeout=300)
    return _rpc


def get_chain_tip() -> int:
    """Return the current Fractal Bitcoin chain tip height via ``getblockcount``."""
    return extract_driver.get_chain_tip(rpc())


def _fetch_params(block_hash: str) -> list:
    """``getblockheader <hash> false true``: compact header + AuxPoW proof,
    without full Fractal transactions."""
    return [block_hash, False, True]


# ---------------------------------------------------------------------------
# Extraction hooks (the gate and the block-to-row parse are the only parts
# that differ from the shared ``extract_driver.run_extraction`` loop; see
# that module for the batched getblockhash/getblockheader, retry, resume, and
# progress/summary logic this used to duplicate).
# ---------------------------------------------------------------------------


def _gate(version: int, stats: dict) -> bool:
    """Keep only versions carrying Fractal chain ID 0x2024 and AuxPoW flag."""
    if not (version & AUXPOW_FLAG) or version >> CHAIN_ID_SHIFT != AUXPOW_CHAIN_ID:
        stats["skipped_no_auxpow_flag"] += 1
        return False
    return True


def _parse_row(height: int, auxpow: dict) -> dict:
    """Build one CSV row from a parsed CAuxPow structure."""
    parent = parse_parent_header(auxpow["parent_header_raw"])
    tx = auxpow["coinbase_tx"]
    scriptsig = tx["vin"][0]["scriptsig"] if tx["vin"] else b""
    btc_height = parse_bip34_height(scriptsig)
    return {
        "fb_height": height,
        "btc_header_hash": parent["hash"],
        "btc_prev_hash": parent["prev_hash"],
        "btc_time": parent["time"],
        "btc_bits": parent["bits_hex"],
        "btc_height": btc_height if btc_height is not None else "",
        "coinbase_scriptsig_hex": scriptsig.hex(),
        "coinbase_outputs": format_outputs_pkhex(tx["vout"]),
        "btc_header_hex": parent["header_hex"],
    }


def main():
    """Parse CLI args, extract Fractal Bitcoin's AuxPoW range in batches,
    and write the output CSV.

    Resolves ``--end`` to the current chain tip when omitted, resumes from
    the last recorded height in an existing output file when ``--resume``
    is set, retries a failed batch one block at a time before giving up on
    it, and prints periodic progress/ETA plus a final per-``stats``-key
    summary.
    """
    ap = argparse.ArgumentParser(description="Extract BTC AuxPoW from Fractal Bitcoin")
    ap.add_argument("--start", type=int, default=DEFAULT_SCAN_START_HEIGHT)
    ap.add_argument("--end", type=int, default=None, help="Exclusive")
    ap.add_argument("--output", default=DEFAULT_OUTPUT)
    ap.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    if args.end is None:
        args.end = get_chain_tip() + 1
        print(f"Chain tip: {args.end - 1}")

    start = args.start
    out_path = Path(args.output)
    if args.resume and out_path.exists():
        resumed = extract_driver.resume_start(out_path, "fb_height", args.start)
        if resumed > args.start:
            start = resumed
            print(f"Resuming from height {start}")

    total = args.end - start
    print(f"Extracting AuxPoW: {start:,} → {args.end - 1:,} ({total:,} blocks)")

    stats = {
        "auxpow_blocks": 0,
        "skipped_empty": 0,
        "skipped_short": 0,
        "skipped_no_auxpow_flag": 0,
        "skipped_parse_error": 0,
    }
    append = args.resume and out_path.exists() and start > args.start

    extract_driver.run_extraction(
        rpc=rpc(),
        start=start,
        end=args.end,
        batch_size=args.batch_size,
        output_path=out_path,
        csv_columns=CSV_COLUMNS,
        gate=_gate,
        parse_row=_parse_row,
        stats=stats,
        append=append,
        block_fetch_method="getblockheader",
        block_fetch_params=_fetch_params,
        progress_interval=PROGRESS_INTERVAL,
    )


if __name__ == "__main__":
    main()
