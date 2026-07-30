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

import argparse
import os
import sys
from pathlib import Path


from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.auxpow_parse import (
    parse_coinbase_height,
    parse_parent_header,
    standard_auxpow_extraction_columns,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_pkhex

# --- Configuration ---
RPC_URL = os.environ.get("UNO_RPC_URL", "http://127.0.0.1:65535")
RPC_USER = os.environ.get("UNO_RPC_USER", "uno")
RPC_PASS = os.environ.get("UNO_RPC_PASS", "")

FIRST_AUXPOW_HEIGHT = 600_000
VERSION_AUXPOW = 1 << 8
BATCH_SIZE = 100
PROGRESS_INTERVAL = 10_000

CSV_COLUMNS = standard_auxpow_extraction_columns("uno_height")


# ---------------------------------------------------------------------------
# RPC
# ---------------------------------------------------------------------------

_rpc = None


def rpc() -> RpcClient:
    """The Unobtanium RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        _rpc = RpcClient(RPC_URL, user=RPC_USER, password=RPC_PASS, timeout=120)
    return _rpc


def get_chain_tip() -> int:
    """Return the current Unobtanium chain tip height via ``getblockcount``."""
    return extract_driver.get_chain_tip(rpc())


# ---------------------------------------------------------------------------
# Extraction hooks (the gate and the block-to-row parse are the only parts
# that differ from the shared ``extract_driver.run_extraction`` loop; see
# that module for the batched getblockhash/getblock, retry, resume, and
# progress/summary logic this used to duplicate).
# ---------------------------------------------------------------------------


def _gate(version: int, stats: dict) -> bool:
    """Keep only AuxPoW-flagged blocks."""
    if not (version & VERSION_AUXPOW):
        stats["skipped_no_auxpow_flag"] += 1
        return False
    return True


def _parse_row(height: int, auxpow: dict, child_fields: dict) -> dict:
    """Build one CSV row from a parsed CAuxPow structure."""
    parent = parse_parent_header(auxpow["parent_header_raw"])
    tx = auxpow["coinbase_tx"]
    scriptsig = tx["vin"][0]["scriptsig"] if tx["vin"] else b""
    btc_height = parse_coinbase_height(scriptsig)
    return {
        "uno_height": height,
        **child_fields,
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
    """Parse CLI args, extract Unobtanium's AuxPoW range in batches, and
    write the output CSV.

    Resolves ``--end`` to the current chain tip when omitted, resumes from
    the last recorded height in an existing output file when ``--resume``
    is set, retries a failed batch one block at a time before giving up on
    it, and prints periodic progress/ETA plus a final per-``stats``-key
    summary. Exits with status 2 if the RPC password env var is unset.
    """
    ap = argparse.ArgumentParser(description="Extract BTC AuxPoW from Unobtanium")
    ap.add_argument("--start", type=int, default=FIRST_AUXPOW_HEIGHT)
    ap.add_argument("--end", type=int, default=None, help="Exclusive")
    ap.add_argument("--output", default="data/unobtanium_auxpow_raw.csv")
    ap.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    if not RPC_PASS:
        print("UNO_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)

    if args.end is None:
        args.end = get_chain_tip() + 1
        print(f"Chain tip: {args.end - 1}")

    start = args.start
    out_path = Path(args.output)
    if args.resume and out_path.exists():
        resumed = extract_driver.resume_start(out_path, "uno_height", args.start)
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
        progress_interval=PROGRESS_INTERVAL,
    )


if __name__ == "__main__":
    main()
