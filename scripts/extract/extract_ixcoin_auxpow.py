#!/usr/bin/env python3
"""
Extract Bitcoin AuxPoW headers from the ixcoin blockchain.

ixcoin is a Bitcoin Core 0.14.x fork. Its `getblock` RPC accepts only a
boolean `verbose` flag and does not serialise AuxPoW into JSON. Fetch
raw block hex (`getblock <hash> false`) and parse the embedded CAuxPow
structure using the same binary layout as Namecoin / Devcoin (Vince
Durham's original specification).
"""

import argparse
import csv
import os
import struct
import time
from pathlib import Path


from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.auxpow_parse import (
    parse_coinbase_height,
    parse_parent_header,
    read_auxpow,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_pkhex
from stale_blocks_analysis.rpc_env import load_local_rpc_env, rpc_auth_from_env

load_local_rpc_env()

RPC_URL = os.environ.get("IXCOIN_RPC_URL", "http://127.0.0.1:8338")

FIRST_AUXPOW_HEIGHT = 45_001
BATCH_SIZE = 100
PROGRESS_INTERVAL = 10_000

VERSION_AUXPOW = 1 << 8

CSV_COLUMNS = [
    "ixc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_height",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
]


_rpc = None


def rpc() -> RpcClient:
    """The ixcoin RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        user, password = rpc_auth_from_env("IXCOIN")
        _rpc = RpcClient(RPC_URL, user=user, password=password, timeout=120)
    return _rpc


def get_chain_tip() -> int:
    """Return the current ixcoin chain tip height via ``getblockcount``."""
    call = [{"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}]
    return rpc().batch(call)[0]["result"]


def extract_from_block_hex(ixc_height: int, block_hex: str) -> dict | None:
    """Parse an ixcoin block's raw hex. Returns AuxPoW parent info or None."""
    raw = bytes.fromhex(block_hex)
    if len(raw) < 80:
        return None
    child_version = struct.unpack_from("<i", raw, 0)[0]
    if not (child_version & VERSION_AUXPOW):
        return None
    try:
        auxpow, _ = read_auxpow(raw, 80)
    except (IndexError, struct.error, ValueError):
        return None
    parent = parse_parent_header(auxpow["parent_header_raw"])
    tx = auxpow["coinbase_tx"]
    scriptsig = tx["vin"][0]["scriptsig"] if tx["vin"] else b""
    btc_height = parse_coinbase_height(scriptsig)
    return {
        "ixc_height": ixc_height,
        "btc_header_hash": parent["hash"],
        "btc_prev_hash": parent["prev_hash"],
        "btc_time": parent["time"],
        "btc_bits": parent["bits_hex"],
        "btc_height": btc_height if btc_height is not None else "",
        "coinbase_scriptsig_hex": scriptsig.hex(),
        "coinbase_outputs": format_outputs_pkhex(tx["vout"]),
        "btc_header_hex": parent["header_hex"],
    }


def extract_range(start: int, end: int, writer: csv.DictWriter, stats: dict):
    """Extract AuxPoW data for ixcoin heights ``[start, end)`` into CSV rows.

    Batches ``getblockhash`` then ``getblock <hash> false`` (raw hex) RPC
    calls and delegates each block to ``extract_from_block_hex``. Heights
    with no returned hex or no parseable AuxPoW are skipped and tallied
    into ``stats``; parsed rows are written immediately.
    """
    # Step 1: batch getblockhash
    hash_calls = [
        {"jsonrpc": "1.0", "id": i, "method": "getblockhash", "params": [h]}
        for i, h in enumerate(range(start, end))
    ]
    hash_results = rpc().batch(hash_calls)
    hash_results.sort(key=lambda x: x["id"])
    hashes = [r["result"] for r in hash_results]

    # Step 2: batch getblock <hash> false (raw hex) — 0.14.x accepts only bool
    block_calls = [
        {"jsonrpc": "1.0", "id": i, "method": "getblock", "params": [h, False]}
        for i, h in enumerate(hashes)
    ]
    block_results = rpc().batch(block_calls)
    block_results.sort(key=lambda x: x["id"])

    for i, br in enumerate(block_results):
        height = start + i
        block_hex = br.get("result")
        if not block_hex:
            stats["skipped_no_block"] += 1
            continue
        row = extract_from_block_hex(height, block_hex)
        if row is None:
            stats["skipped_no_auxpow"] += 1
            continue
        stats["auxpow_blocks"] += 1
        writer.writerow(row)


def main():
    """Parse CLI args, extract ixcoin's AuxPoW range in batches, and write
    the output CSV.

    Resolves ``--end`` to the current chain tip when omitted, resumes from
    the last recorded height in an existing output file when ``--resume``
    is set, retries a failed batch one block at a time before giving up on
    it, and prints periodic progress/ETA plus a final summary.
    """
    parser = argparse.ArgumentParser(description="Extract Bitcoin AuxPoW from ixcoin")
    parser.add_argument("--start", type=int, default=FIRST_AUXPOW_HEIGHT)
    parser.add_argument("--end", type=int, default=None)
    parser.add_argument("--output", type=str, default="data/ixcoin_auxpow_raw.csv")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    if args.end is None:
        args.end = get_chain_tip() + 1
        print(f"Chain tip: {args.end - 1}")

    start = args.start
    if args.resume and Path(args.output).exists():
        with open(args.output) as f:
            last_line = None
            for line in f:
                last_line = line
            if last_line and not last_line.startswith("ixc_height"):
                last_height = int(last_line.split(",")[0])
                start = last_height + 1
                print(f"Resuming from height {start}")

    total = args.end - start
    print(f"Extracting AuxPoW: heights {start} to {args.end - 1} ({total:,} blocks)")

    stats = {"auxpow_blocks": 0, "skipped_no_auxpow": 0, "skipped_no_block": 0}
    mode = (
        "a"
        if args.resume and Path(args.output).exists() and start > args.start
        else "w"
    )

    with open(args.output, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        if mode == "w":
            writer.writeheader()

        t_start = time.time()
        processed = 0

        for batch_start in range(start, args.end, args.batch_size):
            batch_end = min(batch_start + args.batch_size, args.end)

            try:
                extract_range(batch_start, batch_end, writer, stats)
            except Exception as e:
                print(f"\nError at heights {batch_start}-{batch_end}: {e}")
                print("Retrying individually...")
                for h in range(batch_start, batch_end):
                    try:
                        extract_range(h, h + 1, writer, stats)
                    except Exception as e2:
                        print(f"  Failed height {h}: {e2}")
                        stats["skipped_no_block"] += 1

            processed += batch_end - batch_start

            if processed % PROGRESS_INTERVAL < args.batch_size:
                elapsed = time.time() - t_start
                rate = processed / elapsed if elapsed > 0 else 0
                eta = (total - processed) / rate if rate > 0 else 0
                pct = processed / total * 100
                print(
                    f"  {processed:>10,}/{total:,} ({pct:5.1f}%) | "
                    f"{rate:,.0f} blocks/s | "
                    f"AuxPoW: {stats['auxpow_blocks']:,} | "
                    f"ETA: {eta / 60:.0f}m",
                    flush=True,
                )
                f.flush()

    elapsed = time.time() - t_start
    print(f"\nDone in {elapsed / 60:.1f} minutes")
    print(f"  AuxPoW blocks extracted: {stats['auxpow_blocks']:,}")
    print(f"  Skipped (no AuxPoW):     {stats['skipped_no_auxpow']:,}")
    print(f"  Skipped (no block):      {stats['skipped_no_block']:,}")
    print(f"  Output: {args.output}")


if __name__ == "__main__":
    main()
