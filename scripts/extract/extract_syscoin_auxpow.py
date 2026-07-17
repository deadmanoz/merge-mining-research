#!/usr/bin/env python3
"""
Extract Bitcoin AuxPoW headers from the Syscoin blockchain.

Iterates all Syscoin blocks from the first AuxPoW block (height 1973)
to the chain tip, extracting the embedded Bitcoin parent block header
and coinbase transaction data from each merge-mined block.

Output: CSV with one row per Syscoin AuxPoW block containing the
Bitcoin parent header fields and coinbase data for pool identification.
"""

import argparse
import csv
import os
import time
from pathlib import Path


# Repo `src/` is on sys.path when installed via `pip install -e .`; these
# shared modules are pure-stdlib and safe to import on the archival host.
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.auxpow_parse import parse_parent_header
from stale_blocks_analysis.bitcoin_binary import format_outputs_addr
from stale_blocks_analysis.coinbase_markers import parse_bip34_height
from stale_blocks_analysis.rpc_env import load_local_rpc_env, rpc_auth_from_env

load_local_rpc_env()

# --- Configuration ---
RPC_URL = os.environ.get("SYSCOIN_RPC_URL", "http://127.0.0.1:8370")

FIRST_AUXPOW_HEIGHT = 1973
BATCH_SIZE = 100
PROGRESS_INTERVAL = 10_000  # Print progress every N blocks

CSV_COLUMNS = [
    "sys_height",
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
    """The Syscoin RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        user, password = rpc_auth_from_env("SYSCOIN")
        _rpc = RpcClient(RPC_URL, user=user, password=password, timeout=120)
    return _rpc


def get_chain_tip() -> int:
    """Get the current Syscoin chain tip height."""
    call = [{"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}]
    return rpc().batch(call)[0]["result"]


def extract_range(start: int, end: int, writer: csv.DictWriter, stats: dict):
    """Extract AuxPoW data for a range of Syscoin block heights."""
    # Step 1: batch getblockhash
    hash_calls = [
        {"jsonrpc": "1.0", "id": i, "method": "getblockhash", "params": [h]}
        for i, h in enumerate(range(start, end))
    ]
    hash_results = rpc().batch(hash_calls)
    # Sort by id to maintain order
    hash_results.sort(key=lambda x: x["id"])
    hashes = [r["result"] for r in hash_results]

    # Step 2: batch getblock
    block_calls = [
        {"jsonrpc": "1.0", "id": i, "method": "getblock", "params": [h, 1]}
        for i, h in enumerate(hashes)
    ]
    block_results = rpc().batch(block_calls)
    block_results.sort(key=lambda x: x["id"])

    # Step 3: extract AuxPoW data
    for i, br in enumerate(block_results):
        height = start + i
        block = br["result"]
        auxpow = block.get("auxpow")

        if not auxpow or len(auxpow) == 0:
            stats["skipped_no_auxpow"] += 1
            continue

        stats["auxpow_blocks"] += 1

        # Parse parent block header
        parent_hex = auxpow.get("parentblock", "")
        if not parent_hex or len(parent_hex) != 160:
            stats["skipped_bad_header"] += 1
            continue

        header = parse_parent_header(bytes.fromhex(parent_hex))

        # Extract coinbase data
        tx = auxpow.get("tx", {})
        vin = tx.get("vin", [])
        vout = tx.get("vout", [])

        scriptsig = vin[0].get("coinbase", "") if vin else ""
        try:
            btc_height = parse_bip34_height(bytes.fromhex(scriptsig))
        except ValueError:
            btc_height = None
        outputs = format_outputs_addr(vout)

        writer.writerow(
            {
                "sys_height": height,
                "btc_header_hash": header["hash"],
                "btc_prev_hash": header["prev_hash"],
                "btc_time": header["time"],
                "btc_bits": header["bits_hex"],
                "btc_height": btc_height if btc_height is not None else "",
                "coinbase_scriptsig_hex": scriptsig,
                "coinbase_outputs": outputs,
                "btc_header_hex": parent_hex,
            }
        )


def main():
    """Parse CLI args, extract Syscoin's AuxPoW range in batches, and
    write the output CSV.

    Resolves ``--end`` to the current chain tip when omitted, resumes from
    the last recorded height in an existing output file when ``--resume``
    is set, retries a failed batch one block at a time before giving up on
    it, and prints periodic progress/ETA plus a final summary.
    """
    parser = argparse.ArgumentParser(description="Extract Bitcoin AuxPoW from Syscoin")
    parser.add_argument(
        "--start", type=int, default=FIRST_AUXPOW_HEIGHT, help="Start height"
    )
    parser.add_argument("--end", type=int, default=None, help="End height (exclusive)")
    parser.add_argument(
        "--output",
        type=str,
        default="data/syscoin_auxpow_raw.csv",
        help="Output CSV path",
    )
    parser.add_argument(
        "--batch-size", type=int, default=BATCH_SIZE, help="RPC batch size"
    )
    parser.add_argument(
        "--resume", action="store_true", help="Resume from last line of existing output"
    )
    args = parser.parse_args()

    if args.end is None:
        args.end = get_chain_tip() + 1
        print(f"Chain tip: {args.end - 1}")

    start = args.start
    if args.resume and Path(args.output).exists():
        # Find last sys_height in existing CSV
        with open(args.output) as f:
            last_line = None
            for line in f:
                last_line = line
            if last_line and not last_line.startswith("sys_height"):
                last_height = int(last_line.split(",")[0])
                start = last_height + 1
                print(f"Resuming from height {start}")

    total = args.end - start
    print(f"Extracting AuxPoW: heights {start} to {args.end - 1} ({total:,} blocks)")

    stats = {"auxpow_blocks": 0, "skipped_no_auxpow": 0, "skipped_bad_header": 0}
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
                print(f"Retrying individually...")
                for h in range(batch_start, batch_end):
                    try:
                        extract_range(h, h + 1, writer, stats)
                    except Exception as e2:
                        print(f"  Failed height {h}: {e2}")
                        stats["skipped_bad_header"] += 1

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
                # Flush CSV periodically
                f.flush()

    elapsed = time.time() - t_start
    print(f"\nDone in {elapsed / 60:.1f} minutes")
    print(f"  AuxPoW blocks extracted: {stats['auxpow_blocks']:,}")
    print(f"  Skipped (no AuxPoW):     {stats['skipped_no_auxpow']:,}")
    print(f"  Skipped (bad header):    {stats['skipped_bad_header']:,}")
    print(f"  Output: {args.output}")


if __name__ == "__main__":
    main()
