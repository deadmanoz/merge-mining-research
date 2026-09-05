#!/usr/bin/env python3
"""
Extract Bitcoin AuxPoW headers from the Elastos (ELA) blockchain.

Elastos RPC returns the `auxpow` field as a hex-encoded blob using the standard
CAuxPow field layout. Elastos uses chain ID 1224 for tree-index validation.
This script fetches `getblockbyheight` for each ELA height, parses the
AuxPoW hex, and writes the Bitcoin parent header + coinbase data to CSV.

Supports the hybrid extraction flow described in
`docs/chains/elastos.md`:

  # Phase 2a: local node (high concurrency, no rate limit)
  python3 extract_elastos_auxpow.py \\
      --rpc-url http://localhost:20336 \\
      --start 177000 --end 1817251 \\
      --rpc-concurrency 32 \\
      --output data/elastos_auxpow_raw.csv

  # Phase 2b: public endpoint (rate-limited)
  python3 extract_elastos_auxpow.py \\
      --rpc-url https://api.elastos.io/ela \\
      --start 1817251 \\
      --rpc-concurrency 8 \\
      --output data/elastos_auxpow_raw.csv \\
      --resume
"""

import argparse
import csv
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# Shared modules: standard Namecoin-style CAuxPow tail parser + output formatter.
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.auxpow_parse import (
    parse_coinbase_height,
    parse_parent_header,
    read_auxpow,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_canonical

# Scan slightly before the observed transition so the data, rather than an
# assumed activation boundary, determines where non-dummy parent proofs begin.
# The archived run's first retained row is ELA height 177,153.
DEFAULT_SCAN_START_HEIGHT = 177_000
PROGRESS_INTERVAL = 10_000
FLUSH_INTERVAL = 10_000

# Dummy-AuxPoW filter: pre-activation ELA blocks self-mine with these nbits.
DUMMY_BITS = {0, 0x7FFFFFFF}

CSV_COLUMNS = [
    "ela_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_height",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
]


def get_chain_tip(rpc: RpcClient) -> int:
    """Return the current Elastos chain tip via ``getcurrentheight``.

    Elastos's ``getblockcount`` returns height plus one, unlike Bitcoin Core's
    method of the same name, so it is already an exclusive end bound.
    """
    return int(rpc.call("getcurrentheight", []))


def fetch_block(rpc: RpcClient, height: int) -> dict:
    """Fetch the decoded block JSON for an ELA height via ``getblockbyheight``."""
    return rpc.call("getblockbyheight", [height])


def parse_auxpow_hex(auxpow_hex: str) -> dict | None:
    """Parse an Elastos AuxPoW hex blob into parent-header + coinbase data.

    Returns a dict with the fields needed for the output CSV, or None if
    the blob is a dummy (bits ∈ {0, 0x7FFFFFFF}) or has no coinbase
    outputs.
    """
    buf = bytes.fromhex(auxpow_hex)
    aux, _ = read_auxpow(buf, 0)

    parent = parse_parent_header(aux["parent_header_raw"])
    if parent["bits"] in DUMMY_BITS:
        return None

    vouts = aux["coinbase_tx"]["vout"]
    if not vouts:
        return None

    vin = aux["coinbase_tx"]["vin"]
    scriptsig = vin[0]["scriptsig"] if vin else b""
    btc_height = parse_coinbase_height(scriptsig)

    # The shared canonical rendering (docs/data-reference.md), preserving
    # the outputs for later attribution research.
    outputs = format_outputs_canonical(vouts)

    return {
        "btc_header_hash": parent["hash"],
        "btc_prev_hash": parent["prev_hash"],
        "btc_time": parent["time"],
        "btc_bits": parent["bits_hex"],
        "btc_height": btc_height if btc_height is not None else "",
        "coinbase_scriptsig_hex": scriptsig.hex(),
        "coinbase_outputs": outputs,
        "btc_header_hex": parent["header_hex"],
    }


def extract_one(rpc: RpcClient, height: int) -> tuple[int, dict | None, str | None]:
    """Fetch+parse one height. Returns (height, row_or_None, error_or_None)."""
    try:
        block = fetch_block(rpc, height)
    except Exception as e:
        return height, None, f"fetch: {e}"
    ap = block.get("auxpow")
    if not ap:
        return height, None, None  # No AuxPoW, skip silently
    try:
        parsed = parse_auxpow_hex(ap)
    except Exception as e:
        return height, None, f"parse: {e}"
    if parsed is None:
        return height, None, None  # Dummy or empty outputs
    parsed["ela_height"] = height
    return height, parsed, None


def resume_start(output: Path, default_start: int) -> int:
    """Read last ela_height from an existing CSV and return next height."""
    if not output.exists():
        return default_start
    last_height = None
    with open(output) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("ela_height"):
                continue
            try:
                last_height = int(line.split(",", 1)[0])
            except ValueError:
                continue
    if last_height is None:
        return default_start
    return last_height + 1


def main():
    """Parse CLI args, extract Elastos's AuxPoW range concurrently, and
    write the output CSV.

    Resolves ``--end`` to the current chain tip when omitted, resumes
    from the last recorded height in ``--output`` when ``--resume`` is
    set, and dispatches ``extract_one`` across a thread pool sized by
    ``--rpc-concurrency``, draining in ``--batch-size``-height windows so
    a worker exception only loses that window's progress. Rows are
    written in ascending height order within each window; prints periodic
    progress/ETA and flushes the output file every ``FLUSH_INTERVAL``
    heights.
    """
    parser = argparse.ArgumentParser(
        description="Extract Bitcoin AuxPoW from the Elastos chain via JSON-RPC"
    )
    parser.add_argument(
        "--rpc-url",
        required=True,
        help="JSON-RPC endpoint (e.g. http://localhost:20336 or https://api.elastos.io/ela)",
    )
    parser.add_argument(
        "--start",
        type=int,
        default=DEFAULT_SCAN_START_HEIGHT,
        help="Start ELA height (inclusive)",
    )
    parser.add_argument(
        "--end",
        type=int,
        default=None,
        help="End ELA height (exclusive). Defaults to chain tip + 1",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/elastos_auxpow_raw.csv",
        help="Output CSV path",
    )
    parser.add_argument(
        "--rpc-concurrency", type=int, default=8, help="Concurrent in-flight RPC calls"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Height window scheduled per worker-pool drain (bounds memory)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from the last ela_height in --output (append mode)",
    )
    args = parser.parse_args()

    rpc = RpcClient(args.rpc_url, jsonrpc="2.0")
    if args.end is None:
        tip = get_chain_tip(rpc)
        args.end = tip + 1
        print(f"Chain tip: {tip}")

    output_path = Path(args.output)
    start = args.start
    if args.resume:
        resumed = resume_start(output_path, args.start)
        if resumed > args.start:
            start = resumed
            print(f"Resuming from ELA height {start}")

    if start >= args.end:
        print(f"Nothing to do: start={start}, end={args.end}")
        return

    total = args.end - start
    print(
        f"Extracting ELA AuxPoW: heights {start}..{args.end - 1} "
        f"({total:,} blocks) via {args.rpc_url} (concurrency={args.rpc_concurrency})"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Append when the file already holds useful rows: either resume
    # bumped the start, or the user passed --resume with a --start that
    # already matched the existing tail (still nothing to rewrite).
    is_append = args.resume and output_path.exists() and output_path.stat().st_size > 0
    mode = "a" if is_append else "w"

    stats = {"written": 0, "skipped": 0, "errors": 0}
    t_start = time.time()

    with open(output_path, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        if not is_append:
            writer.writeheader()

        # Drain in windows so errors bounded by --batch-size heights.
        with ThreadPoolExecutor(max_workers=args.rpc_concurrency) as pool:
            for window_start in range(start, args.end, args.batch_size):
                window_end = min(window_start + args.batch_size, args.end)
                futures = {
                    pool.submit(extract_one, rpc, h): h
                    for h in range(window_start, window_end)
                }
                results: dict[int, dict | None] = {}
                for fut in as_completed(futures):
                    h = futures[fut]
                    try:
                        height, row, err = fut.result()
                    except Exception as e:
                        print(f"  height {h} worker exception: {e}", flush=True)
                        stats["errors"] += 1
                        continue
                    if err:
                        print(f"  height {height}: {err}", flush=True)
                        stats["errors"] += 1
                        continue
                    results[height] = row

                # Write in ascending height order for CSV monotonicity.
                for h in sorted(results.keys()):
                    row = results[h]
                    if row is None:
                        stats["skipped"] += 1
                        continue
                    writer.writerow(row)
                    stats["written"] += 1

                processed = window_end - start
                if processed % PROGRESS_INTERVAL < args.batch_size:
                    elapsed = time.time() - t_start
                    rate = processed / elapsed if elapsed > 0 else 0
                    eta = (total - processed) / rate if rate > 0 else 0
                    pct = processed / total * 100
                    print(
                        f"  {processed:>10,}/{total:,} ({pct:5.1f}%) | "
                        f"{rate:5.1f} blk/s | "
                        f"written: {stats['written']:,} | "
                        f"skipped: {stats['skipped']:,} | "
                        f"errors: {stats['errors']:,} | "
                        f"ETA: {eta / 60:.0f}m",
                        flush=True,
                    )
                if processed % FLUSH_INTERVAL < args.batch_size:
                    f.flush()

    elapsed = time.time() - t_start
    print(f"\nDone in {elapsed / 60:.1f} minutes")
    print(f"  Written:  {stats['written']:,}")
    print(f"  Skipped:  {stats['skipped']:,}  (no auxpow / dummy / empty outputs)")
    print(f"  Errors:   {stats['errors']:,}")
    print(f"  Output:   {args.output}")


if __name__ == "__main__":
    main()
