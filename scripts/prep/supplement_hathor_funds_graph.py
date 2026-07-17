#!/usr/bin/env python3
"""Supplement-extract Hathor funds+graph bytes for the existing AuxPoW raw CSV.

The existing extraction (``hathor_auxpow_raw.csv``) only saves
``aux_pow_hex``. Correct RFC 0006 merkle reconstruction needs
``aux_block_hash = sha256d(sha256(funds) || sha256(graph))``, which
requires the funds + graph bytes — the portion of the raw block that
precedes ``aux_pow``.

This script walks the existing CSV, fetches ``/v1a/transaction`` for each
``hathor_block_hash`` (= ``tx_id``), extracts ``funds + graph`` (the
bytes of ``raw`` before ``aux_pow``), and writes one row per block to a
supplement CSV that the corrected classifier joins on
``hathor_height``.

Resumable. Output is small (avg ~150 bytes funds+graph per row × 5.5M
rows ≈ 825 MB).

Usage on <archival-host>::

    data/hathor/.hvenv/bin/python3 supplement_hathor_funds_graph.py \\
        --input  data/hathor/hathor_auxpow_raw.csv \\
        --output data/hathor/hathor_funds_graph.csv \\
        --api-url https://node1.mainnet.hathor.network/v1a \\
        --concurrency 8 \\
        --resume
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


from hathor_client import HathorClient

DEFAULT_API = "https://node1.mainnet.hathor.network/v1a"

CSV_COLUMNS = ["hathor_height", "hathor_block_hash", "funds_graph_hex"]


def fetch_funds_graph(
    client: HathorClient, height: int, tx_id: str, aux_pow_hex: str
) -> tuple[int, dict | None, str | None]:
    """Returns (height, row_or_None, error_or_None)."""
    try:
        d = client.get_json("/transaction", {"id": tx_id})
    except Exception as e:
        return height, None, f"tx_fetch: {e}"
    if not d.get("success"):
        return height, None, "tx_fetch: not success"
    tx = d.get("tx") or {}
    raw_hex = tx.get("raw") or ""
    if not raw_hex:
        return height, None, "no raw field"
    idx = raw_hex.find(aux_pow_hex)
    if idx < 0:
        return height, None, "aux_pow_hex not in raw"
    funds_graph_hex = raw_hex[:idx]
    return (
        height,
        {
            "hathor_height": height,
            "hathor_block_hash": tx_id,
            "funds_graph_hex": funds_graph_hex,
        },
        None,
    )


def load_resume_set(output_path: Path) -> set[int]:
    """Set of heights already in the supplement CSV."""
    done: set[int] = set()
    if not output_path.exists() or output_path.stat().st_size == 0:
        return done
    with open(output_path) as f:
        next(f, None)  # header
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                done.add(int(line.split(",", 1)[0]))
            except ValueError:
                continue
    return done


def iter_input(input_path: Path):
    """Yield (height, tx_id, aux_pow_hex) from the raw CSV."""
    with open(input_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                h = int(row["hathor_height"])
            except (KeyError, ValueError):
                continue
            yield h, row.get("hathor_block_hash", ""), row.get("aux_pow_hex", "")


def main():
    """Walk the raw AuxPoW CSV, fetch the funds+graph bytes for each height
    from the Hathor API in a thread pool, and write the supplement CSV
    (optionally resuming from an existing output).
    """
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--input", default="data/hathor/hathor_auxpow_raw.csv")
    p.add_argument("--output", default="data/hathor/hathor_funds_graph.csv")
    p.add_argument("--api-url", default=DEFAULT_API)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument(
        "--resume",
        action="store_true",
        help="Skip heights already present in --output (append mode).",
    )
    p.add_argument(
        "--start-height",
        type=int,
        default=None,
        help="Skip input rows with hathor_height < this value.",
    )
    p.add_argument(
        "--end-height",
        type=int,
        default=None,
        help="Skip input rows with hathor_height >= this value.",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after this many newly-written rows (smoke test).",
    )
    args = p.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    if not in_path.exists():
        print(f"Input not found: {in_path}", file=sys.stderr)
        sys.exit(1)

    client = HathorClient(
        args.api_url, user_agent="merge-mining-research/supplement-hathor"
    )

    done: set[int] = set()
    is_append = False
    if args.resume:
        done = load_resume_set(out_path)
        is_append = bool(done)
        print(f"Resume: {len(done):,} heights already in {out_path}", file=sys.stderr)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if is_append else "w"

    stats = {"written": 0, "skipped_done": 0, "errors": 0}
    t0 = time.time()

    with open(out_path, mode, newline="") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=CSV_COLUMNS)
        if not is_append:
            writer.writeheader()

        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            batch: list[tuple[int, str, str]] = []

            def flush(batch):
                """Submit ``batch`` to the thread pool, tally errors, and write
                each successful row (in height order) to the output CSV.
                """
                if not batch:
                    return
                futures = {
                    pool.submit(fetch_funds_graph, client, h, txid, aux): h
                    for (h, txid, aux) in batch
                }
                results = {}
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
                for h in sorted(results):
                    row = results[h]
                    if row is None:
                        continue
                    writer.writerow(row)
                    stats["written"] += 1

            for h, txid, aux in iter_input(in_path):
                if args.start_height is not None and h < args.start_height:
                    continue
                if args.end_height is not None and h >= args.end_height:
                    break  # CSV is sorted by height; once past end, done
                if h in done:
                    stats["skipped_done"] += 1
                    continue
                batch.append((h, txid, aux))
                if len(batch) >= args.batch_size:
                    flush(batch)
                    batch = []
                    if stats["written"] % 5000 < args.batch_size:
                        elapsed = time.time() - t0
                        rate = stats["written"] / elapsed if elapsed > 0 else 0
                        print(
                            f"  {stats['written']:>10,} written | "
                            f"{rate:6.1f}/s | errors: {stats['errors']:,}",
                            flush=True,
                        )
                    if args.limit and stats["written"] >= args.limit:
                        break
                    f_out.flush()
            if batch and (not args.limit or stats["written"] < args.limit):
                flush(batch)

    elapsed = time.time() - t0
    print(file=sys.stderr)
    print(f"Done in {elapsed / 3600:.2f}h", file=sys.stderr)
    for k, v in stats.items():
        print(f"  {k:>16s}: {v:,}", file=sys.stderr)


if __name__ == "__main__":
    main()
