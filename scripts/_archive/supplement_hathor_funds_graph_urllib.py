#!/usr/bin/env python3
"""Supplement-extract Hathor funds+graph bytes (stdlib urllib version).

Same purpose as ``supplement_hathor_funds_graph.py`` but uses stdlib
``urllib`` instead of the third-party ``requests`` module — so it runs
on NixOS VPS hosts without a Python environment build step.

Also relaxes the input schema: needs only ``hathor_height`` and
``hathor_block_hash`` columns (no ``aux_pow_hex``) — the ``aux_pow``
value is taken from the ``/transaction`` API response itself.

Output schema matches the requests-based version, so all per-host CSVs
can be loaded by the same classifier.

Usage::

    python3 supplement_hathor_funds_graph_urllib.py \\
        --input  heights_tx_ids.csv \\
        --output funds_graph_vps.csv \\
        --api-url https://node1.mainnet.hathor.network/v1a \\
        --concurrency 8 \\
        --start-height 3220000 --end-height 4330000 \\
        --resume
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


CSV_COLUMNS = ["hathor_height", "hathor_block_hash", "funds_graph_hex"]
UA = "merge-mining-research/supplement-hathor-urllib"


def http_get_json(
    url: str, timeout: float = 30.0, max_retries: int = 30
) -> dict | None:
    """GET <url> as JSON with retries on 429/5xx; returns None on 404."""
    backoff = 0.2
    for attempt in range(max_retries):
        req = Request(
            url,
            headers={
                "user-agent": UA,
                "accept": "application/json",
            },
        )
        try:
            with urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (429, 502, 503, 504) and attempt < max_retries - 1:
                time.sleep(min(backoff, 5.0) + random.uniform(0, 0.3))
                backoff = min(backoff * 1.7, 5.0)
                continue
            raise
        except (URLError, json.JSONDecodeError, OSError):
            if attempt == max_retries - 1:
                raise
            time.sleep(min(backoff, 5.0) + random.uniform(0, 0.3))
            backoff = min(backoff * 1.7, 5.0)
    return None


def fetch_funds_graph(
    api_url: str, height: int, tx_id: str
) -> tuple[int, dict | None, str | None]:
    """Returns (height, row_or_None, error_or_None)."""
    url = f"{api_url}/transaction?id={tx_id}"
    try:
        d = http_get_json(url)
    except Exception as e:
        return height, None, f"tx_fetch: {e}"
    if not d or not d.get("success"):
        return height, None, "tx_fetch: not success"
    tx = d.get("tx") or {}
    raw_hex = tx.get("raw") or ""
    aux_pow_hex = tx.get("aux_pow") or ""
    if not raw_hex or not aux_pow_hex:
        return height, None, "raw or aux_pow missing"
    idx = raw_hex.find(aux_pow_hex)
    if idx < 0:
        return height, None, "aux_pow not in raw"
    return (
        height,
        {
            "hathor_height": height,
            "hathor_block_hash": tx_id,
            "funds_graph_hex": raw_hex[:idx],
        },
        None,
    )


def load_resume_set(output_path: Path) -> set[int]:
    """Return the Hathor heights already present in the output CSV, for resume."""
    done: set[int] = set()
    if not output_path.exists() or output_path.stat().st_size == 0:
        return done
    with open(output_path) as f:
        next(f, None)
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
    """Yield ``(hathor_height, block_hash)`` pairs from the slim input CSV."""
    with open(input_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                h = int(row["hathor_height"])
            except (KeyError, ValueError):
                continue
            yield h, row.get("hathor_block_hash", "")


def main():
    """Fetch funds/graph bytes for each input block and append them to the CSV."""
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument(
        "--input",
        required=True,
        help="Slim CSV with (hathor_height, hathor_block_hash).",
    )
    p.add_argument("--output", required=True)
    p.add_argument("--api-url", required=True)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--start-height", type=int, default=None)
    p.add_argument("--end-height", type=int, default=None)
    p.add_argument("--limit", type=int, default=None)
    args = p.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    if not in_path.exists():
        print(f"Input not found: {in_path}", file=sys.stderr)
        sys.exit(1)

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
            batch: list[tuple[int, str]] = []

            def flush(batch):
                """Fetch one batch concurrently and write its rows in input order."""
                if not batch:
                    return
                futures = {
                    pool.submit(fetch_funds_graph, args.api_url, h, txid): h
                    for (h, txid) in batch
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

            for h, txid in iter_input(in_path):
                if args.start_height is not None and h < args.start_height:
                    continue
                if args.end_height is not None and h >= args.end_height:
                    break
                if h in done:
                    stats["skipped_done"] += 1
                    continue
                batch.append((h, txid))
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
