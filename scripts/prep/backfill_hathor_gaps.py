#!/usr/bin/env python3
"""Backfill missing Hathor heights after the main 5-instance supplement run.

Three gap classes to plug:

1. **Raw-extraction holes** (~822 heights): no row in
   ``hathor_auxpow_raw.csv``. Need BOTH ``aux_pow_hex`` and
   ``funds_graph_hex``. Fetch via:
   - ``GET /v1a/block_at_height?height=H`` → tx_id
   - ``GET /v1a/transaction?id=<tx_id>`` → aux_pow + raw
   Append to raw CSV + funds_graph_backfill CSV.

2. **Supplement-only holes** (~144 heights, vps-dev-01's lifetime 429s):
   row exists in raw CSV but no matching height in any supplement file.
   Fetch only ``/v1a/transaction``. Append to funds_graph_backfill CSV.

3. **New-tail heights** (~12K heights): heights in current
   ``hathor_auxpow_raw.csv`` past the snapshot of ``heights_tx_ids.csv``.
   Same as case 2 — fetch ``/v1a/transaction`` only.

Outputs:
  ``data/hathor/hathor_auxpow_backfill.csv`` — new raw rows (case 1 only)
  ``data/hathor/hathor_funds_graph_backfill.csv`` — new funds+graph rows (all cases)

Both backfill CSVs are loaded by the classifier alongside the 5 main
supplement files. Use the existing ``--supplement`` multi-arg.

Usage::

    data/hathor/.hvenv/bin/python3 backfill_hathor_gaps.py \\
        --raw      data/hathor/hathor_auxpow_raw.csv \\
        --supplement-dir data/hathor/ \\
        --backfill-raw      data/hathor/hathor_auxpow_backfill.csv \\
        --backfill-supp     data/hathor/hathor_funds_graph_backfill.csv \\
        --api-url           https://node1.mainnet.hathor.network/v1a \\
        --concurrency       4
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

RAW_COLUMNS = ["hathor_height", "hathor_block_hash", "hathor_timestamp", "aux_pow_hex"]
SUPP_COLUMNS = ["hathor_height", "hathor_block_hash", "funds_graph_hex"]


def fetch_full_block(client: HathorClient, height: int):
    """Fetch a missing-from-raw block: needs height → tx_id → /transaction.

    Returns (raw_row, supp_row, error). Both rows on success.
    """
    try:
        d = client.get_json("/block_at_height", {"height": height})
    except Exception as e:
        return None, None, f"block_at_height: {e}"
    if not d.get("success"):
        return None, None, "block_at_height: not success"
    block = d.get("block") or {}
    tx_id = block.get("tx_id")
    version = block.get("version")
    if not tx_id or version != 3:
        return None, None, f"not v3 (version={version})"
    try:
        d = client.get_json("/transaction", {"id": tx_id})
    except Exception as e:
        return None, None, f"transaction: {e}"
    if not d.get("success"):
        return None, None, "transaction: not success"
    tx = d.get("tx") or {}
    aux_pow_hex = tx.get("aux_pow") or ""
    raw_hex = tx.get("raw") or ""
    ts = tx.get("timestamp")
    if not aux_pow_hex or not raw_hex:
        return None, None, "missing aux_pow or raw"
    idx = raw_hex.find(aux_pow_hex)
    if idx < 0:
        return None, None, "aux_pow_hex not in raw"
    raw_row = {
        "hathor_height": height,
        "hathor_block_hash": tx_id,
        "hathor_timestamp": ts if ts is not None else "",
        "aux_pow_hex": aux_pow_hex,
    }
    supp_row = {
        "hathor_height": height,
        "hathor_block_hash": tx_id,
        "funds_graph_hex": raw_hex[:idx],
    }
    return raw_row, supp_row, None


def fetch_supp_only(client: HathorClient, height: int, tx_id: str, aux_pow_hex: str):
    """Fetch funds+graph for a height we already have in raw.

    Returns (None, supp_row, error).
    """
    try:
        d = client.get_json("/transaction", {"id": tx_id})
    except Exception as e:
        return None, None, f"transaction: {e}"
    if not d.get("success"):
        return None, None, "transaction: not success"
    tx = d.get("tx") or {}
    raw_hex = tx.get("raw") or ""
    if not raw_hex:
        return None, None, "no raw"
    idx = raw_hex.find(aux_pow_hex)
    if idx < 0:
        return None, None, "aux_pow_hex not in raw"
    return (
        None,
        {
            "hathor_height": height,
            "hathor_block_hash": tx_id,
            "funds_graph_hex": raw_hex[:idx],
        },
        None,
    )


def load_heights_in_csv(path: Path) -> set[int]:
    """Return the set of hathor_height values present in a CSV."""
    out: set[int] = set()
    if not path.exists():
        return out
    with open(path) as f:
        next(f, None)  # header
        for line in f:
            try:
                out.add(int(line.split(",", 1)[0]))
            except ValueError:
                continue
    return out


def load_raw_rows(path: Path) -> dict[int, tuple[str, str]]:
    """Return {height: (tx_id, aux_pow_hex)} for all rows in the raw CSV."""
    out: dict[int, tuple[str, str]] = {}
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                h = int(row["hathor_height"])
            except (KeyError, ValueError):
                continue
            out[h] = (row.get("hathor_block_hash", ""), row.get("aux_pow_hex", ""))
    return out


def main():
    """Compute the raw-extraction and supplement-only height gaps, fetch each
    missing height from the Hathor API in a thread pool, and append the
    results to the two backfill CSVs.
    """
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--raw", required=True, help="Path to hathor_auxpow_raw.csv (read).")
    p.add_argument(
        "--supplement-dir",
        required=True,
        help="Directory containing the 5 supplement CSVs.",
    )
    p.add_argument(
        "--backfill-raw",
        required=True,
        help="Output: new rows for hathor_auxpow_raw.csv.",
    )
    p.add_argument(
        "--backfill-supp",
        required=True,
        help="Output: new rows for the funds_graph backfill CSV.",
    )
    p.add_argument("--api-url", default=DEFAULT_API)
    p.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Concurrent API requests. Stay polite — gap is small.",
    )
    p.add_argument(
        "--start-height",
        type=int,
        default=1_000_000,
        help="Lowest height to consider (defaults to merge-mining era).",
    )
    p.add_argument(
        "--end-height",
        type=int,
        default=None,
        help="Highest height to consider (default: raw CSV's tip).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Report gap counts without making API calls.",
    )
    args = p.parse_args()

    raw_path = Path(args.raw)
    supp_dir = Path(args.supplement_dir)
    backfill_raw_path = Path(args.backfill_raw)
    backfill_supp_path = Path(args.backfill_supp)

    if not raw_path.exists():
        print(f"Raw CSV not found: {raw_path}", file=sys.stderr)
        sys.exit(1)

    # Load raw CSV.
    print(f"Loading raw CSV {raw_path}...", file=sys.stderr)
    raw_rows = load_raw_rows(raw_path)
    raw_heights = set(raw_rows.keys())
    raw_min = min(raw_heights)
    raw_max = max(raw_heights)
    print(
        f"  {len(raw_heights):,} rows; height range {raw_min:,}..{raw_max:,}",
        file=sys.stderr,
    )

    end_height = args.end_height or raw_max
    span = set(range(args.start_height, end_height + 1))

    # Load all supplement files in the directory.
    supp_files = sorted(supp_dir.glob("hathor_funds_graph*.csv"))
    print(f"Loading {len(supp_files)} supplement CSV(s)...", file=sys.stderr)
    supp_heights: set[int] = set()
    for sp in supp_files:
        h = load_heights_in_csv(sp)
        supp_heights |= h
        print(f"  {sp.name}: {len(h):,} heights", file=sys.stderr)
    print(f"  Union of supplement heights: {len(supp_heights):,}", file=sys.stderr)

    # Also include any prior backfill outputs.
    if backfill_raw_path.exists():
        prior_raw = load_heights_in_csv(backfill_raw_path)
        raw_heights |= prior_raw
        print(f"  Prior backfill-raw: {len(prior_raw):,} heights", file=sys.stderr)
    if backfill_supp_path.exists():
        prior_supp = load_heights_in_csv(backfill_supp_path)
        supp_heights |= prior_supp
        print(f"  Prior backfill-supp: {len(prior_supp):,} heights", file=sys.stderr)

    # Compute the three gap categories.
    raw_gap = sorted(span - raw_heights)
    supp_gap = sorted((raw_heights & span) - supp_heights)

    print(file=sys.stderr)
    print(
        f"Raw-extraction holes (no row in raw CSV): {len(raw_gap):,}", file=sys.stderr
    )
    print(
        f"Supplement-only holes (row in raw, no row in any supp): {len(supp_gap):,}",
        file=sys.stderr,
    )
    print(
        f"Total backfill API calls: {len(raw_gap) * 2 + len(supp_gap):,}",
        file=sys.stderr,
    )

    if args.dry_run:
        print(file=sys.stderr)
        print("Dry run; exiting before any API calls.", file=sys.stderr)
        return

    if not raw_gap and not supp_gap:
        print("\nNo gaps; nothing to backfill.", file=sys.stderr)
        return

    client = HathorClient(
        args.api_url, user_agent="merge-mining-research/backfill-hathor"
    )

    backfill_raw_path.parent.mkdir(parents=True, exist_ok=True)
    backfill_supp_path.parent.mkdir(parents=True, exist_ok=True)

    raw_is_append = backfill_raw_path.exists() and backfill_raw_path.stat().st_size > 0
    supp_is_append = (
        backfill_supp_path.exists() and backfill_supp_path.stat().st_size > 0
    )

    stats = {
        "raw_done": 0,
        "raw_errors": 0,
        "supp_done": 0,
        "supp_errors": 0,
    }
    t0 = time.time()

    f_raw = open(backfill_raw_path, "a" if raw_is_append else "w", newline="")
    f_supp = open(backfill_supp_path, "a" if supp_is_append else "w", newline="")
    try:
        w_raw = csv.DictWriter(f_raw, fieldnames=RAW_COLUMNS)
        if not raw_is_append:
            w_raw.writeheader()
        w_supp = csv.DictWriter(f_supp, fieldnames=SUPP_COLUMNS)
        if not supp_is_append:
            w_supp.writeheader()

        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            # Phase 1: raw_gap (need /block_at_height + /transaction)
            if raw_gap:
                print(
                    f"\n=== Phase 1: backfilling {len(raw_gap):,} raw holes ===",
                    file=sys.stderr,
                )
                futures = {pool.submit(fetch_full_block, client, h): h for h in raw_gap}
                for fut in as_completed(futures):
                    h = futures[fut]
                    try:
                        raw_row, supp_row, err = fut.result()
                    except Exception as e:
                        print(f"  height {h}: worker exception {e}", flush=True)
                        stats["raw_errors"] += 1
                        continue
                    if err:
                        print(f"  height {h}: {err}", flush=True)
                        stats["raw_errors"] += 1
                        continue
                    w_raw.writerow(raw_row)
                    w_supp.writerow(supp_row)
                    stats["raw_done"] += 1
                    if stats["raw_done"] % 100 == 0:
                        f_raw.flush()
                        f_supp.flush()
                        elapsed = time.time() - t0
                        rate = stats["raw_done"] / elapsed if elapsed > 0 else 0
                        print(
                            f"  raw: {stats['raw_done']:,}/{len(raw_gap):,} "
                            f"({rate:.1f}/s, errors: {stats['raw_errors']:,})",
                            flush=True,
                        )

            # Phase 2: supp_gap (need /transaction only)
            if supp_gap:
                print(
                    f"\n=== Phase 2: backfilling {len(supp_gap):,} supplement holes ===",
                    file=sys.stderr,
                )
                fut_to_h = {}
                for h in supp_gap:
                    tx_id, aux_pow_hex = raw_rows[h]
                    fut_to_h[
                        pool.submit(fetch_supp_only, client, h, tx_id, aux_pow_hex)
                    ] = h
                for fut in as_completed(fut_to_h):
                    h = fut_to_h[fut]
                    try:
                        _, supp_row, err = fut.result()
                    except Exception as e:
                        print(f"  height {h}: worker exception {e}", flush=True)
                        stats["supp_errors"] += 1
                        continue
                    if err:
                        print(f"  height {h}: {err}", flush=True)
                        stats["supp_errors"] += 1
                        continue
                    w_supp.writerow(supp_row)
                    stats["supp_done"] += 1
                    if stats["supp_done"] % 500 == 0:
                        f_supp.flush()
                        elapsed = time.time() - t0
                        rate = (stats["raw_done"] + stats["supp_done"]) / elapsed
                        print(
                            f"  supp: {stats['supp_done']:,}/{len(supp_gap):,} "
                            f"({rate:.1f}/s total, errors: {stats['supp_errors']:,})",
                            flush=True,
                        )
    finally:
        f_raw.close()
        f_supp.close()

    elapsed = time.time() - t0
    print(file=sys.stderr)
    print(f"Done in {elapsed / 60:.1f}min", file=sys.stderr)
    for k, v in stats.items():
        print(f"  {k:>15s}: {v:,}", file=sys.stderr)


if __name__ == "__main__":
    main()
