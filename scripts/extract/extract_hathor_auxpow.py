#!/usr/bin/env python3
"""Extract raw ``aux_pow`` proof blobs from Hathor via the public REST API.

Hathor mainnet P2P access is allowlisted, so this recovery uses the documented
public REST endpoint. Two requests per height: ``GET /v1a/block_at_height`` for the block
metadata + tx_id, then ``GET /v1a/transaction`` for the full payload
including the ``aux_pow`` hex blob.

Phase 1 (this script) saves the raw blob untouched. Phase 2
(``classify_hathor_stales.py``) handles header reconstruction, Bitcoin
predecessor linkage, PoW validation, and BIP34 height parsing. RPC misses remain
unresolved rather than being assigned to another parent chain.

Usage:

    # Public endpoint with conservative concurrency
    python3 scripts/extract/extract_hathor_auxpow.py \\
        --start 1000000 \\
        --concurrency 6 \\
        --output data/hathor_auxpow_raw.csv

    # Resume after interruption
    python3 scripts/extract/extract_hathor_auxpow.py --resume \\
        --output data/hathor_auxpow_raw.csv
"""

from __future__ import annotations

import argparse
import csv
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter

DEFAULT_API = "https://node1.mainnet.hathor.network/v1a"

# Hathor merge-mining adoption is essentially 100% from height ~1M onward
# (probe results 2026-04-24). Earlier heights have version-0 blocks mixed
# in; safe to start at 1M to skip the noise unless the user overrides.
DEFAULT_START = 1_000_000

PROGRESS_INTERVAL = 5_000
FLUSH_INTERVAL = 5_000

CSV_COLUMNS = [
    "hathor_height",
    "hathor_block_hash",
    "hathor_timestamp",
    "aux_pow_hex",
]


class HathorClient:
    """REST client with thread-local sessions and 429-aware backoff."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        max_retries: int = 30,
        pool_size: int = 16,
    ):
        """Store the API base URL and retry/pool-sizing config for later calls."""
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.pool_size = pool_size
        self._tls = threading.local()

    def _session(self) -> requests.Session:
        """Return this thread's ``requests.Session``, creating it on first use.

        Sessions are thread-local so worker threads in the pool don't
        contend over one shared connection pool.
        """
        s = getattr(self._tls, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update(
                {
                    "user-agent": "merge-mining-research/extract-hathor",
                    "accept": "application/json",
                }
            )
            adapter = HTTPAdapter(
                pool_connections=self.pool_size,
                pool_maxsize=self.pool_size,
            )
            s.mount("http://", adapter)
            s.mount("https://", adapter)
            self._tls.session = s
        return s

    def get_json(self, path: str, params: dict | None = None) -> dict:
        """Issue one GET against ``base_url + path`` and return the decoded JSON body.

        Retries on connection errors and 429/502/503/504 with jittered
        backoff (capped at 5s per attempt, up to ``max_retries``
        attempts), raising ``RuntimeError`` once retries are exhausted.
        """
        url = f"{self.base_url}{path}"
        session = self._session()
        backoff = 0.2
        for attempt in range(self.max_retries):
            try:
                resp = session.get(url, params=params, timeout=self.timeout)
            except requests.RequestException:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(min(backoff, 5.0) + random.uniform(0, 0.3))
                backoff = min(backoff * 1.7, 5.0)
                continue
            if resp.status_code in (429, 502, 503, 504):
                time.sleep(min(backoff, 5.0) + random.uniform(0, 0.3))
                backoff = min(backoff * 1.7, 5.0)
                continue
            resp.raise_for_status()
            return resp.json()
        raise RuntimeError(f"Exceeded {self.max_retries} retries for GET {url}")


def get_chain_tip(client: HathorClient) -> int:
    """Return the current Hathor chain tip height from ``GET /status``'s
    best-block-tips list (the max height across all reported tips).
    """
    s = client.get_json("/status")
    tips = s["dag"]["best_block_tips"]
    return max(t["height"] for t in tips)


def fetch_block_meta(client: HathorClient, height: int):
    """Return (tx_id, version) for the block at this height, or (None, None)."""
    d = client.get_json("/block_at_height", {"height": height})
    if not d.get("success"):
        return None, None
    block = d.get("block") or {}
    return block.get("tx_id"), block.get("version")


def fetch_tx(client: HathorClient, tx_id: str):
    """Return (aux_pow_hex, timestamp) for the transaction, or (None, None)."""
    d = client.get_json("/transaction", {"id": tx_id})
    if not d.get("success"):
        return None, None
    tx = d.get("tx") or {}
    return tx.get("aux_pow"), tx.get("timestamp")


def extract_one(client: HathorClient, height: int):
    """Returns (height, row_or_None, error_or_None)."""
    try:
        tx_id, version = fetch_block_meta(client, height)
    except Exception as e:
        return height, None, f"block_meta: {e}"
    if not tx_id:
        return (
            height,
            None,
            None,
        )  # no block at height (shouldn't happen, but defensive)
    if version != 3:
        return height, None, None  # not merge-mined; skip silently
    try:
        aux_hex, ts = fetch_tx(client, tx_id)
    except Exception as e:
        return height, None, f"tx_fetch: {e}"
    if not aux_hex:
        return (
            height,
            None,
            None,
        )  # v3 block but no aux_pow (genuinely shouldn't happen)
    return (
        height,
        {
            "hathor_height": height,
            "hathor_block_hash": tx_id,
            "hathor_timestamp": ts if ts is not None else "",
            "aux_pow_hex": aux_hex,
        },
        None,
    )


def resume_start(output: Path, default_start: int) -> int:
    """Return one past the highest ``hathor_height`` already in ``output``,
    or ``default_start`` if the file doesn't exist, is empty, or has no
    data rows.
    """
    if not output.exists() or output.stat().st_size == 0:
        return default_start
    last = None
    with open(output) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("hathor_height"):
                continue
            try:
                last = int(line.split(",", 1)[0])
            except ValueError:
                continue
    return (last + 1) if last is not None else default_start


def main():
    """Parse CLI args, extract Hathor's raw ``aux_pow`` proof blobs concurrently, and
    write the output CSV.

    Resolves ``--end`` to the current chain tip when omitted, resumes
    from the last recorded height in ``--output`` when ``--resume`` is
    set, and dispatches ``extract_one`` across a thread pool sized by
    ``--concurrency``, draining in ``--batch-size``-height windows so a
    worker exception only loses that window's progress. Rows are written
    in ascending height order within each window; prints periodic
    progress/ETA and flushes the output file every ``FLUSH_INTERVAL``
    heights. This phase saves the raw ``aux_pow_hex`` blob untouched —
    header reconstruction and validation happen downstream.
    """
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument(
        "--api-url",
        default=DEFAULT_API,
        help=f"Hathor REST API base URL (default: {DEFAULT_API})",
    )
    p.add_argument(
        "--start",
        type=int,
        default=DEFAULT_START,
        help=f"Start Hathor height (default: {DEFAULT_START:,})",
    )
    p.add_argument(
        "--end",
        type=int,
        default=None,
        help="End height exclusive (default: chain tip + 1)",
    )
    p.add_argument("--output", default="data/hathor_auxpow_raw.csv")
    p.add_argument(
        "--concurrency",
        type=int,
        default=6,
        help="Concurrent in-flight extract_one calls "
        "(each does up to 2 sequential GETs)",
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Heights per scheduling window (bounds memory + flush cadence)",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last hathor_height in --output (append mode)",
    )
    args = p.parse_args()

    client = HathorClient(args.api_url)

    if args.end is None:
        tip = get_chain_tip(client)
        args.end = tip + 1
        print(f"Hathor tip: {tip:,}")

    output_path = Path(args.output)
    start = args.start
    if args.resume:
        resumed = resume_start(output_path, args.start)
        if resumed > args.start:
            start = resumed
            print(f"Resuming from Hathor height {start:,}")

    if start >= args.end:
        print(f"Nothing to do: start={start:,}, end={args.end:,}")
        return

    total = args.end - start
    print(
        f"Extracting Hathor merge-mining proofs: heights {start:,}..{args.end - 1:,} "
        f"({total:,} blocks) via {args.api_url} (concurrency={args.concurrency})"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    is_append = args.resume and output_path.exists() and output_path.stat().st_size > 0
    mode = "a" if is_append else "w"

    stats = {"written": 0, "skipped": 0, "errors": 0}
    t0 = time.time()

    with open(output_path, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        if not is_append:
            writer.writeheader()

        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            for ws in range(start, args.end, args.batch_size):
                we = min(ws + args.batch_size, args.end)
                futures = {
                    pool.submit(extract_one, client, h): h for h in range(ws, we)
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

                for h in sorted(results):
                    row = results[h]
                    if row is None:
                        stats["skipped"] += 1
                        continue
                    writer.writerow(row)
                    stats["written"] += 1

                processed = we - start
                if processed % PROGRESS_INTERVAL < args.batch_size:
                    elapsed = time.time() - t0
                    rate = processed / elapsed if elapsed > 0 else 0
                    eta_min = (total - processed) / rate / 60 if rate > 0 else 0
                    pct = processed / total * 100
                    print(
                        f"  {processed:>10,}/{total:,} ({pct:5.1f}%) | "
                        f"{rate:5.1f} blk/s | "
                        f"written: {stats['written']:,} | "
                        f"skipped: {stats['skipped']:,} | "
                        f"errors: {stats['errors']:,} | "
                        f"ETA: {eta_min / 60:.1f}h",
                        flush=True,
                    )
                if processed % FLUSH_INTERVAL < args.batch_size:
                    f.flush()

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed / 3600:.2f}h")
    print(f"  Written:  {stats['written']:,}")
    print(f"  Skipped:  {stats['skipped']:,}  (non-v3 / no aux_pow)")
    print(f"  Errors:   {stats['errors']:,}")
    print(f"  Output:   {args.output}")


if __name__ == "__main__":
    main()
