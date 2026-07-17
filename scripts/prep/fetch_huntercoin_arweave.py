#!/usr/bin/env python3
"""Fetch Huntercoin block payloads preserved on Arweave by domob1812/arblockstore.

Queries Arweave GraphQL for all transactions tagged
    App-Name: ArBlockStore
    Blockchain: Huntercoin
owned by lCwDNgPD94JySVSIAzpEfUKuzXXIRm81DLZswBvftEs, and downloads each payload
via permagate.io (arweave.net returns 404 for these). Resumable: skips files
already on disk.

Outputs:
    data/prototype/huntercoin/arweave-blocks/block-<height>.bin  (raw HUC block)
    data/prototype/huntercoin/arweave-index.csv                  (height, txid, hash, size)
"""

from __future__ import annotations

import csv
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

OWNER = "lCwDNgPD94JySVSIAzpEfUKuzXXIRm81DLZswBvftEs"
GRAPHQL = "https://arweave.net/graphql"
PRIMARY_GATEWAY = "https://ar-io.dev"
FALLBACK_GATEWAYS = [
    "https://arweave.developerdao.com",
    "https://aoweave.tech",
    "https://frostor.xyz",
    "https://sulapan.com",
    "https://vevo.ar.io",
    "https://permagate.io",
    "https://arweave.net/raw",
]
OUT_DIR = (
    Path(__file__).resolve().parent.parent.parent / "data" / "prototype" / "huntercoin"
)
BLOCKS_DIR = OUT_DIR / "arweave-blocks"
INDEX_CSV = OUT_DIR / "arweave-index.csv"
WORKERS = 16
REQUEST_TIMEOUT = 15
TX_DEADLINE_S = 45

QUERY = """
query($owner:String!, $cursor:String) {
  transactions(
    owners: [$owner],
    tags: [
      { name: "App-Name", values: ["ArBlockStore"] },
      { name: "Blockchain", values: ["Huntercoin"] }
    ],
    first: 100,
    after: $cursor
  ) {
    pageInfo { hasNextPage }
    edges {
      cursor
      node {
        id
        data { size }
        tags { name value }
      }
    }
  }
}
"""


def _post_graphql(cursor):
    """POST the paginated Arweave GraphQL query at ``cursor``, retrying with
    exponential backoff on a retryable HTTP status or connection error.
    """
    delay = 2.0
    for attempt in range(8):
        try:
            r = requests.post(
                GRAPHQL,
                json={"query": QUERY, "variables": {"owner": OWNER, "cursor": cursor}},
                timeout=60,
            )
            if r.status_code in (502, 503, 504, 429):
                raise requests.HTTPError(f"retryable {r.status_code}")
            r.raise_for_status()
            return r.json()
        except (requests.HTTPError, requests.ConnectionError, requests.Timeout) as exc:
            if attempt == 7:
                raise
            print(
                f"  GraphQL {exc}; retry {attempt + 1}/7 after {delay:.1f}s", flush=True
            )
            time.sleep(delay)
            delay = min(delay * 2, 60)


def iter_txs():
    """Page through the Arweave GraphQL query, yielding one dict per matching
    transaction: ``{txid, size, height, block_hash}`` (``height``/``block_hash``
    are None when the tag is absent).
    """
    cursor = None
    while True:
        payload = _post_graphql(cursor)
        page = payload["data"]["transactions"]
        for edge in page["edges"]:
            node = edge["node"]
            tags = {t["name"]: t["value"] for t in node["tags"]}
            yield {
                "txid": node["id"],
                "size": int(node["data"]["size"]),
                "height": tags.get("Block-Height"),
                "block_hash": tags.get("Block-Hash"),
            }
            cursor = edge["cursor"]
        if not page["pageInfo"]["hasNextPage"]:
            return


def _try_gateway(gw: str, txid: str, expected_size: int, timeout: float):
    """Return payload bytes on success, else raise."""
    r = requests.get(f"{gw}/{txid}", timeout=timeout)
    if r.status_code == 200 and len(r.content) == expected_size:
        return r.content
    raise requests.HTTPError(
        f"{gw} → {r.status_code} size={len(r.content)}/{expected_size}"
    )


def download(txid: str, dest: Path, expected_size: int) -> int:
    """ar-io.dev first (verified to serve bundled items reliably);
    fall back across mirrors; write atomically; hard wall-clock cap."""
    deadline = time.time() + TX_DEADLINE_S
    last_exc: Exception | None = None
    order = [PRIMARY_GATEWAY, PRIMARY_GATEWAY] + random.sample(
        FALLBACK_GATEWAYS, k=len(FALLBACK_GATEWAYS)
    )
    for gw in order:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        try:
            payload = _try_gateway(
                gw, txid, expected_size, min(REQUEST_TIMEOUT, remaining)
            )
            tmp = dest.with_suffix(dest.suffix + ".part")
            tmp.write_bytes(payload)
            tmp.rename(dest)
            return len(payload)
        except (requests.ConnectionError, requests.Timeout, requests.HTTPError) as exc:
            last_exc = exc
    raise RuntimeError(f"all gateways failed: {last_exc}")


def main() -> int:
    """Discover HUC block transactions via Arweave GraphQL (resuming from
    ``arweave-txs.csv`` if present), pick the largest transaction per height,
    download any not already on disk in a thread pool, and write
    ``arweave-index.csv`` plus a failure log.

    Returns 0 if every pending download succeeded, else 1.
    """
    BLOCKS_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    raw_index = OUT_DIR / "arweave-txs.csv"
    rows: list[dict] = []
    if raw_index.exists():
        with raw_index.open() as fh:
            rdr = csv.DictReader(fh)
            for r in rdr:
                rows.append(
                    {
                        "txid": r["txid"],
                        "size": int(r["size"]),
                        "height": r["height"] or None,
                        "block_hash": r["block_hash"] or None,
                    }
                )
        print(f"Resuming with {len(rows)} txs already discovered in {raw_index.name}.")
    else:
        print(f"Querying Arweave GraphQL for HUC blocks from {OWNER[:10]}…")
        fh = raw_index.open("w", newline="")
        w = csv.writer(fh)
        w.writerow(["txid", "height", "block_hash", "size"])
        try:
            for tx in iter_txs():
                rows.append(tx)
                w.writerow(
                    [tx["txid"], tx["height"] or "", tx["block_hash"] or "", tx["size"]]
                )
                if len(rows) % 500 == 0:
                    fh.flush()
                    print(f"  discovered {len(rows)} txs so far…", flush=True)
        finally:
            fh.close()
    print(f"Discovered {len(rows)} transactions.")

    with_height = [r for r in rows if r["height"] is not None]
    by_height: dict[int, dict] = {}
    for r in with_height:
        h = int(r["height"])
        if h not in by_height or r["size"] > by_height[h]["size"]:
            by_height[h] = r

    missing_height = len(rows) - len(with_height)
    print(
        f"Unique heights: {len(by_height)} "
        f"(min {min(by_height)}, max {max(by_height)}); "
        f"{missing_height} txs without Block-Height tag"
    )

    pending = []
    skipped = 0
    for h in sorted(by_height):
        tx = by_height[h]
        dest = BLOCKS_DIR / f"block-{h:07d}.bin"
        if dest.exists() and dest.stat().st_size == tx["size"]:
            skipped += 1
            continue
        pending.append((h, tx, dest))
    print(
        f"Skipping {skipped} already-downloaded blocks. Fetching {len(pending)} with {WORKERS} workers."
    )

    downloaded = failed = 0
    failed_log = OUT_DIR / "arweave-failures.csv"
    failed_fh = failed_log.open("w", newline="")
    failed_w = csv.writer(failed_fh)
    failed_w.writerow(["height", "txid", "error"])

    def _fetch(item):
        """Download one pending ``(height, tx, dest)`` item and return ``(height, tx, bytes_written)``."""
        h, tx, dest = item
        return h, tx, download(tx["txid"], dest, tx["size"])

    start = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(_fetch, item): item for item in pending}
        for fut in as_completed(futures):
            h, tx, dest = futures[fut]
            try:
                h_ok, _tx, n = fut.result()
                downloaded += 1
                if downloaded % 500 == 0:
                    rate = downloaded / max(time.time() - start, 1e-3)
                    eta = (len(pending) - downloaded) / max(rate, 1e-3)
                    print(
                        f"  {downloaded}/{len(pending)} "
                        f"({rate:.1f}/s, eta {eta / 60:.1f}m)",
                        flush=True,
                    )
            except Exception as exc:
                failed += 1
                failed_w.writerow([h, tx["txid"], str(exc)[:200]])
                if failed <= 20 or failed % 100 == 0:
                    print(f"  FAIL h={h}: {str(exc)[:120]}", file=sys.stderr)
    failed_fh.close()

    with INDEX_CSV.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["height", "txid", "block_hash", "size"])
        for h in sorted(by_height):
            tx = by_height[h]
            w.writerow([h, tx["txid"], tx["block_hash"] or "", tx["size"]])

    print(
        f"\nDone. downloaded={downloaded} skipped={skipped} failed={failed} "
        f"index={INDEX_CSV.relative_to(OUT_DIR.parent.parent)}"
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
