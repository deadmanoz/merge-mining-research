#!/usr/bin/env python3
"""Classify Hathor merge-mined blocks: header reconstruction + PoW filter
+ BTC RPC parent lookup.

This is Phase A of the full classifier. Runs on <archival-host> (where the raw
extraction + supplement live at data/hathor/ and the BTC RPC is
local). Joins ``hathor_auxpow_raw.csv`` (aux_pow blobs) with
``hathor_funds_graph.csv`` (funds+graph bytes per height — see
``supplement_hathor_funds_graph.py``) on ``hathor_height``. Output: an
intermediate CSV with all PoW-passing rows tagged Bitcoin-predecessor-found
(RPC hit) or unresolved (RPC miss). An RPC miss does not identify the parent
chain. Phase B classifies the predecessor-linked rows as canonical or
stale-labelled; Phase C parses the coinbase and applies the remaining
available-evidence publication gates.

Reconstruction follows Hathor RFC 0006 strictly: the value embedded
between cb_head and cb_tail is ``aux_block_hash =
sha256d(sha256(funds) || sha256(graph))`` in display byte order, not the
full Hathor block hash; merkle path links are also byte-reversed before
each fold step. See the integration findings doc for the bug history
the existing verify_hathor_extraction.py never caught.

Self-contained — no project imports — so it can run on <archival-host> with
only stdlib + requests.

Usage on <archival-host>::

    data/hathor/.hvenv/bin/python3 classify_hathor_stales.py \\
        --input      data/hathor/hathor_auxpow_raw.csv \\
        --supplement data/hathor/hathor_funds_graph.csv \\
        --output     data/hathor/hathor_phase_a.csv \\
        --rpc-url    http://bitcoin:bitcoin@127.0.0.1:8332 \\
        --workers 16
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

PHASE_A_COLUMNS = [
    "hathor_height",
    "hathor_block_hash",
    "hathor_timestamp",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_nonce",
    "btc_header_hex",
    "full_coinbase_hex",
    "btc_rpc_match",  # "true" / "false"
]


# ---------------------------------------------------------------------------
# Binary helpers
# ---------------------------------------------------------------------------


def sha256d(b: bytes) -> bytes:
    """Double-SHA256, the Bitcoin block/tx hash primitive."""
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Read a Bitcoin CompactSize varint at ``pos``. Returns ``(value, new_pos)``."""
    n = buf[pos]
    if n < 0xFD:
        return n, pos + 1
    if n == 0xFD:
        return int.from_bytes(buf[pos + 1 : pos + 3], "little"), pos + 3
    if n == 0xFE:
        return int.from_bytes(buf[pos + 1 : pos + 5], "little"), pos + 5
    return int.from_bytes(buf[pos + 1 : pos + 9], "little"), pos + 9


def parse_aux_pow(hex_blob: str) -> dict | None:
    """Decode the Hathor RFC-0006 ``aux_pow`` proof layout.

    Returns dict with keys ``head_36``, ``cb_head``, ``cb_tail``,
    ``merkle_path``, ``tail_12``. Returns None on parse failure.
    """
    try:
        buf = bytes.fromhex(hex_blob)
    except ValueError:
        return None
    if len(buf) < 36 + 1 + 1 + 1 + 12:
        return None
    pos = 0
    head = buf[pos : pos + 36]
    pos += 36
    try:
        cb_head_len, pos = read_varint(buf, pos)
        cb_head = buf[pos : pos + cb_head_len]
        pos += cb_head_len
        cb_tail_len, pos = read_varint(buf, pos)
        cb_tail = buf[pos : pos + cb_tail_len]
        pos += cb_tail_len
        merkle_count, pos = read_varint(buf, pos)
        if merkle_count > 64:  # sanity bound; BTC merkle path is ~12-14 typically
            return None
        merkle_path = []
        for _ in range(merkle_count):
            merkle_path.append(buf[pos : pos + 32])
            pos += 32
        tail = buf[pos : pos + 12]
        if len(tail) != 12:
            return None
    except (IndexError, ValueError):
        return None
    return {
        "head_36": head,
        "cb_head": cb_head,
        "cb_tail": cb_tail,
        "merkle_path": merkle_path,
        "tail_12": tail,
    }


def sha256(b: bytes) -> bytes:
    """Single SHA256 digest."""
    return hashlib.sha256(b).digest()


def reconstruct(
    parsed: dict, funds_graph_bytes: bytes, expected_hathor_block_hash: str
) -> tuple[bytes, bytes, int] | None:
    """Reconstruct the 80-byte BTC header and full coinbase tx per RFC 0006.

    The value embedded between cb_head and cb_tail is ``aux_block_hash`` =
    ``sha256d(sha256(block_funds) || sha256(block_graph))``, where
    ``block_funds`` and ``block_graph`` together are the bytes preceding
    ``aux_pow`` in the Hathor block's ``raw`` field.

    Hathor's binary format places the funds/graph boundary at a per-block
    offset (depends on output count + per-output script length + the
    optional 4-vs-8-byte value encoding). Rather than re-implement the
    parser, we brute-force the split and accept the first one whose
    reconstructed header satisfies the smoking-gun check:
    ``sha256d(reconstructed_header)[::-1] == expected_hathor_block_hash``.

    Returns (80-byte header, full coinbase tx, split offset) on success;
    None if no split succeeds (signal of bad data).

    Three RFC-0006 byte-order corrections vs. the buggy verify_hathor_extraction
    pattern:
      - aux_block_hash is byte-reversed before embedding (display order)
      - merkle path links are byte-reversed before each fold step
      - the result is consistent with sha256d(reconstructed) == tx_id
    """
    try:
        expected = bytes.fromhex(expected_hathor_block_hash)
    except ValueError:
        return None

    head_36 = parsed["head_36"]
    cb_head = parsed["cb_head"]
    cb_tail = parsed["cb_tail"]
    merkle_path = parsed["merkle_path"]
    tail_12 = parsed["tail_12"]

    n = len(funds_graph_bytes)
    if n < 2:
        return None

    for split in range(2, n):
        funds_h = sha256(funds_graph_bytes[:split])
        graph_h = sha256(funds_graph_bytes[split:])
        abh = sha256d(funds_h + graph_h)[::-1]  # display order for embedding

        full_coinbase = cb_head + abh + cb_tail
        cur = sha256d(full_coinbase)
        for sibling in merkle_path:
            cur = sha256d(cur + sibling[::-1])  # links stored display-order

        header = head_36 + cur + tail_12
        if len(header) != 80:
            return None
        if sha256d(header)[::-1] == expected:
            return header, full_coinbase, split

    return None


def compact_target(nbits: int) -> int:
    """Standard Bitcoin compact-bits → target conversion."""
    exp = nbits >> 24
    mantissa = nbits & 0x007FFFFF
    if exp <= 3:
        return mantissa >> (8 * (3 - exp))
    return mantissa << (8 * (exp - 3))


def pow_passes(header: bytes) -> bool:
    """Return whether SHA256d(header) meets the header's encoded target."""
    nbits = int.from_bytes(header[72:76], "little")
    target = compact_target(nbits)
    h = sha256d(header)
    h_int = int.from_bytes(h, "little")
    return h_int <= target


# ---------------------------------------------------------------------------
# BTC RPC
# ---------------------------------------------------------------------------


class BitcoinRPC:
    """Tiny JSON-RPC client with a pooled Session."""

    def __init__(self, url: str, timeout: float = 30.0, pool_size: int = 32):
        self.url = url
        self.timeout = timeout
        self._id = 0
        self._session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def call(self, method: str, params: list | None = None, max_retries: int = 5):
        """JSON-RPC call with retry on *transient* faults only.

        A JSON-RPC error (e.g. code -5 "block not found") is a real
        answer — raised immediately, never retried. Network faults and
        non-RPC 5xx responses are transient — retried with backoff, then
        raised if still failing. Callers must NOT swallow a raised
        exception into a negative result: a transient fault that
        exhausts retries means the lookup is *unknown*, not *false*.
        """
        self._id += 1
        body = {
            "jsonrpc": "1.0",
            "id": str(self._id),
            "method": method,
            "params": params or [],
        }
        backoff = 0.3
        for attempt in range(max_retries):
            try:
                r = self._session.post(self.url, json=body, timeout=self.timeout)
            except requests.RequestException:
                if attempt == max_retries - 1:
                    raise
                time.sleep(backoff + random.uniform(0, 0.2))
                backoff = min(backoff * 1.8, 5.0)
                continue
            if r.status_code == 500:
                # bitcoind returns 500 with a JSON-RPC error body for
                # "block not found" etc. — a real answer, raise as-is.
                try:
                    data = r.json()
                except ValueError:
                    data = None
                if data is not None and "error" in data:
                    err = data.get("error") or {}
                    raise BitcoinRPCError(err.get("code"), err.get("message"))
                # 500 without a JSON-RPC body — treat as transient.
                if attempt == max_retries - 1:
                    r.raise_for_status()
                time.sleep(backoff + random.uniform(0, 0.2))
                backoff = min(backoff * 1.8, 5.0)
                continue
            if r.status_code in (502, 503, 504):
                if attempt == max_retries - 1:
                    r.raise_for_status()
                time.sleep(backoff + random.uniform(0, 0.2))
                backoff = min(backoff * 1.8, 5.0)
                continue
            r.raise_for_status()
            data = r.json()
            if data.get("error"):
                err = data["error"]
                raise BitcoinRPCError(err.get("code"), err.get("message"))
            return data["result"]
        raise RuntimeError(f"Exceeded {max_retries} retries for RPC {method}")

    def get_block_header(self, block_hash: str, verbose: bool = True):
        """Call ``getblockheader`` for ``block_hash`` and return its result."""
        return self.call("getblockheader", [block_hash, verbose])


class BitcoinRPCError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


# ---------------------------------------------------------------------------
# Per-row pipeline
# ---------------------------------------------------------------------------


def process_row(
    row: dict, funds_graph_hex: str | None, rpc: BitcoinRPC
) -> tuple[str, dict | None]:
    """Returns (status, output_row_or_None).

    Status is one of:
      - "pow_pass_btc": PoW passed, BTC RPC found the prev hash
      - "pow_pass_nonbtc": legacy status name for a PoW-passing RPC miss;
                           the parent chain remains unresolved
      - "pow_fail": PoW filter rejected (most rows)
      - "parse_fail": AuxPoW blob couldn't be decoded
      - "no_supplement": funds+graph missing — row skipped, supplement
                        extraction still in progress for this height
      - "recon_fail": reconstruction's smoking-gun check (sha256d == tx_id)
                      didn't match any split — should not happen with valid
                      inputs
    """
    aux_hex = row.get("aux_pow_hex")
    if not aux_hex:
        return "parse_fail", None
    if not funds_graph_hex:
        return "no_supplement", None

    parsed = parse_aux_pow(aux_hex)
    if parsed is None:
        return "parse_fail", None

    try:
        funds_graph_bytes = bytes.fromhex(funds_graph_hex)
    except ValueError:
        return "recon_fail", None

    recon = reconstruct(parsed, funds_graph_bytes, row["hathor_block_hash"])
    if recon is None:
        return "recon_fail", None
    header, full_cb, _split = recon

    if not pow_passes(header):
        return "pow_fail", None

    prev_be = header[4:36][::-1].hex()
    n_time = int.from_bytes(header[68:72], "little")
    n_bits = header[72:76][::-1].hex()
    n_nonce = int.from_bytes(header[76:80], "little")

    # prev_hash lookup. Only RPC error -5 ("block not found") is a
    # definitive "not on this Bitcoin node" result. Any other RPC error, or an exhausted
    # retry, means the lookup is UNKNOWN — we must NOT file it as
    # RPC miss (that would silently drop a real BTC-parent candidate).
    # Re-raise so the worker future surfaces it and the run aborts
    # rather than producing a false negative.
    btc_match = False
    try:
        rpc.get_block_header(prev_be, verbose=False)
        btc_match = True
    except BitcoinRPCError as e:
        if e.code == -5:
            btc_match = False
        else:
            raise

    out = {
        "hathor_height": row["hathor_height"],
        "hathor_block_hash": row["hathor_block_hash"],
        "hathor_timestamp": row.get("hathor_timestamp", ""),
        "btc_prev_hash": prev_be,
        "btc_time": n_time,
        "btc_bits": n_bits,
        "btc_nonce": n_nonce,
        "btc_header_hex": header.hex(),
        "full_coinbase_hex": full_cb.hex(),
        "btc_rpc_match": "true" if btc_match else "false",
    }
    return ("pow_pass_btc" if btc_match else "pow_pass_nonbtc"), out


def load_supplement(supplement_paths: list[Path]) -> dict[int, str]:
    """Load hathor_height → funds_graph_hex from one or more supplement CSVs.

    Multiple paths supported because the supplement extraction is
    range-split across node1 and node2 endpoints to parallelise the
    public-API rate limits — each instance writes its own CSV.
    """
    out: dict[int, str] = {}
    for path in supplement_paths:
        if not path.exists():
            continue
        with open(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    h = int(row["hathor_height"])
                except (KeyError, ValueError):
                    continue
                fg = row.get("funds_graph_hex")
                if fg:
                    out[h] = fg
    return out


def main():
    """Run Phase A: reconstruct headers from raw AuxPoW blobs, filter by PoW,
    look up each prev hash against Bitcoin Core, and write the intermediate
    predecessor-linked/unresolved CSV plus a stats summary to stderr.
    """
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--input", default="data/hathor/hathor_auxpow_raw.csv")
    p.add_argument(
        "--supplement",
        action="append",
        default=None,
        help="Supplement CSV with funds+graph bytes per "
        "hathor_height. Repeatable — pass once per range "
        "shard (see supplement_hathor_funds_graph.py).",
    )
    p.add_argument("--output", default="data/hathor/hathor_phase_a.csv")
    p.add_argument("--rpc-url", default="http://bitcoin:bitcoin@127.0.0.1:8332")
    p.add_argument(
        "--workers",
        type=int,
        default=16,
        help="Concurrent RPC calls. bitcoind handles many; bound by rpcworkqueue.",
    )
    p.add_argument("--progress-interval", type=int, default=50_000)
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after this many input rows (smoke test).",
    )
    args = p.parse_args()

    in_path = Path(args.input)
    # Default loads the consolidated supplement file built from all 5
    # extraction shards (archival-host node1+node2 + 3 worker hosts) plus
    # the gap-fill backfill — deduped by hathor_height. Use repeatable
    # --supplement to override (e.g. for re-validation with shard-level
    # provenance).
    supp_paths = [
        Path(s)
        for s in (
            args.supplement
            or [
                "data/hathor/hathor_funds_graph.csv",
            ]
        )
    ]
    out_path = Path(args.output)
    if not in_path.exists():
        print(f"Input not found: {in_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading supplement from {[str(p) for p in supp_paths]}...", file=sys.stderr)
    supplement = load_supplement(supp_paths)
    print(f"  loaded {len(supplement):,} funds+graph rows total", file=sys.stderr)

    rpc = BitcoinRPC(args.rpc_url)

    # Probe RPC.
    try:
        height = rpc.call("getblockcount")
    except Exception as e:
        print(f"RPC probe failed: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"BTC RPC OK, height={height:,}", file=sys.stderr)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    stats = {
        "input_rows": 0,
        "parse_fail": 0,
        "recon_fail": 0,
        "no_supplement": 0,
        "pow_fail": 0,
        "pow_pass_btc": 0,
        "pow_pass_nonbtc": 0,
    }
    t0 = time.time()

    with open(in_path) as f_in, open(out_path, "w", newline="") as f_out:
        reader = csv.DictReader(f_in)
        writer = csv.DictWriter(f_out, fieldnames=PHASE_A_COLUMNS)
        writer.writeheader()

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            batch_size = max(args.workers * 32, 256)
            batch: list[tuple[dict, str | None]] = []

            def flush(batch):
                """Submit ``batch`` to the thread pool, tally each row's status, and
                write any produced output row.
                """
                nonlocal stats
                futures = [
                    pool.submit(process_row, row, fg, rpc) for (row, fg) in batch
                ]
                for fut in futures:
                    status, out_row = fut.result()
                    stats[status] += 1
                    if out_row is not None:
                        writer.writerow(out_row)

            for row in reader:
                stats["input_rows"] += 1
                try:
                    h = int(row["hathor_height"])
                except (KeyError, ValueError):
                    h = -1
                fg = supplement.get(h)
                batch.append((row, fg))
                if len(batch) >= batch_size:
                    flush(batch)
                    batch = []

                    if stats["input_rows"] % args.progress_interval < batch_size:
                        elapsed = time.time() - t0
                        rate = stats["input_rows"] / elapsed if elapsed > 0 else 0
                        print(
                            f"  {stats['input_rows']:>10,} rows | "
                            f"{rate:7.1f}/s | "
                            f"no_supp={stats['no_supplement']:,} | "
                            f"recon_fail={stats['recon_fail']:,} | "
                            f"pow_fail={stats['pow_fail']:,} | "
                            f"btc_prev_found={stats['pow_pass_btc']:,} | "
                            f"unresolved={stats['pow_pass_nonbtc']:,}",
                            flush=True,
                        )
                    if args.limit and stats["input_rows"] >= args.limit:
                        break

            if batch:
                flush(batch)

    elapsed = time.time() - t0
    print(file=sys.stderr)
    print("=" * 64, file=sys.stderr)
    print(f"Phase A complete in {elapsed / 60:.1f}min", file=sys.stderr)
    for k, v in stats.items():
        print(f"  {k:>20s}: {v:>10,}", file=sys.stderr)
    pow_pass_total = stats["pow_pass_btc"] + stats["pow_pass_nonbtc"]
    if pow_pass_total:
        unresolved_pct = 100 * stats["pow_pass_nonbtc"] / pow_pass_total
        print(
            f"\nUnresolved share of PoW-passing rows: {unresolved_pct:.1f}% "
            f"({stats['pow_pass_nonbtc']:,} / {pow_pass_total:,})",
            file=sys.stderr,
        )
        print(
            "These rows lack canonical Bitcoin predecessor linkage; "
            "their parent chains are not identified.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
