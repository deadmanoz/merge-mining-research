#!/usr/bin/env python3
"""
Extract Bitcoin parent headers from RSK (Rootstock) merge-mining proofs.

RSK is an EVM chain, not a Bitcoin Core fork — it exposes merge-mining data
directly on each block via Ethereum-style JSON-RPC:

    eth_getBlockByNumber returns:
      bitcoinMergedMiningHeader              — 80-byte Bitcoin parent header
      bitcoinMergedMiningCoinbaseTransaction : trimmed SHA-256 state plus the
                                               unhashed coinbase tail; the full
                                               scriptSig is not preserved
      bitcoinMergedMiningMerkleProof         : Merkle path linking the proof
                                               commitment to the BTC coinbase
      hashForMergedMining                    — 32-byte hash committed in coinbase
      miner                                  - RBTC miner address retained for analysis

The historical extraction starts at RSK block 139,999. This is an acquisition
lower bound, not a consensus activation: earlier blocks interleave full 80-byte
merge-mining headers with 69/70-byte fallback signatures and require a
format-aware backfill.

Output: CSV with one row per extracted RSK merge-mining proof containing the Bitcoin parent
header fields and the available miner and truncated-coinbase evidence.
"""

import argparse
import csv
import hashlib
import struct
import sys
import time
from pathlib import Path

import requests

# Repo `src/` is on sys.path when installed via `pip install -e .`; the shared
# module is pure-stdlib and safe to import on the extraction host.
from stale_blocks_analysis.bitcoin_binary import format_outputs_canonical

# --- Configuration ---
RPC_URL = "http://127.0.0.1:4444"
RPC_HEADERS = {"content-type": "application/json"}

DEFAULT_EXTRACTION_START_HEIGHT = 139_999
BATCH_SIZE = 50  # RSKj caps batched JSON-RPC at 50 calls; bigger gets HTTP 400.
PROGRESS_INTERVAL = 10_000
MAX_RETRIES = 5

CSV_COLUMNS = [
    "rsk_height",
    "rsk_timestamp",
    "rsk_hash",  # RSK block hash, for explorer correlation
    "rsk_miner",  # RBTC miner address retained for later attribution research
    "rsk_difficulty",  # RSK difficulty at this block (hex)
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "merge_mining_hash",  # hashForMergedMining: 32-byte commit in BTC coinbase
    "merge_mining_merkle_proof",  # SPV proof linking RSK's commitment to the BTC merkle root
    "coinbase_outputs",  # shared canonical rendering (parsed from tail)
    "coinbase_op_return",  # semicolon-separated OP_RETURN data hex
    "coinbase_ascii_strings",  # semicolon-separated printable runs (>=4 chars)
    "coinbase_tail_hex",  # raw RSK-stored truncated tail (for re-parsing)
    "btc_header_hex",
    "is_uncle",  # 0 if canonical, 1 if uncle/ommer
    "uncle_index",  # uncle index within the canonical parent (empty for canonical)
    "uncle_parent_height",  # canonical RSK height that referenced this uncle (empty for canonical)
]

# Bitcoin coinbase output sanity bounds. RSK's truncated tail lacks the input
# section, so we have to find where outputs start by sliding offsets and
# accepting the first parse that consumes exactly (tail - locktime) bytes.
MAX_REASONABLE_VALUE = 50 * 100_000_000  # 50 BTC in sats; bigger means parse is wrong
MAX_REASONABLE_SCRIPT_LEN = 200  # coinbase scripts in practice; OP_RETURN max 80


def rpc_batch(calls: list[dict]) -> list:
    """Send a batch of JSON-RPC calls and return results.

    RSKj returns a *list* per the JSON-RPC 2.0 spec for a successful batch,
    but if the batch as a whole is rejected (e.g. concurrent-load contention,
    over-50 batch size), it returns a *dict* with an "error" key. We surface
    that as a RequestException so the caller's retry loop kicks in.
    """
    resp = requests.post(RPC_URL, json=calls, headers=RPC_HEADERS, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list):
        err = data.get("error") if isinstance(data, dict) else None
        msg = (
            (err or {}).get("message")
            if err
            else f"unexpected response: {str(data)[:200]}"
        )
        raise requests.RequestException(f"RSKj batch error: {msg}")
    # Per-call errors within an otherwise-200 batch — also retry whole batch.
    for r in data:
        if isinstance(r, dict) and "error" in r:
            err = r["error"] or {}
            raise requests.RequestException(
                f"per-call error in batch: id={r.get('id')} msg={err.get('message')}"
            )
    return data


def get_chain_tip() -> int:
    """Get the current RSK chain tip height (decimal)."""
    call = [{"jsonrpc": "2.0", "id": 0, "method": "eth_blockNumber", "params": []}]
    return int(rpc_batch(call)[0]["result"], 16)


def sha256d(data: bytes) -> bytes:
    """Double SHA-256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def parse_header(raw: bytes) -> dict:
    """Parse an 80-byte Bitcoin block header."""
    assert len(raw) == 80, f"header is {len(raw)} bytes, expected 80"
    version = struct.unpack_from("<I", raw, 0)[0]
    prev_hash = raw[4:36][::-1].hex()
    timestamp = struct.unpack_from("<I", raw, 68)[0]
    bits = struct.unpack_from("<I", raw, 72)[0]
    nonce = struct.unpack_from("<I", raw, 76)[0]
    block_hash = sha256d(raw)[::-1].hex()
    return {
        "hash": block_hash,
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "bits": f"{bits:08x}",
        "version": version,
        "nonce": nonce,
    }


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Bitcoin CompactSize varint. Returns (value, bytes_consumed)."""
    n = data[offset]
    if n < 0xFD:
        return n, 1
    if n == 0xFD:
        return struct.unpack_from("<H", data, offset + 1)[0], 3
    if n == 0xFE:
        return struct.unpack_from("<I", data, offset + 1)[0], 5
    return struct.unpack_from("<Q", data, offset + 1)[0], 9


def _try_parse_outputs(body: bytes) -> list[dict] | None:
    """Try to parse a sequence of Bitcoin tx outputs that exactly fills body.

    Returns list of {value, script_hex} on success, None on failure. Sanity
    bounds (value, script_len) reject obviously-wrong offsets quickly.
    """
    outputs: list[dict] = []
    off = 0
    while off < len(body):
        if len(body) - off < 9:  # 8-byte value + at least 1-byte script_len
            return None
        value = struct.unpack_from("<Q", body, off)[0]
        if value > MAX_REASONABLE_VALUE:
            return None
        off += 8
        n = body[off]
        if n < 0xFD:
            script_len = n
            off += 1
        elif n == 0xFD and off + 3 <= len(body):
            script_len = struct.unpack_from("<H", body, off + 1)[0]
            off += 3
        else:
            return None
        if script_len == 0 or script_len > MAX_REASONABLE_SCRIPT_LEN:
            return None
        if off + script_len > len(body):
            return None
        outputs.append(
            {
                "value": value,
                "script_hex": body[off : off + script_len].hex(),
            }
        )
        off += script_len
    return outputs if outputs else None


def parse_coinbase_tail(tail_hex: str) -> list[dict] | None:
    """Locate the outputs section in RSK's truncated coinbase tail.

    The tail starts at a SHA-256 midstate boundary inside the coinbase tx, so
    its leading bytes are arbitrary mid-data. We walk forward from each offset
    looking for a parse that lands exactly on the locktime (last 4 bytes of
    the tx). If multiple offsets succeed we prefer the leftmost (more output
    history captured).
    """
    try:
        raw = bytes.fromhex(tail_hex.removeprefix("0x"))
    except ValueError:
        return None
    if len(raw) < 13:  # 8 + 1 + 0 + 4 minimum
        return None
    body = raw[:-4]  # strip locktime
    for start in range(len(body)):
        outputs = _try_parse_outputs(body[start:])
        if outputs:
            return outputs
    return None


def extract_op_returns(outputs: list[dict]) -> list[str]:
    """Pull the data payload from any OP_RETURN outputs."""
    payloads = []
    for o in outputs:
        s = bytes.fromhex(o["script_hex"])
        if not s or s[0] != 0x6A:  # OP_RETURN
            continue
        # Push opcodes follow; just return everything past the OP_RETURN
        # opcode and any push-length byte(s).
        i = 1
        if i >= len(s):
            continue
        if s[i] <= 0x4B:  # direct push 1-75
            data = s[i + 1 : i + 1 + s[i]]
        elif s[i] == 0x4C and i + 1 < len(s):  # OP_PUSHDATA1
            push_len = s[i + 1]
            data = s[i + 2 : i + 2 + push_len]
        elif s[i] == 0x4D and i + 2 < len(s):  # OP_PUSHDATA2
            push_len = struct.unpack_from("<H", s, i + 1)[0]
            data = s[i + 3 : i + 3 + push_len]
        else:
            data = s[i:]  # best-effort: dump rest
        payloads.append(data.hex())
    return payloads


def extract_ascii_strings(raw: bytes, min_len: int = 4) -> list[str]:
    """Find runs of printable ASCII >= min_len chars. Useful for pool tags."""
    out = []
    cur = bytearray()
    for b in raw:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return out


def format_outputs(outputs: list[dict]) -> str:
    """Render parsed coinbase outputs in the shared canonical rendering.

    Semicolon-joined ``<payout>:<value_sats>`` per docs/data-reference.md;
    the tail parse yields integer-satoshi values and raw script bytes, so the
    rendering is exact-script evidence.
    """
    return format_outputs_canonical(
        [(o["value"], bytes.fromhex(o["script_hex"])) for o in outputs]
    )


def block_to_row(
    block: dict,
    rsk_height: int,
    *,
    is_uncle: bool = False,
    uncle_index: int | None = None,
    uncle_parent_height: int | None = None,
) -> dict | None:
    """Render an RSK block (canonical or uncle) into the output CSV row.

    Returns None if the block doesn't have a valid 80-byte merge-mining header
    (for example, a fallback signature or malformed value). The caller increments
    skip statistics in that case.
    """
    hdr_hex = block.get("bitcoinMergedMiningHeader") or ""
    hdr_bytes = bytes.fromhex(hdr_hex.removeprefix("0x")) if hdr_hex else b""
    if len(hdr_bytes) != 80:
        return None

    header = parse_header(hdr_bytes)

    cb_hex = block.get("bitcoinMergedMiningCoinbaseTransaction") or ""
    cb_clean = cb_hex.removeprefix("0x") if cb_hex else ""
    outputs = parse_coinbase_tail(cb_clean) if cb_clean else None
    op_returns = extract_op_returns(outputs) if outputs else []
    ascii_runs = extract_ascii_strings(bytes.fromhex(cb_clean)) if cb_clean else []

    mm_proof = (block.get("bitcoinMergedMiningMerkleProof") or "").removeprefix("0x")
    mm_hash = (block.get("hashForMergedMining") or "").removeprefix("0x")

    return {
        "rsk_height": rsk_height,
        "rsk_timestamp": int(block["timestamp"], 16),
        "rsk_hash": (block.get("hash") or "").removeprefix("0x"),
        "rsk_miner": (block.get("miner") or "").removeprefix("0x"),
        "rsk_difficulty": (block.get("difficulty") or "").removeprefix("0x"),
        "btc_header_hash": header["hash"],
        "btc_prev_hash": header["prev_hash"],
        "btc_time": header["timestamp"],
        "btc_bits": header["bits"],
        "merge_mining_hash": mm_hash,
        "merge_mining_merkle_proof": mm_proof,
        "coinbase_outputs": format_outputs(outputs) if outputs else "",
        "coinbase_op_return": ";".join(op_returns),
        "coinbase_ascii_strings": ";".join(ascii_runs),
        "coinbase_tail_hex": cb_clean,
        "btc_header_hex": hdr_hex.removeprefix("0x"),
        "is_uncle": 1 if is_uncle else 0,
        "uncle_index": uncle_index if uncle_index is not None else "",
        "uncle_parent_height": uncle_parent_height
        if uncle_parent_height is not None
        else "",
    }


def extract_range(start: int, end: int, writer: csv.DictWriter, stats: dict):
    """Extract merge-mining data for [start, end) RSK heights.

    Walks both canonical RSK blocks and any uncle/ommer blocks they reference.
    RSK uncles carry their own 80-byte BTC parent header (each uncle is a
    separate merge-mining attempt), confirmed via `eth_getUncleByBlockNumberAndIndex`.
    Skipping them loses candidates the self-target PoW filter would otherwise
    surface.
    """
    calls = [
        {
            "jsonrpc": "2.0",
            "id": i,
            "method": "eth_getBlockByNumber",
            "params": [hex(h), False],
        }
        for i, h in enumerate(range(start, end))
    ]
    results = rpc_batch(calls)
    results.sort(key=lambda x: x["id"])

    # Two-phase: canonical first, then any uncle calls batched together. The
    # uncle index list comes from the canonical response's `uncles` array, so
    # the uncle batch shape depends on phase 1's output.
    uncle_calls: list[dict] = []
    uncle_lookup: list[tuple[int, int]] = []  # (parent_height, uncle_index)
    next_id = 0

    for i, r in enumerate(results):
        height = start + i
        block = r.get("result")
        if not block:
            stats["skipped_no_block"] += 1
            continue

        row = block_to_row(block, height)
        if row is None:
            stats["skipped_pre_auxpow"] += 1
        else:
            stats["auxpow_blocks"] += 1
            writer.writerow(row)

        # Queue uncle RPCs for phase 2. RSK uncles can have their own full
        # merge-mining header even if the canonical block at this height has a
        # fallback signature (and vice versa). Emit every uncle regardless of
        # the canonical block's proof format.
        for ui in range(len(block.get("uncles") or [])):
            uncle_calls.append(
                {
                    "jsonrpc": "2.0",
                    "id": next_id,
                    "method": "eth_getUncleByBlockNumberAndIndex",
                    "params": [hex(height), hex(ui)],
                }
            )
            uncle_lookup.append((height, ui))
            next_id += 1

    # Phase 2: fetch and emit uncles. Chunk by BATCH_SIZE to respect RSKj's
    # batched-RPC cap.
    for chunk_start in range(0, len(uncle_calls), BATCH_SIZE):
        chunk = uncle_calls[chunk_start : chunk_start + BATCH_SIZE]
        # Re-id within the chunk because RSKj caps batches at 50 — the global
        # next_id values would still work, but using a 0..N-1 sequence per chunk
        # makes the response sort straightforward.
        for j, call in enumerate(chunk):
            call["id"] = j
        chunk_results = rpc_batch(chunk)
        chunk_results.sort(key=lambda x: x["id"])
        for j, rr in enumerate(chunk_results):
            parent_height, ui = uncle_lookup[chunk_start + j]
            u = rr.get("result")
            if not u:
                stats["uncle_skipped_null"] += 1
                continue
            uncle_height = int(u["number"], 16)
            row = block_to_row(
                u,
                uncle_height,
                is_uncle=True,
                uncle_index=ui,
                uncle_parent_height=parent_height,
            )
            if row is None:
                stats["uncle_skipped_pre_auxpow"] += 1
            else:
                stats["uncle_auxpow_blocks"] += 1
                writer.writerow(row)


def main():
    """Parse CLI args, extract RSK's merge-mining range (canonical blocks plus
    uncles) in batches, and write the output CSV.

    Resolves ``--end`` to the current chain tip when omitted. Each batch
    is retried with exponential backoff (up to ``MAX_RETRIES``) on
    ``requests.RequestException``, exiting with status 1 if retries are
    exhausted. Flushes the output file after every batch (long runs can
    span millions of blocks) and prints periodic progress/ETA plus a
    final per-``stats``-key summary.
    """
    p = argparse.ArgumentParser(
        description="Extract Bitcoin merge-mining proofs from RSK"
    )
    p.add_argument(
        "--start",
        type=int,
        default=DEFAULT_EXTRACTION_START_HEIGHT,
        help="Start RSK height (default: historical acquisition floor 139999)",
    )
    p.add_argument(
        "--end",
        type=int,
        default=None,
        help="End RSK height, exclusive (default: chain tip)",
    )
    p.add_argument(
        "--output", type=str, default="data/rsk_auxpow_raw.csv", help="Output CSV path"
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=BATCH_SIZE,
        help="RPC batch size (blocks per HTTP request)",
    )
    args = p.parse_args()

    tip = get_chain_tip()
    end = args.end if args.end is not None else tip + 1
    print(f"RSK chain tip: {tip:,}", file=sys.stderr)
    print(
        f"Extracting blocks [{args.start:,}, {end:,}) = {end - args.start:,} blocks",
        file=sys.stderr,
    )

    out_path = Path(args.output)
    stats = {
        "auxpow_blocks": 0,
        "skipped_pre_auxpow": 0,
        "skipped_no_block": 0,
        "uncle_auxpow_blocks": 0,
        "uncle_skipped_pre_auxpow": 0,
        "uncle_skipped_null": 0,
    }
    t0 = time.time()
    last_progress = args.start

    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        h = args.start
        while h < end:
            batch_end = min(h + args.batch_size, end)
            attempt = 0
            while True:
                try:
                    extract_range(h, batch_end, writer, stats)
                    break
                except requests.RequestException as e:
                    attempt += 1
                    if attempt > MAX_RETRIES:
                        print(
                            f"\nFATAL: RPC error at h={h} after "
                            f"{MAX_RETRIES} retries: {e}",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    backoff = min(2**attempt, 30)
                    print(
                        f"  RPC error at h={h} (attempt {attempt}/"
                        f"{MAX_RETRIES}): {e}; retry in {backoff}s",
                        file=sys.stderr,
                    )
                    time.sleep(backoff)
            h = batch_end
            f.flush()  # 8.65M-block run: don't lose progress on crash
            if h - last_progress >= PROGRESS_INTERVAL:
                elapsed = time.time() - t0
                rate = (h - args.start) / elapsed if elapsed > 0 else 0
                eta_sec = (end - h) / rate if rate > 0 else 0
                print(
                    f"  h={h:,} canon={stats['auxpow_blocks']:,} "
                    f"uncle={stats['uncle_auxpow_blocks']:,} "
                    f"pre={stats['skipped_pre_auxpow']:,} "
                    f"rate={rate:,.0f} bps eta={eta_sec / 60:.0f}m",
                    file=sys.stderr,
                )
                last_progress = h

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed / 60:.1f} min", file=sys.stderr)
    print(f"  auxpow_blocks:           {stats['auxpow_blocks']:,}", file=sys.stderr)
    print(
        f"  skipped_pre_auxpow:      {stats['skipped_pre_auxpow']:,}", file=sys.stderr
    )
    print(f"  skipped_no_block:        {stats['skipped_no_block']:,}", file=sys.stderr)
    print(
        f"  uncle_auxpow_blocks:     {stats['uncle_auxpow_blocks']:,}", file=sys.stderr
    )
    print(
        f"  uncle_skipped_pre_auxpow:{stats['uncle_skipped_pre_auxpow']:,}",
        file=sys.stderr,
    )
    print(
        f"  uncle_skipped_null:      {stats['uncle_skipped_null']:,}", file=sys.stderr
    )
    print(f"  output:                  {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
