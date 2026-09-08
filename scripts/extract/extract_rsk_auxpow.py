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

The retained historical extraction starts at RSK block 139,999. This is an
acquisition lower bound, not a consensus activation: earlier blocks interleave
full 80-byte merge-mining headers with 69/70-byte fallback signatures. Current
runs require explicit bounds and retain the full headers while accounting for
those fallback shapes and the exact height-zero ``0x00`` sentinel as skips.

Output: CSV with one row per extracted RSK merge-mining proof containing the Bitcoin parent
header fields and the available miner and truncated-coinbase evidence.
"""

import argparse
import hashlib
import os
import struct
import sys
import time
from pathlib import Path

import requests

# Repo `src/` is on sys.path when installed via `pip install -e .`; the shared
# module is pure-stdlib and safe to import on the extraction host.
from stale_blocks_analysis.bitcoin_binary import format_outputs_canonical
from stale_blocks_analysis.rsk_extraction import (
    commit_interval,
    default_checkpoint_path,
    default_skip_ledger_path,
    empty_stats,
    prepare_extraction,
    seal_extraction,
)

# --- Configuration ---
RPC_URL = "http://127.0.0.1:4444"
RPC_HEADERS = {"content-type": "application/json"}

BATCH_SIZE = 50  # RSKj caps batched JSON-RPC at 50 calls; bigger gets HTTP 400.
CHECKPOINT_INTERVAL = 10_000
PROGRESS_INTERVAL = 10_000
MAX_RETRIES = 5

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
    resp = requests.post(
        os.environ.get("RSK_RPC_URL", RPC_URL),
        json=calls,
        headers=RPC_HEADERS,
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list):
        err = data.get("error") if isinstance(data, dict) else None
        msg = (
            err.get("message")
            if isinstance(err, dict)
            else repr(err)
            if err is not None
            else f"unexpected response: {data!r}"
        )
        raise requests.RequestException(f"RSKj batch error: {msg}")
    # Per-call errors within an otherwise-200 batch — also retry whole batch.
    for r in data:
        if isinstance(r, dict) and "error" in r:
            err = r["error"]
            message = err.get("message") if isinstance(err, dict) else repr(err)
            raise requests.RequestException(
                f"per-call error in batch: id={r.get('id')} msg={message}"
            )
    return data


def ordered_rpc_results(results: list, expected_count: int, method: str) -> list[dict]:
    """Validate and order one RSKj batch by its exact integer IDs."""
    if len(results) != expected_count or any(
        not isinstance(row, dict) for row in results
    ):
        raise requests.RequestException(
            f"{method} returned {len(results)} responses for {expected_count} calls"
        )
    ids = [row.get("id") for row in results]
    if any(type(response_id) is not int for response_id in ids):
        raise requests.RequestException(
            f"{method} returned a non-integer JSON-RPC response ID"
        )
    by_id = {row["id"]: row for row in results}
    expected_ids = set(range(expected_count))
    if len(by_id) != expected_count or set(by_id) != expected_ids:
        raise requests.RequestException(
            f"{method} returned duplicate, missing, or unexpected response IDs"
        )
    return [by_id[index] for index in range(expected_count)]


def get_chain_tip() -> int:
    """Get the current RSK chain tip height (decimal)."""
    call = [{"jsonrpc": "2.0", "id": 0, "method": "eth_blockNumber", "params": []}]
    result = ordered_rpc_results(rpc_batch(call), 1, "eth_blockNumber")[0].get("result")
    try:
        tip = int(result, 16)
    except (TypeError, ValueError) as exc:
        raise requests.RequestException(
            f"eth_blockNumber returned malformed result {result!r}"
        ) from exc
    if tip < 0:
        raise requests.RequestException("eth_blockNumber returned a negative height")
    return tip


def _hex_bytes(value: object, *, field: str, expected_bytes: int | None = None) -> str:
    """Normalize one 0x-prefixed or plain hex value, failing on bad shape."""
    if not isinstance(value, str):
        raise requests.RequestException(f"RSK {field} is not a hex string")
    normalized = value.removeprefix("0x").lower()
    if len(normalized) % 2 or (
        expected_bytes is not None and len(normalized) != 2 * expected_bytes
    ):
        raise requests.RequestException(f"RSK {field} has malformed length")
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise requests.RequestException(f"RSK {field} is malformed hex") from exc
    return normalized


def _quantity(value: object, *, field: str) -> int:
    """Parse one non-negative Ethereum JSON-RPC quantity."""
    if not isinstance(value, str) or not value.startswith("0x"):
        raise requests.RequestException(f"RSK {field} is not an RPC quantity")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise requests.RequestException(f"RSK {field} is malformed") from exc
    if parsed < 0:
        raise requests.RequestException(f"RSK {field} is negative")
    return parsed


def canonical_identity(block: object, expected_height: int, *, context: str) -> dict:
    """Validate and return one canonical RSK block's continuity identity."""
    if not isinstance(block, dict):
        raise requests.RequestException(f"{context} returned a null/non-object block")
    height = _quantity(block.get("number"), field=f"{context} number")
    if height != expected_height:
        raise requests.RequestException(
            f"{context} returned height {height}, expected {expected_height}"
        )
    uncles = block.get("uncles")
    if not isinstance(uncles, list):
        raise requests.RequestException(f"{context} has a malformed uncles list")
    advertised_uncles = [
        _hex_bytes(value, field=f"{context} uncle hash", expected_bytes=32)
        for value in uncles
    ]
    if len(advertised_uncles) != len(set(advertised_uncles)):
        raise requests.RequestException(f"{context} advertises duplicate uncle hashes")
    return {
        "height": height,
        "hash": _hex_bytes(
            block.get("hash"), field=f"{context} hash", expected_bytes=32
        ),
        "parent_hash": _hex_bytes(
            block.get("parentHash"), field=f"{context} parentHash", expected_bytes=32
        ),
        "timestamp": _quantity(block.get("timestamp"), field=f"{context} timestamp"),
        "advertised_uncles": advertised_uncles,
    }


def get_block_identity(height: int) -> dict:
    """Return one fully validated canonical RSK endpoint identity."""
    call = [
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "eth_getBlockByNumber",
            "params": [hex(height), False],
        }
    ]
    result = ordered_rpc_results(rpc_batch(call), 1, "endpoint pin")[0].get("result")
    identity = canonical_identity(result, height, context=f"RSK block {height}")
    return {
        field: identity[field]
        for field in ("height", "hash", "parent_hash", "timestamp")
    }


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


def _optional_hex(value: object, *, field: str) -> str:
    """Normalize an optional even-length hexadecimal proof component."""
    if value in (None, "", "0x"):
        return ""
    return _hex_bytes(value, field=field)


def block_to_record(
    block: dict,
    identity: dict,
    *,
    is_uncle: bool = False,
    uncle_index: int | None = None,
    uncle_parent_height: int | None = None,
) -> tuple[dict | None, dict | None]:
    """Return exactly one raw row or intentional-skip ledger row for a block."""
    context = (
        f"RSK uncle {identity['hash']}"
        if is_uncle
        else f"RSK canonical block {identity['height']}"
    )
    hdr_hex = _hex_bytes(
        block.get("bitcoinMergedMiningHeader"), field=f"{context} merge-mining header"
    )
    hdr_bytes = bytes.fromhex(hdr_hex)
    if len(hdr_bytes) != 80:
        is_genesis_sentinel = (
            not is_uncle and identity["height"] == 0 and hdr_bytes == b"\x00"
        )
        is_fallback = len(hdr_bytes) in (69, 70)
        if not (is_genesis_sentinel or is_fallback):
            raise requests.RequestException(
                f"{context} has unsupported merge-mining proof length "
                f"{len(hdr_bytes)} bytes"
            )
        return None, {
            "rsk_height": identity["height"],
            "rsk_timestamp": identity["timestamp"],
            "rsk_hash": identity["hash"],
            "is_uncle": 1 if is_uncle else 0,
            "uncle_index": uncle_index if uncle_index is not None else "",
            "uncle_parent_height": (
                uncle_parent_height if uncle_parent_height is not None else ""
            ),
            "advertised_uncle_hash": identity["hash"] if is_uncle else "",
            "proof_bytes": len(hdr_bytes),
            "reason": "genesis_sentinel"
            if is_genesis_sentinel
            else "fallback_signature",
        }

    header = parse_header(hdr_bytes)

    cb_clean = _optional_hex(
        block.get("bitcoinMergedMiningCoinbaseTransaction"),
        field=f"{context} coinbase tail",
    )
    outputs = parse_coinbase_tail(cb_clean) if cb_clean else None
    op_returns = extract_op_returns(outputs) if outputs else []
    ascii_runs = extract_ascii_strings(bytes.fromhex(cb_clean)) if cb_clean else []

    mm_proof = _optional_hex(
        block.get("bitcoinMergedMiningMerkleProof"),
        field=f"{context} merge-mining merkle proof",
    )
    mm_hash = _hex_bytes(
        block.get("hashForMergedMining"),
        field=f"{context} merge-mining hash",
        expected_bytes=32,
    )
    miner = _hex_bytes(block.get("miner"), field=f"{context} miner", expected_bytes=20)
    difficulty = _quantity(block.get("difficulty"), field=f"{context} difficulty")

    return {
        "rsk_height": identity["height"],
        "rsk_timestamp": identity["timestamp"],
        "rsk_hash": identity["hash"],
        "rsk_miner": miner,
        "rsk_difficulty": f"{difficulty:x}",
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
    }, None


def _uncle_identity(block: object, advertised_hash: str, *, context: str) -> dict:
    """Validate one listed uncle and bind the RPC result to its advertised hash."""
    if not isinstance(block, dict):
        raise requests.RequestException(f"{context} returned a null/non-object uncle")
    identity = {
        "height": _quantity(block.get("number"), field=f"{context} number"),
        "hash": _hex_bytes(
            block.get("hash"), field=f"{context} hash", expected_bytes=32
        ),
        "parent_hash": _hex_bytes(
            block.get("parentHash"), field=f"{context} parentHash", expected_bytes=32
        ),
        "timestamp": _quantity(block.get("timestamp"), field=f"{context} timestamp"),
    }
    if identity["hash"] != advertised_hash:
        raise requests.RequestException(
            f"{context} returned {identity['hash']}, advertised {advertised_hash}"
        )
    return identity


def extract_range(
    start: int,
    end: int,
    *,
    rpc_batch_size: int = BATCH_SIZE,
    previous_hash: str = "",
    expected_start_identity: dict | None = None,
) -> tuple[list[dict], list[dict], dict[str, int], dict, dict, int]:
    """Extract and validate one durable interval of canonical heights.

    Walks both canonical RSK blocks and any uncle/ommer blocks they reference.
    RPC batches are independently capped by ``rpc_batch_size`` while the whole
    interval remains in memory as one durable checkpoint unit.  Every canonical
    height and every advertised uncle has exactly one raw-row or skip-ledger
    outcome. Transient RPC failures retry the affected batch. Null responses,
    unadvertised identities, broken continuity and unsupported proof shapes
    fail immediately without advancing the checkpoint; diagnose the source
    before resuming those integrity failures.
    """
    if not 1 <= rpc_batch_size <= BATCH_SIZE:
        raise ValueError(f"rpc_batch_size must be between 1 and {BATCH_SIZE}")
    rows: list[dict] = []
    skips: list[dict] = []
    stats = empty_stats()
    first_identity: dict | None = None
    last_identity: dict | None = None
    expected_parent_hash = previous_hash
    advertised_uncle_count = 0

    for chunk_start in range(start, end, rpc_batch_size):
        chunk_end = min(chunk_start + rpc_batch_size, end)
        calls = [
            {
                "jsonrpc": "2.0",
                "id": index,
                "method": "eth_getBlockByNumber",
                "params": [hex(height), False],
            }
            for index, height in enumerate(range(chunk_start, chunk_end))
        ]
        results = ordered_rpc_results(
            retry_rpc("canonical block batch", lambda: rpc_batch(calls)),
            len(calls),
            "canonical block batch",
        )
        uncle_calls: list[dict] = []
        uncle_lookup: list[tuple[int, int, str]] = []
        for offset, response in enumerate(results):
            height = chunk_start + offset
            block = response.get("result")
            identity_with_uncles = canonical_identity(
                block, height, context=f"RSK canonical block {height}"
            )
            identity = {
                field: identity_with_uncles[field]
                for field in ("height", "hash", "parent_hash", "timestamp")
            }
            if first_identity is None:
                first_identity = identity
                if (
                    expected_start_identity is not None
                    and identity != expected_start_identity
                ):
                    raise requests.RequestException(
                        "canonical extraction does not match the pinned start identity"
                    )
            if expected_parent_hash and identity["parent_hash"] != expected_parent_hash:
                raise requests.RequestException(
                    f"canonical continuity break at RSK height {height}: "
                    f"{identity['parent_hash']} != {expected_parent_hash}"
                )
            expected_parent_hash = identity["hash"]
            last_identity = identity

            row, skip = block_to_record(block, identity)
            if row is not None:
                stats["auxpow_blocks"] += 1
                rows.append(row)
            else:
                stats["skipped_pre_auxpow"] += 1
                skips.append(skip)

            for uncle_index, advertised_hash in enumerate(
                identity_with_uncles["advertised_uncles"]
            ):
                uncle_calls.append(
                    {
                        "jsonrpc": "2.0",
                        "id": len(uncle_calls),
                        "method": "eth_getUncleByBlockNumberAndIndex",
                        "params": [hex(height), hex(uncle_index)],
                    }
                )
                uncle_lookup.append((height, uncle_index, advertised_hash))
        advertised_uncle_count += len(uncle_calls)

        for uncle_chunk_start in range(0, len(uncle_calls), rpc_batch_size):
            uncle_chunk = uncle_calls[
                uncle_chunk_start : uncle_chunk_start + rpc_batch_size
            ]
            for response_id, call in enumerate(uncle_chunk):
                call["id"] = response_id
            uncle_results = ordered_rpc_results(
                retry_rpc("uncle block batch", lambda: rpc_batch(uncle_chunk)),
                len(uncle_chunk),
                "uncle block batch",
            )
            for offset, response in enumerate(uncle_results):
                parent_height, uncle_index, advertised_hash = uncle_lookup[
                    uncle_chunk_start + offset
                ]
                context = f"RSK uncle {parent_height}:{uncle_index}"
                block = response.get("result")
                identity = _uncle_identity(block, advertised_hash, context=context)
                row, skip = block_to_record(
                    block,
                    identity,
                    is_uncle=True,
                    uncle_index=uncle_index,
                    uncle_parent_height=parent_height,
                )
                if row is not None:
                    stats["uncle_auxpow_blocks"] += 1
                    rows.append(row)
                else:
                    stats["uncle_skipped_pre_auxpow"] += 1
                    skips.append(skip)

    if first_identity is None or last_identity is None:
        raise ValueError("RSK extraction interval is empty")
    return (
        rows,
        skips,
        stats,
        first_identity,
        last_identity,
        advertised_uncle_count,
    )


def parse_args(argv: list[str] | None = None):
    """Parse the explicit, resumable RSK extraction contract."""
    parser = argparse.ArgumentParser(
        description="Extract Bitcoin merge-mining proofs from RSK"
    )
    parser.add_argument("--start", type=int, required=True, help="Start RSK height")
    parser.add_argument(
        "--end", type=int, required=True, help="End RSK height, exclusive"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="Private raw output CSV path"
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        help="Checkpoint sidecar (default: <output>.checkpoint.json)",
    )
    parser.add_argument(
        "--skip-ledger",
        type=Path,
        default=None,
        help="Private fallback ledger (default: <output>.skips.csv)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=BATCH_SIZE,
        help="RPC batch size (1-50 blocks per HTTP request)",
    )
    parser.add_argument(
        "--checkpoint-interval",
        type=int,
        default=CHECKPOINT_INTERVAL,
        help="Canonical heights per durable commit (independent of RPC batch size)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume the exact start/end/output contract from its checkpoint",
    )
    args = parser.parse_args(argv)
    if args.start < 0 or args.end <= args.start:
        parser.error("require 0 <= --start < --end")
    if not 1 <= args.batch_size <= BATCH_SIZE:
        parser.error(f"--batch-size must be between 1 and {BATCH_SIZE}")
    if args.checkpoint_interval < 1:
        parser.error("--checkpoint-interval must be positive")
    return args


def retry_rpc(label: str, operation):
    """Retry one fail-closed RSK RPC acquisition unit."""
    attempt = 0
    while True:
        try:
            return operation()
        except requests.RequestException as exc:
            attempt += 1
            if attempt > MAX_RETRIES:
                raise RuntimeError(
                    f"{label} failed after {MAX_RETRIES} retries: {exc}"
                ) from exc
            backoff = min(2**attempt, 30)
            print(
                f"  {label} error (attempt {attempt}/{MAX_RETRIES}): "
                f"{exc}; retry in {backoff}s",
                file=sys.stderr,
            )
            time.sleep(backoff)


def main():
    """Parse CLI args, extract RSK's merge-mining range (canonical blocks plus
    uncles) in batches, and write the output CSV.

    Requires an explicit half-open range and pins both source-chain endpoints.
    RPC batches remain capped independently from the durable commit interval.
    Each interval holds canonical rows, uncles, and intentional fallback skips
    in memory until every RPC and invariant succeeds, then fsyncs both CSVs
    before advancing the checkpoint. The end identity is fetched again before
    the completed content digests are sealed.
    """
    args = parse_args()

    tip = retry_rpc("RSK tip pin", get_chain_tip)
    if args.end > tip + 1:
        raise ValueError(
            f"requested end {args.end:,} is beyond current RSK tip {tip:,}"
        )
    start_identity = retry_rpc("RSK start pin", lambda: get_block_identity(args.start))
    end_identity = retry_rpc("RSK end pin", lambda: get_block_identity(args.end - 1))
    print(f"RSK chain tip: {tip:,}", file=sys.stderr)
    print(
        f"Extracting blocks [{args.start:,}, {args.end:,}) = "
        f"{args.end - args.start:,} blocks "
        f"(start {start_identity['hash']}, end {end_identity['hash']})",
        file=sys.stderr,
    )

    out_path = args.output
    checkpoint_path = args.checkpoint or default_checkpoint_path(out_path)
    skip_path = args.skip_ledger or default_skip_ledger_path(out_path)
    state = prepare_extraction(
        out_path,
        checkpoint_path,
        skip_path,
        start=args.start,
        end=args.end,
        start_identity=start_identity,
        end_identity=end_identity,
        resume=args.resume,
    )
    if args.resume:
        print(
            f"Resuming from RSK height {state['next_height']:,} "
            f"using {checkpoint_path}",
            file=sys.stderr,
        )

    t0 = time.time()
    run_start = state["next_height"]
    last_progress = run_start

    h = state["next_height"]
    while h < args.end:
        batch_end = min(h + args.checkpoint_interval, args.end)
        (
            rows,
            skips,
            stats_delta,
            first_identity,
            last_identity,
            advertised_uncles,
        ) = extract_range(
            h,
            batch_end,
            rpc_batch_size=args.batch_size,
            previous_hash=(state["last_canonical_identity"] or {}).get("hash", ""),
            expected_start_identity=(start_identity if h == args.start else None),
        )
        state = commit_interval(
            out_path,
            checkpoint_path,
            skip_path,
            state,
            rows=rows,
            skips=skips,
            stats_delta=stats_delta,
            next_height=batch_end,
            first_identity=first_identity,
            last_identity=last_identity,
            advertised_uncles=advertised_uncles,
        )
        h = batch_end
        if h - last_progress >= PROGRESS_INTERVAL:
            elapsed = time.time() - t0
            rate = (h - run_start) / elapsed if elapsed > 0 else 0
            eta_sec = (args.end - h) / rate if rate > 0 else 0
            stats = state["stats"]
            print(
                f"  h={h:,} canon={stats['auxpow_blocks']:,} "
                f"uncle={stats['uncle_auxpow_blocks']:,} "
                f"pre={stats['skipped_pre_auxpow']:,} "
                f"rate={rate:,.0f} bps eta={eta_sec / 60:.0f}m",
                file=sys.stderr,
            )
            last_progress = h

    if not state["complete"]:
        rechecked_end = retry_rpc(
            "RSK final end recheck", lambda: get_block_identity(args.end - 1)
        )
        state = seal_extraction(
            out_path,
            checkpoint_path,
            skip_path,
            state,
            rechecked_end_identity=rechecked_end,
        )

    elapsed = time.time() - t0
    stats = state["stats"]
    print(f"\nDone in {elapsed / 60:.1f} min", file=sys.stderr)
    print(f"  auxpow_blocks:           {stats['auxpow_blocks']:,}", file=sys.stderr)
    print(
        f"  skipped_pre_auxpow:      {stats['skipped_pre_auxpow']:,}", file=sys.stderr
    )
    print(
        f"  uncle_auxpow_blocks:     {stats['uncle_auxpow_blocks']:,}", file=sys.stderr
    )
    print(
        f"  uncle_skipped_pre_auxpow:{stats['uncle_skipped_pre_auxpow']:,}",
        file=sys.stderr,
    )
    print(f"  output:                  {out_path}", file=sys.stderr)
    print(f"  fallback ledger:         {skip_path}", file=sys.stderr)
    print(f"  checkpoint:              {checkpoint_path}", file=sys.stderr)
    print(f"  content sha256:          {state['content_sha256']}", file=sys.stderr)


if __name__ == "__main__":
    main()
