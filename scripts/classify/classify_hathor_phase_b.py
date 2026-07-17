#!/usr/bin/env python3
"""Phase B: classify Phase A's BTC-parent candidates as canonical / stale / unknown.

Reads ``hathor_phase_a.csv`` (Phase A output), filters to rows with
``btc_rpc_match == "true"`` (3,612 candidates per the run on 2026-05-20),
computes ``SHA256d(btc_header_hex)`` → the candidate BTC block hash,
then calls ``getblockheader`` against the local BTC RPC.

Categorisation:
  - ``canonical``: getblockheader returns a result with confirmations > 0
    (= the block sits on BTC's main chain at that height — uninteresting
    for stale-block recovery, but we count them for the report)
  - ``stale``: getblockheader returns confirmations == -1 (= the BTC node
    knows the block as a side-chain block) **OR** the BTC node returns
    "block not found" (= our node never saw it; valid PoW + valid prev,
    but lost the race and never propagated to this node). The brief
    treats both as "stale" for our purposes — the deeper distinction
    (stale vs unknown) is left to downstream pool/coinbase analysis.

Output: ``hathor_stale_blocks.csv`` with the full Phase A columns plus:
  - ``classification``: "canonical" | "stale"
  - ``btc_canonical_height``: int (for canonical) or empty
  - ``btc_confirmations``: from getblockheader, or empty for not-found

Self-contained — runs on the archival host with stdlib + requests.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests


OUTPUT_COLUMNS = [
    # All Phase A columns:
    "hathor_height",
    "hathor_block_hash",
    "hathor_timestamp",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_nonce",
    "btc_header_hex",
    "full_coinbase_hex",
    "btc_rpc_match",
    # Phase B additions:
    "btc_header_hash",
    "classification",  # "canonical" | "stale"
    "btc_canonical_height",  # int for canonical, empty otherwise
    "btc_confirmations",  # from getblockheader, or empty if not-found
    "btc_parent_height",  # height of btc_prev_hash on the main chain
    "btc_parent_mediantime",  # MTP of btc_prev_hash on the main chain
    "expected_nbits",  # canonical nBits at btc_parent_height + 1
    # VALID | NBITS_MISMATCH | PARENT_NOT_CANONICAL | PARENT_CONTEXT_UNAVAILABLE
    "validation_status",
]


def sha256d(b: bytes) -> bytes:
    """Double-SHA256, the Bitcoin block/tx hash primitive."""
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class BitcoinRPC:
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

    def call(self, method: str, params: list | None = None):
        """Make one JSON-RPC 1.0 call and return its ``result``.

        Raises ``BitcoinRPCError`` on an HTTP 500 or a non-null ``error``
        field in the response body.
        """
        self._id += 1
        body = {
            "jsonrpc": "1.0",
            "id": str(self._id),
            "method": method,
            "params": params or [],
        }
        r = self._session.post(self.url, json=body, timeout=self.timeout)
        if r.status_code == 500:
            data = r.json()
            err = data.get("error") or {}
            raise BitcoinRPCError(err.get("code"), err.get("message"))
        r.raise_for_status()
        data = r.json()
        if data.get("error"):
            err = data["error"]
            raise BitcoinRPCError(err.get("code"), err.get("message"))
        return data["result"]


class BitcoinRPCError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


class MalformedRPCResponse(ValueError):
    """Raised when Bitcoin Core returns incomplete or contradictory header data."""


def _normalise_bits(value: object, *, source: str) -> str:
    """Return an eight-digit compact-target string or raise a clear error."""
    if not isinstance(value, str) or len(value) != 8:
        raise ValueError(f"{source} nBits is not an eight-digit hex string")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{source} nBits is not hexadecimal") from exc
    return value.lower()


def _parse_serialized_header(header_hex: object, *, source: str) -> dict[str, object]:
    """Parse the fields needed to corroborate an 80-byte Bitcoin header."""
    if not isinstance(header_hex, str) or not header_hex:
        raise ValueError(f"{source} header is missing")
    try:
        header = bytes.fromhex(header_hex)
    except ValueError as exc:
        raise ValueError(f"{source} header is not hexadecimal") from exc
    if len(header) != 80:
        raise ValueError(f"{source} header is {len(header)} bytes, expected 80")
    return {
        "bytes": header,
        "hex": header.hex(),
        "hash": sha256d(header)[::-1].hex(),
        "previousblockhash": header[4:36][::-1].hex(),
        "time": int.from_bytes(header[68:72], "little"),
        "bits": f"{int.from_bytes(header[72:76], 'little'):08x}",
        "bits_int": int.from_bytes(header[72:76], "little"),
        "nonce": int.from_bytes(header[76:80], "little"),
    }


def _target_from_compact(nbits: int) -> int:
    """Decode compact nBits, rejecting negative, zero, or overflowing targets."""
    exponent = nbits >> 24
    mantissa = nbits & 0x007FFFFF
    if nbits & 0x00800000 or mantissa == 0:
        raise ValueError("reconstructed header encodes an invalid PoW target")
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    if target == 0 or target.bit_length() > 256:
        raise ValueError("reconstructed header PoW target is out of range")
    return target


def _parse_nonnegative_int(value: object, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise MalformedRPCResponse(f"RPC {field} is not a non-negative integer")
    return value


def _corroborate_verbose_header(
    rpc: BitcoinRPC,
    requested_hash: str,
    result: object,
) -> tuple[dict, dict[str, object]]:
    """Cross-check verbose RPC metadata against the raw serialized header."""
    if not isinstance(result, dict):
        raise MalformedRPCResponse("getblockheader verbose result is not an object")
    if result.get("hash") != requested_hash:
        raise MalformedRPCResponse("getblockheader returned a different block hash")

    raw_header = rpc.call("getblockheader", [requested_hash, False])
    try:
        parsed = _parse_serialized_header(raw_header, source="RPC")
    except ValueError as exc:
        raise MalformedRPCResponse(str(exc)) from exc
    if parsed["hash"] != requested_hash:
        raise MalformedRPCResponse(
            "serialized RPC header does not hash to requested hash"
        )

    try:
        verbose_bits = _normalise_bits(result.get("bits"), source="RPC")
    except ValueError as exc:
        raise MalformedRPCResponse(str(exc)) from exc
    if verbose_bits != parsed["bits"]:
        raise MalformedRPCResponse("verbose and serialized RPC header nBits differ")
    if result.get("previousblockhash") != parsed["previousblockhash"]:
        raise MalformedRPCResponse("verbose and serialized RPC previous hashes differ")
    if result.get("time") != parsed["time"]:
        raise MalformedRPCResponse("verbose and serialized RPC header times differ")
    _parse_nonnegative_int(result.get("height"), field="height")
    return result, parsed


def _parse_candidate_header(row: dict) -> tuple[str, dict[str, object]]:
    """Parse a Phase A header and corroborate its persisted component fields."""
    parsed = _parse_serialized_header(row.get("btc_header_hex"), source="reconstructed")
    previous_hash = row.get("btc_prev_hash")
    if (
        not isinstance(previous_hash, str)
        or previous_hash.lower() != parsed["previousblockhash"]
    ):
        raise ValueError(
            "reconstructed header previous hash does not match Phase A row"
        )
    try:
        persisted_time = int(row.get("btc_time", ""))
    except (TypeError, ValueError) as exc:
        raise ValueError("Phase A BTC header time is missing or invalid") from exc
    if persisted_time != parsed["time"]:
        raise ValueError("reconstructed header time does not match Phase A row")
    persisted_bits = _normalise_bits(row.get("btc_bits"), source="Phase A")
    if persisted_bits != parsed["bits"]:
        raise ValueError("reconstructed header nBits does not match Phase A row")
    try:
        persisted_nonce = int(row.get("btc_nonce", ""))
    except (TypeError, ValueError) as exc:
        raise ValueError("Phase A BTC header nonce is missing or invalid") from exc
    if persisted_nonce != parsed["nonce"]:
        raise ValueError("reconstructed header nonce does not match Phase A row")
    target = _target_from_compact(int(parsed["bits_int"]))
    if int.from_bytes(sha256d(parsed["bytes"]), "little") > target:
        raise ValueError("reconstructed header does not meet its encoded PoW target")
    return str(parsed["hash"]), parsed


def validate_stale(row: dict, rpc: BitcoinRPC) -> tuple[object, object, str, str]:
    """Derive parent height/MTP, expected nBits, and validation status.

    The reconstructed header claims to extend ``btc_prev_hash`` — so it
    sits at ``parent_height + 1``. A genuine BTC stale at that height
    must carry the same nBits as the canonical block there (difficulty
    is height-deterministic). Comparing the reconstructed header's nBits
    against the canonical nBits at parent_height+1 is the project's
    standard post-2017 validation gate (cf. syscoin/elastos
    expected_nbits column).

    Returns empty context fields plus a status when the parent is not canonical. The
    parent-height+1 expectation is only well-defined off the main chain.
    """
    prev_hash = row.get("btc_prev_hash") or ""
    if not prev_hash:
        return "", "", "", "PARENT_CONTEXT_UNAVAILABLE"
    try:
        parent = rpc.call("getblockheader", [prev_hash, True])
    except BitcoinRPCError as e:
        if e.code == -5:
            return "", "", "", "PARENT_NOT_CANONICAL"
        raise
    try:
        parent, _ = _corroborate_verbose_header(rpc, prev_hash, parent)
        parent_height = _parse_nonnegative_int(parent.get("height"), field="height")
        confirmations = parent.get("confirmations")
        if not isinstance(confirmations, int) or isinstance(confirmations, bool):
            raise MalformedRPCResponse("RPC confirmations is not an integer")
    except MalformedRPCResponse:
        return "", "", "", "PARENT_CONTEXT_UNAVAILABLE"

    if confirmations == -1:
        # Parent is itself a side-chain block — height+1 canonical
        # expectation doesn't apply.
        return parent_height, "", "", "PARENT_NOT_CANONICAL"
    if confirmations <= 0:
        return parent_height, "", "", "PARENT_CONTEXT_UNAVAILABLE"

    parent_mediantime = parent.get("mediantime")
    if not isinstance(parent_mediantime, int) or isinstance(parent_mediantime, bool):
        return parent_height, "", "", "PARENT_CONTEXT_UNAVAILABLE"

    canon_height = parent_height + 1
    try:
        canon_hash = rpc.call("getblockhash", [canon_height])
        if not isinstance(canon_hash, str) or len(canon_hash) != 64:
            raise MalformedRPCResponse("getblockhash result is not a block hash")
        int(canon_hash, 16)
        canon_header_result = rpc.call("getblockheader", [canon_hash, True])
        canon_header, _ = _corroborate_verbose_header(
            rpc, canon_hash, canon_header_result
        )
    except BitcoinRPCError:
        return parent_height, parent_mediantime, "", "PARENT_CONTEXT_UNAVAILABLE"
    except (MalformedRPCResponse, ValueError):
        return parent_height, parent_mediantime, "", "PARENT_CONTEXT_UNAVAILABLE"

    try:
        returned_height = _parse_nonnegative_int(
            canon_header.get("height"), field="height"
        )
        canon_confirmations = canon_header.get("confirmations")
        if (
            not isinstance(canon_confirmations, int)
            or isinstance(canon_confirmations, bool)
            or canon_confirmations <= 0
        ):
            raise MalformedRPCResponse("canonical header is not on the active chain")
        if returned_height != canon_height:
            raise MalformedRPCResponse("canonical header height does not match request")
        expected_nbits = _normalise_bits(
            canon_header.get("bits"), source="canonical RPC"
        )
        reconstructed_nbits = _normalise_bits(row.get("btc_bits"), source="Phase A")
    except (MalformedRPCResponse, ValueError):
        return parent_height, parent_mediantime, "", "PARENT_CONTEXT_UNAVAILABLE"

    status = "VALID" if reconstructed_nbits == expected_nbits else "NBITS_MISMATCH"
    return parent_height, parent_mediantime, expected_nbits, status


def process_row(row: dict, rpc: BitcoinRPC) -> dict:
    """Classify one Phase A row or raise if its evidence cannot be processed."""
    header_hash, parsed_header = _parse_candidate_header(row)

    try:
        result = rpc.call("getblockheader", [header_hash, True])
    except BitcoinRPCError as e:
        if e.code != -5:
            raise
        # A definitive miss on the initial lookup means this node does not
        # know the candidate. Later corroboration failures are not equivalent.
        classification, conf, height = "stale", None, None
    else:
        result, rpc_header = _corroborate_verbose_header(rpc, header_hash, result)
        if rpc_header["hex"] != parsed_header["hex"]:
            raise MalformedRPCResponse(
                "Bitcoin Core header differs from reconstructed Phase A header"
            )
        confirmations = result.get("confirmations")
        if not isinstance(confirmations, int) or isinstance(confirmations, bool):
            raise MalformedRPCResponse("RPC confirmations is not an integer")
        height = _parse_nonnegative_int(result.get("height"), field="height")
        if confirmations > 0:
            classification, conf = "canonical", confirmations
        elif confirmations == -1:
            # confirmations == -1: node knows it as a side-chain block.
            classification, conf = "stale", confirmations
        else:
            raise MalformedRPCResponse("RPC confirmations is neither active nor stale")

    if classification == "stale":
        parent_height, parent_mediantime, expected_nbits, status = validate_stale(
            row, rpc
        )
    else:
        parent_height, parent_mediantime, expected_nbits, status = "", "", "", ""

    return _make_output_row(
        row,
        header_hash,
        classification,
        height,
        conf,
        parent_height,
        parent_mediantime,
        expected_nbits,
        status,
    )


def _make_output_row(
    input_row: dict,
    header_hash: str,
    classification: str,
    height,
    confirmations,
    parent_height="",
    parent_mediantime="",
    expected_nbits="",
    validation_status="",
) -> dict:
    """Merge the Phase A input row with the Phase B classification fields into
    an ``OUTPUT_COLUMNS``-shaped row dict.
    """
    out = {col: input_row.get(col, "") for col in OUTPUT_COLUMNS}
    out["btc_header_hash"] = header_hash
    out["classification"] = classification
    out["btc_canonical_height"] = height if classification == "canonical" else ""
    out["btc_confirmations"] = confirmations if confirmations is not None else ""
    out["btc_parent_height"] = parent_height
    out["btc_parent_mediantime"] = parent_mediantime
    out["expected_nbits"] = expected_nbits
    out["validation_status"] = validation_status
    return out


def _write_rows_atomically(output: Path, rows: list[dict]) -> None:
    """Replace ``output`` only after a complete CSV has been written."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as f_out:
            temp_path = Path(f_out.name)
            writer = csv.DictWriter(f_out, fieldnames=OUTPUT_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temp_path, output)
    except BaseException:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise


def main():
    """Read Phase A's BTC-parent candidates, classify each against Bitcoin
    Core in a thread pool, and write Phase B's stale/canonical CSV plus a
    stats summary to stderr.
    """
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--input", default="data/hathor/hathor_phase_a.csv")
    p.add_argument("--output", default="data/hathor/hathor_stale_blocks.csv")
    p.add_argument("--rpc-url", default="http://bitcoin:bitcoin@127.0.0.1:8332")
    p.add_argument("--workers", type=int, default=16)
    args = p.parse_args()

    rpc = BitcoinRPC(args.rpc_url)
    # Probe.
    height = rpc.call("getblockcount")
    print(f"BTC RPC OK, height={height:,}", file=sys.stderr)

    stats = {
        "input_rows": 0,
        "skipped_nonbtc": 0,
        "canonical": 0,
        "stale": 0,
    }
    vstatus = {}  # validation_status histogram for stale rows
    t0 = time.time()

    with open(args.input, encoding="utf-8") as f_in:
        reader = csv.DictReader(f_in)
        required_columns = set(OUTPUT_COLUMNS[:10])
        missing_columns = required_columns.difference(reader.fieldnames or [])
        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise ValueError(f"Phase A input is missing required columns: {missing}")

        # Filter to BTC-parent candidates only.
        btc_rows = []
        for row in reader:
            stats["input_rows"] += 1
            rpc_match = row.get("btc_rpc_match")
            if rpc_match == "false":
                stats["skipped_nonbtc"] += 1
                continue
            if rpc_match != "true":
                raise ValueError(
                    f"invalid btc_rpc_match in Phase A input row "
                    f"{stats['input_rows']}: {rpc_match!r}"
                )
            btc_rows.append(row)

        print(
            f"Read {stats['input_rows']:,} Phase A rows; "
            f"{len(btc_rows):,} BTC-parent candidates",
            file=sys.stderr,
        )

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            output_rows = list(pool.map(lambda row: process_row(row, rpc), btc_rows))

    if len(output_rows) != len(btc_rows):
        raise RuntimeError("Phase B did not return exactly one result per candidate")
    for out_row in output_rows:
        if out_row is None:
            raise RuntimeError("Phase B worker returned no result")
        cls = out_row["classification"]
        stats[cls] += 1
        if cls == "stale":
            vs = out_row["validation_status"] or "(none)"
            vstatus[vs] = vstatus.get(vs, 0) + 1

    unavailable = [
        row
        for row in output_rows
        if row.get("classification") == "stale"
        and row.get("validation_status") == "PARENT_CONTEXT_UNAVAILABLE"
    ]
    if unavailable:
        raise RuntimeError(
            "Phase B validation context is incomplete; refusing to replace "
            f"output ({len(unavailable)} stale candidates unavailable)"
        )

    _write_rows_atomically(Path(args.output), output_rows)

    elapsed = time.time() - t0
    print(file=sys.stderr)
    print("=" * 64, file=sys.stderr)
    print(f"Phase B complete in {elapsed:.1f}s", file=sys.stderr)
    for k, v in stats.items():
        print(f"  {k:>15s}: {v:,}", file=sys.stderr)
    if stats["stale"] + stats["canonical"]:
        pct = 100 * stats["stale"] / (stats["stale"] + stats["canonical"])
        print(
            f"\nStale rate among BTC blocks: {pct:.2f}% "
            f"({stats['stale']:,} / {stats['stale'] + stats['canonical']:,})",
            file=sys.stderr,
        )
    if vstatus:
        print("\nStale validation_status:", file=sys.stderr)
        for k, v in sorted(vstatus.items()):
            print(f"  {k:>22s}: {v:,}", file=sys.stderr)


if __name__ == "__main__":
    main()
