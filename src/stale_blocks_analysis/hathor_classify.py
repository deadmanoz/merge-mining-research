"""Unified Hathor RFC0006 reconstruction and Bitcoin classification.

The classifier consumes the current sealed acquisition CSV directly. Every
observation is written to exactly one terminal category and a VALID-only stale
projection is written beside those categories. Outputs are built in a sibling
temporary directory and published with one directory rename.
"""

from __future__ import annotations

import csv
import hashlib
import os
import shutil
import tempfile
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .auxpow_chainid import hash_from_header_bytes
from .auxpow_parse import (
    hash_meets_btc_difficulty,
    nbits_to_target,
    parse_parent_header,
)
from .bitcoin_binary import parse_coinbase_tx, sha256d
from .btc_classify import (
    RULES_VIOLATED_COLUMN,
    classify_candidates,
    output_columns,
    route_rejected_stale_rows,
)
from .btc_rpc import BtcRpc
from .btc_stale_validation import validate_stale_header_context
from .hathor_acquisition import ACQUISITION_COLUMNS, acquisition_record_sha256


OUTPUT_COLUMNS = output_columns("hathor_height")
ERROR_OUTPUT_COLUMNS = [*OUTPUT_COLUMNS, RULES_VIOLATED_COLUMN]
CATEGORIES = ("near", "canonical", "stale", "unknown", "error_block")
CATEGORY_FILENAMES = {
    "near": "hathor_near_blocks.csv",
    "canonical": "hathor_canonical_blocks.csv",
    "stale": "hathor_stale_blocks.csv",
    "unknown": "hathor_unknown_blocks.csv",
    "error_block": "hathor_error_blocks.csv",
}
VALIDATED_FILENAME = "hathor_validated_stales.csv"
DEFAULT_BATCH_SIZE = 200


@dataclass(frozen=True)
class ReconstructedObservation:
    """Bitcoin evidence reconstructed from one Hathor RFC0006 proof."""

    header: bytes
    coinbase: bytes
    split_offset: int


def _compact_size(data: bytes, offset: int) -> tuple[int, int]:
    """Read one canonical Bitcoin CompactSize integer."""
    if offset >= len(data):
        raise ValueError("truncated CompactSize")
    marker = data[offset]
    if marker < 0xFD:
        return marker, offset + 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[marker]
    end = offset + 1 + width
    if end > len(data):
        raise ValueError("truncated CompactSize")
    value = int.from_bytes(data[offset + 1 : end], "little")
    minimum = {0xFD: 0xFD, 0xFE: 0x10000, 0xFF: 0x100000000}[marker]
    if value < minimum:
        raise ValueError("non-canonical CompactSize")
    return value, end


def parse_aux_pow(aux_pow_hex: str) -> dict[str, object]:
    """Parse one complete Hathor RFC0006 AuxPoW proof."""
    try:
        data = bytes.fromhex(aux_pow_hex)
    except (TypeError, ValueError) as exc:
        raise ValueError("aux_pow_hex is not hexadecimal") from exc
    if len(data) < 51:
        raise ValueError("AuxPoW proof is too short")

    offset = 36
    head = data[:offset]
    coinbase_head_length, offset = _compact_size(data, offset)
    end = offset + coinbase_head_length
    if end > len(data):
        raise ValueError("truncated coinbase head")
    coinbase_head = data[offset:end]
    offset = end

    coinbase_tail_length, offset = _compact_size(data, offset)
    end = offset + coinbase_tail_length
    if end > len(data):
        raise ValueError("truncated coinbase tail")
    coinbase_tail = data[offset:end]
    offset = end

    merkle_count, offset = _compact_size(data, offset)
    if merkle_count > 64:
        raise ValueError("unreasonable merkle path length")
    merkle_path: list[bytes] = []
    for _ in range(merkle_count):
        sibling = data[offset : offset + 32]
        if len(sibling) != 32:
            raise ValueError("truncated merkle sibling")
        merkle_path.append(sibling)
        offset += 32

    tail = data[offset : offset + 12]
    offset += len(tail)
    if len(tail) != 12:
        raise ValueError("truncated parent-header tail")
    if offset != len(data):
        raise ValueError("trailing bytes after RFC0006 proof")
    if not coinbase_head.endswith(b"Hath"):
        raise ValueError("coinbase head lacks the RFC0006 Hath marker")

    return {
        "head_36": head,
        "coinbase_head": coinbase_head,
        "coinbase_tail": coinbase_tail,
        "merkle_path": merkle_path,
        "tail_12": tail,
    }


def reconstruct_rfc0006(
    parsed: dict[str, object],
    funds_graph: bytes,
    expected_hathor_hash: str,
) -> ReconstructedObservation:
    """Reconstruct the Bitcoin header and coinbase committed by RFC0006."""
    try:
        expected_hash = bytes.fromhex(expected_hathor_hash)
    except (TypeError, ValueError) as exc:
        raise ValueError("Hathor block hash is not hexadecimal") from exc
    if len(expected_hash) != 32:
        raise ValueError("Hathor block hash is not 32 bytes")
    if len(funds_graph) < 3:
        raise ValueError("funds/graph prefix is too short")

    head = parsed["head_36"]
    coinbase_head = parsed["coinbase_head"]
    coinbase_tail = parsed["coinbase_tail"]
    merkle_path = parsed["merkle_path"]
    tail = parsed["tail_12"]
    if not all(
        isinstance(value, bytes) for value in (head, coinbase_head, coinbase_tail, tail)
    ):
        raise ValueError("malformed parsed AuxPoW bytes")
    if not isinstance(merkle_path, list):
        raise ValueError("malformed parsed AuxPoW merkle path")

    preferred_splits = ([35] if len(funds_graph) > 35 else []) + [
        split for split in range(2, len(funds_graph)) if split != 35
    ]
    for split in preferred_splits:
        funds_hash = hashlib.sha256(funds_graph[:split]).digest()
        graph_hash = hashlib.sha256(funds_graph[split:]).digest()
        aux_block_hash = sha256d(funds_hash + graph_hash)[::-1]
        coinbase = coinbase_head + aux_block_hash + coinbase_tail
        merkle_root = sha256d(coinbase)
        for sibling in merkle_path:
            if not isinstance(sibling, bytes) or len(sibling) != 32:
                raise ValueError("malformed parsed AuxPoW merkle path")
            merkle_root = sha256d(merkle_root + sibling[::-1])
        header = head + merkle_root + tail
        if len(header) != 80:
            raise ValueError("reconstructed Bitcoin header is not 80 bytes")
        if sha256d(header)[::-1] == expected_hash:
            return ReconstructedObservation(header, coinbase, split)
    raise ValueError("RFC0006 reconstruction did not reproduce the block hash")


def _source_observation(
    row: dict[str, str], line_number: int
) -> ReconstructedObservation:
    observed_seal = row.get("record_sha256", "")
    if observed_seal != acquisition_record_sha256(row):
        raise ValueError(f"acquisition record seal mismatch at CSV line {line_number}")
    try:
        funds_graph = bytes.fromhex(row["funds_graph_hex"])
    except ValueError as exc:
        raise ValueError(f"invalid funds_graph_hex at CSV line {line_number}") from exc
    return reconstruct_rfc0006(
        parse_aux_pow(row["aux_pow_hex"]),
        funds_graph,
        row["hathor_block_hash"],
    )


def _source_height(row: dict[str, str], line_number: int) -> int:
    try:
        height = int(row["hathor_height"])
    except ValueError as exc:
        raise ValueError(f"invalid Hathor height at CSV line {line_number}") from exc
    if height < 0 or row["hathor_height"] != str(height):
        raise ValueError(f"invalid Hathor height at CSV line {line_number}")
    return height


def _base_output_row(
    source: dict[str, str], reconstructed: ReconstructedObservation
) -> tuple[dict[str, Any], bool]:
    header = parse_parent_header(reconstructed.header)
    if header["hash"] != source["hathor_block_hash"]:
        raise ValueError(
            "reconstructed Bitcoin header does not match acquisition identity at "
            f"Hathor height {source['hathor_height']}"
        )
    coinbase = parse_coinbase_tx(reconstructed.coinbase)
    scriptsig = b"" if coinbase is None else coinbase["scriptsig"]
    outputs = [] if coinbase is None else coinbase["outputs"]
    row: dict[str, Any] = {
        "btc_height": "",
        "btc_header_hash": header["hash"],
        "btc_prev_hash": header["prev_hash"],
        "btc_time": str(header["time"]),
        "btc_bits": header["bits_hex"],
        "coinbase_scriptsig_hex": scriptsig.hex(),
        "coinbase_outputs": _format_outputs(outputs),
        "btc_header_hex": reconstructed.header.hex(),
        "hathor_height": source["hathor_height"],
        "child_block_hash": hash_from_header_bytes(reconstructed.header).hex(),
        "child_header_hex": "",
        "child_block_time": source["hathor_timestamp"],
        "child_nbits": "",
        "classification": "",
        "validation_status": "",
        "expected_nbits": "",
    }
    return row, coinbase is not None


def _format_outputs(outputs: Iterable[tuple[int, bytes]]) -> str:
    """Preserve Hathor's established raw-script-and-value convention."""
    return "|".join(f"{script.hex()}:{value}" for value, script in outputs)


def _meets_self_target(row: dict[str, Any]) -> bool:
    header = bytes.fromhex(row["btc_header_hex"])
    bits = int(row["btc_bits"], 16)
    target = nbits_to_target(bits)
    if bits & 0x00800000 or bits & 0x007FFFFF == 0:
        raise ValueError("reconstructed header encodes an invalid PoW target")
    if target <= 0 or target.bit_length() > 256:
        raise ValueError("reconstructed header PoW target is out of range")
    return hash_meets_btc_difficulty(hash_from_header_bytes(header), bits)


def _classify_batch(
    pending: list[tuple[dict[str, Any], bool]], rpc: BtcRpc
) -> list[dict[str, Any]]:
    candidates = [row for row, _coinbase_parsed in pending]
    coinbase_status = {row["hathor_height"]: parsed for row, parsed in pending}
    results = classify_candidates(candidates, rpc)
    if len(results) != len(candidates):
        raise RuntimeError(
            f"classification returned {len(results)} of {len(candidates)} rows"
        )

    stales: list[dict[str, Any]] = []
    for row in results:
        if row["classification"] == "stale":
            if coinbase_status[row["hathor_height"]]:
                stales.append(row)
            else:
                row["classification"] = "unknown"

    validate_stale_header_context(stales, rpc.batch)
    route_rejected_stale_rows(stales)
    incomplete = [
        row
        for row in stales
        if row["classification"] == "stale"
        and str(row.get("validation_status", "")).startswith("UNKNOWN:")
    ]
    if incomplete:
        raise RuntimeError(
            "stale validation context is incomplete for "
            f"{len(incomplete)} Hathor observations"
        )

    for row in results:
        classification = row.get("classification")
        if classification not in CATEGORIES:
            raise ValueError(f"unrecognised classification: {classification!r}")
        if classification in {"near", "canonical", "unknown"}:
            row["validation_status"] = ""
            row["expected_nbits"] = ""
    return sorted(results, key=lambda row: int(row["hathor_height"]))


def _write_row(
    writer: csv.DictWriter,
    row: dict[str, Any],
    columns: list[str],
) -> None:
    writer.writerow({column: row.get(column, "") for column in columns})


def classify_hathor(
    input_paths: Iterable[Path],
    output_dir: Path,
    rpc: BtcRpc,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> dict[str, int | str]:
    """Classify ordered acquisition shards and publish a fresh output directory."""
    source_paths = [Path(path) for path in input_paths]
    output_dir = Path(output_dir)
    if (
        not isinstance(batch_size, int)
        or isinstance(batch_size, bool)
        or batch_size < 1
    ):
        raise ValueError("batch_size must be a positive integer")
    if output_dir.exists():
        raise FileExistsError(f"output directory already exists: {output_dir}")
    if not source_paths:
        raise ValueError("at least one acquisition input is required")
    for input_path in source_paths:
        if not input_path.is_file():
            raise FileNotFoundError(input_path)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staged = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent)
    )
    counts: Counter[str] = Counter()
    try:
        with ExitStack() as stack:
            writers: dict[str, csv.DictWriter] = {}
            for category in CATEGORIES:
                columns = (
                    ERROR_OUTPUT_COLUMNS
                    if category == "error_block"
                    else OUTPUT_COLUMNS
                )
                handle = stack.enter_context(
                    (staged / CATEGORY_FILENAMES[category]).open("w", newline="")
                )
                writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
                writer.writeheader()
                writers[category] = writer
            validated_handle = stack.enter_context(
                (staged / VALIDATED_FILENAME).open("w", newline="")
            )
            validated_writer = csv.DictWriter(
                validated_handle, fieldnames=OUTPUT_COLUMNS, lineterminator="\n"
            )
            validated_writer.writeheader()

            pending: list[tuple[dict[str, Any], bool]] = []

            def flush_pending() -> None:
                if not pending:
                    return
                for result in _classify_batch(pending, rpc):
                    category = result["classification"]
                    columns = (
                        ERROR_OUTPUT_COLUMNS
                        if category == "error_block"
                        else OUTPUT_COLUMNS
                    )
                    _write_row(writers[category], result, columns)
                    counts[category] += 1
                    if category == "stale" and result["validation_status"] == "VALID":
                        _write_row(validated_writer, result, OUTPUT_COLUMNS)
                        counts["validated_stales"] += 1
                pending.clear()

            previous_height = -1
            for input_path in source_paths:
                with input_path.open(newline="") as source_handle:
                    reader = csv.DictReader(source_handle)
                    if reader.fieldnames != ACQUISITION_COLUMNS:
                        raise ValueError(
                            f"unexpected acquisition columns in {input_path}: "
                            f"{reader.fieldnames}"
                        )
                    for line_number, source in enumerate(reader, start=2):
                        if set(source) != set(ACQUISITION_COLUMNS) or any(
                            value is None for value in source.values()
                        ):
                            raise ValueError(
                                f"malformed acquisition row in {input_path} "
                                f"at CSV line {line_number}"
                            )
                        height = _source_height(source, line_number)
                        if height <= previous_height:
                            raise ValueError(
                                "acquisition heights must be globally strictly "
                                "ascending across input files"
                            )
                        previous_height = height
                        reconstructed = _source_observation(source, line_number)
                        row, coinbase_parsed = _base_output_row(source, reconstructed)
                        counts["input_rows"] += 1
                        if not _meets_self_target(row):
                            row["classification"] = "near"
                            _write_row(writers["near"], row, OUTPUT_COLUMNS)
                            counts["near"] += 1
                            continue
                        pending.append((row, coinbase_parsed))
                        if len(pending) == batch_size:
                            flush_pending()
            flush_pending()

        os.rename(staged, output_dir)
    except BaseException:
        shutil.rmtree(staged, ignore_errors=True)
        raise

    return {
        "input_rows": counts["input_rows"],
        "input_files": len(source_paths),
        "near": counts["near"],
        "canonical": counts["canonical"],
        "stale": counts["stale"],
        "unknown": counts["unknown"],
        "error_block": counts["error_block"],
        "validated_stales": counts["validated_stales"],
        "output_dir": str(output_dir),
    }
