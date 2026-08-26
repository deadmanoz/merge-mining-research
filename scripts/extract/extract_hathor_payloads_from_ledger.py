#!/usr/bin/env python3
"""Acquire complete Hathor v3 evidence from an audited metadata ledger.

The metadata ledger establishes one ``tx_id`` for every ``version_3_ready``
height. This collector requests each missing transaction and appends one sealed
row to the acquisition dataset. Failed attempts remain append-only history and
are retried on later runs. The failure log also schedules bounded runs by least
completed failure round then height, so a permanent early failure cannot starve
later heights under ``--limit``. Each dataset row retains the lossless
transaction and AuxPoW bytes, its derived funds-graph prefix, request
provenance, and a SHA-256 record seal. Resume and audit reject damaged rows.
Run one process for each dataset/failure-output pair.

The dataset is private archival data. The repository's default ``data/hathor/``
location is gitignored.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import os
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stale_blocks_analysis.hathor_acquisition import (
    ACQUISITION_COLUMNS,
    HttpResult,
    PacedHttpClient,
    acquisition_record_sha256,
)


DEFAULT_API = "https://node1.mainnet.hathor.network/v1a"
DEFAULT_FALLBACK_API = "https://node2.mainnet.hathor.network/v1a"
DEFAULT_REQUESTS_PER_SECOND = 0.25
USER_AGENT = "merge-mining-research/hathor-acquisition"

LEDGER_COLUMNS = [
    "hathor_height",
    "outcome",
    "http_status",
    "block_version",
    "tx_id",
    "endpoint",
    "attempt_count",
    "error_reason",
]
RESOLVED_LEDGER_OUTCOMES = {"version_3_ready", "non_version_3"}
LOWER_HEX_DIGITS = frozenset("0123456789abcdef")
COMPACT_HEX_DIGITS = LOWER_HEX_DIGITS | frozenset("ABCDEF")
FAILURE_COLUMNS = [
    "hathor_height",
    "hathor_block_hash",
    "http_status",
    "endpoint",
    "attempt_count",
    "error_reason",
    "recorded_at_utc",
]


@dataclass(frozen=True)
class ReadyRow:
    height: int
    tx_id: str


@dataclass(frozen=True)
class Payload:
    height: int
    tx_id: str
    timestamp: int
    aux_pow_hex: str
    raw_hex: str
    funds_graph_hex: str
    endpoint: str
    http_status: int
    attempt_count: int


def is_canonical_tx_id(value: object) -> bool:
    """Return whether a transaction ID is canonical lowercase 32-byte hex."""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in LOWER_HEX_DIGITS for character in value)
    )


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return parsed


def decode_compact_hex(value: str) -> bytes:
    """Decode even-length ASCII hex without accepting embedded whitespace."""
    if len(value) % 2 or any(
        character not in COMPACT_HEX_DIGITS for character in value
    ):
        raise ValueError("not compact hexadecimal")
    return bytes.fromhex(value)


def funds_graph_hex(raw_hex: str, aux_pow_hex: str) -> str:
    """Return the transaction prefix before its one embedded AuxPoW payload."""
    raw = decode_compact_hex(raw_hex)
    aux_pow = decode_compact_hex(aux_pow_hex)
    if not aux_pow:
        raise ValueError("empty_aux_pow")
    occurrence_count = raw.count(aux_pow)
    if occurrence_count != 1:
        raise ValueError(f"aux_pow_occurrences_{occurrence_count}")
    offset = raw.find(aux_pow)
    if offset < 3:
        raise ValueError("funds_graph_prefix_too_short")
    return raw[:offset].hex()


def require_api_timestamp(value: object) -> int:
    """Require one exact non-negative JSON integer timestamp."""
    if type(value) is not int or value < 0:
        raise ValueError("invalid_timestamp")
    return value


def validate_dataset_timestamp(value: object, height: int) -> int:
    """Require a non-negative timestamp in the acquisition dataset."""
    try:
        parsed = int(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid timestamp at height {height}") from exc
    if parsed < 0:
        raise ValueError(f"invalid timestamp at height {height}")
    return parsed


def paths_alias(left: Path, right: Path) -> bool:
    """Return whether two path spellings resolve to the same location."""
    return left.resolve(strict=False) == right.resolve(strict=False)


def require_distinct_paths(**paths: Path) -> None:
    """Reject destructive input/output aliases before writes."""
    labelled_paths = list(paths.items())
    for index, (left_label, left_path) in enumerate(labelled_paths):
        for right_label, right_path in labelled_paths[index + 1 :]:
            if paths_alias(left_path, right_path):
                raise ValueError(
                    f"{left_label} and {right_label} must be distinct paths"
                )


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_ready_rows(ledger_path: Path, start: int, end: int) -> dict[int, ReadyRow]:
    """Load ready rows only from an exact, resolved metadata-ledger range."""
    if start >= end:
        raise ValueError("start must be lower than end")
    if ledger_path.stat().st_size == 0:
        raise ValueError("metadata ledger is empty")
    with ledger_path.open("rb") as handle:
        handle.seek(-1, os.SEEK_END)
        if handle.read(1) != b"\n":
            raise ValueError("metadata ledger ends with a truncated row")

    ready: dict[int, ReadyRow] = {}
    canonical_tx_heights: dict[str, int] = {}
    observed_heights: list[int] = []
    try:
        with ledger_path.open(newline="") as handle:
            reader = csv.DictReader(handle, strict=True)
            if reader.fieldnames != LEDGER_COLUMNS:
                raise ValueError(
                    f"unexpected metadata ledger columns: {reader.fieldnames}"
                )
            for row in reader:
                if set(row) != set(LEDGER_COLUMNS) or any(
                    value is None for value in row.values()
                ):
                    raise ValueError("metadata ledger row has an incomplete schema")

                height = metadata_integer(
                    row["hathor_height"], "hathor_height", minimum=0
                )
                if height < start or height >= end:
                    continue
                observed_heights.append(height)

                outcome = row["outcome"]
                if outcome not in RESOLVED_LEDGER_OUTCOMES:
                    raise ValueError(
                        f"unresolved metadata outcome at height {height}: {outcome!r}"
                    )
                status = metadata_integer(
                    row["http_status"], "http_status", minimum=100
                )
                if not 200 <= status < 300:
                    raise ValueError(
                        f"invalid resolved metadata http_status at height {height}: "
                        f"{status}"
                    )
                version = metadata_integer(
                    row["block_version"], "block_version", minimum=0
                )
                metadata_integer(row["attempt_count"], "attempt_count", minimum=1)
                if not row["endpoint"].strip() or row["error_reason"]:
                    raise ValueError(
                        f"invalid resolved metadata fields at height {height}"
                    )

                tx_id = row["tx_id"]
                if tx_id and is_canonical_tx_id(tx_id):
                    previous_height = canonical_tx_heights.get(tx_id)
                    if previous_height is not None:
                        raise ValueError(
                            "canonical transaction ID is assigned to multiple "
                            f"heights: {previous_height}, {height}"
                        )
                    canonical_tx_heights[tx_id] = height
                if outcome == "version_3_ready":
                    if version != 3 or not is_canonical_tx_id(tx_id):
                        raise ValueError(
                            f"invalid version_3_ready fields at height {height}"
                        )
                    ready[height] = ReadyRow(height, tx_id)
                elif version == 3:
                    raise ValueError(f"invalid non_version_3 fields at height {height}")
    except csv.Error as exc:
        raise ValueError("malformed metadata ledger CSV") from exc

    expected_heights = list(range(start, end))
    if observed_heights != expected_heights:
        raise ValueError(
            "metadata ledger coverage or ordering is invalid: "
            f"expected={len(expected_heights)} observed={len(observed_heights)}"
        )
    return ready


def metadata_integer(value: str, field: str, *, minimum: int) -> int:
    """Parse one bounded integer from a metadata row."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid metadata {field}: {value!r}") from exc
    if parsed < minimum:
        raise ValueError(f"invalid metadata {field}: {value!r}")
    return parsed


def csv_height(value: str, path: Path) -> int:
    """Parse one non-negative height from an evidence CSV."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid height in {path}: {value!r}") from exc
    if parsed < 0:
        raise ValueError(f"invalid height in {path}: {value!r}")
    return parsed


def read_csv_rows_with_order(
    path: Path, columns: list[str]
) -> tuple[dict[int, dict[str, str]], list[int]]:
    """Read a dataset CSV, retaining physical order for reproducibility checks."""
    if not path.exists() or path.stat().st_size == 0:
        return {}, []
    with path.open("rb") as handle:
        handle.seek(-1, os.SEEK_END)
        if handle.read(1) != b"\n":
            raise ValueError(f"CSV ends with a truncated row: {path}")

    rows: dict[int, dict[str, str]] = {}
    observed_order: list[int] = []
    try:
        with path.open(newline="") as handle:
            reader = csv.DictReader(handle, strict=True)
            if reader.fieldnames != columns:
                raise ValueError(f"unexpected columns in {path}: {reader.fieldnames}")
            for row in reader:
                if set(row) != set(columns) or any(
                    value is None for value in row.values()
                ):
                    raise ValueError(f"incomplete or extra CSV cells in {path}")
                height = csv_height(row["hathor_height"], path)
                if height in rows:
                    raise ValueError(f"duplicate height in {path}: {height}")
                rows[height] = row
                observed_order.append(height)
    except csv.Error as exc:
        raise ValueError(f"malformed CSV: {path}") from exc
    return rows, observed_order


def read_failure_rounds(path: Path, ready_rows: dict[int, ReadyRow]) -> Counter[int]:
    """Count durable failure rows per ready height for fair retries."""
    rounds: Counter[int] = Counter()
    if not path.exists() or path.stat().st_size == 0:
        return rounds
    with path.open("rb") as handle:
        handle.seek(-1, os.SEEK_END)
        if handle.read(1) != b"\n":
            raise ValueError(f"CSV ends with a truncated row: {path}")
    try:
        with path.open(newline="") as handle:
            reader = csv.DictReader(handle, strict=True)
            if reader.fieldnames != FAILURE_COLUMNS:
                raise ValueError(f"unexpected columns in {path}: {reader.fieldnames}")
            for row in reader:
                if set(row) != set(FAILURE_COLUMNS) or any(
                    value is None for value in row.values()
                ):
                    raise ValueError(f"incomplete or extra CSV cells in {path}")
                height = csv_height(row["hathor_height"], path)
                ready = ready_rows.get(height)
                if ready is None:
                    raise ValueError(
                        f"failure history without a ready height in {path}: {height}"
                    )
                if row["hathor_block_hash"] != ready.tx_id:
                    raise ValueError(f"failure tx_id mismatch at height {height}")
                rounds[height] += 1
    except csv.Error as exc:
        raise ValueError(f"malformed CSV: {path}") from exc
    return rounds


def read_acquisition_rows(
    path: Path,
) -> tuple[dict[int, dict[str, str]], list[int]]:
    """Read the sealed acquisition dataset."""
    if not path.exists() or path.stat().st_size == 0:
        return {}, []
    return read_csv_rows_with_order(path, ACQUISITION_COLUMNS)


def require_ordered_heights(path: Path, observed_order: list[int]) -> None:
    """Reject evidence whose bytes depend on retry completion order."""
    if observed_order != sorted(observed_order):
        raise ValueError(f"rows are not in ascending height order: {path}")


def open_csv_writer(path: Path, columns: list[str]):
    """Open an append-only CSV, writing its header only for a new file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    validate_append_csv(path, columns)
    handle = path.open("a" if exists else "w", newline="")
    try:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        if not exists:
            writer.writeheader()
            handle.flush()
            os.fsync(handle.fileno())
        return handle, writer
    except BaseException:
        handle.close()
        raise


def validate_append_csv(path: Path, columns: list[str]) -> None:
    """Validate an append target without creating or modifying it."""
    if not path.exists() or path.stat().st_size == 0:
        return
    with path.open(newline="") as existing:
        header = next(csv.reader(existing), None)
    if header != columns:
        raise ValueError(f"unexpected columns in {path}: {header}")
    with path.open("rb") as existing:
        existing.seek(-1, os.SEEK_END)
        if existing.read(1) != b"\n":
            raise ValueError(f"refusing to append after a truncated row: {path}")


def replace_acquisition_rows_atomically(
    path: Path,
    rows: dict[int, dict[str, object]],
) -> None:
    """Replace the dataset in deterministic height order."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            dir=path.parent,
            prefix=f".{path.name}.tmp-",
            newline="",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            writer = csv.DictWriter(
                handle,
                fieldnames=ACQUISITION_COLUMNS,
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(rows[height] for height in sorted(rows))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def write_durable_row(handle, writer: csv.DictWriter, row: dict[str, object]) -> None:
    """Append one row before moving on to another API request."""
    writer.writerow(row)
    handle.flush()
    os.fsync(handle.fileno())


def append_acquisition_row_durably(path: Path, row: dict[str, object]) -> None:
    """Append one sealed row before any canonical-order rewrite."""
    handle, writer = open_csv_writer(path, ACQUISITION_COLUMNS)
    try:
        write_durable_row(handle, writer, row)
    finally:
        handle.close()


def parse_payload(
    ready: ReadyRow,
    response: dict[str, Any],
    endpoint: str,
    http_status: int,
    attempt_count: int,
) -> Payload:
    """Require exact identity, version, timestamp, and non-voided payload evidence."""
    if response.get("success") is not True:
        raise ValueError("api_success_false")
    tx = response.get("tx")
    if not isinstance(tx, dict):
        raise ValueError("missing_tx")
    response_hash = tx.get("hash")
    if not isinstance(response_hash, str) or response_hash != ready.tx_id:
        raise ValueError("tx_hash_mismatch")
    response_version = tx.get("version")
    if type(response_version) is not int or response_version != 3:
        raise ValueError("tx_version_mismatch")
    if tx.get("is_voided"):
        # Match the metadata block-at-height contract: a truthy voided flag
        # stays retryable and must never be sealed as payload evidence.
        raise ValueError("child_block_voided")
    raw_hex = tx.get("raw")
    aux_pow_hex = tx.get("aux_pow")
    if not isinstance(raw_hex, str) or not raw_hex:
        raise ValueError("missing_raw")
    if not isinstance(aux_pow_hex, str) or not aux_pow_hex:
        raise ValueError("missing_aux_pow")
    prefix = funds_graph_hex(raw_hex, aux_pow_hex)
    timestamp = require_api_timestamp(tx.get("timestamp"))
    return Payload(
        height=ready.height,
        tx_id=ready.tx_id,
        timestamp=timestamp,
        aux_pow_hex=aux_pow_hex,
        raw_hex=raw_hex,
        funds_graph_hex=prefix,
        endpoint=endpoint,
        http_status=http_status,
        attempt_count=attempt_count,
    )


def canonical_endpoint(value: str, name: str, *, allow_blank: bool) -> str:
    """Normalize an endpoint, allowing an omitted fallback."""
    endpoint = value.strip().rstrip("/")
    if not endpoint:
        if allow_blank:
            return ""
        raise ValueError(f"{name} endpoint must be non-empty")
    scheme, separator, remainder = endpoint.partition("://")
    if scheme not in ("http", "https") or not separator or not remainder.split("/")[0]:
        raise ValueError(f"{name} endpoint must be an absolute http or https URL")
    return endpoint


def fetch_payload(
    client: PacedHttpClient,
    ready: ReadyRow,
    primary_endpoint: str,
    fallback_endpoint: str,
) -> tuple[Payload | None, dict[str, object] | None]:
    """Fetch a ready transaction, returning a payload or one visible failure row."""
    primary = canonical_endpoint(primary_endpoint, "primary", allow_blank=False)
    endpoints = [primary]
    fallback = canonical_endpoint(fallback_endpoint, "fallback", allow_blank=True)
    if fallback and fallback != endpoints[0]:
        endpoints.append(fallback)

    last: HttpResult | None = None
    last_endpoint = endpoints[0]
    attempt_count = 0
    for attempt in range(client.max_attempts):
        endpoint = endpoints[attempt % len(endpoints)]
        last_endpoint = endpoint
        attempt_count = attempt + 1
        result = client.get_json(endpoint, "/transaction", {"id": ready.tx_id})
        last = result
        if result.payload is not None:
            try:
                if result.status is None:
                    raise ValueError("missing_http_status")
                if not 200 <= result.status < 300:
                    raise ValueError(f"non_success_http_{result.status}")
                return (
                    parse_payload(
                        ready,
                        result.payload,
                        endpoint,
                        result.status,
                        attempt + 1,
                    ),
                    None,
                )
            except ValueError as exc:
                last = HttpResult(result.status, None, str(exc), True)
        if not result.retryable:
            if result.payload is None and not (
                attempt == 0 and len(endpoints) > 1 and client.max_attempts > 1
            ):
                break
        if attempt + 1 < client.max_attempts:
            client.sleep(min(2**attempt, 30))

    return None, failure_row(
        ready,
        last.status if last else None,
        last_endpoint,
        attempt_count,
        last.error if last and last.error else "unknown_request_failure",
    )


def failure_row(
    ready: ReadyRow,
    http_status: int | None,
    endpoint: str,
    attempt_count: int,
    error_reason: str,
) -> dict[str, object]:
    return {
        "hathor_height": ready.height,
        "hathor_block_hash": ready.tx_id,
        "http_status": "" if http_status is None else http_status,
        "endpoint": endpoint,
        "attempt_count": attempt_count,
        "error_reason": error_reason,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def check_acquisition_rows(
    ready_rows: dict[int, ReadyRow],
    dataset_rows: dict[int, dict[str, str]],
) -> None:
    """Validate dataset rows against the ready-ledger contract."""
    extra = set(dataset_rows).difference(ready_rows)
    if extra:
        raise ValueError(
            "acquisition dataset contains heights absent from its ready ledger: "
            f"extra={len(extra)}"
        )
    for height, row in dataset_rows.items():
        ready = ready_rows[height]
        if row.get("hathor_block_hash") != ready.tx_id:
            raise ValueError(f"dataset tx_id mismatch at height {height}")
        validate_request_provenance(row, height)
        validate_dataset_timestamp(row.get("hathor_timestamp"), height)
        if row.get("record_sha256") != acquisition_record_sha256(row):
            raise ValueError(f"acquisition record digest mismatch at height {height}")
        try:
            expected_prefix = funds_graph_hex(row["raw_hex"], row["aux_pow_hex"])
        except (KeyError, ValueError) as exc:
            raise ValueError(
                f"invalid acquisition evidence at height {height}"
            ) from exc
        if row.get("funds_graph_hex") != expected_prefix:
            raise ValueError(
                f"funds+graph does not match transaction bytes at height {height}"
            )


def validate_request_provenance(row: dict[str, object], height: int) -> None:
    """Require successful-request metadata in every dataset row."""
    endpoint = row.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError(f"missing successful request endpoint at height {height}")
    try:
        http_status = int(str(row.get("http_status", "")))
    except ValueError as exc:
        raise ValueError(f"invalid successful HTTP status at height {height}") from exc
    if not 200 <= http_status < 300:
        raise ValueError(f"invalid successful HTTP status at height {height}")
    try:
        attempt_count = int(str(row.get("attempt_count", "")))
    except ValueError as exc:
        raise ValueError(
            f"invalid successful attempt count at height {height}"
        ) from exc
    if attempt_count < 1:
        raise ValueError(f"invalid successful attempt count at height {height}")


def make_acquisition_row(payload: Payload) -> dict[str, object]:
    """Create one sealed dataset row with successful request provenance."""
    validate_dataset_timestamp(payload.timestamp, payload.height)
    row = {
        "hathor_height": payload.height,
        "hathor_block_hash": payload.tx_id,
        "hathor_timestamp": payload.timestamp,
        "aux_pow_hex": payload.aux_pow_hex,
        "funds_graph_hex": payload.funds_graph_hex,
        "raw_hex": payload.raw_hex,
        "endpoint": payload.endpoint,
        "http_status": payload.http_status,
        "attempt_count": payload.attempt_count,
    }
    validate_request_provenance(row, payload.height)
    row["record_sha256"] = acquisition_record_sha256(row)
    return row


def run_acquisition(
    *,
    ledger_path: Path,
    dataset_path: Path,
    failure_output: Path,
    start: int,
    end: int,
    client: PacedHttpClient,
    primary_endpoint: str,
    fallback_endpoint: str,
    limit: int | None = None,
) -> Counter[str]:
    """Resume one range with durable appends and one final ordering rewrite."""
    canonical_endpoint(primary_endpoint, "primary", allow_blank=False)
    canonical_endpoint(fallback_endpoint, "fallback", allow_blank=True)
    require_distinct_paths(
        ledger=ledger_path,
        dataset=dataset_path,
        failure_output=failure_output,
    )
    ready_rows = load_ready_rows(ledger_path, start, end)
    dataset_rows, observed_order = read_acquisition_rows(dataset_path)
    check_acquisition_rows(ready_rows, dataset_rows)
    pending = [
        ready_rows[height]
        for height in sorted(ready_rows)
        if height not in dataset_rows
    ]
    validate_append_csv(failure_output, FAILURE_COLUMNS)
    retry_rounds = read_failure_rounds(failure_output, ready_rows)
    if observed_order != sorted(observed_order) or not dataset_path.exists():
        replace_acquisition_rows_atomically(dataset_path, dataset_rows)

    pending.sort(key=lambda ready: (retry_rounds[ready.height], ready.height))
    if limit is not None:
        pending = pending[:limit]
    if not pending:
        return Counter(
            ready_total=len(ready_rows),
            dataset_complete=len(dataset_rows),
        )

    failure_handle, failure_writer = open_csv_writer(failure_output, FAILURE_COLUMNS)
    try:
        stats: Counter[str] = Counter()
        for ready in pending:
            payload, failure = fetch_payload(
                client, ready, primary_endpoint, fallback_endpoint
            )
            if failure is not None:
                write_durable_row(failure_handle, failure_writer, failure)
                stats["failure"] += 1
                continue
            assert payload is not None
            row = make_acquisition_row(payload)
            append_acquisition_row_durably(dataset_path, row)
            dataset_rows[payload.height] = {
                column: str(row[column]) for column in ACQUISITION_COLUMNS
            }
            observed_order.append(payload.height)
            stats["acquired"] += 1
        if observed_order != sorted(observed_order):
            replace_acquisition_rows_atomically(dataset_path, dataset_rows)
        stats["ready_total"] = len(ready_rows)
        stats["dataset_complete"] = len(dataset_rows)
        return stats
    finally:
        failure_handle.close()


def audit(
    ledger_path: Path,
    dataset_path: Path,
    start: int,
    end: int,
) -> dict[str, object]:
    """Fail closed unless the dataset exactly covers the ledger's ready rows."""
    require_distinct_paths(ledger=ledger_path, dataset=dataset_path)
    ready_rows = load_ready_rows(ledger_path, start, end)
    dataset_rows, dataset_order = read_acquisition_rows(dataset_path)
    check_acquisition_rows(ready_rows, dataset_rows)
    require_ordered_heights(dataset_path, dataset_order)
    missing = set(ready_rows).difference(dataset_rows)
    if missing:
        raise ValueError(f"acquisition coverage incomplete: missing={len(missing)}")
    digest = hashlib.sha256()
    for height in sorted(ready_rows):
        row = dataset_rows[height]
        digest.update(
            "\t".join(
                [
                    str(height),
                    ready_rows[height].tx_id,
                    hashlib.sha256(row["raw_hex"].encode()).hexdigest(),
                    hashlib.sha256(row["aux_pow_hex"].encode()).hexdigest(),
                    hashlib.sha256(row["funds_graph_hex"].encode()).hexdigest(),
                ]
            ).encode()
        )
        digest.update(b"\n")
    return {
        "ready_rows": len(ready_rows),
        "dataset_rows": len(dataset_rows),
        "ledger_sha256": file_sha256(ledger_path),
        "dataset_sha256": file_sha256(dataset_path),
        "evidence_root_sha256": digest.hexdigest(),
    }


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    mode = argument_parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--audit", action="store_true")
    argument_parser.add_argument("--ledger", required=True, type=Path)
    argument_parser.add_argument("--dataset", required=True, type=Path)
    argument_parser.add_argument("--failure-output", type=Path)
    argument_parser.add_argument("--start", required=True, type=nonnegative_int)
    argument_parser.add_argument("--end", required=True, type=nonnegative_int)
    argument_parser.add_argument("--api-url", default=DEFAULT_API)
    argument_parser.add_argument("--fallback-api-url", default=DEFAULT_FALLBACK_API)
    argument_parser.add_argument(
        "--requests-per-second",
        type=positive_float,
        default=DEFAULT_REQUESTS_PER_SECOND,
        help="Per-worker maximum request starts per second (default: 0.25)",
    )
    argument_parser.add_argument("--timeout", type=positive_float, default=30.0)
    argument_parser.add_argument("--max-attempts", type=int, default=3)
    argument_parser.add_argument(
        "--limit",
        type=nonnegative_int,
        help=(
            "Maximum pending heights scheduled this invocation, ordered by "
            "least completed failure round then height"
        ),
    )
    return argument_parser


def main() -> None:
    args = parser().parse_args()
    if args.start >= args.end:
        raise SystemExit("--start must be lower than --end")
    if args.max_attempts < 1:
        raise SystemExit("--max-attempts must be at least one")
    if args.failure_output is None:
        args.failure_output = args.dataset.with_name(
            f"{args.dataset.stem}-failures.csv"
        )

    if args.audit:
        report = audit(
            args.ledger,
            args.dataset,
            args.start,
            args.end,
        )
        for key, value in report.items():
            print(f"{key}={value}")
        return

    client = PacedHttpClient(
        args.requests_per_second,
        args.timeout,
        args.max_attempts,
        user_agent=USER_AGENT,
    )
    stats = run_acquisition(
        ledger_path=args.ledger,
        dataset_path=args.dataset,
        failure_output=args.failure_output,
        start=args.start,
        end=args.end,
        client=client,
        primary_endpoint=args.api_url,
        fallback_endpoint=args.fallback_api_url,
        limit=args.limit,
    )
    for key, value in sorted(stats.items()):
        print(f"{key}={value}")


if __name__ == "__main__":
    main()
