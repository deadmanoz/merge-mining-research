#!/usr/bin/env python3
"""Fetch complete Hathor v3 payload evidence from an audited metadata ledger.

The pre-million metadata census already establishes one ``tx_id`` for every
``version_3_ready`` height. This collector makes one ``/transaction`` request
per ready row that lacks a sealed source record in the current run and writes
one complete record to an augmented ``hathor_auxpow_raw.csv``. Failed attempts
remain append-only history and are retried on later runs until a sealed source
row exists. The durable failure log is the retry-round scheduler: pending
heights are fetched in least-completed-failure-round then height order, so a
permanently failing early height cannot starve later ones under ``--limit``
and remains retryable after a full pass. New payloads must locate their unique
``aux_pow`` at a byte offset of at least three inside the raw transaction;
shorter funds-graph prefixes fail as ``funds_graph_prefix_too_short``. Each
source row includes the existing AuxPoW columns plus the
lossless ``raw_hex`` payload and its derived ``funds_graph_hex`` bytes. New v2
rows also retain the serving endpoint, HTTP status, and total attempt count. A
SHA-256 record seal covers every source field, so an interrupted or manually
damaged primary row is rejected before a resume or publication audit can treat
it as complete. Completed sealed-v1 files remain readable and immutable, but
cannot be resumed because their request provenance was never recorded.

The established three-column ``hathor_funds_graph.csv`` is not written beside
each fetched row. ``--build-supplement`` creates it atomically from the complete
source CSV after acquisition, so it is a checked projection of one source of
truth, never an independently resumed second dataset.

All source and result records remain CSV.  The output is private archival data
and is intentionally not written under the repository's ``data/`` directory.
"""

from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import json
import math
import os
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.client import IncompleteRead
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


DEFAULT_API = "https://node1.mainnet.hathor.network/v1a"
DEFAULT_FALLBACK_API = "https://node2.mainnet.hathor.network/v1a"
DEFAULT_REQUESTS_PER_SECOND = 0.25
USER_AGENT = "merge-mining-research/hathor-pre-million-payload"

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
LEGACY_RAW_COLUMNS = [
    "hathor_height",
    "hathor_block_hash",
    "hathor_timestamp",
    "aux_pow_hex",
    "funds_graph_hex",
    "raw_hex",
]
RAW_V1_COLUMNS = [
    *LEGACY_RAW_COLUMNS,
    "record_sha256",
]
UNSEALED_RAW_COLUMNS = [
    *LEGACY_RAW_COLUMNS,
    "endpoint",
    "http_status",
    "attempt_count",
]
RAW_COLUMNS = [
    *UNSEALED_RAW_COLUMNS,
    "record_sha256",
]
SUPPLEMENT_COLUMNS = ["hathor_height", "hathor_block_hash", "funds_graph_hex"]
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
class HttpResult:
    status: int | None
    payload: dict[str, Any] | None
    error: str | None
    retryable: bool


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


def require_api_timestamp(value: object) -> int:
    """Require one exact non-negative JSON integer timestamp."""
    if type(value) is not int or value < 0:
        raise ValueError("invalid_timestamp")
    return value


def validate_archived_timestamp(value: object, height: int) -> int:
    """Require canonical non-negative timestamp text in durable evidence."""
    try:
        parsed = int(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid timestamp at height {height}") from exc
    if str(parsed) != str(value) or parsed < 0:
        raise ValueError(f"non-canonical timestamp at height {height}")
    return parsed


def paths_alias(left: Path, right: Path) -> bool:
    """Return whether two path spellings can address the same filesystem entry."""
    if left.resolve(strict=False) == right.resolve(strict=False):
        return True
    try:
        return left.samefile(right)
    except FileNotFoundError:
        return False


def require_distinct_paths(**paths: Path) -> None:
    """Reject destructive input/output aliases before locks or writes."""
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


def raw_record_sha256(
    row: dict[str, object], raw_columns: list[str] | None = None
) -> str:
    """Hash one v1 or v2 primary source row without inventing provenance."""
    if raw_columns == RAW_V1_COLUMNS:
        sealed_columns = LEGACY_RAW_COLUMNS
    elif raw_columns == RAW_COLUMNS:
        sealed_columns = UNSEALED_RAW_COLUMNS
    elif raw_columns is not None:
        raise ValueError(f"unsupported sealed raw schema: {raw_columns}")
    else:
        provenance_fields = ("endpoint", "http_status", "attempt_count")
        provenance_present = [field in row for field in provenance_fields]
        if all(provenance_present):
            sealed_columns = UNSEALED_RAW_COLUMNS
        elif not any(provenance_present):
            sealed_columns = LEGACY_RAW_COLUMNS
        else:
            raise ValueError("raw source row has partial request provenance")

    digest = hashlib.sha256()
    for column in sealed_columns:
        value = row.get(column)
        if value is None:
            raise ValueError(f"missing {column} in raw source row")
        encoded = str(value).encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def fsync_directory(path: Path) -> None:
    """Persist a directory entry after creating or replacing an artifact."""
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


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
    ready_tx_heights: dict[str, int] = {}
    observed_heights: list[int] = []
    try:
        with ledger_path.open(newline="") as handle:
            reader = csv.DictReader(handle, strict=True)
            if reader.fieldnames != LEDGER_COLUMNS:
                raise ValueError(
                    f"unexpected metadata ledger columns: {reader.fieldnames}"
                )
            previous_line = reader.line_num
            for row in reader:
                if reader.line_num != previous_line + 1:
                    raise ValueError("metadata ledger has a malformed physical row")
                previous_line = reader.line_num
                if set(row) != set(LEDGER_COLUMNS) or any(
                    value is None for value in row.values()
                ):
                    raise ValueError("metadata ledger row has an incomplete schema")

                height = canonical_metadata_integer(
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
                status = canonical_metadata_integer(
                    row["http_status"], "http_status", minimum=100
                )
                if not 200 <= status < 300:
                    raise ValueError(
                        f"invalid resolved metadata http_status at height {height}: "
                        f"{status}"
                    )
                version = canonical_metadata_integer(
                    row["block_version"], "block_version", minimum=0
                )
                canonical_metadata_integer(
                    row["attempt_count"], "attempt_count", minimum=1
                )
                if not row["endpoint"].strip() or row["error_reason"]:
                    raise ValueError(
                        f"invalid resolved metadata fields at height {height}"
                    )

                tx_id = row["tx_id"]
                if outcome == "version_3_ready":
                    if version != 3 or not is_canonical_tx_id(tx_id):
                        raise ValueError(
                            f"invalid version_3_ready fields at height {height}"
                        )
                    previous_height = ready_tx_heights.get(tx_id)
                    if previous_height is not None:
                        raise ValueError(
                            "version_3_ready transaction ID is assigned to multiple "
                            f"heights: {previous_height}, {height}"
                        )
                    ready_tx_heights[tx_id] = height
                    ready[height] = ReadyRow(height, tx_id)
                elif version == 3:
                    raise ValueError(f"invalid non_version_3 fields at height {height}")
            if reader.line_num != previous_line:
                raise ValueError("metadata ledger has a malformed trailing row")
    except csv.Error as exc:
        raise ValueError("malformed metadata ledger CSV") from exc

    expected_heights = list(range(start, end))
    if observed_heights != expected_heights:
        raise ValueError(
            "metadata ledger coverage or ordering is invalid: "
            f"expected={len(expected_heights)} observed={len(observed_heights)}"
        )
    return ready


def canonical_metadata_integer(value: str, field: str, *, minimum: int) -> int:
    """Parse one canonical non-padded integer from a metadata row."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid metadata {field}: {value!r}") from exc
    if str(parsed) != value or parsed < minimum:
        raise ValueError(f"non-canonical metadata {field}: {value!r}")
    return parsed


def canonical_csv_height(value: str, path: Path) -> int:
    """Parse one canonical non-negative height from an evidence CSV."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid height in {path}: {value!r}") from exc
    if str(parsed) != value or parsed < 0:
        raise ValueError(f"non-canonical height in {path}: {value!r}")
    return parsed


def read_csv_rows_with_order(
    path: Path, columns: list[str]
) -> tuple[dict[int, dict[str, str]], list[int]]:
    """Read a payload CSV, retaining physical order for reproducibility checks."""
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
            previous_line = reader.line_num
            for row in reader:
                if reader.line_num != previous_line + 1:
                    raise ValueError(f"malformed physical CSV row in {path}")
                previous_line = reader.line_num
                if set(row) != set(columns) or any(
                    value is None for value in row.values()
                ):
                    raise ValueError(f"incomplete or extra CSV cells in {path}")
                height = canonical_csv_height(row["hathor_height"], path)
                if height in rows:
                    raise ValueError(f"duplicate height in {path}: {height}")
                rows[height] = row
                observed_order.append(height)
            if reader.line_num != previous_line:
                raise ValueError(f"malformed trailing CSV row in {path}")
    except csv.Error as exc:
        raise ValueError(f"malformed CSV: {path}") from exc
    return rows, observed_order


def read_csv_rows(path: Path, columns: list[str]) -> dict[int, dict[str, str]]:
    """Read a payload CSV, rejecting header drift and duplicate heights."""
    rows, _observed_order = read_csv_rows_with_order(path, columns)
    return rows


def validate_failure_http_status(value: str, path: Path) -> None:
    """Require the blank-or-canonical status form emitted by ``failure_row``."""
    if value == "":
        return
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid failure http_status in {path}: {value!r}") from exc
    if str(parsed) != value or not 100 <= parsed <= 599:
        raise ValueError(f"non-canonical failure http_status in {path}: {value!r}")


def validate_failure_timestamp(value: str, path: Path) -> None:
    """Require the exact timezone-aware UTC form emitted by ``failure_row``."""
    if not value:
        raise ValueError(f"blank recorded_at_utc in failure history: {path}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"invalid recorded_at_utc in {path}: {value!r}") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
        or parsed.isoformat() != value
    ):
        raise ValueError(f"non-canonical recorded_at_utc in {path}: {value!r}")


def read_failure_rounds(path: Path, ready_rows: dict[int, ReadyRow]) -> Counter[int]:
    """Count validated durable failure rows per ready height for fair retries.

    A missing or empty failure log means zero completed rounds. Any malformed
    history fails closed so a later run never schedules against corrupt state.
    """
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
            previous_line = reader.line_num
            for row in reader:
                if reader.line_num != previous_line + 1:
                    raise ValueError(f"malformed physical CSV row in {path}")
                previous_line = reader.line_num
                if set(row) != set(FAILURE_COLUMNS) or any(
                    value is None for value in row.values()
                ):
                    raise ValueError(f"incomplete or extra CSV cells in {path}")
                height = canonical_csv_height(row["hathor_height"], path)
                ready = ready_rows.get(height)
                if ready is None:
                    raise ValueError(
                        f"failure history without a ready height in {path}: {height}"
                    )
                if row["hathor_block_hash"] != ready.tx_id:
                    raise ValueError(f"failure tx_id mismatch at height {height}")
                validate_failure_http_status(row["http_status"], path)
                try:
                    attempt_count = int(row["attempt_count"])
                except ValueError as exc:
                    raise ValueError(
                        f"invalid attempt_count in {path}: {row['attempt_count']!r}"
                    ) from exc
                if str(attempt_count) != row["attempt_count"] or attempt_count < 1:
                    raise ValueError(
                        f"non-canonical attempt_count in {path}: "
                        f"{row['attempt_count']!r}"
                    )
                for field in ("endpoint", "error_reason"):
                    value = row[field]
                    if not value.strip():
                        raise ValueError(
                            f"blank {field} in failure history at height {height}"
                        )
                    if value != value.strip():
                        raise ValueError(
                            f"non-canonical {field} in failure history at height {height}"
                        )
                validate_failure_timestamp(row["recorded_at_utc"], path)
                rounds[height] += 1
            if reader.line_num != previous_line:
                raise ValueError(f"malformed trailing CSV row in {path}")
    except csv.Error as exc:
        raise ValueError(f"malformed CSV: {path}") from exc
    return rounds


def read_raw_rows(
    path: Path,
) -> tuple[list[str], dict[int, dict[str, str]], list[int]]:
    """Read either immutable sealed-v1 evidence or the current v2 schema."""
    if not path.exists() or path.stat().st_size == 0:
        return RAW_COLUMNS, {}, []
    with path.open(newline="") as handle:
        header = next(csv.reader(handle), None)
    if header not in (RAW_V1_COLUMNS, RAW_COLUMNS):
        raise ValueError(f"unexpected columns in {path}: {header}")
    rows, observed_order = read_csv_rows_with_order(path, header)
    return header, rows, observed_order


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
            fsync_directory(path.parent)
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


def replace_csv_atomically(
    path: Path,
    columns: list[str],
    rows: Iterable[dict[str, object]],
) -> None:
    """Durably replace one CSV from a unique same-directory staging file."""
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
                fieldnames=columns,
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def replace_raw_rows_atomically(
    path: Path,
    rows: dict[int, dict[str, object]],
) -> None:
    """Persist a complete primary row map in deterministic height order."""
    replace_csv_atomically(path, RAW_COLUMNS, (rows[height] for height in sorted(rows)))


def replace_sealed_rows_atomically(
    path: Path,
    columns: list[str],
    rows: dict[int, dict[str, object]],
) -> None:
    """Persist one versioned sealed row family in deterministic height order."""
    replace_csv_atomically(path, columns, (rows[height] for height in sorted(rows)))


def write_durable_row(handle, writer: csv.DictWriter, row: dict[str, object]) -> None:
    """Append one source row before moving on to another API request."""
    writer.writerow(row)
    handle.flush()
    os.fsync(handle.fileno())


def append_raw_row_durably(path: Path, row: dict[str, object]) -> None:
    """Append one sealed v2 row before any canonical-order rewrite."""
    handle, writer = open_csv_writer(path, RAW_COLUMNS)
    try:
        write_durable_row(handle, writer, row)
    finally:
        handle.close()


def acquire_locks(paths: Iterable[Path]):
    """Acquire process-lifetime exclusive locks for all output paths."""
    handles = []
    try:
        for path in sorted(paths):
            lock_path = path.with_suffix(f"{path.suffix}.lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            handle = lock_path.open("a")
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                handle.close()
                raise RuntimeError(f"output is already in use: {path}") from exc
            handles.append(handle)
        return handles
    except BaseException:
        for handle in reversed(handles):
            handle.close()
        raise


class PacedHttpClient:
    """A sequential, endpoint-fallback client with bounded retries."""

    def __init__(
        self,
        requests_per_second: float,
        timeout: float,
        max_attempts: int,
        opener: Callable[..., Any] = urlopen,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.min_interval = 1.0 / requests_per_second
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.opener = opener
        self.sleep = sleep
        self.monotonic = monotonic
        self._last_request_start: float | None = None

    def get_json(self, endpoint: str, path: str, params: dict[str, str]) -> HttpResult:
        """Fetch a JSON response, pacing every attempt including retries."""
        url = f"{endpoint.rstrip('/')}{path}?{urlencode(params)}"
        now = self.monotonic()
        if self._last_request_start is not None:
            remaining = self.min_interval - (now - self._last_request_start)
            if remaining > 0:
                self.sleep(remaining)
        self._last_request_start = self.monotonic()
        request = Request(
            url,
            headers={"accept": "application/json", "user-agent": USER_AGENT},
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                status = response.getcode()
                try:
                    body = response.read()
                except IncompleteRead:
                    return HttpResult(status, None, "IncompleteRead", True)
                try:
                    payload = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return HttpResult(status, None, "invalid_json", True)
                if not isinstance(payload, dict):
                    return HttpResult(status, None, "json_not_object", True)
                return HttpResult(status, payload, None, False)
        except HTTPError as error:
            return HttpResult(
                error.code,
                None,
                f"http_{error.code}",
                error.code in {429, 500, 502, 503, 504},
            )
        except (URLError, TimeoutError, OSError, IncompleteRead) as error:
            return HttpResult(None, None, type(error).__name__, True)


def parse_payload(
    ready: ReadyRow,
    response: dict[str, Any],
    endpoint: str,
    http_status: int,
    attempt_count: int,
) -> Payload:
    """Require exact identity, version, timestamp, and payload evidence."""
    if not response.get("success"):
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
    raw_hex = tx.get("raw")
    aux_pow_hex = tx.get("aux_pow")
    if not isinstance(raw_hex, str) or not raw_hex:
        raise ValueError("missing_raw")
    if not isinstance(aux_pow_hex, str) or not aux_pow_hex:
        raise ValueError("missing_aux_pow")
    try:
        raw = decode_compact_hex(raw_hex)
        aux_pow = decode_compact_hex(aux_pow_hex)
    except ValueError as exc:
        raise ValueError("invalid_hex") from exc
    if not aux_pow:
        raise ValueError("empty_aux_pow")
    occurrence_count = raw.count(aux_pow)
    if occurrence_count != 1:
        raise ValueError(f"aux_pow_occurrences_{occurrence_count}")
    offset = raw.find(aux_pow)
    if offset < 3:
        raise ValueError("funds_graph_prefix_too_short")
    timestamp = require_api_timestamp(tx.get("timestamp"))
    return Payload(
        height=ready.height,
        tx_id=ready.tx_id,
        timestamp=timestamp,
        aux_pow_hex=aux_pow_hex,
        raw_hex=raw_hex,
        funds_graph_hex=raw[:offset].hex(),
        endpoint=endpoint,
        http_status=http_status,
        attempt_count=attempt_count,
    )


def canonical_endpoint(value: str, name: str, *, allow_blank: bool) -> str:
    """Trim endpoint padding and reject whitespace that remains inside it."""
    endpoint = value.strip().rstrip("/")
    if not endpoint:
        if allow_blank:
            return ""
        raise ValueError(f"{name} endpoint must be non-empty")
    if any(character.isspace() for character in endpoint):
        raise ValueError(f"{name} endpoint must not contain whitespace")
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


def raw_to_supplement(row: dict[str, str]) -> dict[str, str]:
    """Derive an established supplement row from durable raw evidence."""
    try:
        raw = decode_compact_hex(row["raw_hex"])
        aux_pow = decode_compact_hex(row["aux_pow_hex"])
    except (KeyError, ValueError) as exc:
        raise ValueError(
            f"invalid raw evidence at height {row.get('hathor_height', '?')}"
        ) from exc
    if not aux_pow:
        raise ValueError(f"empty aux_pow at height {row['hathor_height']}")
    occurrence_count = raw.count(aux_pow)
    if occurrence_count != 1:
        raise ValueError(
            f"aux_pow_occurrences_{occurrence_count} at height {row['hathor_height']}"
        )
    return {
        "hathor_height": row["hathor_height"],
        "hathor_block_hash": row["hathor_block_hash"],
        "funds_graph_hex": raw[: raw.find(aux_pow)].hex(),
    }


def check_raw_rows(
    ready_rows: dict[int, ReadyRow],
    raw_rows: dict[int, dict[str, str]],
    raw_columns: list[str],
) -> None:
    """Validate versioned primary rows against the ready-ledger contract."""
    if raw_columns not in (RAW_V1_COLUMNS, RAW_COLUMNS):
        raise ValueError(f"unsupported sealed raw schema: {raw_columns}")
    raw_extra = set(raw_rows).difference(ready_rows)
    if raw_extra:
        raise ValueError(
            "payload output contains heights absent from its ready ledger: "
            f"raw={len(raw_extra)}"
        )
    for height, row in raw_rows.items():
        ready = ready_rows[height]
        if row.get("hathor_block_hash") != ready.tx_id:
            raise ValueError(f"raw tx_id mismatch at height {height}")
        if raw_columns == RAW_COLUMNS:
            validate_request_provenance(row, height)
        if row.get("record_sha256") != raw_record_sha256(row, raw_columns):
            raise ValueError(f"raw record digest mismatch at height {height}")
        expected = raw_to_supplement(row)
        if row.get("funds_graph_hex") != expected["funds_graph_hex"]:
            raise ValueError(
                f"funds+graph does not match raw evidence at height {height}"
            )


def validate_request_provenance(row: dict[str, object], height: int) -> None:
    """Require canonical successful-request metadata in every primary row."""
    endpoint = row.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError(f"missing successful request endpoint at height {height}")
    try:
        http_status = int(str(row.get("http_status", "")))
    except ValueError as exc:
        raise ValueError(f"invalid successful HTTP status at height {height}") from exc
    if str(http_status) != str(row.get("http_status")) or not 200 <= http_status < 300:
        raise ValueError(f"invalid successful HTTP status at height {height}")
    try:
        attempt_count = int(str(row.get("attempt_count", "")))
    except ValueError as exc:
        raise ValueError(
            f"invalid successful attempt count at height {height}"
        ) from exc
    if str(attempt_count) != str(row.get("attempt_count")) or attempt_count < 1:
        raise ValueError(f"invalid successful attempt count at height {height}")


def check_unsealed_raw_rows(
    ready_rows: dict[int, ReadyRow],
    raw_rows: dict[int, dict[str, str]],
    *,
    require_request_provenance: bool,
) -> None:
    """Validate pre-seal rows before their schema-preserving local upgrade."""
    raw_extra = set(raw_rows).difference(ready_rows)
    if raw_extra:
        raise ValueError(
            "payload output contains heights absent from its ready ledger: "
            f"raw={len(raw_extra)}"
        )
    for height, row in raw_rows.items():
        ready = ready_rows[height]
        if row.get("hathor_block_hash") != ready.tx_id:
            raise ValueError(f"raw tx_id mismatch at height {height}")
        validate_archived_timestamp(row.get("hathor_timestamp"), height)
        if require_request_provenance:
            validate_request_provenance(row, height)
        expected = raw_to_supplement(row)
        if row.get("funds_graph_hex") != expected["funds_graph_hex"]:
            raise ValueError(
                f"funds+graph does not match raw evidence at height {height}"
            )


def make_raw_row(payload: Payload) -> dict[str, object]:
    """Create one sealed source row including successful request provenance."""
    validate_archived_timestamp(payload.timestamp, payload.height)
    raw = {
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
    validate_request_provenance(raw, payload.height)
    raw["record_sha256"] = raw_record_sha256(raw, RAW_COLUMNS)
    return raw


def run_extraction(
    *,
    ledger_path: Path,
    raw_output: Path,
    failure_output: Path,
    start: int,
    end: int,
    client: PacedHttpClient,
    primary_endpoint: str,
    fallback_endpoint: str,
    limit: int | None = None,
) -> Counter[str]:
    """Resume one range with durable appends and one final ordering rewrite."""
    require_distinct_paths(
        ledger=ledger_path,
        raw_output=raw_output,
        failure_output=failure_output,
    )
    ready_rows = load_ready_rows(ledger_path, start, end)
    locks = acquire_locks([raw_output, failure_output])
    try:
        raw_columns, raw_rows, observed_order = read_raw_rows(raw_output)
        check_raw_rows(ready_rows, raw_rows, raw_columns)
        pending = [
            ready_rows[height]
            for height in sorted(ready_rows)
            if height not in raw_rows
        ]
        if raw_columns == RAW_V1_COLUMNS:
            require_ordered_heights(raw_output, observed_order)
            if pending:
                raise ValueError(
                    "sealed v1 payload evidence is incomplete and cannot be resumed "
                    "without successful request provenance; reacquire into a new output"
                )
            return Counter(
                ready_total=len(ready_rows),
                raw_complete=len(raw_rows),
            )

        validate_append_csv(failure_output, FAILURE_COLUMNS)
        retry_rounds = read_failure_rounds(failure_output, ready_rows)
        if observed_order != sorted(observed_order) or not raw_output.exists():
            replace_raw_rows_atomically(raw_output, raw_rows)

        pending.sort(key=lambda ready: (retry_rounds[ready.height], ready.height))
        if limit is not None:
            pending = pending[:limit]
        if not pending:
            return Counter(
                ready_total=len(ready_rows),
                raw_complete=len(raw_rows),
            )

        failure_handle, failure_writer = open_csv_writer(
            failure_output, FAILURE_COLUMNS
        )
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
                raw = make_raw_row(payload)
                append_raw_row_durably(raw_output, raw)
                raw_rows[payload.height] = {
                    column: str(raw[column]) for column in RAW_COLUMNS
                }
                observed_order.append(payload.height)
                stats["archived"] += 1
            if observed_order != sorted(observed_order):
                replace_raw_rows_atomically(raw_output, raw_rows)
            stats["ready_total"] = len(ready_rows)
            stats["raw_complete"] = len(raw_rows)
            return stats
        finally:
            failure_handle.close()
    finally:
        for handle in reversed(locks):
            handle.close()


def upgrade_raw(
    ledger_path: Path,
    raw_path: Path,
    start: int,
    end: int,
) -> dict[str, int]:
    """Atomically seal v1 or v2 rows without changing their evidence schema."""
    require_distinct_paths(ledger=ledger_path, raw_output=raw_path)
    ready_rows = load_ready_rows(ledger_path, start, end)
    locks = acquire_locks([raw_path])
    try:
        with raw_path.open(newline="") as handle:
            header = next(csv.reader(handle), None)
        if header == LEGACY_RAW_COLUMNS:
            sealed_columns = RAW_V1_COLUMNS
            require_request_provenance = False
        elif header == UNSEALED_RAW_COLUMNS:
            sealed_columns = RAW_COLUMNS
            require_request_provenance = True
        else:
            raise ValueError(f"unexpected columns in {raw_path}: {header}")

        unsealed_rows = read_csv_rows(raw_path, header)
        check_unsealed_raw_rows(
            ready_rows,
            unsealed_rows,
            require_request_provenance=require_request_provenance,
        )
        missing = set(ready_rows).difference(unsealed_rows)
        if missing:
            raise ValueError(f"raw payload coverage incomplete: missing={len(missing)}")
        sealed_rows: dict[int, dict[str, object]] = {}
        for height, unsealed in unsealed_rows.items():
            row: dict[str, object] = dict(unsealed)
            row["record_sha256"] = raw_record_sha256(row, sealed_columns)
            sealed_rows[height] = row
        replace_sealed_rows_atomically(raw_path, sealed_columns, sealed_rows)
    finally:
        for handle in reversed(locks):
            handle.close()
    return {"upgraded_rows": len(unsealed_rows)}


def build_supplement(
    ledger_path: Path,
    raw_path: Path,
    supplement_path: Path,
    start: int,
    end: int,
) -> dict[str, int]:
    """Atomically build the established supplement CSV from primary evidence."""
    require_distinct_paths(
        ledger=ledger_path,
        raw_output=raw_path,
        supplement_output=supplement_path,
    )
    ready_rows = load_ready_rows(ledger_path, start, end)
    locks = acquire_locks([raw_path, supplement_path])
    try:
        raw_columns, raw_rows, raw_order = read_raw_rows(raw_path)
        check_raw_rows(ready_rows, raw_rows, raw_columns)
        require_ordered_heights(raw_path, raw_order)
        missing = set(ready_rows).difference(raw_rows)
        if missing:
            raise ValueError(f"raw payload coverage incomplete: missing={len(missing)}")
        replace_csv_atomically(
            supplement_path,
            SUPPLEMENT_COLUMNS,
            (raw_to_supplement(raw_rows[height]) for height in sorted(ready_rows)),
        )
    finally:
        for handle in reversed(locks):
            handle.close()
    return {"ready_rows": len(ready_rows), "supplement_rows": len(raw_rows)}


def audit(
    ledger_path: Path,
    raw_path: Path,
    supplement_path: Path,
    start: int,
    end: int,
) -> dict[str, object]:
    """Fail closed unless both evidence CSVs exactly cover their ready rows."""
    require_distinct_paths(
        ledger=ledger_path,
        raw_output=raw_path,
        supplement_output=supplement_path,
    )
    ready_rows = load_ready_rows(ledger_path, start, end)
    raw_columns, raw_rows, raw_order = read_raw_rows(raw_path)
    supplement_rows, supplement_order = read_csv_rows_with_order(
        supplement_path, SUPPLEMENT_COLUMNS
    )
    check_raw_rows(ready_rows, raw_rows, raw_columns)
    require_ordered_heights(raw_path, raw_order)
    require_ordered_heights(supplement_path, supplement_order)
    raw_missing = set(ready_rows).difference(raw_rows)
    supplement_missing = set(ready_rows).difference(supplement_rows)
    supplement_extra = set(supplement_rows).difference(ready_rows)
    if raw_missing or supplement_missing or supplement_extra:
        raise ValueError(
            "payload coverage incomplete: "
            f"raw_missing={len(raw_missing)} supplement_missing={len(supplement_missing)} "
            f"supplement_extra={len(supplement_extra)}"
        )
    digest = hashlib.sha256()
    for height in sorted(ready_rows):
        raw = raw_rows[height]
        supplement = supplement_rows[height]
        if supplement != raw_to_supplement(raw):
            raise ValueError(
                f"supplement does not match raw evidence at height {height}"
            )
        digest.update(
            "\t".join(
                [
                    str(height),
                    ready_rows[height].tx_id,
                    hashlib.sha256(raw["raw_hex"].encode()).hexdigest(),
                    hashlib.sha256(raw["aux_pow_hex"].encode()).hexdigest(),
                    hashlib.sha256(supplement["funds_graph_hex"].encode()).hexdigest(),
                ]
            ).encode()
        )
        digest.update(b"\n")
    return {
        "ready_rows": len(ready_rows),
        "raw_rows": len(raw_rows),
        "supplement_rows": len(supplement_rows),
        "raw_schema": "sealed_v1" if raw_columns == RAW_V1_COLUMNS else "sealed_v2",
        "ledger_sha256": file_sha256(ledger_path),
        "raw_sha256": file_sha256(raw_path),
        "evidence_root_sha256": digest.hexdigest(),
    }


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    mode = argument_parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--upgrade-raw", action="store_true")
    mode.add_argument("--build-supplement", action="store_true")
    mode.add_argument("--audit", action="store_true")
    argument_parser.add_argument("--ledger", required=True, type=Path)
    argument_parser.add_argument("--raw-output", required=True, type=Path)
    argument_parser.add_argument("--supplement-output", type=Path)
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
        args.failure_output = args.raw_output.with_name(
            f"{args.raw_output.stem}-failures.csv"
        )

    if (args.build_supplement or args.audit) and args.supplement_output is None:
        raise SystemExit("--build-supplement and --audit require --supplement-output")

    if args.upgrade_raw:
        report = upgrade_raw(
            args.ledger,
            args.raw_output,
            args.start,
            args.end,
        )
        for key, value in report.items():
            print(f"{key}={value}")
        return

    if args.build_supplement:
        report = build_supplement(
            args.ledger,
            args.raw_output,
            args.supplement_output,
            args.start,
            args.end,
        )
        for key, value in report.items():
            print(f"{key}={value}")
        return

    if args.audit:
        report = audit(
            args.ledger,
            args.raw_output,
            args.supplement_output,
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
    )
    stats = run_extraction(
        ledger_path=args.ledger,
        raw_output=args.raw_output,
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
