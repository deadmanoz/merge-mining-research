#!/usr/bin/env python3
"""Safely survey Hathor heights into a complete, resumable metadata ledger.

The historical Hathor extractor deliberately writes only ``version == 3``
blocks. It is therefore not evidence that an absent height was ever scanned:
it may instead be a normal version-0 block. This tool records one terminal
metadata outcome for every assigned height before any version-3 payload fetch.

The worker is deliberately sequential. ``--requests-per-second`` limits each
worker's request starts, including retries, and failures remain visible in the
ledger rather than being silently retried forever. Use a declared, immutable
manifest to partition the inclusive start / exclusive end range across workers.

Examples:

    # Create the private manifest before starting any worker.
    python scripts/extract/hathor_metadata_ledger.py --write-manifest \
        <chain-archive>/hathor/pre-million/manifest.csv \
        --workers worker-a,worker-b,worker-c,worker-d,worker-e,worker-f

    # Run one assigned shard at the conservative default rate.
    python scripts/extract/hathor_metadata_ledger.py --manifest manifest.csv \
        --shard-id shard-003 --ledger shard-003-ledger.csv

    # Audit a completed merged ledger before payload work.
    python scripts/extract/hathor_metadata_ledger.py --audit-ledger ledger.csv \
        --start 0 --end 1000000

    # Re-drive terminal failures into a new, ordered ledger.
    python scripts/extract/hathor_metadata_ledger.py --manifest manifest.csv \
        --shard-id shard-003 --ledger shard-003-ledger.csv \
        --retry-outcomes request_failure,unavailable_block \
        --retry-output shard-003-ledger-retry.csv
"""

from __future__ import annotations

import argparse
import csv
import fcntl
import json
import math
import os
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from http.client import IncompleteRead
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


DEFAULT_API = "https://node1.mainnet.hathor.network/v1a"
DEFAULT_FALLBACK_API = "https://node2.mainnet.hathor.network/v1a"
DEFAULT_START = 0
DEFAULT_END = 1_000_000
DEFAULT_REQUESTS_PER_SECOND = 0.5
USER_AGENT = "merge-mining-research/hathor-pre-million-metadata"

MANIFEST_COLUMNS = [
    "shard_id",
    "start_height",
    "end_height",
    "worker",
    "primary_endpoint",
    "fallback_endpoint",
    "extractor_revision",
    "status",
]
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
FINAL_LEDGER_OUTCOMES = frozenset({"version_3_ready", "non_version_3"})
RETRYABLE_LEDGER_OUTCOMES = frozenset({"request_failure", "unavailable_block"})
LEDGER_OUTCOMES = FINAL_LEDGER_OUTCOMES | RETRYABLE_LEDGER_OUTCOMES
LOWER_HEX_DIGITS = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class Shard:
    shard_id: str
    start_height: int
    end_height: int
    worker: str
    primary_endpoint: str
    fallback_endpoint: str
    extractor_revision: str
    status: str


@dataclass(frozen=True)
class HttpResult:
    status: int | None
    payload: dict[str, Any] | None
    error: str | None
    retryable: bool


def is_canonical_tx_id(value: object) -> bool:
    """Return whether a transaction ID is canonical lowercase 32-byte hex."""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in LOWER_HEX_DIGITS for character in value)
    )


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def parse_retry_outcomes(value: str) -> frozenset[str]:
    outcomes = frozenset(part.strip() for part in value.split(",") if part.strip())
    if not outcomes:
        raise argparse.ArgumentTypeError("must name at least one retry outcome")
    invalid = outcomes.difference(RETRYABLE_LEDGER_OUTCOMES)
    if invalid:
        raise argparse.ArgumentTypeError(
            "unsupported retry outcomes: " + ", ".join(sorted(invalid))
        )
    return outcomes


def fsync_directory(path: Path) -> None:
    """Persist a completed no-clobber output's directory entry."""
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def make_shards(
    start: int,
    end: int,
    workers: list[str],
    primary_endpoint: str,
    fallback_endpoint: str,
    extractor_revision: str,
) -> list[Shard]:
    """Partition ``[start, end)`` deterministically into contiguous shards."""
    if start >= end:
        raise ValueError("start must be lower than end")
    if not workers or any(not worker for worker in workers):
        raise ValueError("at least one non-empty worker is required")
    if len(set(workers)) != len(workers):
        raise ValueError("workers must be unique")

    span = end - start
    width = math.ceil(span / len(workers))
    shards: list[Shard] = []
    for index, worker in enumerate(workers, start=1):
        shard_start = start + (index - 1) * width
        shard_end = min(shard_start + width, end)
        if shard_start >= shard_end:
            break
        shards.append(
            Shard(
                shard_id=f"shard-{index:03d}",
                start_height=shard_start,
                end_height=shard_end,
                worker=worker,
                primary_endpoint=primary_endpoint.rstrip("/"),
                fallback_endpoint=fallback_endpoint.rstrip("/"),
                extractor_revision=extractor_revision,
                status="pending",
            )
        )
    validate_shards(shards, start, end)
    return shards


def validate_shards(shards: Iterable[Shard], start: int, end: int) -> list[Shard]:
    """Require one exact, gap-free partition of ``[start, end)``."""
    ordered = sorted(shards, key=lambda shard: (shard.start_height, shard.end_height))
    if not ordered:
        raise ValueError("manifest has no shards")
    if ordered[0].start_height != start or ordered[-1].end_height != end:
        raise ValueError("manifest does not cover the requested range")
    expected = start
    seen_ids: set[str] = set()
    for shard in ordered:
        if shard.shard_id in seen_ids:
            raise ValueError(f"duplicate shard id: {shard.shard_id}")
        seen_ids.add(shard.shard_id)
        if shard.start_height != expected or shard.start_height >= shard.end_height:
            raise ValueError("manifest has a gap, overlap, or empty interval")
        expected = shard.end_height
    return ordered


def write_manifest(path: Path, shards: list[Shard]) -> None:
    """Write a new manifest, refusing to replace an existing run contract."""
    if path.exists():
        raise ValueError(f"manifest already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=MANIFEST_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        for shard in shards:
            writer.writerow(
                {
                    "shard_id": shard.shard_id,
                    "start_height": shard.start_height,
                    "end_height": shard.end_height,
                    "worker": shard.worker,
                    "primary_endpoint": shard.primary_endpoint,
                    "fallback_endpoint": shard.fallback_endpoint,
                    "extractor_revision": shard.extractor_revision,
                    "status": shard.status,
                }
            )
        handle.flush()
        os.fsync(handle.fileno())


def read_manifest(path: Path) -> list[Shard]:
    """Load and structurally validate a previously frozen manifest."""
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != MANIFEST_COLUMNS:
            raise ValueError(f"unexpected manifest columns: {reader.fieldnames}")
        shards = [
            Shard(
                shard_id=row["shard_id"],
                start_height=int(row["start_height"]),
                end_height=int(row["end_height"]),
                worker=row["worker"],
                primary_endpoint=row["primary_endpoint"].rstrip("/"),
                fallback_endpoint=row["fallback_endpoint"].rstrip("/"),
                extractor_revision=row["extractor_revision"],
                status=row["status"],
            )
            for row in reader
        ]
    if not shards:
        raise ValueError("manifest has no shards")
    validate_shards(
        shards, min(s.start_height for s in shards), max(s.end_height for s in shards)
    )
    return shards


class PacedHttpClient:
    """One-request-at-a-time client with bounded retry and endpoint fallback."""

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

    def get_json(self, endpoint: str, path: str, params: dict[str, int]) -> HttpResult:
        """Fetch JSON at a paced request rate without hiding terminal failures."""
        query = urlencode(params)
        url = f"{endpoint.rstrip('/')}{path}?{query}"
        now = self.monotonic()
        if self._last_request_start is not None:
            remaining = self.min_interval - (now - self._last_request_start)
            if remaining > 0:
                self.sleep(remaining)
        self._last_request_start = self.monotonic()
        request = Request(
            url, headers={"accept": "application/json", "user-agent": USER_AGENT}
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
            retryable = error.code in {429, 500, 502, 503, 504}
            return HttpResult(error.code, None, f"http_{error.code}", retryable)
        except (URLError, TimeoutError, OSError, IncompleteRead) as error:
            return HttpResult(None, None, type(error).__name__, True)


def fetch_height(
    client: PacedHttpClient,
    shard: Shard,
    height: int,
) -> dict[str, str | int]:
    """Return one terminal row with final-attempt provenance and total attempts."""
    endpoints = [shard.primary_endpoint]
    if shard.fallback_endpoint and shard.fallback_endpoint != shard.primary_endpoint:
        endpoints.append(shard.fallback_endpoint)

    attempt_count = 0
    last: HttpResult | None = None
    last_unavailable: dict[str, str | int] | None = None
    last_endpoint = shard.primary_endpoint
    for attempt in range(client.max_attempts):
        endpoint = endpoints[attempt % len(endpoints)]
        last_endpoint = endpoint
        attempt_count += 1
        result = client.get_json(endpoint, "/block_at_height", {"height": height})
        last = result
        if result.payload is not None:
            if result.status is None or not 200 <= result.status < 300:
                reason = (
                    "missing_http_status"
                    if result.status is None
                    else f"non_success_http_{result.status}"
                )
                last = HttpResult(result.status, None, reason, True)
                last_unavailable = None
            elif result.payload.get("success") is not True:
                last_unavailable = ledger_row(
                    height,
                    "unavailable_block",
                    result.status,
                    "",
                    "",
                    endpoint,
                    attempt_count,
                    "api_success_false",
                )
            elif (
                not isinstance(result.payload.get("block"), dict)
                or not result.payload["block"]
            ):
                last_unavailable = ledger_row(
                    height,
                    "unavailable_block",
                    result.status,
                    "",
                    "",
                    endpoint,
                    attempt_count,
                    "empty_or_invalid_block",
                )
            else:
                block = result.payload["block"]
                version = block.get("version")
                tx_id_value = block.get("tx_id")
                tx_id = tx_id_value if is_canonical_tx_id(tx_id_value) else ""
                if (
                    not isinstance(version, int)
                    or isinstance(version, bool)
                    or version < 0
                ):
                    reason = (
                        "missing_block_version"
                        if version is None
                        else "invalid_block_version"
                    )
                    last_unavailable = ledger_row(
                        height,
                        "unavailable_block",
                        result.status,
                        "",
                        tx_id,
                        endpoint,
                        attempt_count,
                        reason,
                    )
                elif version == 3:
                    if tx_id:
                        return ledger_row(
                            height,
                            "version_3_ready",
                            result.status,
                            version,
                            tx_id,
                            endpoint,
                            attempt_count,
                            "",
                        )
                    last_unavailable = ledger_row(
                        height,
                        "unavailable_block",
                        result.status,
                        version,
                        "",
                        endpoint,
                        attempt_count,
                        (
                            "version_3_missing_tx_id"
                            if tx_id_value in (None, "")
                            else "version_3_invalid_tx_id"
                        ),
                    )
                else:
                    return ledger_row(
                        height,
                        "non_version_3",
                        result.status,
                        version,
                        tx_id,
                        endpoint,
                        attempt_count,
                        "",
                    )
        else:
            last_unavailable = None
            if not result.retryable and not (
                attempt == 0 and len(endpoints) > 1 and client.max_attempts > 1
            ):
                break

        if attempt + 1 < client.max_attempts:
            client.sleep(min(2**attempt, 30))

    if last_unavailable is not None:
        return last_unavailable

    return ledger_row(
        height,
        "request_failure",
        last.status if last else None,
        "",
        "",
        last_endpoint,
        attempt_count,
        last.error if last and last.error else "unknown_request_failure",
    )


def ledger_row(
    height: int,
    outcome: str,
    http_status: int | None,
    version: int | str,
    tx_id: str,
    endpoint: str,
    attempt_count: int,
    error_reason: str,
) -> dict[str, str | int]:
    return {
        "hathor_height": height,
        "outcome": outcome,
        "http_status": "" if http_status is None else http_status,
        "block_version": version,
        "tx_id": tx_id,
        "endpoint": endpoint,
        "attempt_count": attempt_count,
        "error_reason": error_reason,
    }


def require_complete_ledger_file(path: Path) -> bool:
    """Return whether a ledger has content, rejecting a truncated final row."""
    if not path.exists() or path.stat().st_size == 0:
        return False
    with path.open("rb") as handle:
        handle.seek(-1, os.SEEK_END)
        if handle.read(1) != b"\n":
            raise ValueError(f"ledger ends with a truncated row: {path}")
    return True


def canonical_ledger_integer(
    value: str,
    field: str,
    line_number: int,
    *,
    minimum: int,
) -> int:
    """Parse one canonical base-10 ledger integer without normalization."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"ledger row {line_number} has invalid {field}: {value!r}"
        ) from exc
    if str(parsed) != value or parsed < minimum:
        raise ValueError(
            f"ledger row {line_number} has non-canonical {field}: {value!r}"
        )
    return parsed


def validate_ledger_row(row: dict[Any, Any], line_number: int) -> None:
    """Require the exact schema and internally consistent terminal fields."""
    if set(row) != set(LEDGER_COLUMNS) or any(value is None for value in row.values()):
        raise ValueError(
            f"ledger row {line_number} does not have the exact complete schema"
        )
    if any(not isinstance(value, str) for value in row.values()):
        raise ValueError(f"ledger row {line_number} contains a non-text field")

    canonical_ledger_integer(
        row["hathor_height"], "hathor_height", line_number, minimum=0
    )
    canonical_ledger_integer(
        row["attempt_count"], "attempt_count", line_number, minimum=1
    )

    outcome = row["outcome"]
    if outcome not in LEDGER_OUTCOMES:
        raise ValueError(f"ledger row {line_number} has unknown outcome: {outcome!r}")
    if not row["endpoint"].strip():
        raise ValueError(f"ledger row {line_number} has no endpoint")

    status: int | None = None
    if row["http_status"]:
        status = canonical_ledger_integer(
            row["http_status"], "http_status", line_number, minimum=100
        )
        if status > 599:
            raise ValueError(
                f"ledger row {line_number} has invalid http_status: {status}"
            )

    version: int | None = None
    if row["block_version"]:
        version = canonical_ledger_integer(
            row["block_version"], "block_version", line_number, minimum=0
        )

    if outcome != "request_failure" and (status is None or not 200 <= status < 300):
        raise ValueError(f"ledger row {line_number} has invalid successful http_status")

    if outcome == "version_3_ready":
        if version != 3 or not is_canonical_tx_id(row["tx_id"]):
            raise ValueError(
                f"ledger row {line_number} has invalid version_3_ready fields"
            )
    elif outcome == "non_version_3":
        if version is None or version == 3:
            raise ValueError(
                f"ledger row {line_number} has invalid non_version_3 fields"
            )
    elif outcome == "request_failure":
        if version is not None or row["tx_id"]:
            raise ValueError(
                f"ledger row {line_number} has invalid request_failure fields"
            )

    if outcome in FINAL_LEDGER_OUTCOMES and row["error_reason"]:
        raise ValueError(f"ledger row {line_number} resolves with an error reason")
    if outcome in RETRYABLE_LEDGER_OUTCOMES and not row["error_reason"].strip():
        raise ValueError(f"ledger row {line_number} has no error reason")


def validated_ledger_rows(handle, path: Path):
    """Yield strict one-line ledger records from an already opened handle."""
    try:
        reader = csv.DictReader(handle, strict=True)
        if reader.fieldnames != LEDGER_COLUMNS:
            raise ValueError(f"unexpected ledger columns: {reader.fieldnames}")
        previous_line = reader.line_num
        for row in reader:
            if reader.line_num != previous_line + 1:
                raise ValueError(f"malformed multi-line or blank ledger row: {path}")
            previous_line = reader.line_num
            validate_ledger_row(row, reader.line_num)
            yield row
        if reader.line_num != previous_line:
            raise ValueError(f"malformed trailing blank ledger row: {path}")
    except csv.Error as exc:
        raise ValueError(f"malformed ledger CSV: {path}") from exc


def read_recorded_heights(path: Path) -> set[int]:
    """Read a ledger's recorded heights and reject malformed duplicate state."""
    if not require_complete_ledger_file(path):
        return set()
    recorded: set[int] = set()
    observed_order: list[int] = []
    with path.open(newline="") as handle:
        for row in validated_ledger_rows(handle, path):
            height = int(row["hathor_height"])
            if height in recorded:
                raise ValueError(f"duplicate ledger height: {height}")
            recorded.add(height)
            observed_order.append(height)
    if observed_order != sorted(observed_order):
        raise ValueError("ledger rows are not in ascending height order")
    return recorded


def audit_ledger(path: Path, start: int, end: int) -> Counter[str]:
    """Require one resolved ledger record for each height in ``[start, end)``."""
    recorded: set[int] = set()
    observed_order: list[int] = []
    outcomes: Counter[str] = Counter()
    if require_complete_ledger_file(path):
        with path.open(newline="") as handle:
            for row in validated_ledger_rows(handle, path):
                height = int(row["hathor_height"])
                if height in recorded:
                    raise ValueError(f"duplicate ledger height: {height}")
                recorded.add(height)
                observed_order.append(height)
                outcomes[row["outcome"]] += 1
    if observed_order != sorted(observed_order):
        raise ValueError("ledger rows are not in ascending height order")
    expected = set(range(start, end))
    missing = sorted(expected - recorded)
    outside = sorted(recorded - expected)
    if missing or outside:
        raise ValueError(
            f"ledger coverage mismatch: missing={len(missing)} outside={len(outside)}"
        )
    unresolved = {
        outcome: count
        for outcome, count in outcomes.items()
        if outcome not in FINAL_LEDGER_OUTCOMES
    }
    if unresolved:
        detail = ", ".join(
            f"{outcome}={count}" for outcome, count in sorted(unresolved.items())
        )
        raise ValueError(f"ledger has unresolved outcomes: {detail}")
    return outcomes


def deduplicate_ledger(input_path: Path, output_path: Path) -> int:
    """Write an ordered repair only when duplicate rows agree on their identity."""
    if output_path.exists():
        raise ValueError(f"deduplicated output already exists: {output_path}")
    rows: dict[int, dict[str, str]] = {}
    duplicate_count = 0
    require_complete_ledger_file(input_path)
    with input_path.open(newline="") as handle:
        for row in validated_ledger_rows(handle, input_path):
            height = int(row["hathor_height"])
            existing = rows.get(height)
            if existing is None:
                rows[height] = row
                continue
            identity_columns = ("outcome", "http_status", "block_version", "tx_id")
            if any(existing[column] != row[column] for column in identity_columns):
                raise ValueError(f"conflicting duplicate ledger height: {height}")
            duplicate_count += 1
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEDGER_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for height in sorted(rows):
            writer.writerow(rows[height])
        handle.flush()
        os.fsync(handle.fileno())
    return duplicate_count


def exclusive_ledger_lock(ledger_path: Path):
    """Acquire a non-blocking, process-lifetime lock for one shard ledger."""
    lock_path = ledger_path.with_suffix(f"{ledger_path.suffix}.lock")
    lock_handle = lock_path.open("a")
    try:
        fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        lock_handle.close()
        raise RuntimeError(f"ledger is already in use: {ledger_path}") from error
    return lock_handle


def retry_ledger(
    client: PacedHttpClient,
    shard: Shard,
    input_path: Path,
    output_path: Path,
    retry_outcomes: frozenset[str],
) -> Counter[str]:
    """Re-drive selected failures into a new complete, ordered ledger."""
    if not retry_outcomes:
        raise ValueError("retry outcomes must not be empty")
    invalid = retry_outcomes.difference(RETRYABLE_LEDGER_OUTCOMES)
    if invalid:
        raise ValueError("unsupported retry outcomes: " + ", ".join(sorted(invalid)))
    if output_path.exists():
        raise ValueError(f"retry output already exists: {output_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    input_lock = exclusive_ledger_lock(input_path)
    output_lock = exclusive_ledger_lock(output_path)
    temporary_path: Path | None = None
    stats: Counter[str] = Counter()
    try:
        if output_path.exists():
            raise ValueError(f"retry output already exists: {output_path}")
        require_complete_ledger_file(input_path)
        with (
            input_path.open(newline="") as input_handle,
            tempfile.NamedTemporaryFile(
                mode="w",
                newline="",
                prefix=f".{output_path.name}.tmp-",
                dir=output_path.parent,
                delete=False,
            ) as output_handle,
        ):
            temporary_path = Path(output_handle.name)
            reader = validated_ledger_rows(input_handle, input_path)
            writer = csv.DictWriter(
                output_handle, fieldnames=LEDGER_COLUMNS, lineterminator="\n"
            )
            writer.writeheader()
            for expected_height in range(shard.start_height, shard.end_height):
                row = next(reader, None)
                if row is None:
                    raise ValueError(
                        f"ledger ended before shard height: {expected_height}"
                    )
                try:
                    observed_height = int(row["hathor_height"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError("ledger has an invalid height") from exc
                if row["hathor_height"] != str(observed_height):
                    raise ValueError(
                        f"ledger has a non-canonical height: {row['hathor_height']!r}"
                    )
                if observed_height != expected_height:
                    raise ValueError(
                        "ledger ordering mismatch: "
                        f"expected={expected_height} observed={observed_height}"
                    )

                if row["outcome"] in retry_outcomes:
                    row = fetch_height(client, shard, expected_height)
                    stats["retried"] += 1
                    if row["outcome"] in FINAL_LEDGER_OUTCOMES:
                        stats["resolved"] += 1
                    else:
                        stats["unresolved"] += 1
                writer.writerow(row)

            if next(reader, None) is not None:
                raise ValueError("ledger contains rows outside the shard range")
            output_handle.flush()
            os.fsync(output_handle.fileno())

        if output_path.exists():
            raise ValueError(f"retry output appeared during build: {output_path}")
        os.link(temporary_path, output_path)
        temporary_path.unlink()
        temporary_path = None
        fsync_directory(output_path.parent)
        return stats
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
    finally:
        output_lock.close()
        input_lock.close()


def scan_shard(
    client: PacedHttpClient, shard: Shard, ledger_path: Path
) -> Counter[str]:
    """Resume a shard safely, appending exactly one row for each new height."""
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    lock_handle = exclusive_ledger_lock(ledger_path)
    try:
        recorded = read_recorded_heights(ledger_path)
        invalid = [
            height
            for height in recorded
            if height < shard.start_height or height >= shard.end_height
        ]
        if invalid:
            raise ValueError(f"ledger contains out-of-shard height: {invalid[0]}")
        append = ledger_path.exists() and ledger_path.stat().st_size > 0
        outcomes: Counter[str] = Counter()
        with ledger_path.open("a" if append else "w", newline="") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=LEDGER_COLUMNS, lineterminator="\n"
            )
            if not append:
                writer.writeheader()
            for height in range(shard.start_height, shard.end_height):
                if height in recorded:
                    continue
                row = fetch_height(client, shard, height)
                writer.writerow(row)
                handle.flush()
                os.fsync(handle.fileno())
                outcomes[str(row["outcome"])] += 1
        return outcomes
    finally:
        lock_handle.close()


def selected_shard(shards: list[Shard], shard_id: str) -> Shard:
    matches = [shard for shard in shards if shard.shard_id == shard_id]
    if len(matches) != 1:
        raise ValueError(f"unknown shard id: {shard_id}")
    return matches[0]


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    mode = argument_parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write-manifest", type=Path)
    mode.add_argument("--audit-ledger", type=Path)
    mode.add_argument("--deduplicate-ledger", type=Path)
    mode.add_argument("--manifest", type=Path)
    argument_parser.add_argument(
        "--start",
        type=nonnegative_int,
        help=(
            "Inclusive range start for manifest creation or ledger audit "
            f"(default: {DEFAULT_START})"
        ),
    )
    argument_parser.add_argument(
        "--end",
        type=nonnegative_int,
        help=(
            "Exclusive range end for manifest creation or ledger audit "
            f"(default: {DEFAULT_END})"
        ),
    )
    argument_parser.add_argument(
        "--workers", help="Comma-separated unique worker labels"
    )
    argument_parser.add_argument("--shard-id", help="Manifest shard to scan")
    argument_parser.add_argument("--ledger", type=Path, help="Shard ledger path")
    argument_parser.add_argument(
        "--retry-outcomes",
        type=parse_retry_outcomes,
        help=(
            "Comma-separated failure outcomes to re-drive from --ledger into "
            "a new --retry-output"
        ),
    )
    argument_parser.add_argument(
        "--retry-output",
        type=Path,
        help="New complete ledger written by --retry-outcomes",
    )
    argument_parser.add_argument(
        "--deduplicated-output",
        type=Path,
        help="New output path required with --deduplicate-ledger",
    )
    argument_parser.add_argument("--api-url", default=DEFAULT_API)
    argument_parser.add_argument("--fallback-api-url", default=DEFAULT_FALLBACK_API)
    argument_parser.add_argument("--extractor-revision", default="unknown")
    argument_parser.add_argument(
        "--requests-per-second",
        type=positive_float,
        default=DEFAULT_REQUESTS_PER_SECOND,
        help="Per-worker maximum request starts per second (default: 0.5)",
    )
    argument_parser.add_argument("--timeout", type=positive_float, default=30.0)
    argument_parser.add_argument("--max-attempts", type=int, default=3)
    return argument_parser


def main() -> None:
    args = parser().parse_args()
    if args.max_attempts < 1:
        raise SystemExit("--max-attempts must be at least one")
    if (args.retry_outcomes is not None or args.retry_output is not None) and not (
        args.manifest and args.shard_id and args.ledger
    ):
        raise SystemExit(
            "--retry-outcomes and --retry-output require --manifest, "
            "--shard-id, and --ledger"
        )
    if (args.retry_outcomes is None) != (args.retry_output is None):
        raise SystemExit("--retry-outcomes and --retry-output must be used together")

    if args.write_manifest:
        start = DEFAULT_START if args.start is None else args.start
        end = DEFAULT_END if args.end is None else args.end
        if start >= end:
            raise SystemExit("--start must be lower than --end")
        if not args.workers:
            raise SystemExit("--write-manifest requires --workers")
        workers = [worker.strip() for worker in args.workers.split(",")]
        shards = make_shards(
            start,
            end,
            workers,
            args.api_url,
            args.fallback_api_url,
            args.extractor_revision,
        )
        write_manifest(args.write_manifest, shards)
        print(f"Wrote {len(shards)} frozen shards to {args.write_manifest}")
        return

    if args.audit_ledger:
        if args.start is None or args.end is None:
            raise SystemExit("--audit-ledger requires both --start and --end")
        if args.start >= args.end:
            raise SystemExit("--start must be lower than --end")
        outcomes = audit_ledger(args.audit_ledger, args.start, args.end)
        print(json.dumps(dict(sorted(outcomes.items())), sort_keys=True))
        return

    if args.deduplicate_ledger:
        if not args.deduplicated_output:
            raise SystemExit("--deduplicate-ledger requires --deduplicated-output")
        duplicates = deduplicate_ledger(
            args.deduplicate_ledger, args.deduplicated_output
        )
        print(json.dumps({"duplicate_rows_removed": duplicates}, sort_keys=True))
        return

    if not args.shard_id or not args.ledger:
        raise SystemExit("--manifest requires both --shard-id and --ledger")
    shards = read_manifest(args.manifest)
    if args.start is not None or args.end is not None:
        if args.start is None or args.end is None:
            raise SystemExit("scan range override requires both --start and --end")
        if args.start >= args.end:
            raise SystemExit("--start must be lower than --end")
        validate_shards(shards, args.start, args.end)
    shard = selected_shard(shards, args.shard_id)
    client = PacedHttpClient(args.requests_per_second, args.timeout, args.max_attempts)
    if args.retry_outcomes is not None:
        outcomes = retry_ledger(
            client,
            shard,
            args.ledger,
            args.retry_output,
            args.retry_outcomes,
        )
        print(json.dumps(dict(sorted(outcomes.items())), sort_keys=True))
        return
    outcomes = scan_shard(client, shard, args.ledger)
    print(json.dumps(dict(sorted(outcomes.items())), sort_keys=True))


if __name__ == "__main__":
    main()
