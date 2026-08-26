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
The declared outer bounds are repeated in every shard row so a manifest remains
self-describing wherever it is copied. Run exactly one process for each shard
ledger.

Examples:

    # Create a manifest for the acquisition range before starting any worker.
    python scripts/extract/hathor_metadata_ledger.py --write-manifest \
        <chain-archive>/hathor/acquisition/manifest.csv \
        --start 0 --end <exclusive-end-height> \
        --workers worker-a,worker-b,worker-c,worker-d,worker-e,worker-f

    # Run one assigned shard at the conservative default rate.
    python scripts/extract/hathor_metadata_ledger.py --manifest manifest.csv \
        --shard-id shard-003 --ledger shard-003-ledger.csv

    # Audit a completed merged ledger before payload work.
    python scripts/extract/hathor_metadata_ledger.py --audit-ledger ledger.csv \
        --start 0 --end <exclusive-end-height>

    # Re-drive unresolved heights into a new, ordered ledger.
    python scripts/extract/hathor_metadata_ledger.py --manifest manifest.csv \
        --shard-id shard-003 --ledger shard-003-ledger.csv \
        --retry-output shard-003-ledger-retry.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from stale_blocks_analysis.hathor_acquisition import HttpResult, PacedHttpClient


DEFAULT_API = "https://node1.mainnet.hathor.network/v1a"
DEFAULT_FALLBACK_API = "https://node2.mainnet.hathor.network/v1a"
DEFAULT_START = 0
DEFAULT_REQUESTS_PER_SECOND = 0.5
USER_AGENT = "merge-mining-research/hathor-metadata-acquisition"

MANIFEST_COLUMNS = [
    "manifest_start_height",
    "manifest_end_height",
    "shard_id",
    "start_height",
    "end_height",
    "worker",
    "primary_endpoint",
    "fallback_endpoint",
    "extractor_revision",
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


@dataclass(frozen=True)
class Manifest:
    start_height: int
    end_height: int
    shards: tuple[Shard, ...]


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


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def canonical_endpoint(value: str, name: str, *, allow_blank: bool) -> str:
    """Normalize and require an absolute HTTP(S) base URL."""
    endpoint = value.strip().rstrip("/")
    if not endpoint:
        if allow_blank:
            return ""
        raise ValueError(f"{name} endpoint must be non-empty")
    scheme, separator, remainder = endpoint.partition("://")
    if scheme not in ("http", "https") or not separator or not remainder.split("/")[0]:
        raise ValueError(f"{name} endpoint must be an absolute http or https URL")
    if "?" in endpoint or "#" in endpoint:
        raise ValueError(f"{name} endpoint must not contain a query or fragment")
    return endpoint


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
    primary = canonical_endpoint(primary_endpoint, "primary", allow_blank=False)
    fallback = canonical_endpoint(fallback_endpoint, "fallback", allow_blank=True)

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
                primary_endpoint=primary,
                fallback_endpoint=fallback,
                extractor_revision=extractor_revision,
            )
        )
    validate_shards(shards, start, end)
    return shards


def validate_shards(shards: Iterable[Shard], start: int, end: int) -> list[Shard]:
    """Require non-negative bounds, nonempty IDs, and one exact range partition."""
    if start < 0 or end < 0:
        raise ValueError("manifest bounds must be non-negative")
    ordered = sorted(shards, key=lambda shard: (shard.start_height, shard.end_height))
    if not ordered:
        raise ValueError("manifest has no shards")
    if any(shard.start_height < 0 or shard.end_height < 0 for shard in ordered):
        raise ValueError("manifest bounds must be non-negative")
    if any(not shard.shard_id for shard in ordered):
        raise ValueError("manifest shard IDs must be non-empty")
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


def write_manifest(path: Path, manifest: Manifest) -> None:
    """Write a validated manifest without replacing an existing run contract."""
    canonical_shards = [
        Shard(
            shard.shard_id,
            shard.start_height,
            shard.end_height,
            shard.worker,
            canonical_endpoint(shard.primary_endpoint, "primary", allow_blank=False),
            canonical_endpoint(shard.fallback_endpoint, "fallback", allow_blank=True),
            shard.extractor_revision,
        )
        for shard in manifest.shards
    ]
    shards = validate_shards(
        canonical_shards,
        manifest.start_height,
        manifest.end_height,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        handle = path.open("x", newline="")
        created = True
        with handle:
            writer = csv.DictWriter(
                handle, fieldnames=MANIFEST_COLUMNS, lineterminator="\n"
            )
            writer.writeheader()
            for shard in shards:
                writer.writerow(
                    {
                        "manifest_start_height": manifest.start_height,
                        "manifest_end_height": manifest.end_height,
                        "shard_id": shard.shard_id,
                        "start_height": shard.start_height,
                        "end_height": shard.end_height,
                        "worker": shard.worker,
                        "primary_endpoint": shard.primary_endpoint,
                        "fallback_endpoint": shard.fallback_endpoint,
                        "extractor_revision": shard.extractor_revision,
                    }
                )
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise ValueError(f"manifest already exists: {path}") from None
    except BaseException:
        if created:
            path.unlink(missing_ok=True)
        raise


def manifest_bound(value: str, field: str) -> int:
    """Parse one non-negative manifest boundary."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid manifest {field}: {value!r}") from exc
    if parsed < 0:
        raise ValueError(f"invalid manifest {field}: {value!r}")
    return parsed


def read_manifest(path: Path) -> Manifest:
    """Load and structurally validate a previously frozen manifest.

    The header and cells must match the current schema, and every row must
    agree on the declared range.
    """
    rows: list[dict[str, str]] = []
    try:
        with path.open(newline="") as handle:
            reader = csv.DictReader(handle, strict=True)
            if reader.fieldnames != MANIFEST_COLUMNS:
                raise ValueError(f"unexpected manifest columns: {reader.fieldnames}")
            for row in reader:
                if set(row) != set(MANIFEST_COLUMNS) or any(
                    value is None for value in row.values()
                ):
                    raise ValueError(
                        f"manifest row {reader.line_num} does not have the exact "
                        "complete schema"
                    )
                rows.append(row)
    except csv.Error as exc:
        raise ValueError(f"malformed manifest CSV: {path}") from exc
    if not rows:
        raise ValueError("manifest has no shards")
    declared_ranges = {
        (
            manifest_bound(row["manifest_start_height"], "start height"),
            manifest_bound(row["manifest_end_height"], "end height"),
        )
        for row in rows
    }
    if len(declared_ranges) != 1:
        raise ValueError("manifest rows disagree on the declared range")
    declared_start, declared_end = declared_ranges.pop()

    try:
        shards = [
            Shard(
                shard_id=row["shard_id"],
                start_height=manifest_bound(row["start_height"], "shard start height"),
                end_height=manifest_bound(row["end_height"], "shard end height"),
                worker=row["worker"],
                primary_endpoint=canonical_endpoint(
                    row["primary_endpoint"], "primary", allow_blank=False
                ),
                fallback_endpoint=canonical_endpoint(
                    row["fallback_endpoint"], "fallback", allow_blank=True
                ),
                extractor_revision=row["extractor_revision"],
            )
            for row in rows
        ]
    except (AttributeError, TypeError) as exc:
        raise ValueError("manifest contains an invalid shard row") from exc
    ordered = validate_shards(shards, declared_start, declared_end)
    return Manifest(declared_start, declared_end, tuple(ordered))


def fetch_height(
    client: PacedHttpClient,
    shard: Shard,
    height: int,
) -> dict[str, str | int]:
    """Return one terminal row with final-attempt provenance and total attempts."""
    endpoints = [shard.primary_endpoint]
    fallback = shard.fallback_endpoint.strip().rstrip("/")
    if fallback and fallback != shard.primary_endpoint:
        endpoints.append(fallback)

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
                elif version == 3 and not tx_id:
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
                elif block.get("is_voided"):
                    # Preserve the final observation for diagnosis, but never
                    # resolve a voided block as accepted height evidence.
                    last_unavailable = ledger_row(
                        height,
                        "unavailable_block",
                        result.status,
                        version,
                        tx_id,
                        endpoint,
                        attempt_count,
                        "child_block_voided",
                    )
                elif version == 3:
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


def ledger_integer(
    value: str,
    field: str,
    line_number: int,
    *,
    minimum: int,
) -> int:
    """Parse one bounded ledger integer."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"ledger row {line_number} has invalid {field}: {value!r}"
        ) from exc
    if parsed < minimum:
        raise ValueError(f"ledger row {line_number} has invalid {field}: {value!r}")
    return parsed


def validate_ledger_row(row: dict[Any, Any], line_number: int) -> None:
    """Require the exact schema and internally consistent terminal fields."""
    if set(row) != set(LEDGER_COLUMNS) or any(value is None for value in row.values()):
        raise ValueError(
            f"ledger row {line_number} does not have the exact complete schema"
        )
    if any(not isinstance(value, str) for value in row.values()):
        raise ValueError(f"ledger row {line_number} contains a non-text field")

    ledger_integer(row["hathor_height"], "hathor_height", line_number, minimum=0)
    ledger_integer(row["attempt_count"], "attempt_count", line_number, minimum=1)

    outcome = row["outcome"]
    if outcome not in LEDGER_OUTCOMES:
        raise ValueError(f"ledger row {line_number} has unknown outcome: {outcome!r}")
    if not row["endpoint"].strip():
        raise ValueError(f"ledger row {line_number} has no endpoint")

    status: int | None = None
    if row["http_status"]:
        status = ledger_integer(
            row["http_status"], "http_status", line_number, minimum=100
        )
        if status > 599:
            raise ValueError(
                f"ledger row {line_number} has invalid http_status: {status}"
            )

    version: int | None = None
    if row["block_version"]:
        version = ledger_integer(
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
    """Yield validated ledger records from an already opened handle."""
    try:
        reader = csv.DictReader(handle, strict=True)
        if reader.fieldnames != LEDGER_COLUMNS:
            raise ValueError(f"unexpected ledger columns: {reader.fieldnames}")
        for row in reader:
            validate_ledger_row(row, reader.line_num)
            yield row
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
    """Require one resolved ledger record for each height in ``[start, end)``.

    Duplicate heights are rejected first. Every nonblank transaction ID in the
    ledger must belong to exactly one height.
    """
    recorded: set[int] = set()
    tx_heights: dict[str, int] = {}
    observed_order: list[int] = []
    outcomes: Counter[str] = Counter()
    if require_complete_ledger_file(path):
        with path.open(newline="") as handle:
            for row in validated_ledger_rows(handle, path):
                height = int(row["hathor_height"])
                if height in recorded:
                    raise ValueError(f"duplicate ledger height: {height}")
                recorded.add(height)
                tx_id = row["tx_id"]
                if tx_id:
                    previous_height = tx_heights.get(tx_id)
                    if previous_height is not None:
                        raise ValueError(
                            "canonical transaction ID is assigned to multiple "
                            f"heights: {previous_height}, {height}"
                        )
                    tx_heights[tx_id] = height
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


def retry_ledger(
    client: PacedHttpClient,
    shard: Shard,
    input_path: Path,
    output_path: Path,
) -> Counter[str]:
    """Re-drive every unresolved height into a new complete, ordered ledger."""
    if output_path.exists():
        raise ValueError(f"retry output already exists: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stats: Counter[str] = Counter()
    output_created = False
    try:
        if not require_complete_ledger_file(input_path):
            raise ValueError(f"ledger is empty: {input_path}")
        with input_path.open(newline="") as input_handle:
            output_handle = output_path.open("x", newline="")
            output_created = True
            with output_handle:
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
                    observed_height = int(row["hathor_height"])
                    if observed_height != expected_height:
                        raise ValueError(
                            "ledger ordering mismatch: "
                            f"expected={expected_height} observed={observed_height}"
                        )

                    if row["outcome"] in RETRYABLE_LEDGER_OUTCOMES:
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
        return stats
    except FileExistsError:
        raise ValueError(f"retry output already exists: {output_path}") from None
    except BaseException:
        if output_created:
            output_path.unlink(missing_ok=True)
        raise


def scan_shard(
    client: PacedHttpClient, shard: Shard, ledger_path: Path
) -> Counter[str]:
    """Resume a shard safely, appending exactly one row for each new height."""
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    recorded = read_recorded_heights(ledger_path)
    invalid = [
        height
        for height in recorded
        if height < shard.start_height or height >= shard.end_height
    ]
    if invalid:
        raise ValueError(f"ledger contains out-of-shard height: {invalid[0]}")
    prefix = set(range(shard.start_height, shard.start_height + len(recorded)))
    if recorded != prefix:
        raise ValueError(
            "ledger recorded heights do not form a contiguous prefix "
            f"beginning at shard start {shard.start_height}"
        )
    append = ledger_path.exists() and ledger_path.stat().st_size > 0
    outcomes: Counter[str] = Counter()
    with ledger_path.open("a" if append else "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEDGER_COLUMNS, lineterminator="\n")
        if not append:
            writer.writeheader()
            handle.flush()
            os.fsync(handle.fileno())
        for height in range(shard.start_height, shard.end_height):
            if height in recorded:
                continue
            row = fetch_height(client, shard, height)
            writer.writerow(row)
            handle.flush()
            os.fsync(handle.fileno())
            outcomes[str(row["outcome"])] += 1
    return outcomes


def selected_shard(shards: Iterable[Shard], shard_id: str) -> Shard:
    matches = [shard for shard in shards if shard.shard_id == shard_id]
    if len(matches) != 1:
        raise ValueError(f"unknown shard id: {shard_id}")
    return matches[0]


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    mode = argument_parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write-manifest", type=Path)
    mode.add_argument("--audit-ledger", type=Path)
    mode.add_argument("--manifest", type=Path)
    argument_parser.add_argument(
        "--start",
        type=nonnegative_int,
        help="Inclusive range start; defaults to 0 for manifest creation and "
        "is required for ledger audit",
    )
    argument_parser.add_argument(
        "--end",
        type=nonnegative_int,
        help="Exclusive range end; required for manifest creation or ledger audit",
    )
    argument_parser.add_argument(
        "--workers", help="Comma-separated unique worker labels"
    )
    argument_parser.add_argument("--shard-id", help="Manifest shard to scan")
    argument_parser.add_argument("--ledger", type=Path, help="Shard ledger path")
    argument_parser.add_argument(
        "--retry-output",
        type=Path,
        help="Re-drive unresolved heights into a new complete ledger",
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
    if args.retry_output is not None and not (
        args.manifest and args.shard_id and args.ledger
    ):
        raise SystemExit("--retry-output requires --manifest, --shard-id, and --ledger")

    if args.write_manifest:
        if args.end is None:
            raise SystemExit("--write-manifest requires --end")
        start = DEFAULT_START if args.start is None else args.start
        end = args.end
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
        write_manifest(
            args.write_manifest,
            Manifest(start, end, tuple(shards)),
        )
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

    if not args.shard_id or not args.ledger:
        raise SystemExit("--manifest requires both --shard-id and --ledger")
    manifest = read_manifest(args.manifest)
    shard = selected_shard(manifest.shards, args.shard_id)
    client = PacedHttpClient(
        args.requests_per_second,
        args.timeout,
        args.max_attempts,
        user_agent=USER_AGENT,
    )
    if args.retry_output is not None:
        outcomes = retry_ledger(
            client,
            shard,
            args.ledger,
            args.retry_output,
        )
        print(json.dumps(dict(sorted(outcomes.items())), sort_keys=True))
        return
    outcomes = scan_shard(client, shard, args.ledger)
    print(json.dumps(dict(sorted(outcomes.items())), sort_keys=True))


if __name__ == "__main__":
    main()
