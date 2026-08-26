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
    python scripts/extract/hathor_metadata_ledger.py --audit-ledger ledger.csv
"""

from __future__ import annotations

import argparse
import csv
import fcntl
import json
import math
import time
from collections import Counter
from dataclasses import dataclass
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
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_COLUMNS)
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
                return HttpResult(status, json.loads(response.read()), None, False)
        except HTTPError as error:
            retryable = error.code in {429, 502, 503, 504}
            return HttpResult(error.code, None, f"http_{error.code}", retryable)
        except (URLError, TimeoutError, OSError) as error:
            return HttpResult(None, None, type(error).__name__, True)
        except json.JSONDecodeError:
            return HttpResult(None, None, "invalid_json", True)


def fetch_height(
    client: PacedHttpClient,
    shard: Shard,
    height: int,
) -> dict[str, str | int]:
    """Return one terminal ledger row, retaining every failed attempt's outcome."""
    endpoints = [shard.primary_endpoint]
    if shard.fallback_endpoint and shard.fallback_endpoint != shard.primary_endpoint:
        endpoints.append(shard.fallback_endpoint)

    attempt_count = 0
    last: HttpResult | None = None
    last_endpoint = shard.primary_endpoint
    for attempt in range(client.max_attempts):
        endpoint = endpoints[attempt % len(endpoints)]
        last_endpoint = endpoint
        attempt_count += 1
        result = client.get_json(endpoint, "/block_at_height", {"height": height})
        last = result
        if result.payload is not None:
            block = result.payload.get("block") or {}
            if not result.payload.get("success") or not block:
                return ledger_row(
                    height,
                    "unavailable_block",
                    result.status,
                    "",
                    "",
                    endpoint,
                    attempt_count,
                    "api_success_false",
                )
            version = block.get("version")
            tx_id = block.get("tx_id") or ""
            if version == 3 and tx_id:
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
            return ledger_row(
                height,
                "non_version_3",
                result.status,
                "" if version is None else version,
                tx_id,
                endpoint,
                attempt_count,
                "",
            )
        if not result.retryable:
            break
        if attempt + 1 < client.max_attempts:
            client.sleep(min(2**attempt, 30))

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


def read_recorded_heights(path: Path) -> set[int]:
    """Read a ledger's recorded heights and reject malformed duplicate state."""
    if not path.exists() or path.stat().st_size == 0:
        return set()
    recorded: set[int] = set()
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != LEDGER_COLUMNS:
            raise ValueError(f"unexpected ledger columns: {reader.fieldnames}")
        for row in reader:
            height = int(row["hathor_height"])
            if height in recorded:
                raise ValueError(f"duplicate ledger height: {height}")
            recorded.add(height)
    return recorded


def audit_ledger(path: Path, start: int, end: int) -> Counter[str]:
    """Require one ledger record for each height in ``[start, end)``."""
    recorded = read_recorded_heights(path)
    expected = set(range(start, end))
    missing = sorted(expected - recorded)
    outside = sorted(recorded - expected)
    if missing or outside:
        raise ValueError(
            f"ledger coverage mismatch: missing={len(missing)} outside={len(outside)}"
        )
    outcomes: Counter[str] = Counter()
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            outcomes[row["outcome"]] += 1
    return outcomes


def deduplicate_ledger(input_path: Path, output_path: Path) -> int:
    """Write an ordered repair only when duplicate rows agree on their identity."""
    if output_path.exists():
        raise ValueError(f"deduplicated output already exists: {output_path}")
    rows: dict[int, dict[str, str]] = {}
    duplicate_count = 0
    with input_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != LEDGER_COLUMNS:
            raise ValueError(f"unexpected ledger columns: {reader.fieldnames}")
        for row in reader:
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
        writer = csv.DictWriter(handle, fieldnames=LEDGER_COLUMNS)
        writer.writeheader()
        for height in sorted(rows):
            writer.writerow(rows[height])
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
            writer = csv.DictWriter(handle, fieldnames=LEDGER_COLUMNS)
            if not append:
                writer.writeheader()
            for height in range(shard.start_height, shard.end_height):
                if height in recorded:
                    continue
                row = fetch_height(client, shard, height)
                writer.writerow(row)
                handle.flush()
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
    outcomes = scan_shard(client, shard, args.ledger)
    print(json.dumps(dict(sorted(outcomes.items())), sort_keys=True))


if __name__ == "__main__":
    main()
