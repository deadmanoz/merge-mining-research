#!/usr/bin/env python3
"""Fetch complete Hathor v3 payload evidence from an audited metadata ledger.

The pre-million metadata census already establishes one ``tx_id`` for every
``version_3_ready`` height. This collector makes one ``/transaction`` request
per ready row that lacks a sealed source record in the current run and writes
one complete record to an augmented ``hathor_auxpow_raw.csv``. Failed attempts
remain append-only history and are retried on later runs until a sealed source
row exists. Each source row includes the existing AuxPoW columns plus the
lossless ``raw_hex`` payload and its derived ``funds_graph_hex`` bytes. A
SHA-256 record seal covers every source field, so an interrupted or manually
damaged primary row is rejected before a resume or publication audit can treat
it as complete.

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
import os
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


DEFAULT_API = "https://node1.mainnet.hathor.network/v1a"
DEFAULT_FALLBACK_API = "https://node2.mainnet.hathor.network/v1a"
DEFAULT_REQUESTS_PER_SECOND = 0.25
USER_AGENT = "merge-mining-research/hathor-pre-million-payload"

SOURCE_REQUIRED_COLUMNS = {
    "hathor_height",
    "outcome",
    "block_version",
    "tx_id",
}
RAW_COLUMNS = [
    "hathor_height",
    "hathor_block_hash",
    "hathor_timestamp",
    "aux_pow_hex",
    "funds_graph_hex",
    "raw_hex",
    "record_sha256",
]
LEGACY_RAW_COLUMNS = RAW_COLUMNS[:-1]
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
    timestamp: int | str
    aux_pow_hex: str
    raw_hex: str
    funds_graph_hex: str
    endpoint: str
    http_status: int
    attempt_count: int


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


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def raw_record_sha256(row: dict[str, object]) -> str:
    """Hash every primary source field in a stable, unambiguous encoding."""
    digest = hashlib.sha256()
    for column in LEGACY_RAW_COLUMNS:
        value = row.get(column)
        if value is None:
            raise ValueError(f"missing {column} in raw source row")
        encoded = str(value).encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def fsync_directory(path: Path) -> None:
    """Persist a completed atomic replacement's directory entry."""
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def load_ready_rows(ledger_path: Path, start: int, end: int) -> dict[int, ReadyRow]:
    """Load exactly the ready rows in ``[start, end)`` from a metadata ledger."""
    if start >= end:
        raise ValueError("start must be lower than end")
    with ledger_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        missing = SOURCE_REQUIRED_COLUMNS.difference(fields)
        if missing:
            raise ValueError(
                "metadata ledger is missing required columns: "
                + ", ".join(sorted(missing))
            )
        ready: dict[int, ReadyRow] = {}
        seen_heights: set[int] = set()
        for row in reader:
            try:
                height = int(row["hathor_height"])
            except (TypeError, ValueError) as exc:
                raise ValueError("metadata ledger has an invalid height") from exc
            if height < start or height >= end:
                continue
            if height in seen_heights:
                raise ValueError(f"duplicate height in metadata ledger: {height}")
            seen_heights.add(height)
            if row.get("outcome") != "version_3_ready":
                continue
            tx_id = row.get("tx_id", "")
            if not tx_id:
                raise ValueError(f"ready height {height} has no tx_id")
            if str(row.get("block_version")) != "3":
                raise ValueError(f"ready height {height} does not record version 3")
            ready[height] = ReadyRow(height, tx_id)
    if len(seen_heights) != end - start:
        raise ValueError(
            "metadata ledger coverage is incomplete: "
            f"expected={end - start} observed={len(seen_heights)}"
        )
    return ready


def read_csv_rows(path: Path, columns: list[str]) -> dict[int, dict[str, str]]:
    """Read a payload CSV, rejecting header drift and duplicate heights."""
    if not path.exists() or path.stat().st_size == 0:
        return {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != columns:
            raise ValueError(f"unexpected columns in {path}: {reader.fieldnames}")
        rows: dict[int, dict[str, str]] = {}
        for row in reader:
            try:
                height = int(row["hathor_height"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"invalid height in {path}") from exc
            if height in rows:
                raise ValueError(f"duplicate height in {path}: {height}")
            rows[height] = row
    return rows


def open_csv_writer(path: Path, columns: list[str]):
    """Open an append-only CSV, writing its header only for a new file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    if exists:
        with path.open("rb") as existing:
            existing.seek(-1, os.SEEK_END)
            if existing.read(1) != b"\n":
                raise ValueError(f"refusing to append after a truncated row: {path}")
    handle = path.open("a" if exists else "w", newline="")
    writer = csv.DictWriter(handle, fieldnames=columns)
    if not exists:
        writer.writeheader()
        handle.flush()
        os.fsync(handle.fileno())
    return handle, writer


def write_durable_row(handle, writer: csv.DictWriter, row: dict[str, object]) -> None:
    """Append one source row before moving on to another API request."""
    writer.writerow(row)
    handle.flush()
    os.fsync(handle.fileno())


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
                    payload = json.loads(response.read())
                except json.JSONDecodeError:
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
        except (URLError, TimeoutError, OSError) as error:
            return HttpResult(None, None, type(error).__name__, True)


def parse_payload(
    ready: ReadyRow,
    response: dict[str, Any],
    endpoint: str,
    http_status: int,
    attempt_count: int,
) -> Payload:
    """Validate payload evidence and any identity fields echoed by the API."""
    if not response.get("success"):
        raise ValueError("api_success_false")
    tx = response.get("tx")
    if not isinstance(tx, dict):
        raise ValueError("missing_tx")
    response_hash = tx.get("hash")
    if response_hash not in (None, "") and response_hash != ready.tx_id:
        raise ValueError("tx_hash_mismatch")
    response_version = tx.get("version")
    if response_version not in (None, 3):
        raise ValueError("tx_version_mismatch")
    raw_hex = tx.get("raw")
    aux_pow_hex = tx.get("aux_pow")
    if not isinstance(raw_hex, str) or not raw_hex:
        raise ValueError("missing_raw")
    if not isinstance(aux_pow_hex, str) or not aux_pow_hex:
        raise ValueError("missing_aux_pow")
    try:
        raw = bytes.fromhex(raw_hex)
        aux_pow = bytes.fromhex(aux_pow_hex)
    except ValueError as exc:
        raise ValueError("invalid_hex") from exc
    if not aux_pow:
        raise ValueError("empty_aux_pow")
    occurrence_count = raw.count(aux_pow)
    if occurrence_count != 1:
        raise ValueError(f"aux_pow_occurrences_{occurrence_count}")
    offset = raw.find(aux_pow)
    timestamp = tx.get("timestamp", "")
    if timestamp is None:
        timestamp = ""
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


def fetch_payload(
    client: PacedHttpClient,
    ready: ReadyRow,
    primary_endpoint: str,
    fallback_endpoint: str,
) -> tuple[Payload | None, dict[str, object] | None]:
    """Fetch a ready transaction, returning a payload or one visible failure row."""
    endpoints = [primary_endpoint.rstrip("/")]
    if fallback_endpoint.rstrip("/") != endpoints[0]:
        endpoints.append(fallback_endpoint.rstrip("/"))

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
                return (
                    parse_payload(
                        ready,
                        result.payload,
                        endpoint,
                        result.status or 200,
                        attempt + 1,
                    ),
                    None,
                )
            except ValueError as exc:
                last = HttpResult(result.status, None, str(exc), True)
        if not result.retryable:
            if result.payload is None:
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
        raw = bytes.fromhex(row["raw_hex"])
        aux_pow = bytes.fromhex(row["aux_pow_hex"])
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
) -> None:
    """Validate existing primary rows against the ready-ledger contract."""
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
        if row.get("record_sha256") != raw_record_sha256(row):
            raise ValueError(f"raw record digest mismatch at height {height}")
        expected = raw_to_supplement(row)
        if row.get("funds_graph_hex") != expected["funds_graph_hex"]:
            raise ValueError(
                f"funds+graph does not match raw evidence at height {height}"
            )


def check_legacy_raw_rows(
    ready_rows: dict[int, ReadyRow],
    raw_rows: dict[int, dict[str, str]],
) -> None:
    """Validate pre-seal canary rows before their local, API-free upgrade."""
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
        expected = raw_to_supplement(row)
        if row.get("funds_graph_hex") != expected["funds_graph_hex"]:
            raise ValueError(
                f"funds+graph does not match raw evidence at height {height}"
            )


def make_raw_row(payload: Payload) -> dict[str, object]:
    """Create one sealed source row before it is durably appended."""
    raw = {
        "hathor_height": payload.height,
        "hathor_block_hash": payload.tx_id,
        "hathor_timestamp": payload.timestamp,
        "aux_pow_hex": payload.aux_pow_hex,
        "funds_graph_hex": payload.funds_graph_hex,
        "raw_hex": payload.raw_hex,
    }
    raw["record_sha256"] = raw_record_sha256(raw)
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
    """Resume one range, persisting one complete source row per ready block."""
    ready_rows = load_ready_rows(ledger_path, start, end)
    locks = acquire_locks([raw_output, failure_output])
    try:
        raw_rows = read_csv_rows(raw_output, RAW_COLUMNS)
        check_raw_rows(ready_rows, raw_rows)

        raw_handle, raw_writer = open_csv_writer(raw_output, RAW_COLUMNS)
        failure_handle, failure_writer = open_csv_writer(
            failure_output, FAILURE_COLUMNS
        )
        try:
            stats: Counter[str] = Counter()
            pending = [
                ready_rows[height]
                for height in sorted(ready_rows)
                if height not in raw_rows
            ]
            if limit is not None:
                pending = pending[:limit]
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
                write_durable_row(raw_handle, raw_writer, raw)
                raw_rows[payload.height] = raw
                stats["archived"] += 1
            stats["ready_total"] = len(ready_rows)
            stats["raw_complete"] = len(raw_rows)
            return stats
        finally:
            raw_handle.close()
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
    """Atomically add source-record seals to an already validated CSV.

    This exists only to preserve the completed calibration rows written before
    the record seal was added. It performs no network I/O and refuses any
    schema other than the immediately preceding primary CSV layout.
    """
    locks = acquire_locks([raw_path])
    temporary = raw_path.with_name(f".{raw_path.name}.tmp")
    try:
        ready_rows = load_ready_rows(ledger_path, start, end)
        legacy_rows = read_csv_rows(raw_path, LEGACY_RAW_COLUMNS)
        check_legacy_raw_rows(ready_rows, legacy_rows)
        with temporary.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=RAW_COLUMNS)
            writer.writeheader()
            for height in sorted(legacy_rows):
                row: dict[str, object] = {
                    column: legacy_rows[height][column] for column in LEGACY_RAW_COLUMNS
                }
                row["record_sha256"] = raw_record_sha256(row)
                writer.writerow(row)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, raw_path)
        fsync_directory(raw_path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        for handle in reversed(locks):
            handle.close()
    return {"upgraded_rows": len(legacy_rows)}


def build_supplement(
    ledger_path: Path,
    raw_path: Path,
    supplement_path: Path,
    start: int,
    end: int,
) -> dict[str, int]:
    """Atomically build the established supplement CSV from primary evidence."""
    locks = acquire_locks([raw_path, supplement_path])
    temporary = supplement_path.with_name(f".{supplement_path.name}.tmp")
    try:
        ready_rows = load_ready_rows(ledger_path, start, end)
        raw_rows = read_csv_rows(raw_path, RAW_COLUMNS)
        check_raw_rows(ready_rows, raw_rows)
        missing = set(ready_rows).difference(raw_rows)
        if missing:
            raise ValueError(f"raw payload coverage incomplete: missing={len(missing)}")
        supplement_path.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=SUPPLEMENT_COLUMNS)
            writer.writeheader()
            for height in sorted(ready_rows):
                writer.writerow(raw_to_supplement(raw_rows[height]))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, supplement_path)
        fsync_directory(supplement_path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
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
    ready_rows = load_ready_rows(ledger_path, start, end)
    raw_rows = read_csv_rows(raw_path, RAW_COLUMNS)
    supplement_rows = read_csv_rows(supplement_path, SUPPLEMENT_COLUMNS)
    check_raw_rows(ready_rows, raw_rows)
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
        "ledger_sha256": file_sha256(ledger_path),
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
    argument_parser.add_argument("--limit", type=nonnegative_int)
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
