from __future__ import annotations

import csv
import fcntl
import importlib.util
import json
import sys
from pathlib import Path
from urllib.error import HTTPError

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "extract" / "hathor_metadata_ledger.py"
SPEC = importlib.util.spec_from_file_location("hathor_metadata_ledger", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ledger = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ledger
SPEC.loader.exec_module(ledger)


def test_make_shards_is_contiguous_and_deterministic() -> None:
    shards = ledger.make_shards(
        0,
        10,
        ["worker-a", "worker-b", "worker-c"],
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
        "abc123",
    )

    assert [(s.start_height, s.end_height) for s in shards] == [(0, 4), (4, 8), (8, 10)]
    assert [s.shard_id for s in shards] == ["shard-001", "shard-002", "shard-003"]
    assert [s.worker for s in shards] == ["worker-a", "worker-b", "worker-c"]


def test_validate_shards_rejects_a_gap() -> None:
    shards = [
        ledger.Shard("one", 0, 4, "a", "p", "f", "r", "pending"),
        ledger.Shard("two", 5, 10, "b", "p", "f", "r", "pending"),
    ]

    with pytest.raises(ValueError, match="gap"):
        ledger.validate_shards(shards, 0, 10)


def test_validate_shards_rejects_the_wrong_overall_range() -> None:
    shards = ledger.make_shards(5, 10, ["a"], "p", "f", "r")

    with pytest.raises(ValueError, match="does not cover"):
        ledger.validate_shards(shards, 0, 10)


def test_fetch_height_records_version_three_without_payload_fetch() -> None:
    class Client:
        max_attempts = 3

        def get_json(self, _endpoint, _path, _params):
            return ledger.HttpResult(
                200,
                {"success": True, "block": {"version": 3, "tx_id": "abc"}},
                None,
                False,
            )

        def sleep(self, _seconds):
            raise AssertionError("successful request must not back off")

    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")
    row = ledger.fetch_height(Client(), shard, 0)

    assert row == {
        "hathor_height": 0,
        "outcome": "version_3_ready",
        "http_status": 200,
        "block_version": 3,
        "tx_id": "abc",
        "endpoint": "primary",
        "attempt_count": 1,
        "error_reason": "",
    }


def test_fetch_height_records_version_three_without_tx_id_as_unresolved() -> None:
    class Client:
        max_attempts = 1

        def get_json(self, _endpoint, _path, _params):
            return ledger.HttpResult(
                200,
                {"success": True, "block": {"version": 3}},
                None,
                False,
            )

    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    row = ledger.fetch_height(Client(), shard, 0)

    assert row["outcome"] == "unavailable_block"
    assert row["block_version"] == 3
    assert row["error_reason"] == "version_3_missing_tx_id"


def test_fetch_height_records_exhausted_failure_with_fallback() -> None:
    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            return ledger.HttpResult(429, None, "http_429", True)

        def sleep(self, _seconds):
            pass

    client = Client()
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")
    row = ledger.fetch_height(client, shard, 0)

    assert client.endpoints == ["primary", "fallback"]
    assert row["outcome"] == "request_failure"
    assert row["attempt_count"] == 2
    assert row["endpoint"] == "fallback"


def test_fetch_height_records_non_object_json_as_terminal_failure() -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return 200

        def read(self):
            return json.dumps(["not", "an", "object"]).encode()

    def opener(_request, timeout):
        assert timeout == 30
        return Response()

    client = ledger.PacedHttpClient(
        1000,
        30,
        1,
        opener=opener,
        sleep=lambda _seconds: None,
    )
    shard = ledger.Shard(
        "one",
        0,
        1,
        "a",
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
        "r",
        "pending",
    )

    row = ledger.fetch_height(client, shard, 0)

    assert row["outcome"] == "request_failure"
    assert row["error_reason"] == "json_not_object"
    assert row["attempt_count"] == 1


def test_http_client_retries_status_500() -> None:
    def opener(request, timeout):
        assert timeout == 30
        raise HTTPError(request.full_url, 500, "server error", {}, None)

    client = ledger.PacedHttpClient(
        1000,
        30,
        1,
        opener=opener,
        sleep=lambda _seconds: None,
    )

    result = client.get_json(
        "https://primary.example/v1a", "/block_at_height", {"height": 0}
    )

    assert result == ledger.HttpResult(500, None, "http_500", True)


def test_http_client_preserves_status_for_invalid_json() -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return 200

        def read(self):
            return b"{"

    client = ledger.PacedHttpClient(
        1000,
        30,
        1,
        opener=lambda _request, timeout: Response(),
        sleep=lambda _seconds: None,
    )

    result = client.get_json(
        "https://primary.example/v1a", "/block_at_height", {"height": 0}
    )

    assert result == ledger.HttpResult(200, None, "invalid_json", True)


def test_audit_ledger_requires_complete_exact_range(tmp_path: Path) -> None:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ledger.LEDGER_COLUMNS)
        writer.writeheader()
        writer.writerow(ledger.ledger_row(0, "non_version_3", 200, 0, "a", "p", 1, ""))
        writer.writerow(
            ledger.ledger_row(1, "version_3_ready", 200, 3, "b", "p", 1, "")
        )

    assert ledger.audit_ledger(path, 0, 2) == {
        "non_version_3": 1,
        "version_3_ready": 1,
    }
    with pytest.raises(ValueError, match="missing=1"):
        ledger.audit_ledger(path, 0, 3)


def test_audit_ledger_rejects_unresolved_outcomes(tmp_path: Path) -> None:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ledger.LEDGER_COLUMNS)
        writer.writeheader()
        writer.writerow(
            ledger.ledger_row(
                0, "request_failure", 500, "", "", "primary", 3, "http_500"
            )
        )

    with pytest.raises(ValueError, match="request_failure=1"):
        ledger.audit_ledger(path, 0, 1)


def test_retry_ledger_replaces_selected_failures_in_new_ordered_output(
    tmp_path: Path,
) -> None:
    source = tmp_path / "ledger.csv"
    repaired = tmp_path / "ledger-retry.csv"
    rows = [
        ledger.ledger_row(0, "non_version_3", 200, 0, "a", "primary", 1, ""),
        ledger.ledger_row(1, "request_failure", 500, "", "", "primary", 3, "http_500"),
        ledger.ledger_row(2, "version_3_ready", 200, 3, "c", "primary", 1, ""),
    ]
    with source.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ledger.LEDGER_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    class Client:
        max_attempts = 1

        def get_json(self, _endpoint, _path, params):
            assert params == {"height": 1}
            return ledger.HttpResult(
                200,
                {"success": True, "block": {"version": 3, "tx_id": "b"}},
                None,
                False,
            )

    shard = ledger.Shard("one", 0, 3, "a", "primary", "fallback", "r", "pending")

    assert ledger.retry_ledger(
        Client(),
        shard,
        source,
        repaired,
        frozenset({"request_failure"}),
    ) == {"retried": 1, "resolved": 1}
    with source.open(newline="") as handle:
        source_rows = list(csv.DictReader(handle))
    with repaired.open(newline="") as handle:
        repaired_rows = list(csv.DictReader(handle))
    assert source_rows[1]["outcome"] == "request_failure"
    assert [row["hathor_height"] for row in repaired_rows] == ["0", "1", "2"]
    assert repaired_rows[1]["outcome"] == "version_3_ready"
    assert ledger.audit_ledger(repaired, 0, 3) == {
        "non_version_3": 1,
        "version_3_ready": 2,
    }
    with pytest.raises(ValueError, match="already exists"):
        ledger.retry_ledger(
            Client(),
            shard,
            source,
            repaired,
            frozenset({"request_failure"}),
        )


def test_manifest_range_is_derived_by_default_but_override_must_match(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.csv"
    ledger.write_manifest(
        manifest,
        ledger.make_shards(10, 12, ["a"], "primary", "fallback", "revision"),
    )
    shards = ledger.read_manifest(manifest)

    ledger.validate_shards(shards, 10, 12)
    with pytest.raises(ValueError, match="does not cover"):
        ledger.validate_shards(shards, 0, 1_000_000)


def test_scan_shard_refuses_a_concurrent_ledger_writer(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.csv"
    lock_path = ledger_path.with_suffix(".csv.lock")
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    with lock_path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match="already in use"):
            ledger.scan_shard(object(), shard, ledger_path)


def test_scan_shard_fsyncs_each_terminal_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Client:
        max_attempts = 1

        def get_json(self, _endpoint, _path, _params):
            return ledger.HttpResult(
                200,
                {"success": True, "block": {"version": 0, "tx_id": "abc"}},
                None,
                False,
            )

    fsync_calls: list[int] = []
    monkeypatch.setattr(ledger.os, "fsync", fsync_calls.append)
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    assert ledger.scan_shard(Client(), shard, tmp_path / "ledger.csv") == {
        "non_version_3": 1
    }
    assert len(fsync_calls) == 1


def test_deduplicate_ledger_writes_a_separate_ordered_repair(tmp_path: Path) -> None:
    source = tmp_path / "ledger.csv"
    repaired = tmp_path / "repaired.csv"
    with source.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ledger.LEDGER_COLUMNS)
        writer.writeheader()
        writer.writerow(ledger.ledger_row(2, "non_version_3", 200, 0, "c", "p", 1, ""))
        writer.writerow(
            ledger.ledger_row(1, "version_3_ready", 200, 3, "b", "p", 1, "")
        )
        writer.writerow(ledger.ledger_row(2, "non_version_3", 200, 0, "c", "f", 2, ""))

    assert ledger.deduplicate_ledger(source, repaired) == 1
    with repaired.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["hathor_height"] for row in rows] == ["1", "2"]


def test_deduplicate_ledger_rejects_conflicting_rows(tmp_path: Path) -> None:
    source = tmp_path / "ledger.csv"
    with source.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ledger.LEDGER_COLUMNS)
        writer.writeheader()
        writer.writerow(ledger.ledger_row(2, "non_version_3", 200, 0, "c", "p", 1, ""))
        writer.writerow(
            ledger.ledger_row(2, "version_3_ready", 200, 3, "c", "p", 1, "")
        )

    with pytest.raises(ValueError, match="conflicting duplicate"):
        ledger.deduplicate_ledger(source, tmp_path / "repaired.csv")
