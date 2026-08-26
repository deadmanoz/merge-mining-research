from __future__ import annotations

import csv
import fcntl
import importlib.util
import json
import sys
from http.client import IncompleteRead
from pathlib import Path
from urllib.error import HTTPError

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "extract" / "hathor_metadata_ledger.py"
SPEC = importlib.util.spec_from_file_location("hathor_metadata_ledger", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ledger = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ledger
SPEC.loader.exec_module(ledger)

TX_A = "a" * 64
TX_B = "b" * 64
TX_C = "c" * 64


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf", "1e9999"])
def test_positive_float_rejects_non_positive_or_non_finite_values(value: str) -> None:
    with pytest.raises(ledger.argparse.ArgumentTypeError, match="finite"):
        ledger.positive_float(value)


def test_positive_float_accepts_a_finite_positive_value() -> None:
    assert ledger.positive_float("0.5") == 0.5


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
                {"success": True, "block": {"version": 3, "tx_id": TX_A}},
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
        "tx_id": TX_A,
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


@pytest.mark.parametrize(
    "invalid_tx_id",
    ["a" * 63, "A" * 64, "g" * 64, f" {TX_A}"],
)
def test_fetch_height_retries_malformed_version_three_tx_ids(
    invalid_tx_id: str,
) -> None:
    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            tx_id = invalid_tx_id if endpoint == "primary" else TX_A
            return ledger.HttpResult(
                200,
                {"success": True, "block": {"version": 3, "tx_id": tx_id}},
                None,
                False,
            )

        def sleep(self, _seconds):
            pass

    client = Client()
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    row = ledger.fetch_height(client, shard, 0)

    assert client.endpoints == ["primary", "fallback"]
    assert row["outcome"] == "version_3_ready"
    assert row["tx_id"] == TX_A
    assert row["endpoint"] == "fallback"
    assert row["attempt_count"] == 2


def test_fetch_height_records_exhausted_malformed_tx_id_as_valid_unresolved_row(
    tmp_path: Path,
) -> None:
    class Client:
        max_attempts = 1

        def get_json(self, _endpoint, _path, _params):
            return ledger.HttpResult(
                200,
                {"success": True, "block": {"version": 3, "tx_id": "g" * 64}},
                None,
                False,
            )

    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    row = ledger.fetch_height(Client(), shard, 0)

    assert row["outcome"] == "unavailable_block"
    assert row["http_status"] == 200
    assert row["block_version"] == 3
    assert row["tx_id"] == ""
    assert row["error_reason"] == "version_3_invalid_tx_id"

    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(row)
    assert ledger.read_recorded_heights(path) == {0}


@pytest.mark.parametrize(
    ("version", "error_reason"),
    [
        (None, "missing_block_version"),
        ("0", "invalid_block_version"),
        (-1, "invalid_block_version"),
        (0.0, "invalid_block_version"),
        (True, "invalid_block_version"),
    ],
)
def test_fetch_height_keeps_missing_or_invalid_versions_unresolved(
    version: object, error_reason: str
) -> None:
    class Client:
        max_attempts = 1

        def get_json(self, _endpoint, _path, _params):
            return ledger.HttpResult(
                200,
                {"success": True, "block": {"version": version, "tx_id": "abc"}},
                None,
                False,
            )

    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    row = ledger.fetch_height(Client(), shard, 0)

    assert row["outcome"] == "unavailable_block"
    assert row["block_version"] == ""
    assert row["error_reason"] == error_reason


@pytest.mark.parametrize(
    "primary_payload",
    [
        {"success": False, "block": {}},
        {"success": True, "block": {}},
        {"success": True, "block": ["not", "an", "object"]},
        {"success": True, "block": {"tx_id": "abc"}},
        {"success": True, "block": {"version": "0", "tx_id": "abc"}},
    ],
)
def test_fetch_height_tries_fallback_after_an_unavailable_primary(
    primary_payload: dict[str, object],
) -> None:
    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            payload = (
                primary_payload
                if endpoint == "primary"
                else {"success": True, "block": {"version": 0, "tx_id": "abc"}}
            )
            return ledger.HttpResult(200, payload, None, False)

        def sleep(self, _seconds):
            pass

    client = Client()
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    row = ledger.fetch_height(client, shard, 0)

    assert client.endpoints == ["primary", "fallback"]
    assert row["outcome"] == "non_version_3"
    assert row["endpoint"] == "fallback"
    assert row["attempt_count"] == 2


def test_fetch_height_exhausts_bounded_attempts_before_unavailable() -> None:
    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            return ledger.HttpResult(200, {"success": False, "block": {}}, None, False)

        def sleep(self, _seconds):
            pass

    client = Client()
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    row = ledger.fetch_height(client, shard, 0)

    assert client.endpoints == ["primary", "fallback"]
    assert row["outcome"] == "unavailable_block"
    assert row["endpoint"] == "fallback"
    assert row["attempt_count"] == 2


@pytest.mark.parametrize(
    "primary_result",
    [
        ledger.HttpResult(
            None,
            {"success": True, "block": {"version": 0, "tx_id": "abc"}},
            None,
            False,
        ),
        ledger.HttpResult(
            500,
            {"success": True, "block": {"version": 0, "tx_id": "abc"}},
            None,
            False,
        ),
        ledger.HttpResult(404, None, "http_404", False),
    ],
)
def test_fetch_height_tries_fallback_after_invalid_or_endpoint_specific_status(
    primary_result: ledger.HttpResult,
) -> None:
    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            if endpoint == "primary":
                return primary_result
            return ledger.HttpResult(
                200,
                {"success": True, "block": {"version": 0, "tx_id": "abc"}},
                None,
                False,
            )

        def sleep(self, _seconds):
            pass

    client = Client()
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    row = ledger.fetch_height(client, shard, 0)

    assert client.endpoints == ["primary", "fallback"]
    assert row["outcome"] == "non_version_3"
    assert row["http_status"] == 200
    assert row["endpoint"] == "fallback"


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


def test_http_client_preserves_status_for_truncated_response() -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return 200

        def read(self):
            raise IncompleteRead(b'{"success":', 10)

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

    assert result == ledger.HttpResult(200, None, "IncompleteRead", True)


def test_fetch_height_retries_truncated_responses_and_retains_status() -> None:
    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            return ledger.HttpResult(200, None, "IncompleteRead", True)

        def sleep(self, _seconds):
            pass

    client = Client()
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    row = ledger.fetch_height(client, shard, 0)

    assert client.endpoints == ["primary", "fallback"]
    assert row["outcome"] == "request_failure"
    assert row["http_status"] == 200
    assert row["attempt_count"] == 2
    assert row["error_reason"] == "IncompleteRead"


def test_audit_ledger_requires_complete_exact_range(tmp_path: Path) -> None:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ledger.LEDGER_COLUMNS)
        writer.writeheader()
        writer.writerow(ledger.ledger_row(0, "non_version_3", 200, 0, "a", "p", 1, ""))
        writer.writerow(
            ledger.ledger_row(1, "version_3_ready", 200, 3, TX_B, "p", 1, "")
        )

    assert ledger.audit_ledger(path, 0, 2) == {
        "non_version_3": 1,
        "version_3_ready": 1,
    }
    with pytest.raises(ValueError, match="missing=1"):
        ledger.audit_ledger(path, 0, 3)


def test_audit_ledger_rejects_one_ready_transaction_at_multiple_heights(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(
            ledger.ledger_row(0, "version_3_ready", 200, 3, TX_A, "p", 1, "")
        )
        writer.writerow(
            ledger.ledger_row(1, "version_3_ready", 200, 3, TX_A, "p", 1, "")
        )

    with pytest.raises(ValueError, match="assigned to multiple.*0, 1"):
        ledger.audit_ledger(path, 0, 2)


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


@pytest.mark.parametrize("invalid_tx_id", ["a" * 63, "A" * 64, "g" * 64])
def test_audit_ledger_rejects_malformed_version_three_tx_ids(
    tmp_path: Path, invalid_tx_id: str
) -> None:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(
            ledger.ledger_row(
                0, "version_3_ready", 200, 3, invalid_tx_id, "primary", 1, ""
            )
        )

    with pytest.raises(ValueError, match="invalid version_3_ready fields"):
        ledger.audit_ledger(path, 0, 1)


@pytest.mark.parametrize("operation", ["audit", "resume"])
def test_ledger_consumers_reject_a_truncated_final_row(
    tmp_path: Path, operation: str
) -> None:
    path = tmp_path / "ledger.csv"
    header = ",".join(ledger.LEDGER_COLUMNS)
    path.write_text(f"{header}\n0,non_version_3,200,0,abc,primary,1,")

    with pytest.raises(ValueError, match="truncated row"):
        if operation == "audit":
            ledger.audit_ledger(path, 0, 1)
        else:
            shard = ledger.Shard(
                "one", 0, 1, "a", "primary", "fallback", "r", "pending"
            )
            ledger.scan_shard(object(), shard, path)


@pytest.mark.parametrize("operation", ["audit", "resume"])
def test_ledger_consumers_require_every_schema_cell(
    tmp_path: Path, operation: str
) -> None:
    path = tmp_path / "ledger.csv"
    header = ",".join(ledger.LEDGER_COLUMNS)
    path.write_text(f"{header}\n0,non_version_3,200,0,abc,primary,1\n")

    with pytest.raises(ValueError, match="exact complete schema"):
        if operation == "audit":
            ledger.audit_ledger(path, 0, 1)
        else:
            shard = ledger.Shard(
                "one", 0, 1, "a", "primary", "fallback", "r", "pending"
            )
            ledger.scan_shard(object(), shard, path)


@pytest.mark.parametrize("operation", ["audit", "resume"])
def test_ledger_consumers_reject_extra_schema_cells(
    tmp_path: Path, operation: str
) -> None:
    path = tmp_path / "ledger.csv"
    header = ",".join(ledger.LEDGER_COLUMNS)
    path.write_text(f"{header}\n0,non_version_3,200,0,abc,primary,1,,extra\n")

    with pytest.raises(ValueError, match="exact complete schema"):
        if operation == "audit":
            ledger.audit_ledger(path, 0, 1)
        else:
            shard = ledger.Shard(
                "one", 0, 1, "a", "primary", "fallback", "r", "pending"
            )
            ledger.scan_shard(object(), shard, path)


@pytest.mark.parametrize("operation", ["audit", "resume"])
def test_ledger_consumers_require_the_exact_header(
    tmp_path: Path, operation: str
) -> None:
    path = tmp_path / "ledger.csv"
    reversed_header = ",".join(reversed(ledger.LEDGER_COLUMNS))
    path.write_text(f"{reversed_header}\n")

    with pytest.raises(ValueError, match="unexpected ledger columns"):
        if operation == "audit":
            ledger.audit_ledger(path, 0, 1)
        else:
            shard = ledger.Shard(
                "one", 0, 1, "a", "primary", "fallback", "r", "pending"
            )
            ledger.scan_shard(object(), shard, path)


@pytest.mark.parametrize("operation", ["audit", "resume"])
def test_ledger_consumers_reject_noncanonical_terminal_fields(
    tmp_path: Path, operation: str
) -> None:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        row = ledger.ledger_row(0, "non_version_3", 200, 0, "abc", "primary", 1, "")
        row["attempt_count"] = "01"
        writer.writerow(row)

    with pytest.raises(ValueError, match="non-canonical attempt_count"):
        if operation == "audit":
            ledger.audit_ledger(path, 0, 1)
        else:
            shard = ledger.Shard(
                "one", 0, 1, "a", "primary", "fallback", "r", "pending"
            )
            ledger.scan_shard(object(), shard, path)


def test_audit_rejects_resolved_outcome_without_required_terminal_fields(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(
            ledger.ledger_row(0, "non_version_3", 200, "", "abc", "primary", 1, "")
        )

    with pytest.raises(ValueError, match="invalid non_version_3 fields"):
        ledger.audit_ledger(path, 0, 1)


@pytest.mark.parametrize("operation", ["audit", "resume"])
def test_ledger_consumers_reject_nonascending_rows(
    tmp_path: Path, operation: str
) -> None:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(
            ledger.ledger_row(1, "version_3_ready", 200, 3, TX_B, "p", 1, "")
        )
        writer.writerow(ledger.ledger_row(0, "non_version_3", 200, 0, "a", "p", 1, ""))

    with pytest.raises(ValueError, match="ascending height order"):
        if operation == "audit":
            ledger.audit_ledger(path, 0, 2)
        else:
            shard = ledger.Shard(
                "one", 0, 2, "a", "primary", "fallback", "r", "pending"
            )
            ledger.scan_shard(object(), shard, path)


def test_retry_ledger_replaces_selected_failures_in_new_ordered_output(
    tmp_path: Path,
) -> None:
    source = tmp_path / "ledger.csv"
    repaired = tmp_path / "ledger-retry.csv"
    rows = [
        ledger.ledger_row(0, "non_version_3", 200, 0, "a", "primary", 1, ""),
        ledger.ledger_row(1, "request_failure", 500, "", "", "primary", 3, "http_500"),
        ledger.ledger_row(2, "version_3_ready", 200, 3, TX_C, "primary", 1, ""),
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
                {"success": True, "block": {"version": 3, "tx_id": TX_B}},
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
    assert b"\r\n" not in (tmp_path / "ledger.csv").read_bytes()


def test_deduplicate_ledger_writes_a_separate_ordered_repair(tmp_path: Path) -> None:
    source = tmp_path / "ledger.csv"
    repaired = tmp_path / "repaired.csv"
    with source.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ledger.LEDGER_COLUMNS)
        writer.writeheader()
        writer.writerow(ledger.ledger_row(2, "non_version_3", 200, 0, "c", "p", 1, ""))
        writer.writerow(
            ledger.ledger_row(1, "version_3_ready", 200, 3, TX_B, "p", 1, "")
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
            ledger.ledger_row(2, "version_3_ready", 200, 3, TX_C, "p", 1, "")
        )

    with pytest.raises(ValueError, match="conflicting duplicate"):
        ledger.deduplicate_ledger(source, tmp_path / "repaired.csv")
