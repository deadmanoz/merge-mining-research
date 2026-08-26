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


def test_make_shards_canonicalizes_endpoint_arguments() -> None:
    shards = ledger.make_shards(
        0,
        4,
        ["a"],
        "  https://primary.example/v1a//  ",
        " https://fallback.example/v1a/ ",
        "r",
    )

    assert shards[0].primary_endpoint == "https://primary.example/v1a"
    assert shards[0].fallback_endpoint == "https://fallback.example/v1a"


@pytest.mark.parametrize("fallback", ["", "   ", "/", " /// "])
def test_make_shards_treats_a_blank_fallback_as_disabled(fallback: str) -> None:
    shards = ledger.make_shards(
        0, 4, ["a"], "https://primary.example/v1a", fallback, "r"
    )

    assert shards[0].fallback_endpoint == ""


@pytest.mark.parametrize("primary", ["", "   ", "/", " /// "])
def test_make_shards_requires_a_nonblank_primary(primary: str) -> None:
    with pytest.raises(ValueError, match="primary endpoint must be non-empty"):
        ledger.make_shards(0, 4, ["a"], primary, "fallback", "r")


@pytest.mark.parametrize(
    ("name", "primary", "fallback"),
    [
        ("primary", "https://primary.example/v1a next", "fallback"),
        (
            "fallback",
            "https://primary.example/v1a",
            "https://fallback.example /v1a",
        ),
    ],
)
def test_make_shards_rejects_remaining_endpoint_whitespace(
    name: str, primary: str, fallback: str
) -> None:
    with pytest.raises(
        ValueError, match=f"{name} endpoint must not contain whitespace"
    ):
        ledger.make_shards(0, 4, ["a"], primary, fallback, "r")


def test_validate_shards_rejects_a_gap() -> None:
    shards = [
        ledger.Shard("one", 0, 4, "a", "p", "f", "r", "pending"),
        ledger.Shard("two", 5, 10, "b", "p", "f", "r", "pending"),
    ]

    with pytest.raises(ValueError, match="gap"):
        ledger.validate_shards(shards, 0, 10)


def test_validate_shards_rejects_the_wrong_overall_range() -> None:
    shards = ledger.make_shards(
        5,
        10,
        ["a"],
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
        "r",
    )

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


def test_fetch_height_resolves_a_valid_fallback_after_a_voided_primary() -> None:
    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            if endpoint == "primary":
                return ledger.HttpResult(
                    200,
                    {
                        "success": True,
                        "block": {"version": 3, "tx_id": TX_B, "is_voided": True},
                    },
                    None,
                    False,
                )
            return ledger.HttpResult(
                200,
                {
                    "success": True,
                    "block": {"version": 3, "tx_id": TX_A, "is_voided": False},
                },
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
    assert row["block_version"] == 3
    assert row["tx_id"] == TX_A
    assert row["endpoint"] == "fallback"
    assert row["attempt_count"] == 2
    assert row["error_reason"] == ""


@pytest.mark.parametrize(
    ("voided_block", "expected_version", "expected_tx_id"),
    [
        ({"version": 3, "tx_id": TX_A, "is_voided": True}, 3, TX_A),
        ({"version": 0, "tx_id": "abc", "is_voided": True}, 0, ""),
    ],
)
def test_fetch_height_records_exhausted_voided_blocks_as_unavailable(
    tmp_path: Path,
    voided_block: dict[str, object],
    expected_version: int,
    expected_tx_id: str,
) -> None:
    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            return ledger.HttpResult(
                200, {"success": True, "block": voided_block}, None, False
            )

        def sleep(self, _seconds):
            pass

    client = Client()
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    row = ledger.fetch_height(client, shard, 0)

    assert client.endpoints == ["primary", "fallback"]
    assert row == {
        "hathor_height": 0,
        "outcome": "unavailable_block",
        "http_status": 200,
        "block_version": expected_version,
        "tx_id": expected_tx_id,
        "endpoint": "fallback",
        "attempt_count": 2,
        "error_reason": "child_block_voided",
    }

    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(row)
    with pytest.raises(ValueError, match="unresolved outcomes: unavailable_block=1"):
        ledger.audit_ledger(path, 0, 1)


@pytest.mark.parametrize(
    ("block", "expected_reason"),
    [
        (
            {"tx_id": TX_A, "is_voided": True},
            "missing_block_version",
        ),
        (
            {"version": "3", "tx_id": TX_A, "is_voided": True},
            "invalid_block_version",
        ),
        (
            {"version": 3, "is_voided": True},
            "version_3_missing_tx_id",
        ),
        (
            {"version": 3, "tx_id": "A" * 64, "is_voided": True},
            "version_3_invalid_tx_id",
        ),
    ],
)
def test_fetch_height_validates_voided_block_fields_before_voided_state(
    block: dict[str, object], expected_reason: str
) -> None:
    class Client:
        max_attempts = 1

        def get_json(self, _endpoint, _path, _params):
            return ledger.HttpResult(
                200, {"success": True, "block": block}, None, False
            )

    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    row = ledger.fetch_height(Client(), shard, 0)

    assert row["outcome"] == "unavailable_block"
    assert row["error_reason"] == expected_reason


@pytest.mark.parametrize(
    "block",
    [
        {"version": 3, "tx_id": TX_A, "is_voided": False},
        {"version": 3, "tx_id": TX_A},
    ],
)
def test_fetch_height_resolves_a_non_voided_block(block: dict[str, object]) -> None:
    class Client:
        max_attempts = 3

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            return ledger.HttpResult(
                200, {"success": True, "block": block}, None, False
            )

        def sleep(self, _seconds):
            raise AssertionError("resolved request must not back off")

    client = Client()
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    row = ledger.fetch_height(client, shard, 0)

    assert client.endpoints == ["primary"]
    assert row["outcome"] == "version_3_ready"
    assert row["tx_id"] == TX_A
    assert row["endpoint"] == "primary"
    assert row["attempt_count"] == 1


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


@pytest.mark.parametrize("fallback_endpoint", ["", " ", "/", "///"])
def test_blank_fallback_is_disabled_and_retries_the_primary(
    fallback_endpoint: str,
) -> None:
    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            assert endpoint
            self.endpoints.append(endpoint)
            return ledger.HttpResult(503, None, "http_503", True)

        def sleep(self, _seconds):
            pass

    client = Client()
    shard = ledger.Shard(
        "one",
        0,
        1,
        "a",
        "primary",
        fallback_endpoint,
        "r",
        "pending",
    )

    row = ledger.fetch_height(client, shard, 0)

    assert client.endpoints == ["primary", "primary"]
    assert row["outcome"] == "request_failure"
    assert row["endpoint"] == "primary"
    assert row["attempt_count"] == 2
    assert row["error_reason"] == "http_503"


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


def test_manifest_round_trip_preserves_its_declared_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "manifest.csv"
    shards = tuple(
        ledger.make_shards(
            10,
            17,
            ["a", "b", "c"],
            "https://primary.example/v1a",
            "https://fallback.example/v1a",
            "revision",
        )
    )
    manifest = ledger.Manifest(10, 17, shards)
    sync_events: list[str | tuple[str, Path]] = []
    monkeypatch.setattr(ledger.os, "fsync", lambda _fd: sync_events.append("file"))
    monkeypatch.setattr(
        ledger,
        "fsync_directory",
        lambda directory: sync_events.append(("directory", directory)),
    )
    ledger.write_manifest(path, manifest)

    assert sync_events == ["file", ("directory", tmp_path)]
    assert ledger.read_manifest(path) == manifest
    assert ledger.read_manifest(path, 10, 17) == manifest
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert {
        (row["manifest_start_height"], row["manifest_end_height"]) for row in rows
    } == {("10", "17")}
    with pytest.raises(ValueError, match="does not match requested"):
        ledger.read_manifest(path, 0, 1_000_000)
    with pytest.raises(ValueError, match="requires both"):
        ledger.read_manifest(path, 10, None)


@pytest.mark.parametrize("removed", ["first", "last"])
def test_manifest_rejects_missing_terminal_shard_row(
    tmp_path: Path,
    removed: str,
) -> None:
    path = tmp_path / "manifest.csv"
    manifest = ledger.Manifest(
        0,
        9,
        tuple(
            ledger.make_shards(
                0,
                9,
                ["a", "b", "c"],
                "https://primary.example/v1a",
                "https://fallback.example/v1a",
                "r",
            )
        ),
    )
    ledger.write_manifest(path, manifest)
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    survivors = rows[1:] if removed == "first" else rows[:-1]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.MANIFEST_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(survivors)

    with pytest.raises(ValueError, match="does not cover"):
        ledger.read_manifest(path)


def test_manifest_rejects_inconsistent_declared_ranges(tmp_path: Path) -> None:
    path = tmp_path / "manifest.csv"
    manifest = ledger.Manifest(
        0,
        6,
        tuple(
            ledger.make_shards(
                0,
                6,
                ["a", "b"],
                "https://primary.example/v1a",
                "https://fallback.example/v1a",
                "r",
            )
        ),
    )
    ledger.write_manifest(path, manifest)
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    rows[1]["manifest_start_height"] = "1"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.MANIFEST_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="disagree"):
        ledger.read_manifest(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("manifest_start_height", "00"),
        ("manifest_end_height", "+6"),
        ("start_height", " 0"),
        ("end_height", "6_0"),
    ],
)
def test_manifest_rejects_noncanonical_bound_strings(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    path = tmp_path / "manifest.csv"
    manifest = ledger.Manifest(
        0,
        6,
        tuple(
            ledger.make_shards(
                0,
                6,
                ["a", "b"],
                "https://primary.example/v1a",
                "https://fallback.example/v1a",
                "r",
            )
        ),
    )
    ledger.write_manifest(path, manifest)
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    rows[0][field] = value
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.MANIFEST_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="non-canonical manifest"):
        ledger.read_manifest(path)


@pytest.mark.parametrize("removed", [None, "first", "last"])
def test_legacy_manifest_requires_and_validates_explicit_range(
    tmp_path: Path,
    removed: str | None,
) -> None:
    path = tmp_path / "legacy-manifest.csv"
    shards = ledger.make_shards(
        0,
        9,
        ["a", "b", "c"],
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
        "r",
    )
    if removed == "first":
        shards = shards[1:]
    elif removed == "last":
        shards = shards[:-1]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=ledger.LEGACY_MANIFEST_COLUMNS,
            lineterminator="\n",
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

    with pytest.raises(ValueError, match="legacy manifest requires explicit"):
        ledger.read_manifest(path)
    if removed is None:
        loaded = ledger.read_manifest(path, 0, 9)
        assert (loaded.start_height, loaded.end_height) == (0, 9)
        assert list(loaded.shards) == shards
    else:
        with pytest.raises(ValueError, match="does not cover"):
            ledger.read_manifest(path, 0, 9)


def test_write_manifest_validates_declared_range_before_creation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "manifest.csv"
    shards = tuple(
        ledger.make_shards(
            10,
            12,
            ["a"],
            "https://primary.example/v1a",
            "https://fallback.example/v1a",
            "r",
        )
    )

    with pytest.raises(ValueError, match="does not cover"):
        ledger.write_manifest(path, ledger.Manifest(0, 12, shards))

    assert not path.exists()


def test_scan_shard_refuses_a_concurrent_ledger_writer(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.csv"
    lock_path = ledger_path.with_suffix(".csv.lock")
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    with lock_path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match="already in use"):
            ledger.scan_shard(object(), shard, ledger_path)


def test_scan_shard_fsyncs_new_file_directory_before_terminal_rows(
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

    sync_events: list[str | tuple[str, Path]] = []
    monkeypatch.setattr(ledger.os, "fsync", lambda _fd: sync_events.append("file"))
    monkeypatch.setattr(
        ledger,
        "fsync_directory",
        lambda path: sync_events.append(("directory", path)),
    )
    shard = ledger.Shard("one", 0, 1, "a", "primary", "fallback", "r", "pending")

    assert ledger.scan_shard(Client(), shard, tmp_path / "ledger.csv") == {
        "non_version_3": 1
    }
    assert sync_events == ["file", ("directory", tmp_path), "file"]
    assert b"\r\n" not in (tmp_path / "ledger.csv").read_bytes()


def _prefixed_ledger(tmp_path: Path, recorded_heights: list[int]) -> Path:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ledger.LEDGER_COLUMNS)
        writer.writeheader()
        for height in recorded_heights:
            writer.writerow(
                ledger.ledger_row(
                    height, "non_version_3", 200, 0, "abc", "primary", 1, ""
                )
            )
    return path


@pytest.mark.parametrize(
    ("recorded_heights", "first_missing", "first_unexpected"),
    [([11], 10, 11), ([10, 12], 11, 12)],
)
def test_scan_shard_rejects_a_ledger_that_is_not_a_contiguous_prefix(
    tmp_path: Path,
    recorded_heights: list[int],
    first_missing: int,
    first_unexpected: int,
) -> None:
    path = _prefixed_ledger(tmp_path, recorded_heights)
    before = path.read_bytes()
    shard = ledger.Shard("one", 10, 14, "a", "primary", "fallback", "r", "pending")

    with pytest.raises(ValueError, match="contiguous prefix") as error:
        ledger.scan_shard(object(), shard, path)

    assert f"first missing height={first_missing}" in str(error.value)
    assert f"first unexpected height={first_unexpected}" in str(error.value)
    assert path.read_bytes() == before


def test_scan_shard_still_rejects_out_of_shard_heights(tmp_path: Path) -> None:
    path = _prefixed_ledger(tmp_path, [0, 1, 4])
    shard = ledger.Shard("one", 0, 3, "a", "primary", "fallback", "r", "pending")

    with pytest.raises(ValueError, match="out-of-shard"):
        ledger.scan_shard(object(), shard, path)


def test_scan_shard_still_rejects_duplicate_heights(tmp_path: Path) -> None:
    path = _prefixed_ledger(tmp_path, [0, 0])
    shard = ledger.Shard("one", 0, 3, "a", "primary", "fallback", "r", "pending")

    with pytest.raises(ValueError, match="duplicate ledger height"):
        ledger.scan_shard(object(), shard, path)


def test_scan_shard_resumes_a_valid_partial_prefix(tmp_path: Path) -> None:
    path = _prefixed_ledger(tmp_path, [10, 11])

    class Client:
        max_attempts = 1

        def __init__(self):
            self.heights: list[int] = []

        def get_json(self, _endpoint, _path, params):
            self.heights.append(params["height"])
            return ledger.HttpResult(
                200,
                {"success": True, "block": {"version": 0, "tx_id": "abc"}},
                None,
                False,
            )

    client = Client()
    shard = ledger.Shard("one", 10, 14, "a", "primary", "fallback", "r", "pending")

    assert ledger.scan_shard(client, shard, path) == {"non_version_3": 2}
    assert client.heights == [12, 13]
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["hathor_height"] for row in rows] == ["10", "11", "12", "13"]


def test_deduplicate_ledger_writes_a_separate_ordered_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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

    synced_directories: list[Path] = []
    monkeypatch.setattr(ledger, "fsync_directory", synced_directories.append)

    assert ledger.deduplicate_ledger(source, repaired) == 1
    assert synced_directories == [tmp_path]
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


def _deduplication_source(tmp_path: Path) -> Path:
    source = tmp_path / "ledger.csv"
    with source.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ledger.LEDGER_COLUMNS)
        writer.writeheader()
        writer.writerow(ledger.ledger_row(0, "non_version_3", 200, 0, "a", "p", 1, ""))
        writer.writerow(ledger.ledger_row(0, "non_version_3", 200, 0, "a", "f", 2, ""))
    return source


def test_deduplicate_ledger_competing_winner_is_never_clobbered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _deduplication_source(tmp_path)
    repaired = tmp_path / "repaired.csv"
    real_link = ledger.os.link

    def competing_link(source_path, target):
        Path(target).write_text("competing repair\n")
        real_link(source_path, target)

    monkeypatch.setattr(ledger.os, "link", competing_link)

    with pytest.raises(ValueError, match="deduplicated output already exists"):
        ledger.deduplicate_ledger(source, repaired)

    assert repaired.read_text() == "competing repair\n"
    assert not list(tmp_path.glob(".*.tmp-*"))


def test_deduplicate_ledger_interruption_before_publication_leaves_no_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _deduplication_source(tmp_path)
    repaired = tmp_path / "repaired.csv"

    def fail_fsync(_fd):
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(ledger.os, "fsync", fail_fsync)

    with pytest.raises(OSError, match="simulated fsync failure"):
        ledger.deduplicate_ledger(source, repaired)

    assert not repaired.exists()
    assert not list(tmp_path.glob(".*.tmp-*"))


def test_deduplicate_ledger_syncs_file_then_links_then_syncs_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _deduplication_source(tmp_path)
    repaired = tmp_path / "repaired.csv"
    events: list[str | tuple[str, Path]] = []
    real_link = ledger.os.link
    monkeypatch.setattr(ledger.os, "fsync", lambda _fd: events.append("file"))

    def recording_link(source_path, target):
        events.append("link")
        real_link(source_path, target)

    monkeypatch.setattr(ledger.os, "link", recording_link)
    monkeypatch.setattr(
        ledger,
        "fsync_directory",
        lambda directory: events.append(("directory", directory)),
    )

    assert ledger.deduplicate_ledger(source, repaired) == 1

    assert events == ["file", "link", ("directory", tmp_path)]


def _two_shard_manifest() -> ledger.Manifest:
    return ledger.Manifest(
        0,
        6,
        tuple(
            ledger.make_shards(
                0,
                6,
                ["a", "b"],
                "https://primary.example/v1a",
                "https://fallback.example/v1a",
                "r",
            )
        ),
    )


def test_write_manifest_competing_winner_is_never_clobbered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "manifest.csv"
    real_link = ledger.os.link

    def competing_link(source, target):
        Path(target).write_text("competing manifest\n")
        real_link(source, target)

    monkeypatch.setattr(ledger.os, "link", competing_link)

    with pytest.raises(ValueError, match="manifest already exists"):
        ledger.write_manifest(path, _two_shard_manifest())

    assert path.read_text() == "competing manifest\n"
    assert not list(tmp_path.glob(".*.tmp-*"))


def test_write_manifest_interruption_before_publication_leaves_no_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "manifest.csv"

    def fail_fsync(_fd):
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(ledger.os, "fsync", fail_fsync)

    with pytest.raises(OSError, match="simulated fsync failure"):
        ledger.write_manifest(path, _two_shard_manifest())

    assert not path.exists()
    assert not list(tmp_path.glob(".*.tmp-*"))


def test_write_manifest_syncs_file_then_links_then_syncs_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "manifest.csv"
    events: list[str | tuple[str, Path]] = []
    real_link = ledger.os.link
    monkeypatch.setattr(ledger.os, "fsync", lambda _fd: events.append("file"))

    def recording_link(source, target):
        events.append("link")
        real_link(source, target)

    monkeypatch.setattr(ledger.os, "link", recording_link)
    monkeypatch.setattr(
        ledger,
        "fsync_directory",
        lambda directory: events.append(("directory", directory)),
    )

    manifest = _two_shard_manifest()
    ledger.write_manifest(path, manifest)

    assert events == ["file", "link", ("directory", tmp_path)]
    assert ledger.read_manifest(path) == manifest


def _direct_manifest(primary: str, fallback: str) -> ledger.Manifest:
    return ledger.Manifest(
        0,
        6,
        (
            ledger.Shard("one", 0, 3, "a", primary, fallback, "r", "pending"),
            ledger.Shard("two", 3, 6, "b", primary, fallback, "r", "pending"),
        ),
    )


def test_write_manifest_canonicalizes_direct_shard_endpoints(
    tmp_path: Path,
) -> None:
    path = tmp_path / "manifest.csv"
    manifest = _direct_manifest(
        "  https://primary.example/v1a//  ",
        " https://fallback.example/v1a/ ",
    )

    ledger.write_manifest(path, manifest)

    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert {row["primary_endpoint"] for row in rows} == {"https://primary.example/v1a"}
    assert {row["fallback_endpoint"] for row in rows} == {
        "https://fallback.example/v1a"
    }
    loaded = ledger.read_manifest(path)
    assert all(
        shard.primary_endpoint == "https://primary.example/v1a"
        and shard.fallback_endpoint == "https://fallback.example/v1a"
        for shard in loaded.shards
    )


@pytest.mark.parametrize(
    ("primary", "fallback", "message"),
    [
        ("", "fallback", "primary endpoint must be non-empty"),
        ("   ", "fallback", "primary endpoint must be non-empty"),
        (" /// ", "fallback", "primary endpoint must be non-empty"),
        (
            "https://primary.example/v1a next",
            "fallback",
            "primary endpoint must not contain whitespace",
        ),
        (
            "https://primary.example/v1a",
            "https://fallback.example /v1a",
            "fallback endpoint must not contain whitespace",
        ),
        (
            "ftp://primary.example/v1a",
            "",
            "primary endpoint must be an absolute http or https URL",
        ),
        (
            "https://primary.example/v1a?x=1",
            "",
            "primary endpoint must not contain a query or fragment",
        ),
    ],
)
def test_write_manifest_rejects_invalid_direct_endpoints_without_artifacts(
    tmp_path: Path, primary: str, fallback: str, message: str
) -> None:
    path = tmp_path / "manifest.csv"

    with pytest.raises(ValueError, match=message):
        ledger.write_manifest(path, _direct_manifest(primary, fallback))

    assert not path.exists()
    assert not list(tmp_path.glob(".*.tmp-*"))


def _manifest_with_endpoints(tmp_path: Path, replacements: dict[str, str]) -> Path:
    path = tmp_path / "manifest.csv"
    ledger.write_manifest(path, _two_shard_manifest())
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        row.update(replacements)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.MANIFEST_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)
    return path


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("primary_endpoint", "", "primary endpoint must be non-empty"),
        ("primary_endpoint", "   ", "primary endpoint must be non-empty"),
        (
            "primary_endpoint",
            "https://primary.example /v1a",
            "primary endpoint must not contain whitespace",
        ),
        (
            "fallback_endpoint",
            "https://fallback.example /v1a",
            "fallback endpoint must not contain whitespace",
        ),
    ],
)
def test_read_manifest_rejects_malformed_loaded_endpoints(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    path = _manifest_with_endpoints(tmp_path, {field: value})

    with pytest.raises(ValueError, match=message):
        ledger.read_manifest(path)


def test_read_manifest_normalizes_trailing_slash_endpoints(tmp_path: Path) -> None:
    path = _manifest_with_endpoints(
        tmp_path,
        {
            "primary_endpoint": " https://primary.example/v1a// ",
            "fallback_endpoint": "https://fallback.example/v1a/",
        },
    )

    loaded = ledger.read_manifest(path)

    assert all(
        shard.primary_endpoint == "https://primary.example/v1a"
        and shard.fallback_endpoint == "https://fallback.example/v1a"
        for shard in loaded.shards
    )


def test_audit_ledger_rejects_canonical_tx_reuse_across_mixed_outcomes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(ledger.ledger_row(0, "non_version_3", 200, 0, TX_A, "p", 1, ""))
        writer.writerow(
            ledger.ledger_row(1, "version_3_ready", 200, 3, TX_A, "p", 1, "")
        )

    with pytest.raises(ValueError, match="assigned to multiple heights: 0, 1"):
        ledger.audit_ledger(path, 0, 2)


def test_audit_ledger_checks_canonical_tx_ids_in_unresolved_rows(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(
            ledger.ledger_row(
                0,
                "unavailable_block",
                200,
                3,
                TX_A,
                "p",
                1,
                "child_block_voided",
            )
        )
        writer.writerow(
            ledger.ledger_row(1, "version_3_ready", 200, 3, TX_A, "p", 1, "")
        )

    with pytest.raises(ValueError, match="assigned to multiple heights: 0, 1"):
        ledger.audit_ledger(path, 0, 2)


def test_audit_ledger_preserves_repeated_legacy_noncanonical_tx_ids(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        for height in range(2):
            writer.writerow(
                ledger.ledger_row(height, "non_version_3", 200, 0, "abc", "p", 1, "")
            )

    assert ledger.audit_ledger(path, 0, 2) == {"non_version_3": 2}


def test_audit_ledger_reports_duplicate_height_before_tx_id_reuse(
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
            ledger.ledger_row(0, "version_3_ready", 200, 3, TX_A, "p", 2, "")
        )

    with pytest.raises(ValueError, match="duplicate ledger height: 0"):
        ledger.audit_ledger(path, 0, 2)


def test_read_manifest_rejects_incomplete_record_cells(tmp_path: Path) -> None:
    path = tmp_path / "manifest.csv"
    ledger.write_manifest(path, _two_shard_manifest())
    lines = path.read_text().splitlines(keepends=True)
    lines[1] = lines[1].rsplit(",", 1)[0] + "\n"
    path.write_text("".join(lines))

    with pytest.raises(ValueError, match="exact complete schema"):
        ledger.read_manifest(path)


def test_read_manifest_rejects_extra_record_cells(tmp_path: Path) -> None:
    path = tmp_path / "manifest.csv"
    ledger.write_manifest(path, _two_shard_manifest())
    lines = path.read_text().splitlines(keepends=True)
    lines[1] = lines[1].rstrip("\n") + ",extra\n"
    path.write_text("".join(lines))

    with pytest.raises(ValueError, match="exact complete schema"):
        ledger.read_manifest(path)


def test_read_manifest_rejects_a_multi_line_record(tmp_path: Path) -> None:
    path = tmp_path / "manifest.csv"
    ledger.write_manifest(path, _two_shard_manifest())
    lines = path.read_text().splitlines(keepends=True)
    cells = lines[1].rstrip("\n").split(",")
    cells[5] = '"worker\na"'
    lines[1] = ",".join(cells) + "\n"
    path.write_text("".join(lines))

    with pytest.raises(ValueError, match="malformed multi-line or blank manifest row"):
        ledger.read_manifest(path)


def test_read_manifest_rejects_an_interior_blank_record(tmp_path: Path) -> None:
    path = tmp_path / "manifest.csv"
    ledger.write_manifest(path, _two_shard_manifest())
    lines = path.read_text().splitlines(keepends=True)
    lines.insert(2, "\n")
    path.write_text("".join(lines))

    with pytest.raises(ValueError, match="malformed multi-line or blank manifest row"):
        ledger.read_manifest(path)


def test_read_manifest_rejects_a_trailing_blank_record(tmp_path: Path) -> None:
    path = tmp_path / "manifest.csv"
    ledger.write_manifest(path, _two_shard_manifest())
    path.write_text(path.read_text() + "\n")

    with pytest.raises(ValueError, match="malformed trailing blank manifest row"):
        ledger.read_manifest(path)


def test_read_manifest_wraps_malformed_csv(tmp_path: Path) -> None:
    path = tmp_path / "manifest.csv"
    ledger.write_manifest(path, _two_shard_manifest())
    path.write_text(path.read_text() + '"unterminated\n')

    with pytest.raises(ValueError, match="malformed manifest CSV"):
        ledger.read_manifest(path)


@pytest.mark.parametrize(
    ("endpoint", "message"),
    [
        ("primary", "absolute http or https URL"),
        ("ftp://primary.example/v1a", "absolute http or https URL"),
        ("//primary.example/v1a", "absolute http or https URL"),
        ("https:///v1a", "absolute http or https URL"),
        ("https://primary.example:notaport/v1a", "absolute http or https URL"),
        ("https://primary.example:99999/v1a", "absolute http or https URL"),
        ("https://primary.example:/v1a", "absolute http or https URL"),
        ("https://primary.example/v1a?height=1", "query or fragment"),
        ("https://primary.example/v1a?", "query or fragment"),
        ("https://primary.example/v1a#frag", "query or fragment"),
        ("https://primary.example/v1a#", "query or fragment"),
    ],
)
def test_make_shards_rejects_non_absolute_or_qualified_endpoints(
    endpoint: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        ledger.make_shards(0, 4, ["a"], endpoint, "", "r")


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://primary.example/v1a",
        "https://primary.example/v1a",
        "https://primary.example:8080/v1a",
        "http://127.0.0.1:8332/v1a",
    ],
)
def test_make_shards_accepts_absolute_http_endpoint_forms(endpoint: str) -> None:
    shards = ledger.make_shards(0, 4, ["a"], endpoint, "", "r")

    assert shards[0].primary_endpoint == endpoint


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("primary_endpoint", "ftp://primary.example/v1a", "absolute http or https"),
        (
            "primary_endpoint",
            "https://primary.example/v1a?x=1",
            "query or fragment",
        ),
        (
            "fallback_endpoint",
            "https://fallback.example/v1a#frag",
            "query or fragment",
        ),
    ],
)
def test_read_manifest_rejects_non_http_loaded_endpoints(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    path = _manifest_with_endpoints(tmp_path, {field: value})

    with pytest.raises(ValueError, match=message):
        ledger.read_manifest(path)


def test_http_client_rejects_an_invalid_url_before_pacing_or_opener() -> None:
    def opener(_request, timeout):
        raise AssertionError("an invalid URL must never reach the opener")

    sleeps: list[float] = []
    client = ledger.PacedHttpClient(
        1000,
        30,
        1,
        opener=opener,
        sleep=lambda seconds: sleeps.append(seconds),
    )

    result = client.get_json("primary", "/block_at_height", {"height": 0})

    assert result == ledger.HttpResult(None, None, "invalid_url", False)
    assert client._last_request_start is None
    assert sleeps == []
    assert client.get_json("primary", "/block_at_height", {"height": 1}) == result
