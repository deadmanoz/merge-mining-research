from __future__ import annotations

import copy
import csv
import importlib.util
import json
import sys
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).parents[1]
    / "scripts"
    / "extract"
    / "extract_hathor_payloads_from_ledger.py"
)
SPEC = importlib.util.spec_from_file_location("hathor_payloads_from_ledger", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
payloads = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = payloads
SPEC.loader.exec_module(payloads)

TX_A = "a" * 64
TX_B = "b" * 64
TX_C = "c" * 64
PRIMARY = "https://primary.example/v1a"
FALLBACK = "https://fallback.example/v1a"


def _ledger_row(
    height: int, outcome: str, tx_id: str, *, status: int = 200
) -> dict[str, object]:
    version = 3 if outcome == "version_3_ready" else 0
    return {
        "hathor_height": height,
        "outcome": outcome,
        "http_status": status,
        "block_version": version,
        "tx_id": tx_id,
        "endpoint": PRIMARY,
        "attempt_count": 1,
        "error_reason": "",
    }


def _write_ledger(path: Path, rows: list[dict[str, object]] | None = None) -> None:
    if rows is None:
        rows = [
            _ledger_row(0, "version_3_ready", TX_A),
            _ledger_row(1, "non_version_3", TX_B),
            _ledger_row(2, "version_3_ready", TX_C),
        ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)


def _response(
    tx_id: str,
    *,
    prefix: bytes = b"funds",
    aux_pow: bytes = b"\xaa\x55",
    timestamp: int = 10,
) -> dict:
    return {
        "success": True,
        "tx": {
            "hash": tx_id,
            "version": 3,
            "is_voided": False,
            "timestamp": timestamp,
            "aux_pow": aux_pow.hex(),
            "raw": (prefix + aux_pow + b"tail").hex(),
        },
    }


class _Response:
    def __init__(self, body: dict, status: int = 200):
        self.body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def getcode(self):
        return self.status

    def read(self):
        return json.dumps(self.body).encode()


def _client_for_rows(rows: dict[str, dict]) -> payloads.PacedHttpClient:
    def opener(request, timeout):
        assert timeout == 30
        tx_id = request.full_url.rsplit("id=", 1)[1]
        return _Response(rows[tx_id])

    return payloads.PacedHttpClient(
        1000,
        30,
        2,
        opener=opener,
        sleep=lambda _seconds: None,
    )


def _acquisition_row(
    height: int,
    tx_id: str,
    *,
    prefix: bytes = b"funds",
    aux_pow: bytes = b"\xaa\x55",
) -> dict[str, object]:
    return payloads.make_acquisition_row(
        payloads.Payload(
            height,
            tx_id,
            10 + height,
            aux_pow.hex(),
            (prefix + aux_pow + b"tail").hex(),
            prefix.hex(),
            PRIMARY,
            200,
            1,
        )
    )


def _write_dataset(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.ACQUISITION_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)


def _write_failures(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.FAILURE_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)


def test_load_ready_rows_requires_a_complete_resolved_range(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.csv"
    _write_ledger(ledger)

    assert payloads.load_ready_rows(ledger, 0, 3) == {
        0: payloads.ReadyRow(0, TX_A),
        2: payloads.ReadyRow(2, TX_C),
    }

    rows = [
        _ledger_row(0, "version_3_ready", TX_A),
        {
            **_ledger_row(1, "non_version_3", ""),
            "outcome": "request_failure",
            "http_status": 503,
            "block_version": "",
            "error_reason": "http_503",
        },
    ]
    _write_ledger(ledger, rows)
    with pytest.raises(ValueError, match="unresolved metadata outcome"):
        payloads.load_ready_rows(ledger, 0, 2)


def test_parse_payload_preserves_identity_bytes_and_request_provenance() -> None:
    parsed = payloads.parse_payload(
        payloads.ReadyRow(7, TX_A), _response(TX_A), FALLBACK, 200, 2
    )

    assert parsed.height == 7
    assert parsed.tx_id == TX_A
    assert parsed.funds_graph_hex == b"funds".hex()
    assert parsed.endpoint == FALLBACK
    assert parsed.http_status == 200
    assert parsed.attempt_count == 2


@pytest.mark.parametrize(
    "mutation, message",
    [
        (("success", False), "api_success_false"),
        (("hash", TX_B), "tx_hash_mismatch"),
        (("version", 2), "tx_version_mismatch"),
        (("is_voided", True), "child_block_voided"),
        (("timestamp", True), "invalid_timestamp"),
        (("raw", "zz"), "not compact hexadecimal"),
        (("raw", (b"ab" + b"\xaa\x55").hex()), "prefix_too_short"),
        (
            ("raw", (b"abc" + b"\xaa\x55" + b"x" + b"\xaa\x55").hex()),
            "aux_pow_occurrences_2",
        ),
    ],
)
def test_parse_payload_rejects_invalid_evidence(mutation, message: str) -> None:
    response = copy.deepcopy(_response(TX_A, prefix=b"abc"))
    field, value = mutation
    if field == "success":
        response[field] = value
    else:
        response["tx"][field] = value

    with pytest.raises(ValueError, match=message):
        payloads.parse_payload(payloads.ReadyRow(0, TX_A), response, PRIMARY, 200, 1)


def test_fetch_payload_uses_fallback_after_a_primary_failure() -> None:
    class Client:
        max_attempts = 2

        def __init__(self):
            self.results = iter(
                [
                    payloads.HttpResult(503, None, "http_503", True),
                    payloads.HttpResult(200, _response(TX_A), None, False),
                ]
            )
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            return next(self.results)

        def sleep(self, _seconds):
            pass

    client = Client()
    acquired, failure = payloads.fetch_payload(
        client, payloads.ReadyRow(0, TX_A), PRIMARY, FALLBACK
    )

    assert failure is None
    assert acquired is not None
    assert acquired.endpoint == FALLBACK
    assert acquired.attempt_count == 2
    assert client.endpoints == [PRIMARY, FALLBACK]


def test_fetch_payload_records_an_exhausted_failure() -> None:
    class Client:
        max_attempts = 2

        def __init__(self):
            self.results = iter(
                [
                    payloads.HttpResult(429, None, "http_429", True),
                    payloads.HttpResult(503, None, "http_503", True),
                ]
            )

        def get_json(self, _endpoint, _path, _params):
            return next(self.results)

        def sleep(self, _seconds):
            pass

    acquired, failure = payloads.fetch_payload(
        Client(), payloads.ReadyRow(0, TX_A), PRIMARY, FALLBACK
    )

    assert acquired is None
    assert failure is not None
    assert failure["http_status"] == 503
    assert failure["endpoint"] == FALLBACK
    assert failure["attempt_count"] == 2
    assert failure["error_reason"] == "http_503"


def test_acquire_resume_and_audit_work_end_to_end(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.csv"
    dataset = tmp_path / "acquisition.csv"
    failures = tmp_path / "failures.csv"
    _write_ledger(ledger)
    responses = {
        TX_A: _response(TX_A, prefix=b"funds-a", timestamp=10),
        TX_C: _response(TX_C, prefix=b"funds-c", timestamp=12),
    }

    stats = payloads.run_acquisition(
        ledger_path=ledger,
        dataset_path=dataset,
        failure_output=failures,
        start=0,
        end=3,
        client=_client_for_rows(responses),
        primary_endpoint=PRIMARY,
        fallback_endpoint=FALLBACK,
    )

    assert stats == {"acquired": 2, "ready_total": 2, "dataset_complete": 2}
    with dataset.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
        assert list(rows[0]) == payloads.ACQUISITION_COLUMNS
    assert [row["hathor_height"] for row in rows] == ["0", "2"]
    assert all(
        row["record_sha256"] == payloads.acquisition_record_sha256(row) for row in rows
    )

    no_fetch = payloads.PacedHttpClient(
        1,
        30,
        1,
        opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("completed rows must not be fetched again")
        ),
    )
    assert payloads.run_acquisition(
        ledger_path=ledger,
        dataset_path=dataset,
        failure_output=failures,
        start=0,
        end=3,
        client=no_fetch,
        primary_endpoint=PRIMARY,
        fallback_endpoint=FALLBACK,
    ) == {"ready_total": 2, "dataset_complete": 2}

    report = payloads.audit(ledger, dataset, 0, 3)
    assert report["ready_rows"] == report["dataset_rows"] == 2
    assert set(report) == {
        "ready_rows",
        "dataset_rows",
        "ledger_sha256",
        "dataset_sha256",
        "evidence_root_sha256",
    }


def test_limit_schedules_the_least_retried_height_first(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.csv"
    dataset = tmp_path / "acquisition.csv"
    failures = tmp_path / "failures.csv"
    _write_ledger(ledger)
    _write_failures(
        failures,
        [payloads.failure_row(payloads.ReadyRow(0, TX_A), 503, PRIMARY, 1, "http_503")],
    )
    requested: list[str] = []

    def opener(request, timeout):
        assert timeout == 30
        tx_id = request.full_url.rsplit("id=", 1)[1]
        requested.append(tx_id)
        return _Response(_response(tx_id))

    client = payloads.PacedHttpClient(
        1000, 30, 1, opener=opener, sleep=lambda _seconds: None
    )

    stats = payloads.run_acquisition(
        ledger_path=ledger,
        dataset_path=dataset,
        failure_output=failures,
        start=0,
        end=3,
        client=client,
        primary_endpoint=PRIMARY,
        fallback_endpoint=FALLBACK,
        limit=1,
    )

    assert requested == [TX_C]
    assert stats["acquired"] == 1


def test_resume_rewrites_successes_into_height_order(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.csv"
    dataset = tmp_path / "acquisition.csv"
    failures = tmp_path / "failures.csv"
    _write_ledger(ledger)
    _write_dataset(dataset, [_acquisition_row(2, TX_C)])

    payloads.run_acquisition(
        ledger_path=ledger,
        dataset_path=dataset,
        failure_output=failures,
        start=0,
        end=3,
        client=_client_for_rows({TX_A: _response(TX_A)}),
        primary_endpoint=PRIMARY,
        fallback_endpoint=FALLBACK,
    )

    with dataset.open(newline="") as handle:
        assert [row["hathor_height"] for row in csv.DictReader(handle)] == ["0", "2"]


def test_record_seal_rejects_tampered_source_evidence(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.csv"
    dataset = tmp_path / "acquisition.csv"
    failures = tmp_path / "failures.csv"
    _write_ledger(ledger, [_ledger_row(0, "version_3_ready", TX_A)])
    row = _acquisition_row(0, TX_A)
    row["raw_hex"] = str(row["raw_hex"])[:-2]
    _write_dataset(dataset, [row])

    with pytest.raises(ValueError, match="acquisition record digest mismatch"):
        payloads.run_acquisition(
            ledger_path=ledger,
            dataset_path=dataset,
            failure_output=failures,
            start=0,
            end=1,
            client=_client_for_rows({}),
            primary_endpoint=PRIMARY,
            fallback_endpoint=FALLBACK,
        )


def test_audit_requires_complete_self_consistent_dataset(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.csv"
    dataset = tmp_path / "acquisition.csv"
    _write_ledger(ledger)
    _write_dataset(dataset, [_acquisition_row(0, TX_A)])

    with pytest.raises(ValueError, match="coverage incomplete"):
        payloads.audit(ledger, dataset, 0, 3)

    _write_dataset(
        dataset,
        [_acquisition_row(0, TX_A), _acquisition_row(2, TX_C)],
    )
    with dataset.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    rows[0]["funds_graph_hex"] = "00"
    rows[0]["record_sha256"] = payloads.acquisition_record_sha256(rows[0])
    with dataset.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=payloads.ACQUISITION_COLUMNS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="does not match transaction bytes"):
        payloads.audit(ledger, dataset, 0, 3)


def test_failure_history_must_match_the_ready_ledger(tmp_path: Path) -> None:
    path = tmp_path / "failures.csv"
    ready = {0: payloads.ReadyRow(0, TX_A)}
    _write_failures(
        path,
        [payloads.failure_row(payloads.ReadyRow(0, TX_B), 503, PRIMARY, 1, "http_503")],
    )

    with pytest.raises(ValueError, match="tx_id mismatch"):
        payloads.read_failure_rounds(path, ready)


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        (",".join(payloads.ACQUISITION_COLUMNS[:-1]) + "\n", "unexpected columns"),
        (",".join(payloads.ACQUISITION_COLUMNS) + "\n0", "truncated row"),
    ],
)
def test_acquisition_reader_rejects_malformed_schema(
    tmp_path: Path, contents: str, message: str
) -> None:
    path = tmp_path / "acquisition.csv"
    path.write_text(contents)

    with pytest.raises(ValueError, match=message):
        payloads.read_acquisition_rows(path)


def test_input_and_output_paths_must_be_distinct(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.csv"
    failures = tmp_path / "failures.csv"
    _write_ledger(ledger, [_ledger_row(0, "version_3_ready", TX_A)])

    with pytest.raises(ValueError, match="distinct paths"):
        payloads.run_acquisition(
            ledger_path=ledger,
            dataset_path=ledger,
            failure_output=failures,
            start=0,
            end=1,
            client=_client_for_rows({TX_A: _response(TX_A)}),
            primary_endpoint=PRIMARY,
            fallback_endpoint=FALLBACK,
        )
