from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path


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


def _write_ledger(path: Path) -> None:
    columns = [
        "hathor_height",
        "outcome",
        "http_status",
        "block_version",
        "tx_id",
        "endpoint",
        "attempt_count",
        "error_reason",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerow(
            {
                "hathor_height": 0,
                "outcome": "version_3_ready",
                "http_status": 200,
                "block_version": 3,
                "tx_id": "a" * 64,
                "endpoint": "primary",
                "attempt_count": 1,
                "error_reason": "",
            }
        )
        writer.writerow(
            {
                "hathor_height": 1,
                "outcome": "non_version_3",
                "http_status": 200,
                "block_version": 0,
                "tx_id": "b" * 64,
                "endpoint": "primary",
                "attempt_count": 1,
                "error_reason": "",
            }
        )
        writer.writerow(
            {
                "hathor_height": 2,
                "outcome": "version_3_ready",
                "http_status": 200,
                "block_version": 3,
                "tx_id": "c" * 64,
                "endpoint": "primary",
                "attempt_count": 1,
                "error_reason": "",
            }
        )


class _Response:
    def __init__(self, body: dict):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def getcode(self):
        return 200

    def read(self):
        return json.dumps(self.body).encode()


def _client_for_rows(rows: dict[str, dict]) -> payloads.PacedHttpClient:
    def opener(request, timeout):
        assert timeout == 30
        tx_id = request.full_url.split("id=", 1)[1]
        return _Response(rows[tx_id])

    return payloads.PacedHttpClient(
        1000,
        30,
        2,
        opener=opener,
        sleep=lambda _seconds: None,
    )


def test_one_transaction_fetch_populates_complete_source_then_exports(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "hathor_auxpow_raw.csv"
    supplement_output = tmp_path / "hathor_funds_graph.csv"
    failure_output = tmp_path / "failures.csv"
    _write_ledger(ledger)

    aux_a = bytes.fromhex("aa55")
    aux_c = bytes.fromhex("cc33")
    rows = {
        "a" * 64: {
            "success": True,
            "tx": {
                "hash": "a" * 64,
                "version": 3,
                "timestamp": 10,
                "aux_pow": aux_a.hex(),
                "raw": (b"funds-a" + aux_a + b"tail-a").hex(),
            },
        },
        "c" * 64: {
            "success": True,
            "tx": {
                "hash": "c" * 64,
                "version": 3,
                "timestamp": 12,
                "aux_pow": aux_c.hex(),
                "raw": (b"funds-c" + aux_c + b"tail-c").hex(),
            },
        },
    }

    stats = payloads.run_extraction(
        ledger_path=ledger,
        raw_output=raw_output,
        failure_output=failure_output,
        start=0,
        end=3,
        client=_client_for_rows(rows),
        primary_endpoint="https://primary.example/v1a",
        fallback_endpoint="https://fallback.example/v1a",
    )

    assert stats["archived"] == 2
    with raw_output.open(newline="") as handle:
        raw_rows = list(csv.DictReader(handle))
    assert [row["hathor_height"] for row in raw_rows] == ["0", "2"]
    assert [row["funds_graph_hex"] for row in raw_rows] == [
        b"funds-a".hex(),
        b"funds-c".hex(),
    ]
    payloads.build_supplement(ledger, raw_output, supplement_output, 0, 3)
    assert (
        payloads.audit(ledger, raw_output, supplement_output, 0, 3)["ready_rows"] == 2
    )


def test_payload_validation_failure_uses_fallback_endpoint() -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)

    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            response_hash = "b" * 64 if len(self.endpoints) == 1 else ready.tx_id
            return payloads.HttpResult(
                200,
                {
                    "success": True,
                    "tx": {
                        "hash": response_hash,
                        "version": 3,
                        "timestamp": 10,
                        "aux_pow": aux_pow.hex(),
                        "raw": (b"funds" + aux_pow + b"tail").hex(),
                    },
                },
                None,
                False,
            )

        def sleep(self, _seconds):
            pass

    client = Client()
    payload, failure = payloads.fetch_payload(
        client,
        ready,
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
    )

    assert failure is None
    assert payload is not None
    assert payload.tx_id == ready.tx_id
    assert client.endpoints == [
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
    ]


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

    def opener(_request, timeout):
        assert timeout == 30
        return Response()

    client = payloads.PacedHttpClient(
        1000,
        30,
        1,
        opener=opener,
        sleep=lambda _seconds: None,
    )

    result = client.get_json(
        "https://primary.example/v1a", "/transaction", {"id": "a" * 64}
    )

    assert result == payloads.HttpResult(200, None, "invalid_json", True)


def test_supplement_is_built_from_complete_source_without_another_api_request(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "hathor_auxpow_raw.csv"
    supplement_output = tmp_path / "hathor_funds_graph.csv"
    _write_ledger(ledger)
    aux = bytes.fromhex("aa55")
    raw = b"funds-a" + aux + b"tail-a"
    source_row = {
        "hathor_height": 0,
        "hathor_block_hash": "a" * 64,
        "hathor_timestamp": 10,
        "aux_pow_hex": aux.hex(),
        "funds_graph_hex": b"funds-a".hex(),
        "raw_hex": raw.hex(),
    }
    source_row["record_sha256"] = payloads.raw_record_sha256(source_row)
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=payloads.RAW_COLUMNS)
        writer.writeheader()
        writer.writerow(source_row)

    payloads.build_supplement(ledger, raw_output, supplement_output, 0, 1)
    assert (
        payloads.audit(ledger, raw_output, supplement_output, 0, 1)["supplement_rows"]
        == 1
    )


def test_record_seal_rejects_a_primary_row_changed_after_capture(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "hathor_auxpow_raw.csv"
    failure_output = tmp_path / "failures.csv"
    _write_ledger(ledger)
    aux = bytes.fromhex("aa55")
    rows = {
        "a" * 64: {
            "success": True,
            "tx": {
                "hash": "a" * 64,
                "version": 3,
                "timestamp": 10,
                "aux_pow": aux.hex(),
                "raw": (b"funds-a" + aux + b"tail-a").hex(),
            },
        },
    }
    payloads.run_extraction(
        ledger_path=ledger,
        raw_output=raw_output,
        failure_output=failure_output,
        start=0,
        end=1,
        client=_client_for_rows(rows),
        primary_endpoint="https://primary.example/v1a",
        fallback_endpoint="https://fallback.example/v1a",
    )
    with raw_output.open(newline="") as handle:
        row = next(csv.DictReader(handle))
    row["raw_hex"] = row["raw_hex"][:-2]
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=payloads.RAW_COLUMNS)
        writer.writeheader()
        writer.writerow(row)

    try:
        payloads.run_extraction(
            ledger_path=ledger,
            raw_output=raw_output,
            failure_output=failure_output,
            start=0,
            end=1,
            client=_client_for_rows(rows),
            primary_endpoint="https://primary.example/v1a",
            fallback_endpoint="https://fallback.example/v1a",
        )
    except ValueError as exc:
        assert "raw record digest mismatch" in str(exc)
    else:
        raise AssertionError("tampered primary evidence must not resume")


def test_upgrade_raw_adds_seals_without_fetching(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "hathor_auxpow_raw.csv"
    _write_ledger(ledger)
    aux = bytes.fromhex("aa55")
    legacy_row = {
        "hathor_height": 0,
        "hathor_block_hash": "a" * 64,
        "hathor_timestamp": 10,
        "aux_pow_hex": aux.hex(),
        "funds_graph_hex": b"funds-a".hex(),
        "raw_hex": (b"funds-a" + aux + b"tail-a").hex(),
    }
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=payloads.LEGACY_RAW_COLUMNS)
        writer.writeheader()
        writer.writerow(legacy_row)

    assert payloads.upgrade_raw(ledger, raw_output, 0, 1) == {"upgraded_rows": 1}
    with raw_output.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0]) == payloads.RAW_COLUMNS
    assert rows[0]["record_sha256"] == payloads.raw_record_sha256(rows[0])
