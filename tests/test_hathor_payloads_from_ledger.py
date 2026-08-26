from __future__ import annotations

import csv
import importlib.util
import json
import sys
from http.client import IncompleteRead
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
MISSING = object()


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf", "1e9999"])
def test_positive_float_rejects_non_positive_or_non_finite_values(value: str) -> None:
    with pytest.raises(payloads.argparse.ArgumentTypeError, match="finite"):
        payloads.positive_float(value)


def test_positive_float_accepts_a_finite_positive_value() -> None:
    assert payloads.positive_float("0.25") == 0.25


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
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
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


def _update_ledger_row(path: Path, height: int, **updates: object) -> None:
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    rows[height].update({key: str(value) for key, value in updates.items()})
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)


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


def _sealed_v1_row(height: int, tx_id: str, aux: bytes) -> dict[str, object]:
    funds = f"funds-{height}".encode()
    row: dict[str, object] = {
        "hathor_height": height,
        "hathor_block_hash": tx_id,
        "hathor_timestamp": 10 + height,
        "aux_pow_hex": aux.hex(),
        "funds_graph_hex": funds.hex(),
        "raw_hex": (funds + aux + b"tail").hex(),
    }
    row["record_sha256"] = payloads.raw_record_sha256(row)
    return row


def _sealed_v2_row(height: int, tx_id: str, aux: bytes) -> dict[str, object]:
    funds = f"funds-{height}".encode()
    return payloads.make_raw_row(
        payloads.Payload(
            height=height,
            tx_id=tx_id,
            timestamp=10 + height,
            aux_pow_hex=aux.hex(),
            raw_hex=(funds + aux + b"tail").hex(),
            funds_graph_hex=funds.hex(),
            endpoint="https://primary.example/v1a",
            http_status=200,
            attempt_count=1,
        )
    )


def _write_unresolved_ledger(path: Path, outcome: str) -> None:
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
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerow(
            {
                "hathor_height": 0,
                "outcome": outcome,
                "http_status": "",
                "block_version": "",
                "tx_id": "",
                "endpoint": "",
                "attempt_count": 3,
                "error_reason": "unresolved",
            }
        )


@pytest.mark.parametrize(
    "outcome",
    ["request_failure", "unavailable_block", "unknown", "unexpected_state"],
)
@pytest.mark.parametrize("mode", ["run", "upgrade", "build", "audit"])
def test_every_payload_mode_rejects_unresolved_metadata_before_writing(
    tmp_path: Path,
    outcome: str,
    mode: str,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    supplement_output = tmp_path / "supplement.csv"
    failure_output = tmp_path / "failures.csv"
    _write_unresolved_ledger(ledger, outcome)

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError("an unresolved ledger must fail before network I/O")

    with pytest.raises(ValueError, match="unresolved metadata outcome"):
        if mode == "run":
            payloads.run_extraction(
                ledger_path=ledger,
                raw_output=raw_output,
                failure_output=failure_output,
                start=0,
                end=1,
                client=Client(),
                primary_endpoint="https://primary.example/v1a",
                fallback_endpoint="https://fallback.example/v1a",
            )
        elif mode == "upgrade":
            payloads.upgrade_raw(ledger, raw_output, 0, 1)
        elif mode == "build":
            payloads.build_supplement(
                ledger,
                raw_output,
                supplement_output,
                0,
                1,
            )
        else:
            payloads.audit(ledger, raw_output, supplement_output, 0, 1)

    assert not raw_output.exists()
    assert not supplement_output.exists()
    assert not failure_output.exists()


@pytest.mark.parametrize("mode", ["run", "upgrade", "build", "audit"])
def test_every_payload_mode_rejects_a_short_resolved_metadata_row(
    tmp_path: Path,
    mode: str,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    supplement_output = tmp_path / "supplement.csv"
    failure_output = tmp_path / "failures.csv"
    ledger.write_text(",".join(payloads.LEDGER_COLUMNS) + "\n0,non_version_3\n")

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError("malformed metadata must fail before network I/O")

    with pytest.raises(ValueError, match="incomplete schema"):
        if mode == "run":
            payloads.run_extraction(
                ledger_path=ledger,
                raw_output=raw_output,
                failure_output=failure_output,
                start=0,
                end=1,
                client=Client(),
                primary_endpoint="https://primary.example/v1a",
                fallback_endpoint="https://fallback.example/v1a",
            )
        elif mode == "upgrade":
            payloads.upgrade_raw(ledger, raw_output, 0, 1)
        elif mode == "build":
            payloads.build_supplement(
                ledger,
                raw_output,
                supplement_output,
                0,
                1,
            )
        else:
            payloads.audit(ledger, raw_output, supplement_output, 0, 1)

    assert not raw_output.exists()
    assert not supplement_output.exists()
    assert not failure_output.exists()


@pytest.mark.parametrize(
    ("height", "status"),
    [(0, 199), (0, 300), (1, 404), (2, 500)],
)
def test_payload_ledger_rejects_resolved_rows_with_non_success_status(
    tmp_path: Path, height: int, status: int
) -> None:
    ledger = tmp_path / "ledger.csv"
    _write_ledger(ledger)
    _update_ledger_row(ledger, height, http_status=status)

    with pytest.raises(ValueError, match="invalid resolved metadata http_status"):
        payloads.load_ready_rows(ledger, 0, 3)


@pytest.mark.parametrize("invalid_tx_id", ["a" * 63, "A" * 64, "g" * 64])
def test_payload_ledger_rejects_malformed_version_three_tx_ids(
    tmp_path: Path, invalid_tx_id: str
) -> None:
    ledger = tmp_path / "ledger.csv"
    _write_ledger(ledger)
    _update_ledger_row(ledger, 0, tx_id=invalid_tx_id)

    with pytest.raises(ValueError, match="invalid version_3_ready fields"):
        payloads.load_ready_rows(ledger, 0, 3)


@pytest.mark.parametrize("mode", ["run", "upgrade", "build", "audit"])
def test_every_payload_mode_rejects_one_ready_transaction_at_multiple_heights(
    tmp_path: Path, mode: str
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    supplement_output = tmp_path / "supplement.csv"
    failure_output = tmp_path / "failures.csv"
    _write_ledger(ledger)
    _update_ledger_row(ledger, 2, tx_id="a" * 64)

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError("duplicate metadata must fail before network I/O")

    with pytest.raises(ValueError, match="assigned to multiple.*0, 2"):
        if mode == "run":
            payloads.run_extraction(
                ledger_path=ledger,
                raw_output=raw_output,
                failure_output=failure_output,
                start=0,
                end=3,
                client=Client(),
                primary_endpoint="https://primary.example/v1a",
                fallback_endpoint="https://fallback.example/v1a",
            )
        elif mode == "upgrade":
            payloads.upgrade_raw(ledger, raw_output, 0, 3)
        elif mode == "build":
            payloads.build_supplement(
                ledger,
                raw_output,
                supplement_output,
                0,
                3,
            )
        else:
            payloads.audit(ledger, raw_output, supplement_output, 0, 3)

    assert not raw_output.exists()
    assert not supplement_output.exists()
    assert not failure_output.exists()


@pytest.mark.parametrize("mode", ["run", "upgrade", "build", "audit"])
def test_every_payload_mode_rejects_a_ledger_output_collision_before_io(
    tmp_path: Path, mode: str
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    failure_output = tmp_path / "failures.csv"
    original = b"sentinel ledger bytes\n"
    ledger.write_bytes(original)

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError("path collisions must fail before network I/O")

    with pytest.raises(ValueError, match="must be distinct paths"):
        if mode == "run":
            payloads.run_extraction(
                ledger_path=ledger,
                raw_output=ledger,
                failure_output=failure_output,
                start=0,
                end=1,
                client=Client(),
                primary_endpoint="https://primary.example/v1a",
                fallback_endpoint="https://fallback.example/v1a",
            )
        elif mode == "upgrade":
            payloads.upgrade_raw(ledger, ledger, 0, 1)
        elif mode == "build":
            payloads.build_supplement(ledger, raw_output, ledger, 0, 1)
        else:
            payloads.audit(ledger, raw_output, ledger, 0, 1)

    assert ledger.read_bytes() == original
    assert not list(tmp_path.glob("*.lock"))
    assert not list(tmp_path.glob(".*.tmp-*"))


@pytest.mark.parametrize("mode", ["run", "build", "audit"])
def test_payload_modes_reject_colliding_nonledger_artifacts_before_io(
    tmp_path: Path, mode: str
) -> None:
    ledger = tmp_path / "ledger.csv"
    shared_output = tmp_path / "shared.csv"
    ledger.write_text("invalid sentinel ledger\n")

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError("path collisions must fail before network I/O")

    with pytest.raises(ValueError, match="must be distinct paths"):
        if mode == "run":
            payloads.run_extraction(
                ledger_path=ledger,
                raw_output=shared_output,
                failure_output=shared_output,
                start=0,
                end=1,
                client=Client(),
                primary_endpoint="https://primary.example/v1a",
                fallback_endpoint="https://fallback.example/v1a",
            )
        elif mode == "build":
            payloads.build_supplement(
                ledger,
                shared_output,
                shared_output,
                0,
                1,
            )
        else:
            payloads.audit(ledger, shared_output, shared_output, 0, 1)

    assert not shared_output.exists()
    assert not list(tmp_path.glob("*.lock"))
    assert not list(tmp_path.glob(".*.tmp-*"))


def test_path_preflight_rejects_equivalent_and_filesystem_aliases(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.csv"
    source.write_text("source\n")
    symlink = tmp_path / "symlink.csv"
    symlink.symlink_to(source)
    hardlink = tmp_path / "hardlink.csv"
    hardlink.hardlink_to(source)
    relative_alias = tmp_path / "unused" / ".." / source.name

    for alias in (source, relative_alias, symlink, hardlink):
        with pytest.raises(ValueError, match="must be distinct paths"):
            payloads.require_distinct_paths(source=source, output=alias)


def test_new_csv_header_is_file_synced_before_its_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "failures.csv"
    sync_events: list[str | tuple[str, Path]] = []
    monkeypatch.setattr(payloads.os, "fsync", lambda _fd: sync_events.append("file"))
    monkeypatch.setattr(
        payloads,
        "fsync_directory",
        lambda directory: sync_events.append(("directory", directory)),
    )

    handle, _writer = payloads.open_csv_writer(path, payloads.FAILURE_COLUMNS)
    handle.close()

    assert sync_events == ["file", ("directory", tmp_path)]
    assert path.read_text() == ",".join(payloads.FAILURE_COLUMNS) + "\n"

    sync_events.clear()
    handle, _writer = payloads.open_csv_writer(path, payloads.FAILURE_COLUMNS)
    handle.close()
    assert sync_events == []


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
    assert [row["endpoint"] for row in raw_rows] == [
        "https://primary.example/v1a",
        "https://primary.example/v1a",
    ]
    assert [row["http_status"] for row in raw_rows] == ["200", "200"]
    assert [row["attempt_count"] for row in raw_rows] == ["1", "1"]
    payloads.build_supplement(ledger, raw_output, supplement_output, 0, 3)
    assert (
        payloads.audit(ledger, raw_output, supplement_output, 0, 3)["ready_rows"] == 2
    )
    for evidence_path in (raw_output, supplement_output, failure_output):
        assert b"\r\n" not in evidence_path.read_bytes()


@pytest.mark.parametrize("field", ["raw", "aux_pow"])
@pytest.mark.parametrize("whitespace", [" ", "\t", "\r", "\n", "\u2003"])
def test_parse_payload_rejects_whitespace_bearing_hex(
    field: str, whitespace: str
) -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)
    tx = {
        "hash": ready.tx_id,
        "version": 3,
        "timestamp": 10,
        "aux_pow": aux_pow.hex(),
        "raw": (b"funds" + aux_pow + b"tail").hex(),
    }
    compact = tx[field]
    tx[field] = compact[:2] + whitespace + compact[2:]

    with pytest.raises(ValueError, match="invalid_hex"):
        payloads.parse_payload(
            ready,
            {"success": True, "tx": tx},
            "https://primary.example/v1a",
            200,
            1,
        )


def test_parse_payload_accepts_compact_uppercase_hex() -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)

    parsed = payloads.parse_payload(
        ready,
        {
            "success": True,
            "tx": {
                "hash": ready.tx_id,
                "version": 3,
                "timestamp": 10,
                "aux_pow": aux_pow.hex().upper(),
                "raw": (b"funds" + aux_pow + b"tail").hex().upper(),
            },
        },
        "https://primary.example/v1a",
        200,
        1,
    )

    assert parsed.aux_pow_hex == "AA55"
    assert parsed.raw_hex == (b"funds" + aux_pow + b"tail").hex().upper()


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("hash", MISSING, "tx_hash_mismatch"),
        ("hash", None, "tx_hash_mismatch"),
        ("hash", "", "tx_hash_mismatch"),
        ("hash", "b" * 64, "tx_hash_mismatch"),
        ("hash", "A" * 64, "tx_hash_mismatch"),
        ("hash", 7, "tx_hash_mismatch"),
        ("version", MISSING, "tx_version_mismatch"),
        ("version", None, "tx_version_mismatch"),
        ("version", "3", "tx_version_mismatch"),
        ("version", 3.0, "tx_version_mismatch"),
        ("version", True, "tx_version_mismatch"),
        ("version", 2, "tx_version_mismatch"),
    ],
)
def test_parse_payload_requires_exact_echoed_transaction_identity(
    field: str,
    value: object,
    error: str,
) -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)
    tx: dict[str, object] = {
        "hash": ready.tx_id,
        "version": 3,
        "timestamp": 10,
        "aux_pow": aux_pow.hex(),
        "raw": (b"funds" + aux_pow + b"tail").hex(),
    }
    if value is MISSING:
        tx.pop(field)
    else:
        tx[field] = value

    with pytest.raises(ValueError, match=error):
        payloads.parse_payload(
            ready,
            {"success": True, "tx": tx},
            "https://primary.example/v1a",
            200,
            1,
        )


@pytest.mark.parametrize(
    "timestamp",
    [MISSING, None, "", "10", "10\n", "10\r", 10.0, True, -1],
)
def test_parse_payload_requires_an_exact_nonnegative_integer_timestamp(
    timestamp: object,
) -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)
    tx: dict[str, object] = {
        "hash": ready.tx_id,
        "version": 3,
        "timestamp": timestamp,
        "aux_pow": aux_pow.hex(),
        "raw": (b"funds" + aux_pow + b"tail").hex(),
    }
    if timestamp is MISSING:
        tx.pop("timestamp")

    with pytest.raises(ValueError, match="invalid_timestamp"):
        payloads.parse_payload(
            ready,
            {"success": True, "tx": tx},
            "https://primary.example/v1a",
            200,
            1,
        )


def test_parse_payload_accepts_zero_timestamp() -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)

    parsed = payloads.parse_payload(
        ready,
        {
            "success": True,
            "tx": {
                "hash": ready.tx_id,
                "version": 3,
                "timestamp": 0,
                "aux_pow": aux_pow.hex(),
                "raw": (b"funds" + aux_pow + b"tail").hex(),
            },
        },
        "https://primary.example/v1a",
        200,
        1,
    )

    assert parsed.timestamp == 0


def test_make_raw_row_rejects_noncanonical_timestamp() -> None:
    aux_pow = bytes.fromhex("aa55")
    payload = payloads.Payload(
        height=7,
        tx_id="a" * 64,
        timestamp="10\n",
        aux_pow_hex=aux_pow.hex(),
        raw_hex=(b"funds" + aux_pow + b"tail").hex(),
        funds_graph_hex=b"funds".hex(),
        endpoint="https://primary.example/v1a",
        http_status=200,
        attempt_count=1,
    )

    with pytest.raises(ValueError, match="timestamp"):
        payloads.make_raw_row(payload)


def test_whitespace_bearing_payload_retries_without_archiving_multiline_csv(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    failure_output = tmp_path / "failures.csv"
    _write_ledger(ledger)
    aux_pow = bytes.fromhex("aa55")
    valid_raw = (b"funds" + aux_pow + b"tail").hex()

    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            raw_hex = valid_raw[:2] + "\n" + valid_raw[2:]
            if endpoint.endswith("fallback.example/v1a"):
                raw_hex = valid_raw
            return payloads.HttpResult(
                200,
                {
                    "success": True,
                    "tx": {
                        "hash": "a" * 64,
                        "version": 3,
                        "timestamp": 10,
                        "aux_pow": aux_pow.hex(),
                        "raw": raw_hex,
                    },
                },
                None,
                False,
            )

        def sleep(self, _seconds):
            pass

    client = Client()
    stats = payloads.run_extraction(
        ledger_path=ledger,
        raw_output=raw_output,
        failure_output=failure_output,
        start=0,
        end=1,
        client=client,
        primary_endpoint="https://primary.example/v1a",
        fallback_endpoint="https://fallback.example/v1a",
    )

    assert stats["archived"] == 1
    assert client.endpoints == [
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
    ]
    raw_bytes = raw_output.read_bytes()
    assert raw_bytes.count(b"\n") == 2
    assert b"\r" not in raw_bytes
    with raw_output.open(newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["raw_hex"] == valid_raw


def test_raw_to_supplement_rejects_whitespace_bearing_hex() -> None:
    row = _sealed_v2_row(0, "a" * 64, bytes.fromhex("aa55"))
    row["raw_hex"] = str(row["raw_hex"])[:2] + " " + str(row["raw_hex"])[2:]

    with pytest.raises(ValueError, match="invalid raw evidence"):
        payloads.raw_to_supplement(row)


@pytest.mark.parametrize("columns", [payloads.RAW_V1_COLUMNS, payloads.RAW_COLUMNS])
def test_completed_sealed_rows_preserve_legacy_timestamp_bytes(
    columns: list[str],
) -> None:
    aux_pow = bytes.fromhex("aa55")
    if columns == payloads.RAW_V1_COLUMNS:
        row = _sealed_v1_row(0, "a" * 64, aux_pow)
    else:
        row = _sealed_v2_row(0, "a" * 64, aux_pow)
    row["hathor_timestamp"] = ""
    row["record_sha256"] = payloads.raw_record_sha256(row, columns)

    payloads.check_raw_rows(
        {0: payloads.ReadyRow(0, "a" * 64)},
        {0: row},
        columns,
    )


@pytest.mark.parametrize("require_request_provenance", [False, True])
def test_unsealed_rows_require_a_canonical_timestamp(
    require_request_provenance: bool,
) -> None:
    aux_pow = bytes.fromhex("aa55")
    if require_request_provenance:
        row = _sealed_v2_row(0, "a" * 64, aux_pow)
    else:
        row = _sealed_v1_row(0, "a" * 64, aux_pow)
    row["hathor_timestamp"] = " 10"

    with pytest.raises(ValueError, match="timestamp"):
        payloads.check_unsealed_raw_rows(
            {0: payloads.ReadyRow(0, "a" * 64)},
            {0: row},
            require_request_provenance=require_request_provenance,
        )


@pytest.mark.parametrize(
    ("invalid_field", "invalid_value"),
    [
        ("hash", "b" * 64),
        ("version", None),
        ("timestamp", "10\n"),
    ],
)
def test_payload_validation_failure_uses_fallback_endpoint(
    invalid_field: str,
    invalid_value: object,
) -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)

    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            tx: dict[str, object] = {
                "hash": ready.tx_id,
                "version": 3,
                "timestamp": 10,
                "aux_pow": aux_pow.hex(),
                "raw": (b"funds" + aux_pow + b"tail").hex(),
            }
            if len(self.endpoints) == 1:
                tx[invalid_field] = invalid_value
            return payloads.HttpResult(
                200,
                {
                    "success": True,
                    "tx": tx,
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
    assert payload.endpoint == "https://fallback.example/v1a"
    assert payload.http_status == 200
    assert payload.attempt_count == 2
    raw = payloads.make_raw_row(payload)
    assert raw["endpoint"] == "https://fallback.example/v1a"
    assert raw["http_status"] == 200
    assert raw["attempt_count"] == 2
    original_seal = raw["record_sha256"]
    for field, replacement in (
        ("endpoint", "https://primary.example/v1a"),
        ("http_status", 201),
        ("attempt_count", 1),
    ):
        changed = dict(raw)
        changed[field] = replacement
        assert payloads.raw_record_sha256(changed) != original_seal
    assert client.endpoints == [
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
    ]


@pytest.mark.parametrize("primary_status", [None, 500])
def test_payload_success_with_invalid_status_uses_fallback_without_inventing_200(
    primary_status: int | None,
) -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)

    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            return payloads.HttpResult(
                primary_status if len(self.endpoints) == 1 else 200,
                {
                    "success": True,
                    "tx": {
                        "hash": ready.tx_id,
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
    assert payload.endpoint == "https://fallback.example/v1a"
    assert payload.http_status == 200
    assert payload.attempt_count == 2


def test_payload_endpoint_specific_miss_uses_fallback() -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)

    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            if len(self.endpoints) == 1:
                return payloads.HttpResult(404, None, "http_404", False)
            return payloads.HttpResult(
                200,
                {
                    "success": True,
                    "tx": {
                        "hash": ready.tx_id,
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
    assert payload.endpoint == "https://fallback.example/v1a"
    assert payload.attempt_count == 2


@pytest.mark.parametrize("fallback_endpoint", ["", " ", "/", "///"])
def test_blank_fallback_is_disabled_and_retries_the_primary(
    fallback_endpoint: str,
) -> None:
    ready = payloads.ReadyRow(7, "a" * 64)

    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            assert endpoint
            self.endpoints.append(endpoint)
            return payloads.HttpResult(503, None, "http_503", True)

        def sleep(self, _seconds):
            pass

    client = Client()
    payload, failure = payloads.fetch_payload(
        client,
        ready,
        "https://primary.example/v1a",
        fallback_endpoint,
    )

    assert payload is None
    assert failure is not None
    assert failure["endpoint"] == "https://primary.example/v1a"
    assert failure["attempt_count"] == 2
    assert failure["error_reason"] == "http_503"
    assert client.endpoints == [
        "https://primary.example/v1a",
        "https://primary.example/v1a",
    ]


def test_primary_endpoint_is_canonicalized_before_a_request() -> None:
    ready = payloads.ReadyRow(7, "a" * 64)

    class Client:
        max_attempts = 1

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            return payloads.HttpResult(503, None, "http_503", True)

        def sleep(self, _seconds):
            pass

    client = Client()
    payload, failure = payloads.fetch_payload(
        client,
        ready,
        "  https://primary.example/v1a///  ",
        "",
    )

    assert payload is None
    assert failure is not None
    assert failure["endpoint"] == "https://primary.example/v1a"
    assert client.endpoints == ["https://primary.example/v1a"]


@pytest.mark.parametrize("primary_endpoint", ["", " ", "/", "///"])
def test_blank_primary_endpoint_fails_before_a_request(primary_endpoint: str) -> None:
    ready = payloads.ReadyRow(7, "a" * 64)

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError("blank primary endpoint must fail before I/O")

    with pytest.raises(ValueError, match="primary endpoint must be non-empty"):
        payloads.fetch_payload(Client(), ready, primary_endpoint, "")


@pytest.mark.parametrize(
    ("primary_endpoint", "fallback_endpoint", "error"),
    [
        ("https://primary.example/v1a /", "", "primary endpoint"),
        (
            "https://primary.example/v1a",
            "https://fallback.example/v1a /",
            "fallback endpoint",
        ),
    ],
)
def test_endpoint_whitespace_before_trailing_slashes_fails_before_a_request(
    primary_endpoint: str,
    fallback_endpoint: str,
    error: str,
) -> None:
    ready = payloads.ReadyRow(7, "a" * 64)

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError("non-canonical endpoints must fail before I/O")

    with pytest.raises(ValueError, match=error):
        payloads.fetch_payload(Client(), ready, primary_endpoint, fallback_endpoint)


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

    assert result == payloads.HttpResult(200, None, "IncompleteRead", True)


def test_fetch_payload_retries_truncated_responses_and_retains_status() -> None:
    ready = payloads.ReadyRow(7, "a" * 64)

    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            return payloads.HttpResult(200, None, "IncompleteRead", True)

        def sleep(self, _seconds):
            pass

    client = Client()
    payload, failure = payloads.fetch_payload(
        client,
        ready,
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
    )

    assert client.endpoints == [
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
    ]
    assert payload is None
    assert failure is not None
    assert failure["http_status"] == 200
    assert failure["attempt_count"] == 2
    assert failure["error_reason"] == "IncompleteRead"


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
        "endpoint": "https://primary.example/v1a",
        "http_status": 200,
        "attempt_count": 1,
    }
    source_row["record_sha256"] = payloads.raw_record_sha256(source_row)
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=payloads.RAW_COLUMNS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(source_row)

    payloads.build_supplement(ledger, raw_output, supplement_output, 0, 1)
    assert (
        payloads.audit(ledger, raw_output, supplement_output, 0, 1)["supplement_rows"]
        == 1
    )


def test_audit_rejects_raw_rows_in_retry_completion_order(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    supplement_output = tmp_path / "supplement.csv"
    _write_ledger(ledger)
    raw_rows = [
        _sealed_v2_row(2, "c" * 64, bytes.fromhex("cc33")),
        _sealed_v2_row(0, "a" * 64, bytes.fromhex("aa55")),
    ]
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.RAW_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(raw_rows)
    with supplement_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.SUPPLEMENT_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        for row in reversed(raw_rows):
            writer.writerow(payloads.raw_to_supplement(row))

    with pytest.raises(ValueError, match="ascending height order"):
        payloads.audit(ledger, raw_output, supplement_output, 0, 3)


def test_append_writer_rejects_a_truncated_existing_row(tmp_path: Path) -> None:
    path = tmp_path / "rows.csv"
    path.write_bytes(b"value\nsealed-without-newline")

    try:
        payloads.open_csv_writer(path, ["value"])
    except ValueError as exc:
        assert "truncated row" in str(exc)
    else:
        raise AssertionError("append must reject a missing final newline")


def test_append_writer_rejects_existing_failure_header_drift(tmp_path: Path) -> None:
    path = tmp_path / "failures.csv"
    original = b"wrong,header\nvalue,row\n"
    path.write_bytes(original)

    with pytest.raises(ValueError, match="unexpected columns"):
        payloads.open_csv_writer(path, payloads.FAILURE_COLUMNS)

    assert path.read_bytes() == original


def test_raw_reader_rejects_noncanonical_heights(tmp_path: Path) -> None:
    path = tmp_path / "raw.csv"
    row = _sealed_v2_row(0, "a" * 64, bytes.fromhex("aa55"))
    row["hathor_height"] = "00"
    row["record_sha256"] = payloads.raw_record_sha256(row, payloads.RAW_COLUMNS)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.RAW_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(row)

    with pytest.raises(ValueError, match="non-canonical height"):
        payloads.read_raw_rows(path)


def test_raw_reader_rejects_extra_csv_cells(tmp_path: Path) -> None:
    path = tmp_path / "raw.csv"
    row = _sealed_v2_row(0, "a" * 64, bytes.fromhex("aa55"))
    header = ",".join(payloads.RAW_COLUMNS)
    values = ",".join(str(row[column]) for column in payloads.RAW_COLUMNS)
    path.write_text(f"{header}\n{values},extra\n")

    with pytest.raises(ValueError, match="incomplete or extra CSV cells"):
        payloads.read_raw_rows(path)


def test_run_rejects_failure_header_before_raw_rewrite_or_network(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    failure_output = tmp_path / "failures.csv"
    _write_ledger(ledger)
    rows = [
        _sealed_v2_row(2, "c" * 64, bytes.fromhex("cc33")),
        _sealed_v2_row(0, "a" * 64, bytes.fromhex("aa55")),
    ]
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.RAW_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)
    original_raw = raw_output.read_bytes()
    failure_output.write_text("wrong,header\nvalue,row\n")

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError("header drift must fail before network I/O")

    with pytest.raises(ValueError, match="unexpected columns"):
        payloads.run_extraction(
            ledger_path=ledger,
            raw_output=raw_output,
            failure_output=failure_output,
            start=0,
            end=3,
            client=Client(),
            primary_endpoint="https://primary.example/v1a",
            fallback_endpoint="https://fallback.example/v1a",
        )

    assert raw_output.read_bytes() == original_raw


def test_resume_atomically_rewrites_primary_rows_in_height_order(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "hathor_auxpow_raw.csv"
    failure_output = tmp_path / "failures.csv"
    _write_ledger(ledger)
    aux_a = bytes.fromhex("aa55")
    aux_c = bytes.fromhex("cc33")
    existing = {
        "hathor_height": 2,
        "hathor_block_hash": "c" * 64,
        "hathor_timestamp": 12,
        "aux_pow_hex": aux_c.hex(),
        "funds_graph_hex": b"funds-c".hex(),
        "raw_hex": (b"funds-c" + aux_c + b"tail-c").hex(),
        "endpoint": "https://fallback.example/v1a",
        "http_status": 200,
        "attempt_count": 2,
    }
    existing["record_sha256"] = payloads.raw_record_sha256(existing)
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=payloads.RAW_COLUMNS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(existing)

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
        }
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

    assert stats["archived"] == 1
    with raw_output.open(newline="") as handle:
        raw_rows = list(csv.DictReader(handle))
    assert [row["hathor_height"] for row in raw_rows] == ["0", "2"]
    assert raw_rows[1]["record_sha256"] == existing["record_sha256"]
    assert raw_rows[1]["endpoint"] == existing["endpoint"]
    assert b"\r\n" not in raw_output.read_bytes()


def test_multiple_recovered_gaps_trigger_one_canonical_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    failure_output = tmp_path / "failures.csv"
    with ledger.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        for height, outcome, version, tx_id in (
            (0, "version_3_ready", 3, "a" * 64),
            (1, "version_3_ready", 3, "b" * 64),
            (2, "non_version_3", 0, "c" * 64),
            (3, "version_3_ready", 3, "d" * 64),
        ):
            writer.writerow(
                {
                    "hathor_height": height,
                    "outcome": outcome,
                    "http_status": 200,
                    "block_version": version,
                    "tx_id": tx_id,
                    "endpoint": "primary",
                    "attempt_count": 1,
                    "error_reason": "",
                }
            )
    existing = _sealed_v2_row(3, "d" * 64, bytes.fromhex("dd44"))
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.RAW_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(existing)

    aux_a = bytes.fromhex("aa55")
    aux_b = bytes.fromhex("bb66")
    responses = {
        "a" * 64: {
            "success": True,
            "tx": {
                "hash": "a" * 64,
                "version": 3,
                "timestamp": 10,
                "aux_pow": aux_a.hex(),
                "raw": (b"funds-a" + aux_a + b"tail").hex(),
            },
        },
        "b" * 64: {
            "success": True,
            "tx": {
                "hash": "b" * 64,
                "version": 3,
                "timestamp": 11,
                "aux_pow": aux_b.hex(),
                "raw": (b"funds-b" + aux_b + b"tail").hex(),
            },
        },
    }
    replace = payloads.replace_raw_rows_atomically
    rewrite_calls = 0

    def count_replace(*args):
        nonlocal rewrite_calls
        rewrite_calls += 1
        replace(*args)

    monkeypatch.setattr(payloads, "replace_raw_rows_atomically", count_replace)
    stats = payloads.run_extraction(
        ledger_path=ledger,
        raw_output=raw_output,
        failure_output=failure_output,
        start=0,
        end=4,
        client=_client_for_rows(responses),
        primary_endpoint="https://primary.example/v1a",
        fallback_endpoint="https://fallback.example/v1a",
    )

    assert stats["archived"] == 2
    assert rewrite_calls == 1
    with raw_output.open(newline="") as handle:
        assert [row["hathor_height"] for row in csv.DictReader(handle)] == [
            "0",
            "1",
            "3",
        ]


def test_failed_canonical_rewrite_keeps_recovered_row_for_next_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    failure_output = tmp_path / "failures.csv"
    _write_ledger(ledger)
    existing = _sealed_v2_row(2, "c" * 64, bytes.fromhex("cc33"))
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.RAW_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(existing)

    aux = bytes.fromhex("aa55")
    responses = {
        "a" * 64: {
            "success": True,
            "tx": {
                "hash": "a" * 64,
                "version": 3,
                "timestamp": 10,
                "aux_pow": aux.hex(),
                "raw": (b"funds-0" + aux + b"tail").hex(),
            },
        }
    }
    replace = payloads.replace_raw_rows_atomically

    def fail_replace(*_args):
        raise OSError("simulated canonical rewrite failure")

    monkeypatch.setattr(payloads, "replace_raw_rows_atomically", fail_replace)
    with pytest.raises(OSError, match="simulated canonical rewrite failure"):
        payloads.run_extraction(
            ledger_path=ledger,
            raw_output=raw_output,
            failure_output=failure_output,
            start=0,
            end=3,
            client=_client_for_rows(responses),
            primary_endpoint="https://primary.example/v1a",
            fallback_endpoint="https://fallback.example/v1a",
        )
    with raw_output.open(newline="") as handle:
        assert [row["hathor_height"] for row in csv.DictReader(handle)] == ["2", "0"]

    class NoNetworkClient:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError("the durably appended row must not be refetched")

    monkeypatch.setattr(payloads, "replace_raw_rows_atomically", replace)
    assert payloads.run_extraction(
        ledger_path=ledger,
        raw_output=raw_output,
        failure_output=failure_output,
        start=0,
        end=3,
        client=NoNetworkClient(),
        primary_endpoint="https://primary.example/v1a",
        fallback_endpoint="https://fallback.example/v1a",
    ) == {"ready_total": 2, "raw_complete": 2}
    with raw_output.open(newline="") as handle:
        assert [row["hathor_height"] for row in csv.DictReader(handle)] == ["0", "2"]


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
        writer = csv.DictWriter(
            handle,
            fieldnames=payloads.RAW_COLUMNS,
            lineterminator="\n",
        )
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
    unsealed_row = {
        "hathor_height": 0,
        "hathor_block_hash": "a" * 64,
        "hathor_timestamp": 10,
        "aux_pow_hex": aux.hex(),
        "funds_graph_hex": b"funds-a".hex(),
        "raw_hex": (b"funds-a" + aux + b"tail-a").hex(),
        "endpoint": "https://primary.example/v1a",
        "http_status": 200,
        "attempt_count": 1,
    }
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=payloads.UNSEALED_RAW_COLUMNS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(unsealed_row)

    assert payloads.upgrade_raw(ledger, raw_output, 0, 1) == {"upgraded_rows": 1}
    with raw_output.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0]) == payloads.RAW_COLUMNS
    assert rows[0]["record_sha256"] == payloads.raw_record_sha256(rows[0])
    assert b"\r\n" not in raw_output.read_bytes()


def test_upgrade_raw_preserves_v1_rows_without_inventing_request_provenance(
    tmp_path: Path,
) -> None:
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
        writer = csv.DictWriter(
            handle,
            fieldnames=payloads.LEGACY_RAW_COLUMNS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(legacy_row)
    assert payloads.upgrade_raw(ledger, raw_output, 0, 1) == {"upgraded_rows": 1}
    with raw_output.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0]) == payloads.RAW_V1_COLUMNS
    assert rows[0]["record_sha256"] == payloads.raw_record_sha256(rows[0])
    assert "endpoint" not in rows[0]
    assert b"\r\n" not in raw_output.read_bytes()


def test_complete_sealed_v1_evidence_remains_immutable_and_auditable(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "hathor_auxpow_raw.csv"
    supplement_output = tmp_path / "hathor_funds_graph.csv"
    failure_output = tmp_path / "failures.csv"
    _write_ledger(ledger)
    row = _sealed_v1_row(0, "a" * 64, bytes.fromhex("aa55"))
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=payloads.RAW_V1_COLUMNS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(row)
    original = raw_output.read_bytes()

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError("complete sealed-v1 evidence must not be refetched")

    assert payloads.run_extraction(
        ledger_path=ledger,
        raw_output=raw_output,
        failure_output=failure_output,
        start=0,
        end=1,
        client=Client(),
        primary_endpoint="https://primary.example/v1a",
        fallback_endpoint="https://fallback.example/v1a",
    ) == {"ready_total": 1, "raw_complete": 1}
    assert raw_output.read_bytes() == original
    assert not failure_output.exists()

    payloads.build_supplement(ledger, raw_output, supplement_output, 0, 1)
    assert payloads.audit(ledger, raw_output, supplement_output, 0, 1)["raw_rows"] == 1
    assert raw_output.read_bytes() == original


def test_incomplete_sealed_v1_evidence_requires_a_new_output(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger.csv"
    raw_output = tmp_path / "hathor_auxpow_raw.csv"
    failure_output = tmp_path / "failures.csv"
    _write_ledger(ledger)
    row = _sealed_v1_row(2, "c" * 64, bytes.fromhex("cc33"))
    with raw_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=payloads.RAW_V1_COLUMNS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(row)
    original = raw_output.read_bytes()

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError("sealed-v1 evidence must not mix with v2 rows")

    with pytest.raises(ValueError, match="sealed v1 payload evidence is incomplete"):
        payloads.run_extraction(
            ledger_path=ledger,
            raw_output=raw_output,
            failure_output=failure_output,
            start=0,
            end=3,
            client=Client(),
            primary_endpoint="https://primary.example/v1a",
            fallback_endpoint="https://fallback.example/v1a",
        )

    assert raw_output.read_bytes() == original
    assert not failure_output.exists()


@pytest.mark.parametrize("prefix_length", [0, 1, 2])
def test_parse_payload_rejects_a_structurally_incomplete_funds_graph_prefix(
    prefix_length: int,
) -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)

    with pytest.raises(ValueError, match="funds_graph_prefix_too_short"):
        payloads.parse_payload(
            ready,
            {
                "success": True,
                "tx": {
                    "hash": ready.tx_id,
                    "version": 3,
                    "timestamp": 10,
                    "aux_pow": aux_pow.hex(),
                    "raw": (b"f" * prefix_length + aux_pow + b"tail").hex(),
                },
            },
            "https://primary.example/v1a",
            200,
            1,
        )


def test_parse_payload_accepts_a_three_byte_funds_graph_prefix() -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)

    parsed = payloads.parse_payload(
        ready,
        {
            "success": True,
            "tx": {
                "hash": ready.tx_id,
                "version": 3,
                "timestamp": 10,
                "aux_pow": aux_pow.hex(),
                "raw": (b"fun" + aux_pow + b"tail").hex(),
            },
        },
        "https://primary.example/v1a",
        200,
        1,
    )

    assert parsed.funds_graph_hex == b"fun".hex()


def test_short_funds_graph_prefix_on_primary_retries_a_valid_fallback() -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)

    class Client:
        max_attempts = 2

        def __init__(self):
            self.endpoints: list[str] = []

        def get_json(self, endpoint, _path, _params):
            self.endpoints.append(endpoint)
            prefix = b"fu" if len(self.endpoints) == 1 else b"funds"
            return payloads.HttpResult(
                200,
                {
                    "success": True,
                    "tx": {
                        "hash": ready.tx_id,
                        "version": 3,
                        "timestamp": 10,
                        "aux_pow": aux_pow.hex(),
                        "raw": (prefix + aux_pow + b"tail").hex(),
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
    assert payload.endpoint == "https://fallback.example/v1a"
    assert payload.http_status == 200
    assert payload.attempt_count == 2
    assert payload.funds_graph_hex == b"funds".hex()
    assert client.endpoints == [
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
    ]


def test_short_funds_graph_prefix_returns_a_stable_failure_row() -> None:
    aux_pow = bytes.fromhex("aa55")
    ready = payloads.ReadyRow(7, "a" * 64)

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            return payloads.HttpResult(
                200,
                {
                    "success": True,
                    "tx": {
                        "hash": ready.tx_id,
                        "version": 3,
                        "timestamp": 10,
                        "aux_pow": aux_pow.hex(),
                        "raw": (b"fu" + aux_pow + b"tail").hex(),
                    },
                },
                None,
                False,
            )

        def sleep(self, _seconds):
            pass

    payload, failure = payloads.fetch_payload(
        Client(),
        ready,
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
    )

    assert payload is None
    assert failure is not None
    assert failure["error_reason"] == "funds_graph_prefix_too_short"


def _write_all_ready_ledger(path: Path, heights: list[int]) -> dict[str, int]:
    tx_heights: dict[str, int] = {}
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        for height in heights:
            tx_id = f"{height + 1:064x}"
            tx_heights[tx_id] = height
            writer.writerow(
                {
                    "hathor_height": height,
                    "outcome": "version_3_ready",
                    "http_status": 200,
                    "block_version": 3,
                    "tx_id": tx_id,
                    "endpoint": "primary",
                    "attempt_count": 1,
                    "error_reason": "",
                }
            )
    return tx_heights


def _failure_row(height: int, tx_id: str) -> dict[str, object]:
    return {
        "hathor_height": height,
        "hathor_block_hash": tx_id,
        "http_status": 503,
        "endpoint": "https://primary.example/v1a",
        "attempt_count": 1,
        "error_reason": "http_503",
        "recorded_at_utc": "2024-01-01T00:00:00+00:00",
    }


class _FairnessClient:
    max_attempts = 1

    def __init__(self, tx_heights: dict[str, int], permanent_failures: set[int]):
        self.tx_heights = tx_heights
        self.permanent_failures = permanent_failures
        self.fetched: list[int] = []

    def get_json(self, _endpoint, _path, params):
        tx_id = params["id"]
        height = self.tx_heights[tx_id]
        self.fetched.append(height)
        if height in self.permanent_failures:
            return payloads.HttpResult(503, None, "http_503", True)
        aux = bytes.fromhex("aa55")
        return payloads.HttpResult(
            200,
            {
                "success": True,
                "tx": {
                    "hash": tx_id,
                    "version": 3,
                    "timestamp": 10,
                    "aux_pow": aux.hex(),
                    "raw": (b"funds" + aux + b"tail").hex(),
                },
            },
            None,
            False,
        )

    def sleep(self, _seconds):
        pass


def test_bounded_runs_share_failure_rounds_fairly_across_pending_heights(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    failure_output = tmp_path / "failures.csv"
    tx_heights = _write_all_ready_ledger(ledger_path, [0, 1, 2])
    client = _FairnessClient(tx_heights, permanent_failures={0})

    for _ in range(4):
        payloads.run_extraction(
            ledger_path=ledger_path,
            raw_output=raw_output,
            failure_output=failure_output,
            start=0,
            end=3,
            client=client,
            primary_endpoint="https://primary.example/v1a",
            fallback_endpoint="https://fallback.example/v1a",
            limit=1,
        )

    assert client.fetched == [0, 1, 2, 0]
    with raw_output.open(newline="") as handle:
        assert [row["hathor_height"] for row in csv.DictReader(handle)] == ["1", "2"]
    with failure_output.open(newline="") as handle:
        failures = list(csv.DictReader(handle))
    assert [row["hathor_height"] for row in failures] == ["0", "0"]


def test_seeded_failure_round_defers_a_height_behind_fresh_pending(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    failure_output = tmp_path / "failures.csv"
    tx_heights = _write_all_ready_ledger(ledger_path, [0, 1])
    height_tx = {height: tx_id for tx_id, height in tx_heights.items()}
    with failure_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.FAILURE_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(_failure_row(0, height_tx[0]))
    client = _FairnessClient(tx_heights, permanent_failures=set())

    payloads.run_extraction(
        ledger_path=ledger_path,
        raw_output=raw_output,
        failure_output=failure_output,
        start=0,
        end=2,
        client=client,
        primary_endpoint="https://primary.example/v1a",
        fallback_endpoint="https://fallback.example/v1a",
        limit=1,
    )

    assert client.fetched == [1]


def test_malformed_failure_history_fails_before_network_or_raw_rewrite(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "ledger.csv"
    raw_output = tmp_path / "raw.csv"
    failure_output = tmp_path / "failures.csv"
    _write_all_ready_ledger(ledger_path, [0, 1])
    with failure_output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.FAILURE_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(_failure_row(0, "f" * 64))

    class Client:
        max_attempts = 1

        def get_json(self, *_args):
            raise AssertionError(
                "malformed failure history must fail before network I/O"
            )

    with pytest.raises(ValueError, match="failure tx_id mismatch"):
        payloads.run_extraction(
            ledger_path=ledger_path,
            raw_output=raw_output,
            failure_output=failure_output,
            start=0,
            end=2,
            client=Client(),
            primary_endpoint="https://primary.example/v1a",
            fallback_endpoint="https://fallback.example/v1a",
            limit=1,
        )

    assert not raw_output.exists()


def test_missing_or_empty_failure_log_means_zero_rounds(tmp_path: Path) -> None:
    ready = {0: payloads.ReadyRow(0, "a" * 64)}
    missing = tmp_path / "missing.csv"
    assert payloads.read_failure_rounds(missing, ready) == {}
    empty = tmp_path / "empty.csv"
    empty.write_text("")
    assert payloads.read_failure_rounds(empty, ready) == {}


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("hathor_block_hash", "f" * 64, "failure tx_id mismatch"),
        ("http_status", "garbage", "invalid failure http_status"),
        ("http_status", "0503", "non-canonical failure http_status"),
        ("http_status", "99", "non-canonical failure http_status"),
        ("attempt_count", "0", "non-canonical attempt_count"),
        ("attempt_count", "01", "non-canonical attempt_count"),
        ("endpoint", " ", "blank endpoint"),
        ("endpoint", " primary", "non-canonical endpoint"),
        ("error_reason", "", "blank error_reason"),
        ("error_reason", "http_503 ", "non-canonical error_reason"),
        ("recorded_at_utc", "", "blank recorded_at_utc"),
        ("recorded_at_utc", "not-a-date", "invalid recorded_at_utc"),
        (
            "recorded_at_utc",
            "2024-01-01T00:00:00",
            "non-canonical recorded_at_utc",
        ),
        (
            "recorded_at_utc",
            "2024-01-01T00:00:00+01:00",
            "non-canonical recorded_at_utc",
        ),
    ],
)
def test_failure_history_reader_rejects_malformed_rows(
    tmp_path: Path, field: str, value: str, error: str
) -> None:
    ledger_path = tmp_path / "ledger.csv"
    tx_heights = _write_all_ready_ledger(ledger_path, [0])
    height_tx = {height: tx_id for tx_id, height in tx_heights.items()}
    failure_log = tmp_path / "failures.csv"
    row = _failure_row(0, height_tx[0])
    row[field] = value
    with failure_log.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.FAILURE_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(row)

    ready = payloads.load_ready_rows(ledger_path, 0, 1)
    with pytest.raises(ValueError, match=error):
        payloads.read_failure_rounds(failure_log, ready)


def test_failure_history_accepts_a_blank_status_for_a_network_error(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "ledger.csv"
    tx_heights = _write_all_ready_ledger(ledger_path, [0])
    height_tx = {height: tx_id for tx_id, height in tx_heights.items()}
    failure_log = tmp_path / "failures.csv"
    row = _failure_row(0, height_tx[0])
    row["http_status"] = ""
    with failure_log.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=payloads.FAILURE_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerow(row)

    ready = payloads.load_ready_rows(ledger_path, 0, 1)
    assert payloads.read_failure_rounds(failure_log, ready) == {0: 1}
