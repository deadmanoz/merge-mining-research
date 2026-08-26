from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "extract" / "hathor_metadata_ledger.py"
SPEC = importlib.util.spec_from_file_location("hathor_metadata_ledger", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ledger = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ledger
SPEC.loader.exec_module(ledger)

TX_A = "a" * 64
TX_B = "b" * 64


def _shard(start: int = 0, end: int = 2) -> ledger.Shard:
    return ledger.Shard(
        "shard-001",
        start,
        end,
        "worker-a",
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
        "revision",
    )


def _write_ledger(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ledger.LEDGER_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)


class _Client:
    def __init__(self, results: list[ledger.HttpResult]):
        self.max_attempts = len(results)
        self.results = iter(results)
        self.endpoints: list[str] = []
        self.sleeps: list[float] = []

    def get_json(self, endpoint, _path, _params):
        self.endpoints.append(endpoint)
        return next(self.results)

    def sleep(self, seconds):
        self.sleeps.append(seconds)


def _block(version: int, tx_id: str = "", *, voided: bool = False) -> dict:
    return {
        "success": True,
        "block": {"version": version, "tx_id": tx_id, "is_voided": voided},
    }


def test_manifest_round_trip_partitions_the_declared_range(tmp_path: Path) -> None:
    path = tmp_path / "manifest.csv"
    shards = ledger.make_shards(
        0,
        10,
        ["worker-a", "worker-b", "worker-c"],
        "https://primary.example/v1a/",
        "https://fallback.example/v1a/",
        "revision",
    )

    ledger.write_manifest(path, ledger.Manifest(0, 10, tuple(shards)))
    loaded = ledger.read_manifest(path)

    assert (loaded.start_height, loaded.end_height) == (0, 10)
    assert [(row.start_height, row.end_height) for row in loaded.shards] == [
        (0, 4),
        (4, 8),
        (8, 10),
    ]
    assert loaded.shards[0].primary_endpoint == "https://primary.example/v1a"
    with pytest.raises(ValueError, match="already exists"):
        ledger.write_manifest(path, loaded)


def test_manifest_creation_requires_an_explicit_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "manifest.csv"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--write-manifest",
            str(path),
            "--workers",
            "worker-a",
        ],
    )

    with pytest.raises(SystemExit, match="--write-manifest requires --end"):
        ledger.main()

    assert not path.exists()


@pytest.mark.parametrize(
    "shards, message",
    [
        (
            [
                ledger.Shard("one", 0, 4, "a", "p", "", "r"),
                ledger.Shard("two", 5, 10, "b", "p", "", "r"),
            ],
            "gap",
        ),
        ([ledger.Shard("", 0, 10, "a", "p", "", "r")], "non-empty"),
    ],
)
def test_manifest_rejects_invalid_partitions(shards, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        ledger.validate_shards(shards, 0, 10)


def test_manifest_reader_accepts_only_the_current_schema(tmp_path: Path) -> None:
    path = tmp_path / "old-manifest.csv"
    path.write_text("shard_id,start_height,end_height\none,0,1\n")

    with pytest.raises(ValueError, match="unexpected manifest columns"):
        ledger.read_manifest(path)


@pytest.mark.parametrize(
    "payload, expected",
    [
        (
            _block(3, TX_A),
            {"outcome": "version_3_ready", "block_version": 3, "tx_id": TX_A},
        ),
        (
            _block(0, TX_B),
            {"outcome": "non_version_3", "block_version": 0, "tx_id": TX_B},
        ),
        (
            _block(3, TX_A, voided=True),
            {
                "outcome": "unavailable_block",
                "error_reason": "child_block_voided",
            },
        ),
    ],
)
def test_fetch_height_records_the_observed_block_state(payload, expected) -> None:
    client = _Client([ledger.HttpResult(200, payload, None, False)])

    row = ledger.fetch_height(client, _shard(0, 1), 0)

    assert row | expected == row
    assert row["endpoint"] == "https://primary.example/v1a"
    assert row["attempt_count"] == 1


def test_fetch_height_falls_back_and_preserves_exhausted_failure() -> None:
    client = _Client(
        [
            ledger.HttpResult(429, None, "http_429", True),
            ledger.HttpResult(503, None, "http_503", True),
        ]
    )

    row = ledger.fetch_height(client, _shard(0, 1), 0)

    assert client.endpoints == [
        "https://primary.example/v1a",
        "https://fallback.example/v1a",
    ]
    assert row["outcome"] == "request_failure"
    assert row["endpoint"] == "https://fallback.example/v1a"
    assert row["attempt_count"] == 2


def test_scan_resumes_a_contiguous_prefix(tmp_path: Path) -> None:
    path = tmp_path / "ledger.csv"
    _write_ledger(
        path,
        [ledger.ledger_row(0, "non_version_3", 200, 0, TX_A, "primary", 1, "")],
    )
    client = _Client([ledger.HttpResult(200, _block(3, TX_B), None, False)])

    assert ledger.scan_shard(client, _shard(), path) == {"version_3_ready": 1}
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["hathor_height"] for row in rows] == ["0", "1"]
    assert rows[1]["tx_id"] == TX_B


def test_scan_rejects_nonprefix_resume_state(tmp_path: Path) -> None:
    path = tmp_path / "ledger.csv"
    _write_ledger(
        path,
        [ledger.ledger_row(1, "non_version_3", 200, 0, TX_A, "primary", 1, "")],
    )

    with pytest.raises(ValueError, match="contiguous prefix"):
        ledger.scan_shard(object(), _shard(), path)


def test_retry_re_drives_all_unresolved_rows(tmp_path: Path) -> None:
    source = tmp_path / "ledger.csv"
    output = tmp_path / "retry.csv"
    _write_ledger(
        source,
        [
            ledger.ledger_row(
                0, "request_failure", 503, "", "", "primary", 2, "http_503"
            ),
            ledger.ledger_row(1, "non_version_3", 200, 0, TX_B, "primary", 1, ""),
        ],
    )
    client = _Client([ledger.HttpResult(200, _block(3, TX_A), None, False)])

    stats = ledger.retry_ledger(client, _shard(), source, output)

    assert stats == {"retried": 1, "resolved": 1}
    with output.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["outcome"] for row in rows] == [
        "version_3_ready",
        "non_version_3",
    ]
    completed = output.read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        ledger.retry_ledger(client, _shard(), source, output)
    assert output.read_bytes() == completed


def test_audit_requires_exact_resolved_coverage(tmp_path: Path) -> None:
    path = tmp_path / "ledger.csv"
    _write_ledger(
        path,
        [
            ledger.ledger_row(0, "non_version_3", 200, 0, TX_A, "p", 1, ""),
            ledger.ledger_row(1, "version_3_ready", 200, 3, TX_B, "p", 1, ""),
        ],
    )

    assert ledger.audit_ledger(path, 0, 2) == {
        "non_version_3": 1,
        "version_3_ready": 1,
    }
    with pytest.raises(ValueError, match="missing=1"):
        ledger.audit_ledger(path, 0, 3)


def test_audit_rejects_unresolved_rows_and_duplicate_transaction_ids(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.csv"
    _write_ledger(
        path,
        [ledger.ledger_row(0, "request_failure", 503, "", "", "p", 1, "http_503")],
    )
    with pytest.raises(ValueError, match="unresolved outcomes"):
        ledger.audit_ledger(path, 0, 1)

    _write_ledger(
        path,
        [
            ledger.ledger_row(0, "version_3_ready", 200, 3, TX_A, "p", 1, ""),
            ledger.ledger_row(1, "version_3_ready", 200, 3, TX_A, "p", 1, ""),
        ],
    )
    with pytest.raises(ValueError, match="multiple heights"):
        ledger.audit_ledger(path, 0, 2)


def test_paced_client_waits_between_request_starts() -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return 200

        def read(self):
            return json.dumps({"ok": True}).encode()

    times = iter([0.0, 0.0, 0.25, 1.0])
    sleeps: list[float] = []
    client = ledger.PacedHttpClient(
        1.0,
        30,
        1,
        opener=lambda *_args, **_kwargs: Response(),
        sleep=sleeps.append,
        monotonic=lambda: next(times),
    )

    client.get_json("https://example.test", "/one", {})
    client.get_json("https://example.test", "/two", {})

    assert sleeps == [0.75]
