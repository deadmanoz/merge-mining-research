from __future__ import annotations

import json
from pathlib import Path

import pytest

from stale_blocks_analysis.bitcoin_epoch_reference import (
    EsploraClient,
    HEADERS_FILENAME,
    MANIFEST_FILENAME,
    NBITS_FILENAME,
    ReferenceError,
    normalize_bits,
    refresh_reference,
)


class FakeSource:
    api_base = "https://public.example/api"

    def __init__(self, tip: int = 4040) -> None:
        self.tip = tip
        self.block_requests: list[int] = []
        self.hash_requests: list[int] = []

    @staticmethod
    def block_hash(height: int) -> str:
        return f"{height:064x}"

    def tip_height(self) -> int:
        return self.tip

    def hash_at_height(self, height: int) -> str:
        self.hash_requests.append(height)
        return self.block_hash(height)

    def block_at_height(self, height: int) -> dict[str, object]:
        self.block_requests.append(height)
        return {
            "height": height,
            "hash": self.block_hash(height),
            "time": 1_231_006_505 + height * 600,
            "mediantime": 1_231_006_505 + height * 600 - 3_000,
            "bits": "1d00ffff" if height == 0 else "1c654657",
        }


def test_normalize_bits_accepts_esplora_integer_and_hex() -> None:
    assert normalize_bits(486604799) == "1d00ffff"
    assert normalize_bits("0x1d00ffff") == "1d00ffff"
    assert normalize_bits("1d00ffff") == "1d00ffff"


def test_esplora_client_uses_batched_block_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.dumps(
        [
            {
                "id": "a" * 64,
                "height": 2016,
                "timestamp": 1_232_000_000,
                "mediantime": 1_231_999_000,
                "bits": 486_604_799,
            }
        ]
    ).encode()
    paths: list[str] = []

    def fake_request(_self: EsploraClient, path: str) -> bytes:
        paths.append(path)
        return payload

    monkeypatch.setattr(EsploraClient, "_request", fake_request)
    block = EsploraClient().block_at_height(2016)

    assert paths == ["blocks/2016"]
    assert block["bits"] == "1d00ffff"


def test_refresh_writes_epochs_and_confirmed_horizon(tmp_path: Path) -> None:
    source = FakeSource()
    manifest = refresh_reference(source, tmp_path, confirmations=6)

    bits = json.loads((tmp_path / NBITS_FILENAME).read_text())
    headers = json.loads((tmp_path / HEADERS_FILENAME).read_text())
    persisted_manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text())

    assert list(bits) == ["0", "2016", "4032"]
    assert [row["height"] for row in headers] == [0, 2016, 4032, 4034]
    assert source.block_requests == [0, 2016, 4032, 4034]
    assert manifest == persisted_manifest
    assert manifest["source"]["api_base"] == "https://public.example/api"


def test_refresh_is_incremental_and_replaces_horizon(tmp_path: Path) -> None:
    source = FakeSource()
    refresh_reference(source, tmp_path, confirmations=6)

    later = FakeSource(tip=8071)
    refresh_reference(later, tmp_path, confirmations=6)
    headers = json.loads((tmp_path / HEADERS_FILENAME).read_text())

    assert later.hash_requests == [4032]
    assert later.block_requests == [6048, 8064, 8065]
    assert [row["height"] for row in headers] == [
        0,
        2016,
        4032,
        6048,
        8064,
        8065,
    ]


def test_refresh_rejects_changed_existing_epoch_hash(tmp_path: Path) -> None:
    source = FakeSource()
    refresh_reference(source, tmp_path, confirmations=6)

    changed = FakeSource()
    changed.hash_at_height = lambda _height: "f" * 64  # type: ignore[method-assign]
    with pytest.raises(ReferenceError, match="not canonical"):
        refresh_reference(changed, tmp_path, confirmations=6)


def test_committed_reference_artifacts_are_consistent() -> None:
    reference_dir = (
        Path(__file__).resolve().parents[1] / "data" / "bitcoin-epoch-reference"
    )
    bits = json.loads((reference_dir / NBITS_FILENAME).read_text())
    headers = json.loads((reference_dir / HEADERS_FILENAME).read_text())
    manifest = json.loads((reference_dir / MANIFEST_FILENAME).read_text())

    epoch_headers = [row for row in headers if row["height"] % 2016 == 0]
    assert {str(row["height"]): row["bits"] for row in epoch_headers} == bits
    assert len(epoch_headers) == manifest["epoch_rows"]
    assert headers[-1] == manifest["finalized_horizon"]
    assert headers[-1]["height"] == (
        manifest["observed_tip_height"] - manifest["confirmation_depth"]
    )
