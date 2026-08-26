from __future__ import annotations

import csv
import hashlib
from pathlib import Path

import pytest

from stale_blocks_analysis import hathor_classify as hathor
from stale_blocks_analysis import stale_blocks
from stale_blocks_analysis.bitcoin_binary import parse_coinbase_tx, sha256d


RFC_BLOCK_HASH = "00000000000000001edcb1b01154f8df97199f5fd936d8e7d553d76d01abec3c"
RFC_FUNDS = "0003010000190000001976a914bcdddee6f042c73ff4b947bc9bca929fbd4fa98588ac"
RFC_GRAPH = (
    "404dea2b257375405ef3846b03"
    "000000000000000eab4934332c22f5db57ce7276cc76304384979ff861a5ff5a"
    "000000000706cc3cfe08ea41eb25b22d170193a8dfc0335cf3983d97f70ddbe0"
    "000000009ff1ea03f91bb20e6b2fc55bcd1f46d0564849641adb6c51f1dc6f4b00"
)
RFC_HEADER_HEAD = (
    "000000202f6636c625e1303fffbd016104041dc1e9ca1452109404000000000000000000"
)
RFC_COINBASE_HEAD = (
    "010000000001010000000000000000000000000000000000000000000000000000000000"
    "000000ffffffff33fe05b5090048617468"
)
RFC_COINBASE_TAIL = (
    "9cf38114100000000000ffffffff0140cd4f260000000016a9c384cd403c314e857d68dc"
    "96093c45914c4bbc60870120000000000000000000000000000000000000000000000000"
    "000000000000000000000000"
)
RFC_MERKLE_PATH = [
    "78d994a5f520c138408abcb2665aa39df1bbcde26aa13cce9775276371c09d22",
    "759c3d2229ea39c7740fbffdf299efaf544f5382099e9dec63b9fbdb83f141b6",
    "1c00ad5025f5d3ebb15365d42e4acb8654db3a06ace7d638be146c9ba5e5239f",
    "64efed174ad8651e05669c15ec258fd31cd1ff79927d2476b59aad5a52cf1f32",
    "2b70e3bbddb58e474402e2504c5ce13bb408d0c5066186f5796b38522cc0b9ee",
    "0965361770473985e6d7ba3417274821245898f13cd3c785a1c3cfbddb0357e4",
    "8ac9da66991f8b12cbc51fdd47768c930dde106a95672dcfb55adef505f1bdc8",
    "7c6cec9c7e548007d642495226cb0746e5500dee273bed8c40036bef13f7d671",
    "6c221b75f9904d37ed5b55e829ebe23a447847d31d33b645c8787a9eeb9f7195",
    "a845b78e5a86ede4c5591c0d741fe889a347dfba8345a6dde9e65427727c65cd",
    "0d56f17e358542cfeb3f4702e1d9f0e0e1d24e9f3a632c7b245e6311d96f1a29",
    "113709424b0f60dcc6e7e0263815792d13d53b09452db4d672d26c4d2f0dbfe2",
]
RFC_HEADER_TAIL = "6c84f35ef2d4111798bc21ca"


class FakeRpc:
    def batch(self, _calls: object) -> list[object]:
        raise AssertionError("unexpected Bitcoin RPC batch")


def _rfc_aux_pow_hex() -> str:
    return (
        RFC_HEADER_HEAD
        + "35"
        + RFC_COINBASE_HEAD
        + "54"
        + RFC_COINBASE_TAIL
        + "0c"
        + "".join(RFC_MERKLE_PATH)
        + RFC_HEADER_TAIL
    )


def _header(height: int) -> bytes:
    return (
        (4).to_bytes(4, "little")
        + bytes([height]) * 32
        + bytes([height + 1]) * 32
        + (1_700_000_000 + height).to_bytes(4, "little")
        + (0x207FFFFF).to_bytes(4, "little")
        + height.to_bytes(4, "little")
    )


def _coinbase(height: int) -> bytes:
    scriptsig = b"\x03" + height.to_bytes(3, "little")
    return (
        (1).to_bytes(4, "little")
        + b"\x01"
        + b"\x00" * 32
        + b"\xff\xff\xff\xff"
        + bytes([len(scriptsig)])
        + scriptsig
        + b"\xff\xff\xff\xff"
        + b"\x01"
        + (5_000_000_000).to_bytes(8, "little")
        + b"\x01\x51"
        + b"\x00\x00\x00\x00"
    )


def _observation(height: int) -> hathor.ReconstructedObservation:
    return hathor.ReconstructedObservation(_header(height), _coinbase(height), 35)


def _acquisition_row(height: int) -> dict[str, str]:
    row = {
        "hathor_height": str(height),
        "hathor_block_hash": sha256d(_header(height))[::-1].hex(),
        "hathor_timestamp": str(1_700_000_000 + height),
        "aux_pow_hex": "00",
        "funds_graph_hex": "00",
        "raw_hex": "00",
        "endpoint": "http://example.invalid",
        "http_status": "200",
        "attempt_count": "1",
        "record_sha256": "",
    }
    row["record_sha256"] = hathor.acquisition_record_sha256(row)
    return row


def _write_shard(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=hathor.ACQUISITION_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)


def _read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def test_reconstructs_rfc0006_vector_and_preserves_raw_output_scripts() -> None:
    parsed = hathor.parse_aux_pow(_rfc_aux_pow_hex())
    funds = bytes.fromhex(RFC_FUNDS)
    graph = bytes.fromhex(RFC_GRAPH)

    reconstructed = hathor.reconstruct_rfc0006(parsed, funds + graph, RFC_BLOCK_HASH)

    expected_commitment = sha256d(
        hashlib.sha256(funds).digest() + hashlib.sha256(graph).digest()
    )[::-1]
    assert reconstructed.split_offset == len(funds)
    assert expected_commitment in reconstructed.coinbase
    assert sha256d(reconstructed.header)[::-1].hex() == RFC_BLOCK_HASH

    output, coinbase_parsed = hathor._base_output_row(
        {
            "hathor_block_hash": RFC_BLOCK_HASH,
            "hathor_height": "1",
            "hathor_timestamp": "1",
        },
        reconstructed,
    )
    parsed_coinbase = parse_coinbase_tx(reconstructed.coinbase)
    assert parsed_coinbase is not None
    assert coinbase_parsed is True
    assert output["coinbase_outputs"] == "|".join(
        f"{script.hex()}:{value}" for value, script in parsed_coinbase["outputs"]
    )


def test_self_target_filter_uses_the_encoded_target_and_rejects_invalid_bits() -> None:
    assert hathor._meets_self_target(
        {"btc_header_hex": _header(0).hex(), "btc_bits": "207fffff"}
    )
    assert not hathor._meets_self_target(
        {"btc_header_hex": _header(1).hex(), "btc_bits": "207fffff"}
    )
    with pytest.raises(ValueError, match="invalid PoW target"):
        hathor._meets_self_target(
            {"btc_header_hex": _header(0).hex(), "btc_bits": "20800000"}
        )


def test_publishes_all_terminal_categories_from_ordered_shards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "000000-000001.csv"
    second = tmp_path / "000002-000004.csv"
    output_dir = tmp_path / "published"
    _write_shard(first, [_acquisition_row(height) for height in (0, 1)])
    _write_shard(second, [_acquisition_row(height) for height in (2, 3, 4)])

    def source_observation(
        row: dict[str, str], _line_number: int
    ) -> hathor.ReconstructedObservation:
        assert row["record_sha256"] == hathor.acquisition_record_sha256(row)
        return _observation(int(row["hathor_height"]))

    def classify(
        candidates: list[dict[str, object]], _rpc: FakeRpc
    ) -> list[dict[str, object]]:
        categories = {1: "canonical", 2: "stale", 3: "unknown", 4: "stale"}
        for row in candidates:
            height = int(str(row["hathor_height"]))
            row["classification"] = categories[height]
            if categories[height] in {"canonical", "stale"}:
                row["btc_height"] = str(800_000 + height)
        return list(reversed(candidates))

    def validate(
        stales: list[dict[str, object]], _batch: object
    ) -> list[dict[str, object]]:
        for row in stales:
            if row["hathor_height"] == "2":
                row["validation_status"] = "VALID"
                row["expected_nbits"] = "207fffff"
            else:
                row["validation_status"] = "REJECTED: test rule"
        return stales

    def route(stales: list[dict[str, object]]) -> None:
        for row in stales:
            if str(row["validation_status"]).startswith("REJECTED:"):
                row["classification"] = "error_block"
                row["rules_violated"] = "test_rule"

    monkeypatch.setattr(hathor, "_source_observation", source_observation)
    monkeypatch.setattr(
        hathor,
        "_meets_self_target",
        lambda row: row["hathor_height"] != "0",
    )
    monkeypatch.setattr(hathor, "classify_candidates", classify)
    monkeypatch.setattr(hathor, "validate_stale_header_context", validate)
    monkeypatch.setattr(hathor, "route_rejected_stale_rows", route)

    report = hathor.classify_hathor(
        [first, second], output_dir, FakeRpc(), batch_size=2
    )

    assert report == {
        "input_rows": 5,
        "input_files": 2,
        "near": 1,
        "canonical": 1,
        "stale": 1,
        "unknown": 1,
        "error_block": 1,
        "validated_stales": 1,
        "output_dir": str(output_dir),
    }
    assert {path.name for path in output_dir.iterdir()} == {
        *hathor.CATEGORY_FILENAMES.values(),
        hathor.VALIDATED_FILENAME,
    }
    for category, filename in hathor.CATEGORY_FILENAMES.items():
        columns, rows = _read_rows(output_dir / filename)
        expected_columns = (
            hathor.ERROR_OUTPUT_COLUMNS
            if category == "error_block"
            else hathor.OUTPUT_COLUMNS
        )
        assert columns == expected_columns
        assert [row["classification"] for row in rows] == [category]
        assert rows[0]["coinbase_outputs"] == "51:5000000000"
    _, stale_rows = _read_rows(output_dir / hathor.CATEGORY_FILENAMES["stale"])
    _, validated_rows = _read_rows(output_dir / hathor.VALIDATED_FILENAME)
    assert validated_rows == stale_rows
    assert validated_rows[0]["hathor_height"] == "2"


def test_rejects_duplicate_height_across_shards_without_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    output_dir = tmp_path / "published"
    _write_shard(first, [_acquisition_row(height) for height in (0, 2)])
    _write_shard(second, [_acquisition_row(height) for height in (2, 3)])
    monkeypatch.setattr(
        hathor,
        "_source_observation",
        lambda row, _line: _observation(int(row["hathor_height"])),
    )
    monkeypatch.setattr(hathor, "_meets_self_target", lambda _row: False)

    with pytest.raises(ValueError, match="globally strictly ascending"):
        hathor.classify_hathor([first, second], output_dir, FakeRpc())

    assert not output_dir.exists()
    assert not list(tmp_path.glob(".published.*"))


def test_bad_acquisition_seal_leaves_no_partial_output(tmp_path: Path) -> None:
    source = tmp_path / "source.csv"
    output_dir = tmp_path / "published"
    row = _acquisition_row(0)
    row["record_sha256"] = "0" * 64
    _write_shard(source, [row])

    with pytest.raises(ValueError, match="record seal mismatch"):
        hathor.classify_hathor([source], output_dir, FakeRpc())

    assert not output_dir.exists()
    assert not list(tmp_path.glob(".published.*"))


def test_existing_output_directory_is_never_replaced(tmp_path: Path) -> None:
    source = tmp_path / "source.csv"
    output_dir = tmp_path / "published"
    _write_shard(source, [])
    output_dir.mkdir()
    marker = output_dir / "keep"
    marker.write_text("existing\n")

    with pytest.raises(FileExistsError, match="already exists"):
        hathor.classify_hathor([source], output_dir, FakeRpc())

    assert marker.read_text() == "existing\n"


def test_stale_with_unparseable_coinbase_remains_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row: dict[str, object] = {
        "hathor_height": "5",
        "classification": "",
        "validation_status": "dirty",
        "expected_nbits": "dirty",
    }

    def classify(
        candidates: list[dict[str, object]], _rpc: FakeRpc
    ) -> list[dict[str, object]]:
        candidates[0]["classification"] = "stale"
        return candidates

    def validate(stales: list[dict[str, object]], _batch: object) -> None:
        assert stales == []

    monkeypatch.setattr(hathor, "classify_candidates", classify)
    monkeypatch.setattr(hathor, "validate_stale_header_context", validate)
    monkeypatch.setattr(hathor, "route_rejected_stale_rows", lambda _rows: None)

    result = hathor._classify_batch([(row, False)], FakeRpc())

    assert result[0]["classification"] == "unknown"
    assert result[0]["validation_status"] == ""
    assert result[0]["expected_nbits"] == ""


def test_incomplete_stale_validation_aborts_without_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.csv"
    output_dir = tmp_path / "published"
    _write_shard(source, [_acquisition_row(0)])
    monkeypatch.setattr(
        hathor, "_source_observation", lambda _row, _line: _observation(0)
    )
    monkeypatch.setattr(hathor, "_meets_self_target", lambda _row: True)

    def classify(
        candidates: list[dict[str, object]], _rpc: FakeRpc
    ) -> list[dict[str, object]]:
        candidates[0]["classification"] = "stale"
        candidates[0]["btc_height"] = "800000"
        return candidates

    def validate(stales: list[dict[str, object]], _batch: object) -> None:
        stales[0]["validation_status"] = "UNKNOWN: missing context"

    monkeypatch.setattr(hathor, "classify_candidates", classify)
    monkeypatch.setattr(hathor, "validate_stale_header_context", validate)
    monkeypatch.setattr(hathor, "route_rejected_stale_rows", lambda _rows: None)

    with pytest.raises(RuntimeError, match="validation context is incomplete"):
        hathor.classify_hathor([source], output_dir, FakeRpc())

    assert not output_dir.exists()
    assert not list(tmp_path.glob(".published.*"))


def test_hathor_loader_requires_valid_validation_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    csv_path = tmp_path / "hathor_validated_stales.csv"
    csv_path.write_text(
        "\n".join(
            [
                "btc_height,btc_header_hash,btc_prev_hash,btc_time,btc_bits,"
                "coinbase_scriptsig_hex,coinbase_outputs,btc_header_hex,"
                "hathor_height,child_block_hash,child_header_hex,child_block_time,"
                "child_nbits,classification,validation_status,expected_nbits",
                "700000,validhash,prev,1,170fffff,03a00a00,51:1,00,1,,,,,stale,VALID,170fffff",
                "700001,badhash,prev,1,170fffff,03a10a00,,00,2,,,,,stale,REJECTED,170fffff",
                "700002,oldhash,prev,1,170fffff,03a20a00,,00,3,,,,,stale,,",
            ]
        )
        + "\n"
    )
    monkeypatch.setattr(stale_blocks, "HATHOR_CSV", csv_path)

    rows = stale_blocks.load_hathor_stales(min_height=0)

    assert [row["hash"] for row in rows] == ["validhash"]
    assert rows[0]["_outputs_str"] == "51"
