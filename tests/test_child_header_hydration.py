"""Clean-source child-header hydration tests for bespoke source formats."""

from __future__ import annotations

import csv
import gzip
import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

from stale_blocks_analysis.auxpow_chainid import hash_from_header_bytes
from stale_blocks_analysis.auxpow_parse import ChildHeaderValidationError
from stale_blocks_analysis.evidence_hydration import (
    CHILD_IDENTITY_CORE_FIELDS,
    hydrate_child_identity,
    load_child_identity,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _identity_child_header(
    *, timestamp: int = 1_700_000_000, nbits: int = 0x1D00FFFF
) -> bytes:
    return (
        struct.pack("<i", 1)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", timestamp, nbits, 7)
    )


def _write_child_identity_rows(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=CHILD_IDENTITY_CORE_FIELDS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def test_load_child_identity_returns_verified_unique_row(tmp_path: Path) -> None:
    block_hash = "11" * 32
    child_header = _identity_child_header(timestamp=3)
    row = {
        "chain": "namecoin",
        "btc_header_hash": block_hash,
        "child_height": "2",
        "child_block_hash": hash_from_header_bytes(child_header).hex(),
        "child_block_time": "3",
        "verification": "auxpow_parent_match",
        "note": "",
        "child_header_hex": child_header.hex(),
        "child_nbits": "1d00ffff",
    }
    _write_child_identity_rows(
        tmp_path / "child-identity" / "namecoin_child_identity.csv", [row]
    )

    assert load_child_identity(tmp_path)[("namecoin", block_hash)] == row


def test_load_child_identity_rejects_duplicate_parent_key(tmp_path: Path) -> None:
    block_hash = "11" * 32
    child_header = _identity_child_header(timestamp=3)
    row = {
        "chain": "namecoin",
        "btc_header_hash": block_hash,
        "child_height": "2",
        "child_block_hash": hash_from_header_bytes(child_header).hex(),
        "child_block_time": "3",
        "verification": "auxpow_parent_match",
        "note": "",
        "child_header_hex": child_header.hex(),
        "child_nbits": "1d00ffff",
    }
    _write_child_identity_rows(
        tmp_path / "child-identity" / "namecoin_child_identity.csv", [row, row]
    )

    with pytest.raises(ValueError, match="duplicate child identity"):
        load_child_identity(tmp_path)


def test_load_child_identity_rejects_header_bundle_contradiction(
    tmp_path: Path,
) -> None:
    child_header = _identity_child_header()
    row = {
        "chain": "namecoin",
        "btc_header_hash": "11" * 32,
        "child_height": "2",
        "child_block_hash": "22" * 32,
        "child_block_time": "1700000000",
        "verification": "auxpow_parent_match",
        "note": "",
        "child_header_hex": child_header.hex(),
        "child_nbits": "1d00ffff",
    }
    path = tmp_path / "child-identity" / "namecoin_child_identity.csv"
    _write_child_identity_rows(path, [row])

    with pytest.raises(
        ChildHeaderValidationError,
        match=r"namecoin_child_identity\.csv:2: .*child_block_hash disagrees",
    ):
        load_child_identity(tmp_path)


def test_hydrate_child_identity_fills_complete_five_field_identity() -> None:
    parent_hash = "11" * 32
    child_header = _identity_child_header()
    child_hash = hash_from_header_bytes(child_header).hex()
    row = {
        "chain": "namecoin",
        "btc_header_hash": parent_hash,
        "child_height": "",
        "child_block_hash": "",
        "child_block_time": "",
        "child_header_hex": "",
        "child_nbits": "",
        "classification": "stale",
    }

    stats = hydrate_child_identity(
        [row],
        {
            ("namecoin", parent_hash): {
                "child_height": "2",
                "child_block_hash": child_hash,
                "child_block_time": "1700000000",
                "child_header_hex": child_header.hex(),
                "child_nbits": "1d00ffff",
            }
        },
    )

    assert stats.hydrated == 1
    assert {
        field: row[field]
        for field in (
            "child_height",
            "child_block_hash",
            "child_block_time",
            "child_header_hex",
            "child_nbits",
        )
    } == {
        "child_height": "2",
        "child_block_hash": child_hash,
        "child_block_time": "1700000000",
        "child_header_hex": child_header.hex(),
        "child_nbits": "1d00ffff",
    }


def test_hydrate_child_identity_preserves_authenticated_source_header() -> None:
    parent_hash = "11" * 32
    child_header = _identity_child_header()
    child_hash = hash_from_header_bytes(child_header).hex()
    row = {
        "chain": "namecoin",
        "btc_header_hash": parent_hash,
        "child_height": "2",
        "child_block_hash": child_hash,
        "child_block_time": "1700000000",
        "child_header_hex": child_header.hex(),
        "child_nbits": "1d00ffff",
        "classification": "stale",
    }

    stats = hydrate_child_identity(
        [row],
        {
            ("namecoin", parent_hash): {
                "child_height": "2",
                "child_block_hash": child_hash,
                "child_block_time": "1700000000",
            }
        },
    )

    assert stats.hydrated == 1
    assert row["child_header_hex"] == child_header.hex()
    assert row["child_nbits"] == "1d00ffff"


def _load_script(name: str):
    path = REPO_ROOT / "scripts" / "extract" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_repo_script(relative_path: str):
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("chain", ["namecoin", "syscoin"])
def test_child_identity_recovery_emits_header_and_nbits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    chain: str,
) -> None:
    mod = _load_script("recover_child_identity")
    child_header = _identity_child_header()
    child_hash_display = hash_from_header_bytes(child_header)[::-1].hex()
    parent_hash = "33" * 32

    class FakeRpc:
        def __init__(self, url, *, user=None, password=None):
            self.url = url

        def call(self, method, params):
            if method == "getblockhash":
                assert params == [2]
                return child_hash_display
            if method == "getblock":
                assert params == [child_hash_display]
                return {
                    "auxpow": {"parentblock": {"hash": parent_hash}},
                    "time": 1_700_000_000,
                    "bits": "1d00ffff",
                }
            if method == "getblockheader":
                assert params == [child_hash_display, False]
                return child_header.hex()
            raise AssertionError(method)

    monkeypatch.setattr(mod, "RpcClient", FakeRpc)
    monkeypatch.setattr(mod, "rpc_auth_from_env", lambda _prefix: (None, None))

    rows = mod.recover_auxpow_family(
        chain,
        "http://example.invalid",
        [(parent_hash, 2)],
        1,
    )

    assert rows == [
        {
            "chain": chain,
            "btc_header_hash": parent_hash,
            "child_height": 2,
            "child_block_hash": hash_from_header_bytes(child_header).hex(),
            "child_header_hex": child_header.hex(),
            "child_block_time": 1_700_000_000,
            "child_nbits": "1d00ffff",
            "verification": "auxpow_parent_match",
        }
    ]
    output = mod.write_rows(tmp_path, chain, rows, complete=True)
    with output.open(newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == CHILD_IDENTITY_CORE_FIELDS
        persisted = list(reader)
    assert persisted[0]["child_header_hex"] == child_header.hex()
    assert persisted[0]["child_nbits"] == "1d00ffff"


def test_rsk_recovery_schema_retains_blank_bitcoin_header_fields(
    tmp_path: Path,
) -> None:
    mod = _load_script("recover_child_identity")
    output = mod.write_rows(
        tmp_path,
        "rsk",
        [
            {
                "chain": "rsk",
                "btc_header_hash": "11" * 32,
                "child_height": 2,
                "child_block_hash": "22" * 32,
                "child_block_time": 3,
                "verification": "merged_mining_header_match",
            }
        ],
        complete=True,
    )

    with output.open(newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == [
            *CHILD_IDENTITY_CORE_FIELDS,
            *mod.RSK_EXTRA_FIELDS,
        ]
        row = next(reader)
    assert row["child_header_hex"] == ""
    assert row["child_nbits"] == ""


def test_child_identity_recovery_skips_optional_canonical_rows(tmp_path: Path) -> None:
    mod = _load_script("recover_child_identity")
    evidence = tmp_path / "elastos_monitor_evidence.csv"
    with evidence.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["classification", "btc_header_hash", "child_height"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "classification": "canonical",
                "btc_header_hash": "11" * 32,
                "child_height": "1",
            }
        )
        writer.writerow(
            {
                "classification": "unknown",
                "btc_header_hash": "22" * 32,
                "child_height": "2",
            }
        )

    assert mod.load_targets(evidence) == [("22" * 32, 2)]


def test_child_identity_recovery_refuses_empty_target_set(tmp_path: Path) -> None:
    mod = _load_script("recover_child_identity")
    evidence = tmp_path / "namecoin_monitor_evidence.csv"
    with evidence.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["classification", "btc_header_hash", "child_height"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "classification": "canonical",
                "btc_header_hash": "11" * 32,
                "child_height": "1",
            }
        )

    with pytest.raises(SystemExit, match="no non-canonical child-identity targets"):
        mod.load_targets(evidence)


def test_error_observation_rsk_targets_merge_into_identity_work_list(
    tmp_path: Path,
) -> None:
    mod = _load_script("recover_child_identity")
    ledger = tmp_path / "error_block_observations.csv"
    with ledger.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["chain", "btc_header_hash", "child_height"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "chain": "namecoin",
                "btc_header_hash": "11" * 32,
                "child_height": "1",
            }
        )
        for height, digest in (
            (789982, "aa"),
            (793596, "bb"),
            (793505, "cc"),
            (804553, "dd"),
            (5287383, "ee"),
        ):
            writer.writerow(
                {
                    "chain": "rsk",
                    "btc_header_hash": digest * 32,
                    "child_height": str(height),
                }
            )

    extra = mod.load_error_observation_rsk_targets(ledger)
    assert extra == [
        ("aa" * 32, 789982),
        ("cc" * 32, 793505),
        ("bb" * 32, 793596),
        ("dd" * 32, 804553),
        ("ee" * 32, 5287383),
    ]
    merged = mod.merge_identity_targets([("22" * 32, 2)], extra)
    assert ("aa" * 32, 789982) in merged
    assert ("22" * 32, 2) in merged
    assert len(merged) == 6


def test_error_observation_rsk_targets_refuse_missing_or_empty_ledger(
    tmp_path: Path,
) -> None:
    mod = _load_script("recover_child_identity")
    missing = tmp_path / "missing.csv"
    with pytest.raises(SystemExit, match="error-observation ledger is missing"):
        mod.load_error_observation_rsk_targets(missing)

    empty = tmp_path / "error_block_observations.csv"
    with empty.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["chain", "btc_header_hash", "child_height"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "chain": "namecoin",
                "btc_header_hash": "11" * 32,
                "child_height": "1",
            }
        )
    with pytest.raises(SystemExit, match="no RSK error-observation targets"):
        mod.load_error_observation_rsk_targets(empty)


def test_error_observation_rsk_targets_refuse_height_disagreement(
    tmp_path: Path,
) -> None:
    mod = _load_script("recover_child_identity")
    ledger = tmp_path / "error_block_observations.csv"
    with ledger.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["chain", "btc_header_hash", "child_height"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "chain": "rsk",
                "btc_header_hash": "aa" * 32,
                "child_height": "1",
            }
        )
        writer.writerow(
            {
                "chain": "rsk",
                "btc_header_hash": "aa" * 32,
                "child_height": "2",
            }
        )

    with pytest.raises(SystemExit, match="maps to child height"):
        mod.load_error_observation_rsk_targets(ledger)


def test_recover_rsk_uses_canonical_block_when_metadata_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _load_script("recover_child_identity")
    header = "00" * 80
    btc_hash = mod.display_hash(mod.sha256d(bytes.fromhex(header)))
    height = 793505
    block = {
        "bitcoinMergedMiningHeader": "0x" + header,
        "number": hex(height),
        "timestamp": hex(1_538_453_154),
        "miner": "0x" + "07" * 20,
        "hashForMergedMining": "0x" + "63" * 32,
        "hash": "0x" + "10" * 32,
        "bitcoinMergedMiningMerkleProof": "0x04",
        "bitcoinMergedMiningCoinbaseTransaction": "0x05",
    }

    class FakeRpc:
        def __init__(self, url, jsonrpc="2.0"):
            self.url = url

        def call(self, method, params):
            assert method == "eth_getBlockByNumber"
            assert params == [hex(height), False]
            return block

    monkeypatch.setattr(mod, "RpcClient", FakeRpc)
    rows = mod.recover_rsk("rsk", "http://example.invalid", [(btc_hash, height)], 1, {})
    assert rows[0]["verification"] == "merged_mining_header_match"
    assert rows[0]["is_uncle"] == "0"
    assert rows[0]["child_block_hash"] == "10" * 32
    assert rows[0]["rsk_miner"] == "07" * 20

    mismatch = dict(block)
    mismatch["bitcoinMergedMiningHeader"] = "0x" + "11" * 80

    class MismatchRpc(FakeRpc):
        def call(self, method, params):
            return mismatch

    monkeypatch.setattr(mod, "RpcClient", MismatchRpc)
    failed = mod.recover_rsk(
        "rsk", "http://example.invalid", [(btc_hash, height)], 1, {}
    )
    assert not failed[0].get("verification")
    assert failed[0]["note"].startswith("parent_mismatch:")


@pytest.mark.parametrize(
    ("relative_path", "loader_name"),
    [
        ("scripts/classify/classify_geistgeld_stales.py", "stream_candidates"),
        ("scripts/classify/classify_groupcoin_stales.py", "extract_candidates"),
    ],
)
def test_json_classifiers_preserve_child_header_authentication_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    loader_name: str,
) -> None:
    mod = _load_repo_script(relative_path)
    monkeypatch.setattr(mod, "hash_meets_target", lambda _header_hex: True)
    record = {
        "version": 1,
        "previousblockhash": "11" * 32,
        "merkleroot": "22" * 32,
        "time": 1_700_000_000,
        "bits": "1d00ffff",
        "nonce": 7,
        "hash": "00" * 32,
        "height": 42,
        "auxpow": {
            "parent_block": {
                "version": 1,
                "previousblockhash": "33" * 32,
                "merkleroot": "44" * 32,
                "time": 1_700_000_001,
                "bits": "1d00ffff",
                "nonce": 8,
                "hash": "55" * 32,
            },
            "coinbasetx": {"vin": [{"coinbase": "00"}], "vout": []},
        },
    }
    input_path = tmp_path / "chain.jsonl.gz"
    with gzip.open(input_path, "wt") as handle:
        handle.write(json.dumps(record) + "\n")

    with pytest.raises(ChildHeaderValidationError, match="child header hash mismatch"):
        getattr(mod, loader_name)(input_path)


def test_xaya_child_fields_use_pure_header_and_powdata_nbits():
    mod = _load_script("extract_xaya_auxpow")
    header_nbits = 0
    powdata_nbits = 0x1B123456
    pure_header = (
        struct.pack("<i", 0x100)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", 1_700_000_000, header_nbits, 7)
    )
    block_prefix = (
        pure_header + bytes([mod.FLAG_MERGE_MINED]) + struct.pack("<I", powdata_nbits)
    )

    parsed = mod.parse_xaya_block(block_prefix)

    assert parsed is not None
    assert parsed["merge_mined"] is True
    assert parsed["auxpow"] is None
    assert parsed["child_height"] is None
    assert parsed["child_fields"] == {
        "child_block_hash": hash_from_header_bytes(pure_header).hex(),
        "child_header_hex": pure_header.hex(),
        "child_block_time": 1_700_000_000,
        "child_nbits": "1b123456",
    }


def test_xaya_non_merge_mined_prefix_has_no_child_evidence_row():
    mod = _load_script("extract_xaya_auxpow")
    pure_header = b"\x00" * 80
    parsed = mod.parse_xaya_block(pure_header + b"\x00" + b"\x00" * 4)

    assert parsed == {
        "merge_mined": False,
        "auxpow": None,
        "child_fields": None,
        "child_height": None,
    }


def _minimal_coinbase(height: int) -> bytes:
    height_bytes = height.to_bytes(3, "little")
    scriptsig = bytes([len(height_bytes)]) + height_bytes
    return (
        struct.pack("<i", 1)
        + b"\x01"
        + b"\x00" * 32
        + struct.pack("<I", 0xFFFFFFFF)
        + bytes([len(scriptsig)])
        + scriptsig
        + struct.pack("<I", 0xFFFFFFFF)
        + b"\x01"
        + struct.pack("<Q", 1)
        + b"\x00"
        + struct.pack("<I", 0)
    )


def _xaya_block_with_child_coinbase(mod, child_coinbase: bytes) -> bytes:
    pure_header = (
        struct.pack("<i", 0x100)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", 1_700_000_000, 0, 7)
    )
    parent_header = (
        struct.pack("<i", 1)
        + b"\x33" * 32
        + b"\x44" * 32
        + struct.pack("<III", 1_700_000_001, 0x1D00FFFF, 8)
    )
    auxpow = (
        _minimal_coinbase(500_000)
        + b"\x00" * 32
        + b"\x00"
        + struct.pack("<i", 0)
        + b"\x00"
        + struct.pack("<i", 0)
        + parent_header
    )
    return (
        pure_header
        + bytes([mod.FLAG_MERGE_MINED])
        + struct.pack("<I", 0x1B123456)
        + auxpow
        + b"\x01"
        + child_coinbase
    )


def test_xaya_child_height_comes_from_consensus_coinbase_not_scan_order():
    mod = _load_script("extract_xaya_auxpow")
    child_height = 2_840_038

    parsed = mod.parse_xaya_block(
        _xaya_block_with_child_coinbase(mod, _minimal_coinbase(child_height))
    )

    assert parsed is not None
    assert parsed["auxpow"] is not None
    assert parsed["child_height"] == child_height


def test_xaya_rejects_child_transaction_without_bip34_height():
    mod = _load_script("extract_xaya_auxpow")
    malformed_child_coinbase = bytearray(_minimal_coinbase(1))
    malformed_child_coinbase[42] = 0

    with pytest.raises(
        ChildHeaderValidationError,
        match="Xaya child coinbase lacks its consensus BIP34 height",
    ):
        mod.parse_xaya_block(
            _xaya_block_with_child_coinbase(mod, malformed_child_coinbase)
        )


def _write_xaya_blkdat(path: Path, mod, *blocks: bytes) -> None:
    path.write_bytes(
        b"".join(
            mod.XAYA_MAGIC + struct.pack("<I", len(block)) + block for block in blocks
        )
    )


def _set_xaya_main_argv(
    monkeypatch: pytest.MonkeyPatch, blocks_dir: Path, output_path: Path
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "extract_xaya_auxpow.py",
            "--blocks-dir",
            str(blocks_dir),
            "--output",
            str(output_path),
            "--all-headers",
        ],
    )


def test_xaya_main_publishes_exact_height(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mod = _load_script("extract_xaya_auxpow")
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    valid_height = 2_840_038
    _write_xaya_blkdat(
        blocks_dir / "blk00000.dat",
        mod,
        _xaya_block_with_child_coinbase(mod, _minimal_coinbase(valid_height)),
    )
    output_path = tmp_path / "xaya.csv"
    _set_xaya_main_argv(monkeypatch, blocks_dir, output_path)

    mod.main()

    with output_path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["child_height"] for row in rows] == [str(valid_height)]


def test_xaya_main_fails_closed_after_malformed_height(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mod = _load_script("extract_xaya_auxpow")
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    malformed_coinbase = bytearray(_minimal_coinbase(1))
    malformed_coinbase[42] = 0
    valid_height = 2_840_038
    _write_xaya_blkdat(
        blocks_dir / "blk00000.dat",
        mod,
        _xaya_block_with_child_coinbase(mod, malformed_coinbase),
        _xaya_block_with_child_coinbase(mod, _minimal_coinbase(valid_height)),
    )
    output_path = tmp_path / "xaya.csv"
    output_path.write_text("last good output\n")
    _set_xaya_main_argv(monkeypatch, blocks_dir, output_path)

    with pytest.raises(
        mod.XayaChildHeightError,
        match="1 merge-mined Xaya blocks lacked an exact BIP34 child height",
    ):
        mod.main()

    assert output_path.read_text() == "last good output\n"
    assert not list(tmp_path.glob(".xaya.csv.*.tmp"))


def test_xaya_main_preserves_output_on_child_header_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mod = _load_script("extract_xaya_auxpow")
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    _write_xaya_blkdat(blocks_dir / "blk00000.dat", mod, b"candidate")
    output_path = tmp_path / "xaya.csv"
    output_path.write_text("last good output\n")
    _set_xaya_main_argv(monkeypatch, blocks_dir, output_path)

    def fail(_block_data: bytes):
        raise ChildHeaderValidationError("corrupt child header")

    monkeypatch.setattr(mod, "parse_xaya_block", fail)
    with pytest.raises(ChildHeaderValidationError, match="corrupt child header"):
        mod.main()

    assert output_path.read_text() == "last good output\n"
    assert not list(tmp_path.glob(".xaya.csv.*.tmp"))


def _set_huntercoin_main_argv(
    monkeypatch: pytest.MonkeyPatch,
    *,
    blocks_dir: Path,
    index_path: Path,
    output_path: Path,
    failures_path: Path | None = None,
) -> None:
    argv = [
        "extract_huntercoin_auxpow.py",
        "--blocks-dir",
        str(blocks_dir),
        "--index",
        str(index_path),
    ]
    if failures_path is not None:
        argv.extend(["--failures", str(failures_path)])
    argv.extend(["--output", str(output_path)])
    monkeypatch.setattr(sys, "argv", argv)


def test_huntercoin_main_reports_height_and_file_on_hash_contradiction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mod = _load_script("extract_huntercoin_auxpow")
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    block_path = blocks_dir / "block-7.bin"
    block_path.write_bytes(
        struct.pack("<i", (mod.HUC_CHAIN_ID_SHA256 << 16) | mod.VERSION_AUXPOW)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", 1_700_000_000, 0x1D00FFFF, 7)
    )
    index_path = tmp_path / "index.csv"
    index_path.write_text("height,block_hash\n7," + "00" * 32 + "\n")
    output_path = tmp_path / "output.csv"
    output_path.write_text("last good output\n")
    _set_huntercoin_main_argv(
        monkeypatch,
        blocks_dir=blocks_dir,
        index_path=index_path,
        output_path=output_path,
    )

    with pytest.raises(
        ChildHeaderValidationError,
        match=r"Huntercoin h=7 \(block-7\.bin\): child header hash mismatch",
    ):
        mod.main()
    assert output_path.read_text() == "last good output\n"


def test_huntercoin_main_requires_source_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mod = _load_script("extract_huntercoin_auxpow")
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    _set_huntercoin_main_argv(
        monkeypatch,
        blocks_dir=blocks_dir,
        index_path=tmp_path / "missing-index.csv",
        output_path=tmp_path / "output.csv",
    )

    assert mod.main() == 1


def test_huntercoin_main_rejects_malformed_source_index_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mod = _load_script("extract_huntercoin_auxpow")
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    index_path = tmp_path / "index.csv"
    index_path.write_text("height,block_hash\nnot-a-height," + "00" * 32 + "\n")
    _set_huntercoin_main_argv(
        monkeypatch,
        blocks_dir=blocks_dir,
        index_path=index_path,
        output_path=tmp_path / "output.csv",
    )

    with pytest.raises(
        ChildHeaderValidationError,
        match="Huntercoin source index row 2 has invalid height",
    ):
        mod.main()


def test_huntercoin_main_rejects_source_height_missing_from_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mod = _load_script("extract_huntercoin_auxpow")
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    (blocks_dir / "block-7.bin").write_bytes(
        struct.pack("<i", (mod.HUC_CHAIN_ID_SHA256 << 16) | mod.VERSION_AUXPOW)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", 1_700_000_000, 0x1D00FFFF, 7)
    )
    index_path = tmp_path / "index.csv"
    index_path.write_text("height,block_hash\n")
    _set_huntercoin_main_argv(
        monkeypatch,
        blocks_dir=blocks_dir,
        index_path=index_path,
        output_path=tmp_path / "output.csv",
    )

    with pytest.raises(
        ChildHeaderValidationError,
        match="source index has no block hash for this height",
    ):
        mod.main()


def test_huntercoin_main_rejects_index_height_missing_block_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mod = _load_script("extract_huntercoin_auxpow")
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    index_path = tmp_path / "index.csv"
    index_path.write_text("height,block_hash\n7," + "00" * 32 + "\n")
    output_path = tmp_path / "output.csv"
    output_path.write_text("last good output\n")
    _set_huntercoin_main_argv(
        monkeypatch,
        blocks_dir=blocks_dir,
        index_path=index_path,
        output_path=output_path,
    )

    with pytest.raises(
        ChildHeaderValidationError,
        match="source index contains 1 heights without block binaries",
    ):
        mod.main()

    assert output_path.read_text() == "last good output\n"


def test_huntercoin_main_accepts_exact_documented_acquisition_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    mod = _load_script("extract_huntercoin_auxpow")
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    index_path = tmp_path / "index.csv"
    index_path.write_text(
        "height,txid,block_hash\n7,arweave-transaction," + "00" * 32 + "\n"
    )
    failures_path = tmp_path / "failures.csv"
    failures_path.write_text(
        "height,txid,error\n7,arweave-transaction,all gateways failed\n"
    )
    output_path = tmp_path / "output.csv"
    _set_huntercoin_main_argv(
        monkeypatch,
        blocks_dir=blocks_dir,
        index_path=index_path,
        failures_path=failures_path,
        output_path=output_path,
    )

    assert mod.main() == 0
    assert (
        "Authenticated 1 documented Arweave acquisition gaps" in capsys.readouterr().out
    )
    with output_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == mod.CSV_COLUMNS
        assert list(reader) == []


def test_huntercoin_main_rejects_failure_manifest_txid_contradiction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mod = _load_script("extract_huntercoin_auxpow")
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    index_path = tmp_path / "index.csv"
    index_path.write_text(
        "height,txid,block_hash\n7,index-transaction," + "00" * 32 + "\n"
    )
    failures_path = tmp_path / "failures.csv"
    failures_path.write_text(
        "height,txid,error\n7,different-transaction,all gateways failed\n"
    )
    _set_huntercoin_main_argv(
        monkeypatch,
        blocks_dir=blocks_dir,
        index_path=index_path,
        failures_path=failures_path,
        output_path=tmp_path / "output.csv",
    )

    with pytest.raises(
        ChildHeaderValidationError,
        match="failure manifest transaction ID contradicts",
    ):
        mod.main()


def test_huntercoin_authenticates_non_auxpow_block_before_skipping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mod = _load_script("extract_huntercoin_auxpow")
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    block_path = blocks_dir / "block-7.bin"
    block_path.write_bytes(
        struct.pack("<i", 1)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", 1_700_000_000, 0x1D00FFFF, 7)
    )
    index_path = tmp_path / "index.csv"
    index_path.write_text("height,block_hash\n7," + "00" * 32 + "\n")
    _set_huntercoin_main_argv(
        monkeypatch,
        blocks_dir=blocks_dir,
        index_path=index_path,
        output_path=tmp_path / "output.csv",
    )

    with pytest.raises(
        ChildHeaderValidationError,
        match=r"Huntercoin h=7 \(block-7\.bin\): child header hash mismatch",
    ):
        mod.main()


def test_terracoin_rejects_malformed_rpc_child_header(tmp_path: Path):
    mod = _load_script("extract_terracoin_auxpow")

    class FakeRpc:
        def __init__(self):
            self.calls = 0

        def batch(self, _calls):
            self.calls += 1
            if self.calls == 1:
                return [{"id": 0, "result": "11" * 32}]
            return [
                {
                    "id": 0,
                    "result": {
                        "version": 1,
                        "merkleroot": "22" * 32,
                        "time": 1_700_000_000,
                        "bits": "1d00ffff",
                        "nonce": 7,
                        "auxpow": {"parentblock": "00" * 80},
                    },
                }
            ]

    output = tmp_path / "terracoin.csv"
    stats = {"auxpow_blocks": 0, "skipped_no_auxpow": 0, "skipped_bad_header": 0}
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=mod.CSV_COLUMNS)
        writer.writeheader()
        with pytest.raises(
            ChildHeaderValidationError,
            match="Terracoin h=10: malformed RPC child-header fields",
        ):
            mod.extract_range(10, 11, writer, stats, FakeRpc())


def test_coverage_report_counts_authenticated_and_missing_rows(tmp_path: Path):
    mod = _load_repo_script("scripts/reports/report_child_header_coverage.py")
    header = (
        struct.pack("<i", 1)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", 1_700_000_000, 0x1D00FFFF, 7)
    )
    artifact = tmp_path / "devcoin_monitor_evidence.csv"
    fields = [*mod.CHILD_HEADER_FIELDS, "btc_header_hash", "btc_time"]
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "child_block_hash": hash_from_header_bytes(header).hex(),
                "child_header_hex": header.hex(),
                "child_block_time": "1700000000",
                "child_nbits": "1d00ffff",
                "btc_header_hash": "aa" * 32,
                "btc_time": "1699999990",
            }
        )
        writer.writerow({field: "" for field in fields})

    row = mod.summarize_artifact("devcoin", artifact)

    assert row["total_rows"] == "2"
    assert row["hydrated_rows"] == "1"
    assert row["unrecoverable_rows"] == "1"
    assert row["unrecoverable_reasons"] == '{"missing_child_header_evidence":1}'
    assert row["min_child_time"] == "1700000000"
    assert row["max_child_time"] == "1700000000"
    assert row["child_parent_delta_status"] == "non_degenerate"
    assert row["child_parent_delta_coverage"] == "1/1"
    assert row["min_child_parent_delta"] == "10"


def test_coverage_report_authenticates_populated_fields_in_incomplete_bundle(
    tmp_path: Path,
):
    mod = _load_repo_script("scripts/reports/report_child_header_coverage.py")
    header = (
        struct.pack("<i", 1)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", 1_700_000_000, 0x1D00FFFF, 7)
    )
    artifact = tmp_path / "devcoin_monitor_evidence.csv"
    fields = [*mod.CHILD_HEADER_FIELDS, "btc_header_hash"]
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "child_block_hash": "00" * 32,
                "child_header_hex": header.hex(),
                "child_block_time": "1700000000",
                "child_nbits": "",
                "btc_header_hash": "aa" * 32,
            }
        )

    with pytest.raises(
        ChildHeaderValidationError,
        match=r":2: child_header_hex does not match child_block_hash",
    ):
        mod.summarize_artifact("devcoin", artifact)


def test_coverage_report_loads_each_accepted_descendant_source_observation(
    tmp_path: Path,
):
    mod = _load_repo_script("scripts/reports/report_child_header_coverage.py")
    path = tmp_path / "stale_descendant_observations.csv"
    path.write_bytes(
        (REPO_ROOT / "data/stale_descendant_observations.csv").read_bytes()
    )

    observations = mod.load_stale_descendant_observations(path)

    assert len(observations["devcoin"]) == 3
    assert len(observations["ixcoin"]) == 3
    assert sum(map(len, observations.values())) == 6


def test_coverage_report_requires_stale_descendant_input(tmp_path: Path):
    mod = _load_repo_script("scripts/reports/report_child_header_coverage.py")
    missing = tmp_path / "missing-stale-descendants.csv"

    with pytest.raises(
        FileNotFoundError,
        match="stale-descendant coverage input is not a readable file",
    ):
        mod.load_stale_descendant_observations(missing)


def test_coverage_report_accounts_for_accepted_descendant_observations(
    tmp_path: Path,
):
    mod = _load_repo_script("scripts/reports/report_child_header_coverage.py")
    child_header = (
        struct.pack("<i", 1)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", 1_700_000_000, 0x1D00FFFF, 7)
    )
    parent_hash = "33" * 32
    artifact = tmp_path / "devcoin_evidence.csv"
    fields = [*mod.CHILD_HEADER_FIELDS, "btc_header_hash", "btc_time"]
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "child_block_hash": hash_from_header_bytes(child_header).hex(),
                "child_header_hex": child_header.hex(),
                "child_block_time": "1700000000",
                "child_nbits": "1d00ffff",
                "btc_header_hash": parent_hash,
                "btc_time": "1699999990",
            }
        )

    row = mod.summarize_artifact("devcoin", artifact, frozenset({parent_hash}))

    assert row["stale_descendant_observations"] == "1"
    assert row["hydrated_stale_descendant_observations"] == "1"
    assert row["unrecoverable_stale_descendant_observations"] == "0"
    assert row["stale_descendant_unrecoverable_reasons"] == "{}"


def test_coverage_report_surfaces_missing_descendant_observation(tmp_path: Path):
    mod = _load_repo_script("scripts/reports/report_child_header_coverage.py")
    artifact = tmp_path / "devcoin_evidence.csv"
    artifact.write_text(",".join([*mod.CHILD_HEADER_FIELDS, "btc_header_hash"]) + "\n")

    row = mod.summarize_artifact("devcoin", artifact, frozenset({"33" * 32}))

    assert row["stale_descendant_observations"] == "1"
    assert row["hydrated_stale_descendant_observations"] == "0"
    assert row["unrecoverable_stale_descendant_observations"] == "1"
    assert row["stale_descendant_unrecoverable_reasons"] == (
        '{"artifact_row_missing":1}'
    )


def test_coverage_report_rejects_git_lfs_pointer(tmp_path: Path):
    mod = _load_repo_script("scripts/reports/report_child_header_coverage.py")
    artifact = tmp_path / "devcoin_monitor_evidence.csv"
    artifact.write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:" + "00" * 32 + "\n"
        "size 123\n"
    )

    with pytest.raises(
        ValueError, match="Git LFS evidence payload is not materialized"
    ):
        mod.summarize_artifact("devcoin", artifact)


def test_coverage_report_rejects_ambiguous_artifact_families(tmp_path: Path):
    mod = _load_repo_script("scripts/reports/report_child_header_coverage.py")
    (tmp_path / "devcoin_evidence.csv").write_text("child_block_hash\n")
    (tmp_path / "devcoin_monitor_evidence.csv").write_text("child_block_hash\n")

    with pytest.raises(ValueError, match="ambiguous child-header coverage input"):
        mod._artifact_path(tmp_path, "devcoin")


def test_coverage_report_marks_missing_parent_time_as_incomplete(tmp_path: Path):
    mod = _load_repo_script("scripts/reports/report_child_header_coverage.py")
    header = (
        struct.pack("<i", 1)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", 1_700_000_000, 0x1D00FFFF, 7)
    )
    artifact = tmp_path / "devcoin_monitor_evidence.csv"
    fields = [*mod.CHILD_HEADER_FIELDS, "btc_header_hash", "btc_time"]
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "child_block_hash": hash_from_header_bytes(header).hex(),
                "child_header_hex": header.hex(),
                "child_block_time": "1700000000",
                "child_nbits": "1d00ffff",
                "btc_header_hash": "aa" * 32,
                "btc_time": "",
            }
        )

    row = mod.summarize_artifact("devcoin", artifact)

    assert row["child_parent_delta_status"] == "incomplete"
    assert row["child_parent_delta_coverage"] == "0/1"
    assert row["min_child_parent_delta"] == ""
    assert row["max_child_parent_delta"] == ""


def test_coverage_report_rejects_malformed_parent_time(tmp_path: Path):
    mod = _load_repo_script("scripts/reports/report_child_header_coverage.py")
    header = (
        struct.pack("<i", 1)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", 1_700_000_000, 0x1D00FFFF, 7)
    )
    artifact = tmp_path / "devcoin_monitor_evidence.csv"
    fields = [*mod.CHILD_HEADER_FIELDS, "btc_header_hash", "btc_time"]
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "child_block_hash": hash_from_header_bytes(header).hex(),
                "child_header_hex": header.hex(),
                "child_block_time": "1700000000",
                "child_nbits": "1d00ffff",
                "btc_header_hash": "aa" * 32,
                "btc_time": "not-a-timestamp",
            }
        )

    with pytest.raises(ValueError, match=r":2: btc_time must be an integer"):
        mod.summarize_artifact("devcoin", artifact)


def test_coverage_report_keeps_previous_output_on_contradiction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mod = _load_repo_script("scripts/reports/report_child_header_coverage.py")
    monkeypatch.setattr(mod, "HISTORICAL_CHILD_HEADER_CHAINS", ("devcoin",))
    artifact = tmp_path / "devcoin_evidence.csv"
    fields = [*mod.CHILD_HEADER_FIELDS, "btc_header_hash", "btc_time"]
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "child_block_hash": "00" * 32,
                "child_header_hex": "00" * 80,
                "child_block_time": "0",
                "child_nbits": "00000000",
                "btc_header_hash": "aa" * 32,
                "btc_time": "0",
            }
        )
    output = tmp_path / "coverage.csv"
    output.write_text("last good report\n")

    with pytest.raises(ChildHeaderValidationError, match=r":2: child_header_hex"):
        mod.build_report(tmp_path, output)

    assert output.read_text() == "last good report\n"
    assert not list(tmp_path.glob(".coverage.csv.*.tmp"))
