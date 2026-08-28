"""Unit tests for the shared batched-RPC extraction driver.

No network: ``_FakeRpc`` below implements only ``RpcClient.batch()`` and
serves a tiny synthetic chain from an in-memory dict of raw block hex. The
scenario exercises the gate hook, the parse-row hook, multi-height batching,
a batch-level RPC failure recovered by the per-height retry, and the
append/resume path, then asserts the written CSV bytes.
"""

from __future__ import annotations

import csv
import importlib.util
import struct
from pathlib import Path

import pytest

from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.auxpow_parse import (
    CHILD_HEADER_FIELDS,
    ChildHeaderValidationError,
    parse_parent_header,
    standard_auxpow_extraction_columns,
)
from stale_blocks_analysis.config import CHAIN_SPECS

CSV_COLUMNS = [
    "height",
    *CHILD_HEADER_FIELDS,
    "btc_header_hash",
    "coinbase_scriptsig_hex",
]

# Sentinel nVersion the synthetic chain's gate treats as "AuxPoW present".
GATE_VERSION = 0x00000101
NON_GATE_VERSION = 0x00000001
REPO = Path(__file__).resolve().parents[1]


def _parent_header(nonce: int) -> bytes:
    """An 80-byte synthetic Bitcoin parent header, varied only by nonce."""
    return (
        struct.pack("<i", 0x20000000)
        + b"\x11" * 32  # prev hash (internal order)
        + b"\x22" * 32  # merkle root (internal order)
        + struct.pack("<I", 1_700_000_000)
        + struct.pack("<I", 0x1D00FFFF)
        + struct.pack("<I", nonce)
    )


def _coinbase_tx_bytes(scriptsig: bytes) -> bytes:
    """A minimal one-input/one-output coinbase transaction, wire-encoded."""
    pkscript = b"\x51"  # OP_TRUE, one byte
    vin = (
        b"\x00" * 32  # prev hash: null (coinbase)
        + struct.pack("<I", 0xFFFFFFFF)  # prev index
        + bytes([len(scriptsig)])
        + scriptsig
        + struct.pack("<I", 0xFFFFFFFF)  # sequence
    )
    vout = struct.pack("<Q", 5_000_000_000) + bytes([len(pkscript)]) + pkscript
    return (
        struct.pack("<i", 1)  # tx version
        + b"\x01"
        + vin  # vin_count=1
        + b"\x01"
        + vout  # vout_count=1
        + struct.pack("<I", 0)  # locktime
    )


def _auxpow_block_hex(version: int, scriptsig: bytes, nonce: int) -> str:
    """A full synthetic child block: 80-byte header + CAuxPow tail.

    The CAuxPow tail matches ``auxpow_parse.read_auxpow``'s expected layout
    exactly: coinbase tx, hashBlock, empty merkle branch, nIndex, empty
    chain merkle branch, nChainIndex, then the 80-byte parent header.
    """
    child_header = struct.pack("<i", version) + b"\x00" * 72 + struct.pack("<I", nonce)
    tail = (
        _coinbase_tx_bytes(scriptsig)
        + b"\x00" * 32  # hashBlock
        + b"\x00"  # empty vMerkleBranch
        + struct.pack("<i", 0)  # nIndex
        + b"\x00"  # empty vChainMerkleBranch
        + struct.pack("<i", 0)  # nChainIndex
        + _parent_header(nonce)
    )
    return (child_header + tail).hex()


def _gate(version: int, stats: dict) -> bool:
    if version != GATE_VERSION:
        stats["skipped_gate"] += 1
        return False
    return True


def _parse_row(height: int, auxpow: dict, child_fields: dict) -> dict:
    parent = parse_parent_header(auxpow["parent_header_raw"])
    scriptsig = auxpow["coinbase_tx"]["vin"][0]["scriptsig"]
    return {
        "height": height,
        **child_fields,
        "btc_header_hash": parent["hash"],
        "coinbase_scriptsig_hex": scriptsig.hex(),
    }


class _FakeRpc:
    """Fake ``child_rpc.RpcClient``: only ``batch()`` is used by the driver.

    ``blocks`` maps height -> raw block hex (``""`` simulates a missing
    block). ``fail_hash_batch_heights`` makes the *first* ``getblockhash``
    attempt raise whenever the batch spans more than one height and
    includes one of those heights, so the driver's retry-individually path
    gets exercised; a size-1 retry batch always succeeds.
    """

    def __init__(self, blocks: dict, fail_hash_batch_heights: set | None = None):
        self.blocks = blocks
        self.fail_hash_batch_heights = fail_hash_batch_heights or set()

    def batch(self, calls: list) -> list:
        method = calls[0]["method"]
        if method == "getblockhash":
            heights = [c["params"][0] for c in calls]
            if len(calls) > 1 and self.fail_hash_batch_heights & set(heights):
                raise RuntimeError("simulated getblockhash batch failure")
            results = []
            for c in calls:
                block_hex = self.blocks.get(c["params"][0], "")
                raw = bytes.fromhex(block_hex)
                block_hash = (
                    parse_parent_header(raw[:80])["hash"]
                    if len(raw) >= 80
                    else f"{c['params'][0]:064x}"
                )
                results.append({"id": c["id"], "result": block_hash})
            return results
        if method == "getblock":
            results = []
            for c in calls:
                expected_hash = c["params"][0]
                height = next(
                    h
                    for h, block_hex in self.blocks.items()
                    if (
                        parse_parent_header(bytes.fromhex(block_hex)[:80])["hash"]
                        if len(bytes.fromhex(block_hex)) >= 80
                        else f"{h:064x}"
                    )
                    == expected_hash
                )
                results.append({"id": c["id"], "result": self.blocks.get(height, "")})
            return results
        raise AssertionError(f"unexpected RPC method in test: {method}")


class _MismatchingHashRpc:
    def __init__(self, block_hex: str):
        self.block_hex = block_hex

    def batch(self, calls: list) -> list:
        if calls[0]["method"] == "getblockhash":
            return [{"id": call["id"], "result": "ff" * 32} for call in calls]
        if calls[0]["method"] == "getblock":
            return [{"id": call["id"], "result": self.block_hex} for call in calls]
        raise AssertionError("unexpected RPC method")


def test_run_extraction_fails_hard_on_child_hash_mismatch(tmp_path: Path) -> None:
    stats = {
        "auxpow_blocks": 0,
        "skipped_empty": 0,
        "skipped_short": 0,
        "skipped_gate": 0,
        "skipped_parse_error": 0,
    }

    with pytest.raises(ChildHeaderValidationError, match="hash mismatch"):
        extract_driver.run_extraction(
            rpc=_MismatchingHashRpc(
                _auxpow_block_hex(GATE_VERSION, b"\x01", nonce=100)
            ),
            start=100,
            end=101,
            batch_size=1,
            output_path=tmp_path / "out.csv",
            csv_columns=CSV_COLUMNS,
            gate=_gate,
            parse_row=_parse_row,
            stats=stats,
            append=False,
        )


def test_run_extraction_rejects_resume_with_an_old_csv_schema(
    tmp_path: Path,
) -> None:
    out_path = tmp_path / "out.csv"
    original = "height,btc_header_hash\n100,abc\n"
    out_path.write_text(original)

    with pytest.raises(ValueError, match="existing CSV header does not match"):
        extract_driver.run_extraction(
            rpc=_FakeRpc({}),
            start=101,
            end=101,
            batch_size=1,
            output_path=out_path,
            csv_columns=CSV_COLUMNS,
            gate=_gate,
            parse_row=_parse_row,
            stats={},
            append=True,
        )

    assert out_path.read_text() == original


def test_run_extraction_gate_parse_batching_retry_and_resume(tmp_path: Path) -> None:
    # Heights 100..105: a normal batch (100-102) and a batch (103-105) whose
    # first getblockhash attempt fails and is retried one height at a time.
    blocks = {
        100: _auxpow_block_hex(GATE_VERSION, b"\x01", nonce=100),
        101: _auxpow_block_hex(NON_GATE_VERSION, b"\x02", nonce=101),  # gate fails
        102: "",  # missing block
        103: "00" * 10,  # short raw (< 80 bytes)
        104: _auxpow_block_hex(GATE_VERSION, b"\x04", nonce=104),
        105: _auxpow_block_hex(GATE_VERSION, b"\x05", nonce=105),
    }
    rpc = _FakeRpc(blocks, fail_hash_batch_heights={103, 104, 105})
    out_path = tmp_path / "out.csv"
    stats = {
        "auxpow_blocks": 0,
        "skipped_empty": 0,
        "skipped_short": 0,
        "skipped_gate": 0,
        "skipped_parse_error": 0,
    }

    result = extract_driver.run_extraction(
        rpc=rpc,
        start=100,
        end=106,
        batch_size=3,
        output_path=out_path,
        csv_columns=CSV_COLUMNS,
        gate=_gate,
        parse_row=_parse_row,
        stats=stats,
        append=False,
    )

    assert result is stats
    assert stats == {
        "auxpow_blocks": 3,
        "skipped_empty": 1,
        "skipped_short": 1,
        "skipped_gate": 1,
        "skipped_parse_error": 0,
    }

    with out_path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert [r["height"] for r in rows] == ["100", "104", "105"]
    assert rows[0]["coinbase_scriptsig_hex"] == "01"
    assert rows[1]["coinbase_scriptsig_hex"] == "04"
    assert rows[2]["coinbase_scriptsig_hex"] == "05"
    assert rows[0]["child_header_hex"] == blocks[100][:160]
    assert rows[0]["child_block_time"] == "0"
    assert rows[0]["child_nbits"] == "00000000"
    # The written hash must match what parse_parent_header derives directly
    # from the same synthetic parent header bytes (adversarial cross-check,
    # not a re-assertion of the row-building code under test).
    expected_hash_100 = parse_parent_header(_parent_header(100))["hash"]
    assert rows[0]["btc_header_hash"] == expected_hash_100

    # --- resume / append -----------------------------------------------
    assert extract_driver.resume_start(out_path, "height", default_start=0) == 106

    blocks[106] = _auxpow_block_hex(GATE_VERSION, b"\x06", nonce=106)
    stats2 = {
        "auxpow_blocks": 0,
        "skipped_empty": 0,
        "skipped_short": 0,
        "skipped_gate": 0,
        "skipped_parse_error": 0,
    }
    extract_driver.run_extraction(
        rpc=rpc,
        start=106,
        end=107,
        batch_size=3,
        output_path=out_path,
        csv_columns=CSV_COLUMNS,
        gate=_gate,
        parse_row=_parse_row,
        stats=stats2,
        append=True,
    )

    text = out_path.read_text()
    assert text.count(",".join(CSV_COLUMNS)) == 1
    with out_path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert [r["height"] for r in rows] == ["100", "104", "105", "106"]


def test_get_chain_tip_uses_a_single_call_batch() -> None:
    calls_seen = []

    class _TipRpc:
        def batch(self, calls):
            calls_seen.extend(calls)
            return [{"id": 0, "result": 4242}]

    assert extract_driver.get_chain_tip(_TipRpc()) == 4242
    assert calls_seen == [
        {"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}
    ]


def test_resume_start_defaults_when_file_missing_or_header_only(tmp_path: Path) -> None:
    missing = tmp_path / "missing.csv"
    assert extract_driver.resume_start(missing, "height", default_start=7) == 7

    header_only = tmp_path / "header_only.csv"
    header_only.write_text("height,btc_header_hash\n")
    assert extract_driver.resume_start(header_only, "height", default_start=7) == 7


def test_fractal_gate_requires_auxpow_flag_and_chain_id() -> None:
    path = REPO / "scripts" / "extract" / "extract_fractal_auxpow.py"
    spec = importlib.util.spec_from_file_location("_extract_fractal_auxpow", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    stats = {"skipped_no_auxpow_flag": 0}

    assert module._gate(0x20240100, stats)
    assert module._gate(0x20240101, stats)
    assert not module._gate(0x20240000, stats)
    assert not module._gate(0x20260100, stats)
    assert not module._gate(0x00000100, stats)
    assert stats["skipped_no_auxpow_flag"] == 3


def test_elastos_tip_uses_current_height_not_block_count() -> None:
    path = REPO / "scripts" / "extract" / "extract_elastos_auxpow.py"
    spec = importlib.util.spec_from_file_location("_extract_elastos_auxpow", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls_seen = []

    class _TipRpc:
        def call(self, method, params):
            calls_seen.append((method, params))
            return 4242

    assert module.get_chain_tip(_TipRpc()) == 4242
    assert calls_seen == [("getcurrentheight", [])]


SHA256D_STATS = (
    "auxpow_blocks",
    "skipped_empty",
    "skipped_short",
    "skipped_non_sha256d",
    "skipped_no_auxpow_flag",
    "skipped_parse_error",
)
FLAG_STATS = (
    "auxpow_blocks",
    "skipped_empty",
    "skipped_short",
    "skipped_no_auxpow_flag",
    "skipped_parse_error",
)
THIN_EXTRACTORS = (
    (
        "extract_argentum_auxpow",
        "argentum",
        "ARG_RPC_PASS",
        SHA256D_STATS,
        0,
        "skipped_non_sha256d",
        ("non-sha256d", "skipped_non_sha256d"),
        "getblock",
    ),
    (
        "extract_bitmark_auxpow",
        "bitmark",
        "BTMK_RPC_PASS",
        SHA256D_STATS,
        0,
        "skipped_non_sha256d",
        ("non-sha256d", "skipped_non_sha256d"),
        "getblock",
    ),
    (
        "extract_crown_auxpow",
        "crown",
        "CRW_RPC_PASS",
        FLAG_STATS,
        1,
        "skipped_no_auxpow_flag",
        ("no-flag", "skipped_no_auxpow_flag"),
        "getblock",
    ),
    (
        "extract_fractal_auxpow",
        "fractal",
        None,
        FLAG_STATS,
        0x20260100,
        "skipped_no_auxpow_flag",
        None,
        "getblockheader",
    ),
    (
        "extract_myriadcoin_auxpow",
        "myriadcoin",
        "XMY_RPC_PASS",
        SHA256D_STATS,
        1 << 9,
        "skipped_non_sha256d",
        ("non-sha256d", "skipped_non_sha256d"),
        "getblock",
    ),
    (
        "extract_unobtanium_auxpow",
        "unobtanium",
        "UNO_RPC_PASS",
        FLAG_STATS,
        1,
        "skipped_no_auxpow_flag",
        None,
        "getblock",
    ),
)


def _load_extractor(name: str):
    path = REPO / "scripts" / "extract" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_wrap_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _ExtractionRecorder:
    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return kwargs["stats"]


def test_standard_auxpow_parse_row_uses_spec_height_column() -> None:
    spec = CHAIN_SPECS["argentum"]
    parent_raw = _parent_header(7)
    auxpow = {
        "parent_header_raw": parent_raw,
        "coinbase_tx": {
            "vin": [{"scriptsig": b""}],
            "vout": [{"value": 1, "pkscript": b"\x51"}],
        },
    }
    child_fields = {
        "child_block_hash": "aa" * 32,
        "child_header_hex": "bb" * 40,
        "child_block_time": "1",
        "child_nbits": "1d00ffff",
    }

    row = extract_driver.standard_auxpow_parse_row(
        spec, 1_825_000, auxpow, child_fields
    )

    parent = parse_parent_header(parent_raw)
    assert row[spec.height_column] == 1_825_000
    assert row["child_block_hash"] == child_fields["child_block_hash"]
    assert row["btc_header_hash"] == parent["hash"]
    assert row["btc_prev_hash"] == parent["prev_hash"]
    assert row["btc_time"] == parent["time"]
    assert row["btc_bits"] == parent["bits_hex"]
    assert row["btc_height"] == ""
    assert row["coinbase_scriptsig_hex"] == ""
    assert row["coinbase_outputs"] == "51"
    assert row["btc_header_hex"] == parent["header_hex"]


def test_standard_extractor_cli_defaults_start_output_and_tip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    spec = CHAIN_SPECS["argentum"]
    rec = _ExtractionRecorder()
    monkeypatch.setattr(extract_driver, "run_extraction", rec)
    monkeypatch.chdir(tmp_path)

    class _TipRpc:
        def batch(self, calls):
            assert calls == [
                {"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}
            ]
            return [{"id": 0, "result": 99}]

    extract_driver.run_standard_extractor_cli(
        [],
        spec,
        rpc=_TipRpc(),
        gate=lambda _version, _stats: True,
        stats_keys=SHA256D_STATS,
    )

    assert len(rec.calls) == 1
    call = rec.calls[0]
    assert call["start"] == spec.activation_height
    assert call["end"] == 100
    assert call["output_path"] == Path("data/argentum_auxpow_raw.csv")
    assert call["append"] is False
    assert list(call["stats"]) == list(SHA256D_STATS)


def test_standard_extractor_cli_resume_uses_spec_height_column(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    spec = CHAIN_SPECS["argentum"]
    rec = _ExtractionRecorder()
    monkeypatch.setattr(extract_driver, "run_extraction", rec)
    out_path = tmp_path / "resume.csv"
    out_path.write_text(f"{spec.height_column},btc_header_hash\n1825010,abc\n")

    extract_driver.run_standard_extractor_cli(
        ["--resume", "--end", "1825020", "--output", str(out_path)],
        spec,
        rpc=object(),
        gate=lambda _version, _stats: True,
        stats_keys=SHA256D_STATS,
    )

    assert len(rec.calls) == 1
    call = rec.calls[0]
    assert call["start"] == 1_825_011
    assert call["end"] == 1_825_020
    assert call["append"] is True
    assert call["output_path"] == out_path


def test_standard_extractor_cli_help_does_not_construct_rpc() -> None:
    called: list[bool] = []

    def factory():
        called.append(True)
        raise AssertionError("rpc factory must not run for --help")

    with pytest.raises(SystemExit) as exc:
        extract_driver.run_standard_extractor_cli(
            ["--help"],
            CHAIN_SPECS["argentum"],
            rpc=factory,
            gate=lambda _version, _stats: True,
            stats_keys=SHA256D_STATS,
        )

    assert exc.value.code == 0
    assert called == []


@pytest.mark.parametrize(
    "module_name,key,password_env,stats_keys,rejected_version,reject_key,progress_extra,fetch_method",
    THIN_EXTRACTORS,
)
def test_thin_extractor_forwards_shared_loop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    module_name: str,
    key: str,
    password_env: str | None,
    stats_keys: tuple[str, ...],
    rejected_version: int,
    reject_key: str,
    progress_extra: tuple[str, str] | None,
    fetch_method: str,
) -> None:
    if password_env is not None:
        monkeypatch.setenv(password_env, "secret")
    if key == "fractal":
        monkeypatch.setenv("FRACTAL_RPC_USER", "fractal")
        monkeypatch.setenv("FRACTAL_RPC_PASSWORD", "secret")
    rec = _ExtractionRecorder()
    monkeypatch.setattr("stale_blocks_analysis.extract_driver.run_extraction", rec)
    module = _load_extractor(module_name)
    out_path = tmp_path / "out.csv"
    spec = CHAIN_SPECS[key]

    module.main(["--start", "10", "--end", "12", "--output", str(out_path)])

    assert len(rec.calls) == 1
    call = rec.calls[0]
    assert call["csv_columns"] == standard_auxpow_extraction_columns(spec.height_column)
    assert call["gate"] is module._gate
    assert list(call["stats"]) == list(stats_keys)
    assert call["append"] is False
    assert call["start"] == 10
    assert call["end"] == 12
    assert call["output_path"] == out_path
    assert call["block_fetch_method"] == fetch_method
    assert call["progress_extra"] == progress_extra
    if key == "fractal":
        assert call["block_fetch_params"] is module._fetch_params
        assert module._fetch_params("ab") == ["ab", False, True]

    gate_stats = {name: 0 for name in stats_keys}
    assert module._gate(rejected_version, gate_stats) is False
    assert gate_stats[reject_key] == 1


@pytest.mark.parametrize(
    "module_name,password_env,message",
    (
        ("extract_argentum_auxpow", "ARG_RPC_PASS", "ARG_RPC_PASS env var not set"),
        ("extract_bitmark_auxpow", "BTMK_RPC_PASS", "BTMK_RPC_PASS env var not set"),
        ("extract_crown_auxpow", "CRW_RPC_PASS", "CRW_RPC_PASS env var not set"),
        ("extract_myriadcoin_auxpow", "XMY_RPC_PASS", "XMY_RPC_PASS env var not set"),
        ("extract_unobtanium_auxpow", "UNO_RPC_PASS", "UNO_RPC_PASS env var not set"),
    ),
)
def test_password_required_extractors_exit_2_when_unset(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    module_name: str,
    password_env: str,
    message: str,
) -> None:
    monkeypatch.delenv(password_env, raising=False)
    rec = _ExtractionRecorder()
    monkeypatch.setattr("stale_blocks_analysis.extract_driver.run_extraction", rec)
    module = _load_extractor(module_name)

    with pytest.raises(SystemExit) as exc:
        module.main(["--start", "1", "--end", "2"])

    assert exc.value.code == 2
    assert message in capsys.readouterr().err
    assert rec.calls == []


@pytest.mark.parametrize(
    "module_name,password_env",
    (
        ("extract_argentum_auxpow", "ARG_RPC_PASS"),
        ("extract_bitmark_auxpow", "BTMK_RPC_PASS"),
        ("extract_crown_auxpow", "CRW_RPC_PASS"),
        ("extract_fractal_auxpow", None),
        ("extract_myriadcoin_auxpow", "XMY_RPC_PASS"),
        ("extract_unobtanium_auxpow", "UNO_RPC_PASS"),
    ),
)
def test_thin_extractor_help_does_not_need_credentials(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    module_name: str,
    password_env: str | None,
) -> None:
    if password_env is not None:
        monkeypatch.delenv(password_env, raising=False)
    monkeypatch.delenv("FRACTAL_RPC_USER", raising=False)
    monkeypatch.delenv("FRACTAL_RPC_PASSWORD", raising=False)
    monkeypatch.delenv("FRACTAL_RPC_PASS", raising=False)
    monkeypatch.delenv("FRACTAL_RPC_COOKIEFILE", raising=False)
    rec = _ExtractionRecorder()
    monkeypatch.setattr("stale_blocks_analysis.extract_driver.run_extraction", rec)
    module = _load_extractor(module_name)

    with pytest.raises(SystemExit) as exc:
        module.main(["--help"])

    assert exc.value.code == 0
    assert "usage:" in capsys.readouterr().out.lower()
    assert rec.calls == []
