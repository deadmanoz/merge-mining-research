from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest

from stale_blocks_analysis.config import BIP65_HEIGHT
from stale_blocks_analysis.auxpow_chainid import (
    hash_from_header_bytes,
    hash_to_display_hex,
)


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "classify"
    / "classify_rsk_stales.py"
)
SPEC = importlib.util.spec_from_file_location("classify_rsk_stales", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
rsk = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rsk
SPEC.loader.exec_module(rsk)


BLOCK_HASH = "11" * 32


def _header(
    prev_hash: str,
    nonce: int,
    bits: int = 0x207FFFFF,
    time: int = 1_700_000_000,
) -> str:
    return (
        struct.pack("<i", 4)
        + bytes.fromhex(prev_hash)[::-1]
        + b"\x11" * 32
        + struct.pack("<I", time)
        + struct.pack("<I", bits)
        + struct.pack("<I", nonce)
    ).hex()


def _header_row(header_hex: str) -> dict[str, str]:
    raw = bytes.fromhex(header_hex)
    return {
        "btc_header_hash": hash_to_display_hex(hash_from_header_bytes(raw)),
        "btc_prev_hash": (raw[4:36][::-1]).hex(),
        "btc_time": str(int.from_bytes(raw[68:72], "little")),
        "btc_bits": f"{int.from_bytes(raw[72:76], 'little'):08x}",
        "btc_header_hex": header_hex,
    }


def _response(*, confirmations: int, height: int = 100) -> dict:
    return {
        "id": 0,
        "result": {
            "hash": BLOCK_HASH,
            "height": height,
            "confirmations": confirmations,
        },
        "error": None,
    }


def test_active_header_distinguishes_active_and_known_side_chain() -> None:
    assert rsk.active_header(_response(confirmations=1), BLOCK_HASH)["height"] == 100
    assert rsk.active_header(_response(confirmations=-1), BLOCK_HASH) is None


def test_rpc_args_use_shared_public_configuration(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "stale_blocks_analysis.btc_rpc._COOKIE_PATHS",
        [str(tmp_path / "no-cookie")],
    )
    monkeypatch.setattr(
        "stale_blocks_analysis.btc_rpc._CONF_PATHS",
        [str(tmp_path / "no-conf")],
    )
    monkeypatch.setenv("BTC_RPC_URL", "http://127.0.0.1:18443")
    monkeypatch.setenv("BITCOIN_RPC_USER", "rsk-user")
    monkeypatch.setenv("BITCOIN_RPC_PASSWORD", "rsk-password")

    args = rsk.parse_args([])
    client = rsk.rpc_from_args(args)

    assert args.rpc_url == "http://127.0.0.1:18443"
    assert client.url == args.rpc_url
    assert client.auth == ("rsk-user", "rsk-password")
    assert not hasattr(rsk, "AUTH")


def test_active_header_requires_valid_height_and_matching_hash() -> None:
    bad_height = _response(confirmations=1)
    bad_height["result"]["height"] = "100"
    with pytest.raises(ValueError, match="valid height"):
        rsk.active_header(bad_height, BLOCK_HASH, require_height=True)

    mismatched = _response(confirmations=1)
    mismatched["result"]["hash"] = "22" * 32
    with pytest.raises(ValueError, match="hash mismatch"):
        rsk.active_header(mismatched, BLOCK_HASH)


def test_canonical_hash_rejects_rpc_errors_and_malformed_results() -> None:
    assert rsk.canonical_hash({"result": BLOCK_HASH, "error": None}, 100) == BLOCK_HASH
    with pytest.raises(RuntimeError, match="getblockhash failed"):
        rsk.canonical_hash(
            {"result": None, "error": {"code": -8, "message": "out of range"}},
            100,
        )
    with pytest.raises(ValueError, match="malformed hash"):
        rsk.canonical_hash({"result": "not-a-hash", "error": None}, 100)


def test_stale_validation_rejects_signed_negative_post_bip65_version() -> None:
    row = {
        "btc_bits": "17275a1f",
        "btc_header_hex": (bytes.fromhex("000000a0") + b"\x00" * 76).hex(),
    }

    row["btc_time"] = "1001"
    error = rsk.stale_validation_error(row, BIP65_HEIGHT, "17275a1f", 1000)

    assert error is not None
    assert "required 4 after BIP65" in error


def test_stale_validation_rejects_median_time_past_failure() -> None:
    row = {
        "btc_bits": "17275a1f",
        "btc_time": "1000",
        "btc_header_hex": (bytes.fromhex("00000020") + b"\x00" * 76).hex(),
    }

    error = rsk.stale_validation_error(row, BIP65_HEIGHT, "17275a1f", 1000)

    assert error is not None
    assert "median-time-past" in error


def test_rejected_rows_route_to_error_block_or_unknown() -> None:
    # One height past BIP65 (and not a retarget-epoch start), so the version
    # minimum is 4 and the unapplied-retarget rule is not in play.
    height = BIP65_HEIGHT + 1
    parent_mtp = 1_700_000_000

    # Proven consensus violation: header time is not above the parent's MTP.
    violation = _header_row(_header("22" * 32, 1, time=parent_mtp))
    # Contamination: full proof of work, but not Bitcoin's difficulty here.
    contamination = _header_row(
        _header("22" * 32, 2, bits=0x1D00FFFF, time=parent_mtp + 1)
    )
    clean = _header_row(_header("22" * 32, 3, time=parent_mtp + 1))

    verified, stale_rows, error_blocks, rerouted_unknowns = rsk.gate_and_route(
        [
            (height, violation, parent_mtp),
            (height, contamination, parent_mtp),
            (height, clean, parent_mtp),
        ],
        {height: "207fffff"},
    )

    assert [row for _, row in error_blocks] == [violation]
    assert "median-time-past" in violation["validation_status"]
    assert [row for _, row in rerouted_unknowns] == [contamination]
    assert [row for _, row in stale_rows] == [clean]
    assert [row for _, row in verified] == [clean]
    assert clean["validation_status"] == "VALID"


def test_row_to_out_preserves_miner_evidence_without_pool_attribution() -> None:
    row = {
        "btc_header_hash": "11" * 32,
        "btc_prev_hash": "22" * 32,
        "btc_time": "1000",
        "btc_bits": "17275a1f",
        "rsk_height": "123",
        "rsk_timestamp": "1001",
        "rsk_miner": "33" * 20,
        "merge_mining_hash": "44" * 32,
        "btc_header_hex": "00" * 80,
        "coinbase_op_return": "",
        "coinbase_ascii_strings": "",
    }

    output = rsk.row_to_out(row, "unknown")

    assert output["rsk_miner"] == row["rsk_miner"]
    assert "pool_label" not in output
    assert "pool_label" not in rsk.OUT_COLS


def test_candidate_header_is_corroborated_and_self_pow_checked() -> None:
    passing = next(
        row
        for nonce in range(10_000)
        if rsk.validate_candidate_header(
            row := _header_row(_header("22" * 32, nonce)), nonce + 2
        )["meets_pow"]
    )
    assert rsk.validate_candidate_header(passing, 2)["meets_pow"] is True

    mismatched = dict(passing)
    mismatched["btc_prev_hash"] = "33" * 32
    with pytest.raises(ValueError, match="btc_prev_hash does not match"):
        rsk.validate_candidate_header(mismatched, 2)

    failing = next(
        row
        for nonce in range(10_000)
        if not rsk.validate_candidate_header(
            row := _header_row(_header("22" * 32, nonce)), nonce + 2
        )["meets_pow"]
    )
    assert rsk.validate_candidate_header(failing, 2)["meets_pow"] is False


def test_validated_rows_apply_exact_key_exclusions_and_historical_labels() -> None:
    base = {
        "btc_header_hash": "11" * 32,
        "btc_prev_hash": "22" * 32,
        "btc_time": "1000",
        "btc_bits": "17275a1f",
        "btc_header_hex": "00" * 80,
        "rsk_height": "123",
        "rsk_timestamp": "1001",
        "rsk_miner": "AA" * 20,
        "merge_mining_hash": "44" * 32,
        "coinbase_op_return": "",
        "coinbase_ascii_strings": "",
        "expected_nbits": "17275a1f",
    }
    other = {**base, "btc_header_hash": "33" * 32, "rsk_height": "124"}

    rows = rsk.build_validated_rows(
        [(500, base), (501, other)],
        {("aa" * 20): "Historical Pool"},
        {(500, "11" * 32)},
    )

    assert len(rows) == 1
    assert rows[0]["btc_height"] == "501"
    assert rows[0]["validation_status"] == "VALID"
    assert rows[0]["pool_label"] == "Historical Pool"
    assert list(rows[0]) == rsk.VALIDATED_COLS
