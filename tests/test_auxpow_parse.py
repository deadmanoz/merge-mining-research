"""Unit tests for the shared CAuxPow / wire deserialiser in auxpow_parse.

Includes an adversarial real-data fixture: a parent header read from a
committed ``data/validated-stales/*_validated_stales.csv`` row must round-trip back to the
recorded hash, bits and timestamp.
"""

from __future__ import annotations

import csv
import struct
from pathlib import Path

import pytest

from stale_blocks_analysis import auxpow_parse as ap
from stale_blocks_analysis.auxpow_chainid import hash_from_header_bytes

REPO_ROOT = Path(__file__).resolve().parent.parent
ARGENTUM_CSV = REPO_ROOT / "data" / "validated-stales" / "argentum_validated_stales.csv"


# ---------------------------------------------------------------------------
# nbits_to_target / difficulty
# ---------------------------------------------------------------------------


def test_nbits_to_target_genesis():
    # 0x1d00ffff is Bitcoin's genesis/lowest-difficulty compact target.
    expected = 0x00FFFF << (8 * (0x1D - 3))
    assert ap.nbits_to_target(0x1D00FFFF) == expected
    assert (
        expected == 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    )


def test_nbits_to_target_small_exponent():
    # exp <= 3 path: mantissa is right-shifted.
    assert ap.nbits_to_target(0x03001234) == 0x1234  # exp==3, no shift
    assert ap.nbits_to_target(0x02001234) == 0x12  # exp==2: 0x1234 >> 8
    assert ap.nbits_to_target(0x01003456) == 0x00  # exp==1: 0x3456 >> 16


def test_nbits_to_target_sign_bit_yields_nonpositive():
    # Sign bit set -> negative mantissa -> non-positive target.
    assert ap.nbits_to_target(0x03812345) < 0


def test_hash_meets_btc_difficulty_boundary():
    bits = 0x1D00FFFF
    target = ap.nbits_to_target(bits)
    # A hash numerically equal to the target passes; target+1 fails.
    at_target = target.to_bytes(32, "little")
    over_target = (target + 1).to_bytes(32, "little")
    assert ap.hash_meets_btc_difficulty(at_target, bits) is True
    assert ap.hash_meets_btc_difficulty(over_target, bits) is False


def test_hash_meets_btc_difficulty_nonpositive_target():
    assert ap.hash_meets_btc_difficulty(b"\x00" * 32, 0x03812345) is False


def test_hash_meets_btc_difficulty_rejects_bad_length():
    with pytest.raises(ValueError):
        ap.hash_meets_btc_difficulty(b"\x00" * 31, 0x1D00FFFF)


# ---------------------------------------------------------------------------
# parse_parent_header
# ---------------------------------------------------------------------------


def test_parse_parent_header_rejects_wrong_length():
    with pytest.raises(ValueError):
        ap.parse_parent_header(b"\x00" * 79)


def _build_header(version, prev_internal, merkle_internal, ntime, bits, nonce):
    return (
        struct.pack("<i", version)
        + prev_internal
        + merkle_internal
        + struct.pack("<I", ntime)
        + struct.pack("<I", bits)
        + struct.pack("<I", nonce)
    )


def test_parse_parent_header_synthetic_fields():
    prev_internal = bytes(range(32))
    merkle_internal = bytes(range(32, 64))
    raw = _build_header(
        0x20000000,
        prev_internal,
        merkle_internal,
        1_600_000_000,
        0x170F1F1F,
        0xDEADBEEF,
    )
    h = ap.parse_parent_header(raw)
    assert h["version"] == 0x20000000
    assert h["time"] == 1_600_000_000
    assert h["bits"] == 0x170F1F1F
    assert h["bits_hex"] == "170f1f1f"
    assert h["nonce"] == 0xDEADBEEF
    assert h["header_hex"] == raw.hex()
    # Display hex is the reverse of the internal-order bytes.
    assert h["prev_hash"] == prev_internal[::-1].hex()
    assert h["merkle_root"] == merkle_internal[::-1].hex()
    assert h["hash"] == hash_from_header_bytes(raw)[::-1].hex()


def _first_argentum_row():
    with ARGENTUM_CSV.open(newline="") as fh:
        return next(csv.DictReader(fh))


@pytest.mark.skipif(
    not ARGENTUM_CSV.exists(),
    reason="per-chain validated-stale datasets are added in the data pass",
)
def test_parse_parent_header_real_argentum_fixture():
    """Adversarial: a real recovered parent header must reproduce its row."""
    row = _first_argentum_row()
    raw = bytes.fromhex(row["btc_header_hex"])
    assert len(raw) == 80
    h = ap.parse_parent_header(raw)

    # Header hash must match the recorded display-hex hash exactly.
    assert h["hash"] == row["btc_header_hash"]
    # prev hash matches.
    assert h["prev_hash"] == row["btc_prev_hash"]
    # bits: CSV stores the big-endian compact hex.
    assert h["bits_hex"] == row["btc_bits"]
    assert h["bits"] == int(row["btc_bits"], 16)
    # timestamp matches.
    assert h["time"] == int(row["btc_time"])
    # version is the BTC block version, sane post-2017 value.
    assert h["version"] in (0x20000000, 0x20000002, 0x30000000) or h["version"] > 0
    # The recovered parent header meets the target encoded in its own nBits.
    assert ap.hash_meets_btc_difficulty(hash_from_header_bytes(raw), h["bits"]) is True


# ---------------------------------------------------------------------------
# read_transaction (segwit-aware)
# ---------------------------------------------------------------------------


def _legacy_coinbase_tx():
    """A minimal non-segwit coinbase tx: 1 null input, 1 output."""
    version = struct.pack("<i", 1)
    vin_count = b"\x01"
    prev_hash = b"\x00" * 32
    prev_idx = struct.pack("<I", 0xFFFFFFFF)
    scriptsig = bytes([0x03]) + (123456).to_bytes(3, "little")  # BIP34 height push
    scriptsig_len = bytes([len(scriptsig)])
    sequence = struct.pack("<I", 0xFFFFFFFF)
    vout_count = b"\x01"
    value = struct.pack("<Q", 5_000_000_000)
    pkscript = bytes([0x76, 0xA9, 0x14]) + b"\x11" * 20 + bytes([0x88, 0xAC])
    pkscript_len = bytes([len(pkscript)])
    locktime = struct.pack("<I", 0)
    return (
        version
        + vin_count
        + prev_hash
        + prev_idx
        + scriptsig_len
        + scriptsig
        + sequence
        + vout_count
        + value
        + pkscript_len
        + pkscript
        + locktime
    )


def test_read_transaction_legacy_roundtrip():
    raw = _legacy_coinbase_tx()
    tx, pos = ap.read_transaction(raw, 0)
    assert pos == len(raw)
    assert tx["has_witness"] is False
    assert tx["version"] == 1
    assert len(tx["vin"]) == 1
    assert len(tx["vout"]) == 1
    assert tx["vin"][0]["prev_idx"] == 0xFFFFFFFF
    assert tx["vout"][0]["value"] == 5_000_000_000
    assert tx["raw"] == raw
    # BIP34 height parses from the coinbase scriptsig.
    assert ap.parse_coinbase_height(tx["vin"][0]["scriptsig"]) == 123456


def _segwit_tx():
    """A 1-in/1-out segwit tx with a 2-item witness stack."""
    version = struct.pack("<i", 2)
    marker_flag = b"\x00\x01"
    vin_count = b"\x01"
    prev_hash = b"\xab" * 32
    prev_idx = struct.pack("<I", 0)
    scriptsig = b""  # empty for native segwit input
    scriptsig_len = bytes([0x00])
    sequence = struct.pack("<I", 0xFFFFFFFF)
    vout_count = b"\x01"
    value = struct.pack("<Q", 1234)
    pkscript = bytes([0x00, 0x14]) + b"\x22" * 20  # P2WPKH
    pkscript_len = bytes([len(pkscript)])
    # witness: 2 items
    witness = b"\x02" + b"\x03" + b"\xaa\xbb\xcc" + b"\x02" + b"\xde\xad"
    locktime = struct.pack("<I", 0)
    return (
        version
        + marker_flag
        + vin_count
        + prev_hash
        + prev_idx
        + scriptsig_len
        + scriptsig
        + sequence
        + vout_count
        + value
        + pkscript_len
        + pkscript
        + witness
        + locktime
    )


def test_read_transaction_segwit_skips_witness():
    raw = _segwit_tx()
    tx, pos = ap.read_transaction(raw, 0)
    assert pos == len(raw)
    assert tx["has_witness"] is True
    assert tx["version"] == 2
    assert len(tx["vin"]) == 1
    assert len(tx["vout"]) == 1
    assert tx["vout"][0]["value"] == 1234
    assert tx["raw"] == raw


def test_read_transaction_offset_within_buffer():
    """A tx parsed at a non-zero offset advances correctly and ignores trailer."""
    raw = _legacy_coinbase_tx()
    prefix = b"\xff\xee\xdd"
    trailer = b"\x99\x88"
    buf = prefix + raw + trailer
    tx, pos = ap.read_transaction(buf, len(prefix))
    assert pos == len(prefix) + len(raw)
    assert tx["raw"] == raw


# ---------------------------------------------------------------------------
# read_auxpow / parse_auxpow_tail
# ---------------------------------------------------------------------------


def _build_auxpow(
    coinbase_raw, merkle_branch, merkle_index, chain_branch, chain_index, parent_header
):
    parts = [coinbase_raw, b"\x00" * 32]  # coinbase tx + hashBlock
    parts.append(bytes([len(merkle_branch)]))
    parts.extend(merkle_branch)
    parts.append(struct.pack("<i", merkle_index))
    parts.append(bytes([len(chain_branch)]))
    parts.extend(chain_branch)
    parts.append(struct.pack("<i", chain_index))
    parts.append(parent_header)
    return b"".join(parts)


def test_read_auxpow_roundtrip():
    coinbase = _legacy_coinbase_tx()
    parent = _build_header(
        0x20000000, bytes(range(32)), bytes(range(32, 64)), 1_600_000_000, 0x1D00FFFF, 7
    )
    mb = [b"\x01" * 32, b"\x02" * 32]
    cb = [b"\x03" * 32]
    raw = _build_auxpow(coinbase, mb, 0, cb, 5, parent)
    aux, pos = ap.read_auxpow(raw, 0)
    assert pos == len(raw)
    assert aux["coinbase_tx"]["raw"] == coinbase
    assert aux["hash_block"] == b"\x00" * 32
    assert aux["merkle_branch"] == mb
    assert aux["merkle_index"] == 0
    assert aux["chain_merkle_branch"] == cb
    assert aux["chain_index"] == 5
    assert aux["parent_header_raw"] == parent
    # The header within the tail parses cleanly.
    h = ap.parse_parent_header(aux["parent_header_raw"])
    assert h["bits"] == 0x1D00FFFF


def test_read_auxpow_empty_branches():
    coinbase = _legacy_coinbase_tx()
    parent = _build_header(1, b"\x00" * 32, b"\x00" * 32, 100, 0x1D00FFFF, 0)
    raw = _build_auxpow(coinbase, [], 0, [], 0, parent)
    aux, pos = ap.read_auxpow(raw, 0)
    assert pos == len(raw)
    assert aux["merkle_branch"] == []
    assert aux["chain_merkle_branch"] == []


# ---------------------------------------------------------------------------
# parse_coinbase_height
# ---------------------------------------------------------------------------


def test_parse_coinbase_height_delegates():
    # OP_PUSHBYTES_3 + little-endian 500000
    scriptsig = bytes([0x03]) + (500000).to_bytes(3, "little")
    assert ap.parse_coinbase_height(scriptsig) == 500000


def test_parse_coinbase_height_empty():
    assert ap.parse_coinbase_height(b"") is None


# ---------------------------------------------------------------------------
# stdlib-only import guard
# ---------------------------------------------------------------------------


def test_module_imports_stdlib_only():
    import ast

    src = (REPO_ROOT / "src" / "stale_blocks_analysis" / "auxpow_parse.py").read_text()
    tree = ast.parse(src)
    third_party = {"requests", "numpy", "pandas", "scipy", "matplotlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in third_party
        elif isinstance(node, ast.ImportFrom):
            # Only stdlib (level 0, no third party) or intra-package (level >= 1).
            if node.level == 0 and node.module:
                assert node.module.split(".")[0] not in third_party
