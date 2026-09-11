"""Qbit wire-rule regressions against retained positive and lower-work controls."""

import json
import struct
from pathlib import Path

import pytest

from stale_blocks_analysis.auxpow_chainid import fold_merkle_branch, hash_to_display_hex
from stale_blocks_analysis.bitcoin_binary import sha256d
from stale_blocks_analysis.lyncoin_headers import WireReader, _parse_transaction
from stale_blocks_analysis.qbit import is_auxpow, parse_block, parse_header

CONTROLS = json.loads(
    (Path(__file__).parent / "fixtures/qbit_controls.json").read_text()
)["controls"]
POSITIVE = next(c for c in CONTROLS if c["parent_self_pow"])


def parse(raw):
    return parse_header(
        raw,
        height=POSITIVE["height"],
        expected_hash=hash_to_display_hex(sha256d(raw[:80])),
    )


@pytest.mark.parametrize("control", CONTROLS)
def test_saved_controls(control):
    raw = bytes.fromhex(control["header_hex"])
    result = parse_header(raw, height=control["height"], expected_hash=control["hash"])
    assert result["parent"]["hash"] == control["parent_hash"]
    assert result["parent_self_pow"] is control["parent_self_pow"]
    assert result["row"]["child_nbits"] == raw[72:76][::-1].hex()
    assert result["extended_header_hex"] == raw.hex()
    assert (
        parse_block(
            raw + b"\x01opaque-native-body",
            height=control["height"],
            expected_hash=control["hash"],
        )["extended_header_hex"]
        == raw.hex()
    )


@pytest.mark.parametrize(
    "version", [0x40000100, 0x00000100, 0x2005E300, 0x20060100, 1, 3, 0xA005E100]
)
def test_invalid_mainnet_versions(version):
    with pytest.raises(ValueError):
        is_auxpow(version, 78058)


def test_permissionless_chain_id_rolling_and_legacy_versions():
    assert is_auxpow(0x2005E100, 1)
    assert not is_auxpow(0x3FFFE004, 1)
    assert not is_auxpow(4, 1)
    assert not is_auxpow(1, 0)


def test_exact_header_and_child_identity():
    raw = bytes.fromhex(POSITIVE["header_hex"])
    with pytest.raises(ValueError, match="trailing bytes"):
        parse(raw + b"\0")
    with pytest.raises(ValueError, match="hash mismatch"):
        parse_header(raw, height=78058, expected_hash="00" * 32)
    for end in range(len(raw)):
        with pytest.raises(ValueError):
            parse_header(raw[:end], height=78058, expected_hash=POSITIVE["hash"])


def offsets(raw):
    reader = WireReader(raw)
    reader.take(80)
    tx = _parse_transaction(reader)
    tx_end = reader.pos
    parent_count_pos = reader.pos
    branch = [reader.take(32) for _ in range(reader.compact_size())]
    parent_index_pos = reader.pos
    reader.i32()
    chain_count_pos = reader.pos
    reader.take(32 * reader.compact_size())
    chain_index_pos = reader.pos
    reader.i32()
    return (
        tx,
        tx_end,
        branch,
        parent_count_pos,
        parent_index_pos,
        chain_count_pos,
        chain_index_pos,
        reader.pos,
    )


@pytest.mark.parametrize(
    "field,value,reason",
    [
        (4, -1, "coinbase branch index"),
        (6, -1, "chain index"),
        (6, 2**30, "chain index"),
    ],
)
def test_signed_indices(field, value, reason):
    raw = bytearray.fromhex(POSITIVE["header_hex"])
    pos = offsets(raw)[field]
    struct.pack_into("<i", raw, pos, value)
    with pytest.raises(ValueError, match=reason):
        parse(bytes(raw))


@pytest.mark.parametrize("field,count", [(3, 32), (5, 31)])
def test_branch_limits(field, count):
    raw = bytearray.fromhex(POSITIVE["header_hex"])
    raw[offsets(raw)[field]] = count
    with pytest.raises(ValueError, match="exceeds limit"):
        parse(bytes(raw))


def mutate_commitment(kind):
    raw = bytearray.fromhex(POSITIVE["header_hex"])
    tx, end, branch, *rest = offsets(raw)
    marker = raw.index(bytes.fromhex("fabe6d6d"), 80, end)
    if kind == "order":
        raw[marker + 4 : marker + 36] = raw[marker + 4 : marker + 36][::-1]
    elif kind == "size":
        raw[marker + 36] ^= 1
    else:
        raw[marker + 40] ^= 1
    # Keep parent Merkle inclusion consistent, so the commitment gate is tested.
    parent_pos = rest[-1]
    raw[parent_pos + 36 : parent_pos + 68] = fold_merkle_branch(
        sha256d(raw[80:end]), branch, 0
    )
    return bytes(raw)


@pytest.mark.parametrize(
    "kind,reason",
    [("order", "display-order"), ("size", "tree size"), ("nonce", "chain slot")],
)
def test_mainnet_commitment_rules(kind, reason):
    with pytest.raises(ValueError, match=reason):
        parse(mutate_commitment(kind))


def test_noncanonical_compact_size():
    raw = bytes.fromhex(POSITIVE["header_hex"])
    assert raw[84] == 1
    with pytest.raises(ValueError, match="non-canonical"):
        parse(raw[:84] + b"\xfd\x01\x00" + raw[85:])


def test_child_target_is_header_target():
    raw = bytearray.fromhex(POSITIVE["header_hex"])
    struct.pack_into("<I", raw, 72, 0x1D80FFFF)
    with pytest.raises(ValueError, match="invalid Qbit header target"):
        parse(bytes(raw))


def test_witness_coinbase_encoding_rejected():
    raw = bytes.fromhex(POSITIVE["header_hex"])
    tx_end = offsets(raw)[1]
    encoded = (
        raw[:84] + b"\x00\x01" + raw[84 : tx_end - 4] + b"\x00" + raw[tx_end - 4 :]
    )
    with pytest.raises(ValueError, match="non-witness encoding"):
        parse(encoded)


def test_native_synthetic_parent_is_not_height_evidence():
    control = json.loads(
        (Path(__file__).parent / "fixtures/qbit_synthetic_parent.json").read_text()
    )
    parsed = parse_header(
        bytes.fromhex(control["header_hex"]),
        height=control["height"],
        expected_hash=control["hash"],
    )
    assert parsed["parent"]["hash"] == control["parent_hash"]
    assert parsed["parent_self_pow"]
    assert parsed["row"]["btc_prev_hash"] == "0" * 64
    assert parsed["row"]["btc_height"] == ""
    assert parsed["row"]["btc_bits"] == parsed["row"]["child_nbits"]
    assert parsed["row"]["coinbase_outputs"] == "51:0"
