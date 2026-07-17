from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "extract"))

import stale_blocks_analysis.lyncoin_headers as lh  # noqa: E402
from stale_blocks_analysis.auxpow_registry import get_chain  # noqa: E402
from download_lyncoin_auxpow_headers import (  # noqa: E402
    atomic_write_bytes,
    parse_peer,
    parse_version_payload,
)


def _coinbase(script_sig: bytes) -> bytes:
    return (
        struct.pack("<i", 1)
        + b"\x01"
        + b"\x00" * 32
        + struct.pack("<I", 0xFFFFFFFF)
        + lh.encode_compact_size(len(script_sig))
        + script_sig
        + struct.pack("<I", 0xFFFFFFFF)
        + b"\x01"
        + struct.pack("<Q", 5_000_000_000)
        + b"\x01\x51"
        + struct.pack("<I", 0)
    )


def _mine_parent_header(merkle_root: bytes, child_bits: int) -> bytes:
    target = lh.compact_to_target(child_bits)
    prefix = (
        struct.pack("<i", 0x20000000)
        + b"\x22" * 32
        + merkle_root
        + struct.pack("<II", 1_700_000_000, child_bits)
    )
    for nonce in range(100_000):
        raw = prefix + struct.pack("<I", nonce)
        if int.from_bytes(lh.sha256d(raw), "little") <= target:
            return raw
    raise AssertionError("failed to mine synthetic easy-target parent")


def _synthetic_auxpow_header(
    *,
    previous_hash: bytes = b"\x11" * 32,
    version: int | None = None,
    bits: int = lh.POW_LIMIT_BITS,
    parent_merkle_index: int = 0,
) -> bytes:
    if version is None:
        version = (lh.CHAIN_ID << 16) | lh.VERSION_AUXPOW | 1
    pure = (
        struct.pack("<I", version)
        + previous_hash
        + b"\x33" * 32
        + struct.pack("<III", 1_700_000_001, bits, 7)
    )
    child_hash = lh.sha256d(pure)
    script_sig = bytes.fromhex("fabe6d6d") + child_hash[::-1] + struct.pack("<II", 1, 0)
    coinbase = _coinbase(script_sig)
    coinbase_txid = lh.sha256d(coinbase)
    parent = _mine_parent_header(coinbase_txid, bits)
    auxpow = (
        coinbase
        + b"\x00" * 32
        + b"\x00"
        + struct.pack("<i", parent_merkle_index)
        + b"\x00"
        + struct.pack("<i", 0)
        + parent
    )
    return pure + auxpow


def _previous_summary(hash_internal: bytes = b"\x11" * 32) -> lh.HeaderSummary:
    return lh.HeaderSummary(
        height=0,
        hash_internal=hash_internal,
        version=1,
        timestamp=1_699_999_400,
        bits=lh.POW_LIMIT_BITS,
        has_auxpow=False,
    )


def test_pinned_genesis_round_trips_and_validates():
    parsed = lh.parse_extended_header(lh.GENESIS_RAW)
    summary = lh.validate_genesis(parsed)

    assert summary.height == 0
    assert summary.hash_display == lh.GENESIS_HASH_DISPLAY
    assert summary.bits == lh.GENESIS_BITS


def test_lyncoin_registry_entry_matches_pinned_consensus():
    chain = get_chain("lyncoin")

    assert chain is not None
    assert chain.chain_id == lh.CHAIN_ID
    assert chain.slot_enforcement == "consensus"


def test_bounded_parser_and_full_auxpow_validation():
    raw = _synthetic_auxpow_header()
    parsed = lh.parse_extended_header(raw)
    previous = _previous_summary()

    summary = lh.validate_pre_flex_header(parsed, 1, [previous])
    row = lh.candidate_row(parsed, summary)

    assert parsed.raw == raw
    assert parsed.auxpow is not None
    assert summary.height == 1
    assert summary.has_auxpow is True
    assert row is not None
    assert row["child_height"] == 1
    assert row["child_block_hash"] == summary.hash_internal.hex()
    assert row["child_block_time"] == parsed.timestamp
    assert row["btc_header_hex"] == parsed.auxpow.parent_header_raw.hex()


def test_auxpow_commitment_tamper_fails_closed():
    raw = bytearray(_synthetic_auxpow_header())
    marker = raw.find(bytes.fromhex("fabe6d6d"), 80)
    assert marker > 80
    raw[marker + 4] ^= 1
    parsed = lh.parse_extended_header(bytes(raw))

    with pytest.raises(lh.RecoveryValidationError, match="merkle proof mismatch"):
        lh.validate_auxpow(parsed, 1)


def test_auxpow_parent_coinbase_must_be_at_merkle_index_zero():
    parsed = lh.parse_extended_header(_synthetic_auxpow_header(parent_merkle_index=1))

    with pytest.raises(lh.RecoveryValidationError, match="index is not zero"):
        lh.validate_auxpow(parsed, 1)


def test_wrong_chain_id_and_linkage_fail_closed():
    raw = _synthetic_auxpow_header(
        version=((lh.CHAIN_ID + 1) << 16) | lh.VERSION_AUXPOW | 1
    )
    parsed = lh.parse_extended_header(raw)

    with pytest.raises(lh.RecoveryValidationError, match="chain ID"):
        lh.validate_pre_flex_header(parsed, 1, [_previous_summary()])

    parsed = lh.parse_extended_header(_synthetic_auxpow_header())
    with pytest.raises(lh.RecoveryValidationError, match="linkage mismatch"):
        lh.validate_pre_flex_header(
            parsed,
            1,
            [_previous_summary(b"\x44" * 32)],
        )


def test_headers_payload_requires_zero_tx_count_and_no_trailer():
    header = _synthetic_auxpow_header()
    payload = b"\x01" + header + b"\x00"

    assert lh.parse_headers_payload(payload)[0].raw == header

    with pytest.raises(lh.RecoveryValidationError, match="non-zero transaction"):
        lh.parse_headers_payload(b"\x01" + header + b"\x01")
    with pytest.raises(lh.RecoveryValidationError, match="trailing bytes"):
        lh.parse_headers_payload(payload + b"\x00")


def test_p2p_envelope_encode_and_header_decode_round_trip():
    # Mirrors the live receive path (download_lyncoin_auxpow_headers): encode a
    # message, split off the 24-byte header, decode it, and verify the payload
    # against the header's checksum with the same sha256d(payload)[:4] check.
    encoded = lh.encode_p2p_message("headers", b"payload")
    header, payload = encoded[:24], encoded[24:]
    command, payload_size, checksum = lh.decode_p2p_header(header)
    assert command == "headers"
    assert payload_size == len(payload) == len(b"payload")
    assert lh.sha256d(payload)[:4] == checksum

    wrong_magic = bytearray(header)
    wrong_magic[0] ^= 1
    with pytest.raises(lh.RecoveryValidationError, match="network magic"):
        lh.decode_p2p_header(bytes(wrong_magic))

    # A corrupted payload no longer matches the header checksum — the exact
    # failure the receive loop guards against.
    corrupted = bytearray(payload)
    corrupted[0] ^= 1
    assert lh.sha256d(bytes(corrupted))[:4] != checksum


def test_batch_round_trip_preserves_exact_serialized_headers():
    headers = [lh.GENESIS_RAW, _synthetic_auxpow_header()]
    metadata = {
        "schema": "test",
        "source_commit": lh.SOURCE_COMMIT,
        "start_height": 0,
        "end_height": 1,
    }

    decoded = lh.decode_batch(lh.encode_batch(metadata, headers))

    assert decoded.metadata == metadata
    assert decoded.raw_headers == tuple(headers)


def test_batch_decoder_rejects_truncation():
    encoded = lh.encode_batch({"schema": "test"}, [lh.GENESIS_RAW])
    with pytest.raises(lh.RecoveryValidationError, match="truncated"):
        lh.decode_batch(encoded[:-1])


def test_atomic_batch_write_refuses_overwrite(tmp_path: Path):
    destination = tmp_path / "batch.lhbatch"
    atomic_write_bytes(destination, b"first", refuse_existing=True)
    assert destination.read_bytes() == b"first"

    with pytest.raises(lh.RecoveryValidationError, match="refusing to overwrite"):
        atomic_write_bytes(destination, b"second", refuse_existing=True)
    assert destination.read_bytes() == b"first"


def test_flex_boundary_checks_link_version_chain_id_and_bits():
    previous = lh.HeaderSummary(
        height=lh.AUXPOW_END_HEIGHT,
        hash_internal=b"\x55" * 32,
        version=(lh.CHAIN_ID << 16) | lh.VERSION_AUXPOW | 1,
        timestamp=1_710_000_000,
        bits=0x1800FFFF,
        has_auxpow=True,
    )
    version = (lh.CHAIN_ID << 16) | lh.FLEX_VERSION_FLAG | lh.VERSION_AUXPOW | 1
    raw = _synthetic_auxpow_header(
        previous_hash=previous.hash_internal,
        version=version,
        bits=lh.FLEX_BITS,
    )
    parsed = lh.parse_extended_header(raw)
    boundary = lh.validate_flex_boundary(parsed, previous)

    assert boundary["height"] == lh.FLEX_HEIGHT
    assert boundary["raw_header_hex"] == raw.hex()

    wrong_bits_raw = bytearray(raw)
    wrong_bits_raw[72:76] = struct.pack("<I", 0x1D00FFFF)
    wrong_bits = lh.parse_extended_header(bytes(wrong_bits_raw))
    with pytest.raises(lh.RecoveryValidationError, match="nBits"):
        lh.validate_flex_boundary(wrong_bits, previous)


def test_source_pinned_difficulty_special_heights():
    template = _previous_summary()
    assert lh.expected_next_bits([template], 1) == lh.POW_LIMIT_BITS
    assert (
        lh.expected_next_bits([template] * lh.N2023_HEIGHT, lh.N2023_HEIGHT)
        == lh.N2023_BITS
    )
    assert (
        lh.expected_next_bits(
            [template] * lh.N2023_HEIGHT2,
            lh.N2023_HEIGHT2,
        )
        == lh.N2023_BITS2
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("node.example", ("node.example", 5054)),
        ("node.example:6000", ("node.example", 6000)),
        ("[2001:db8::1]:5054", ("2001:db8::1", 5054)),
    ],
)
def test_peer_parser(text: str, expected: tuple[str, int]):
    assert parse_peer(text) == expected


def test_version_parser_exposes_peer_provenance():
    user_agent = b"/Lyncoin Core:4.0.0/"
    payload = (
        struct.pack("<iQq", lh.PROTOCOL_VERSION, 3149, 1_700_000_000)
        + b"\x00" * 26
        + b"\x00" * 26
        + b"\x01" * 8
        + lh.encode_compact_size(len(user_agent))
        + user_agent
        + struct.pack("<i", 1_364_059)
        + b"\x01"
    )
    parsed = parse_version_payload(payload)

    assert parsed.protocol == lh.PROTOCOL_VERSION
    assert parsed.services == 3149
    assert parsed.user_agent == "/Lyncoin Core:4.0.0/"
    assert parsed.start_height == 1_364_059
    assert parsed.relay is True
