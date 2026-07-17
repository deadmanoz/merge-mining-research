"""Tests for direct-stale header/context validation."""

from __future__ import annotations

from stale_blocks_analysis.btc_stale_validation import (
    bip34_height_error,
    block_version_error,
    coinbase_scriptsig_length_error,
    median_time_past_error,
    stale_header_context_error,
    validate_stale_header_context,
)
from stale_blocks_analysis.config import (
    BIP34_HEIGHT,
    BIP34_VERSION_2_HEIGHT,
    BIP65_HEIGHT,
    BIP66_HEIGHT,
)


def _height_prefix(height: int) -> bytes:
    encoded = bytearray()
    value = height
    while value:
        encoded.append(value & 0xFF)
        value >>= 8
    if encoded[-1] & 0x80:
        encoded.append(0)
    return bytes([len(encoded)]) + bytes(encoded)


def _scriptsig(height: int) -> str:
    return (_height_prefix(height) + b"pool-data").hex()


def _header(version: int) -> str:
    version_bytes = (version & 0xFFFFFFFF).to_bytes(4, "little")
    return (version_bytes + b"\x00" * 76).hex()


def test_bip34_gate_accepts_exact_core_height_prefix():
    row = {
        "btc_bip34_height": str(BIP34_HEIGHT),
        "coinbase_scriptsig_hex": _scriptsig(BIP34_HEIGHT),
        "btc_header_hex": _header(2),
    }
    assert bip34_height_error(row, BIP34_HEIGHT) is None


def test_bip34_gate_rejects_height_mismatch():
    row = {
        "btc_bip34_height": str(BIP34_HEIGHT + 1),
        "coinbase_scriptsig_hex": _scriptsig(BIP34_HEIGHT + 1),
        "btc_header_hex": _header(2),
    }
    error = bip34_height_error(row, BIP34_HEIGHT)
    assert error == (
        "REJECTED: BIP34 coinbase height mismatch "
        f"(got {BIP34_HEIGHT + 1}, expected {BIP34_HEIGHT})"
    )


def test_bip34_gate_rejects_missing_raw_scriptsig_even_with_decoded_column():
    row = {
        "btc_bip34_height": str(BIP34_HEIGHT),
        "btc_header_hex": _header(2),
    }
    assert bip34_height_error(row, BIP34_HEIGHT) == (
        "REJECTED: missing coinbase scriptSig for BIP34 validation"
    )


def test_bip34_gate_rejects_nonminimal_equal_height_encoding():
    body = _height_prefix(BIP34_HEIGHT)[1:]
    row = {
        "btc_bip34_height": str(BIP34_HEIGHT),
        "coinbase_scriptsig_hex": (b"\x4c" + bytes([len(body)]) + body).hex(),
        "btc_header_hex": _header(2),
    }
    assert bip34_height_error(row, BIP34_HEIGHT).startswith("REJECTED")


def test_bip34_gate_rejects_decoded_column_disagreement():
    row = {
        "btc_bip34_height": str(BIP34_HEIGHT + 1),
        "coinbase_scriptsig_hex": _scriptsig(BIP34_HEIGHT),
        "btc_header_hex": _header(2),
    }
    assert "disagrees" in bip34_height_error(row, BIP34_HEIGHT)


def test_bip34_gate_is_not_applied_before_version_2_transition():
    assert bip34_height_error({}, BIP34_VERSION_2_HEIGHT - 1) is None


def test_bip34_transition_allows_version_1_without_height_prefix():
    row = {"btc_header_hex": _header(1), "coinbase_scriptsig_hex": "00"}
    assert bip34_height_error(row, BIP34_VERSION_2_HEIGHT) is None


def test_bip34_transition_accepts_version_2_exact_height_prefix():
    row = {
        "btc_header_hex": _header(2),
        "coinbase_scriptsig_hex": _scriptsig(BIP34_VERSION_2_HEIGHT),
    }
    assert bip34_height_error(row, BIP34_VERSION_2_HEIGHT) is None


def test_bip34_transition_rejects_version_2_height_mismatch():
    row = {
        "btc_header_hex": _header(2),
        "coinbase_scriptsig_hex": _scriptsig(BIP34_VERSION_2_HEIGHT + 1),
    }
    assert bip34_height_error(row, BIP34_VERSION_2_HEIGHT).startswith(
        "REJECTED: BIP34 coinbase height mismatch"
    )


def test_bip34_transition_accepts_exact_prefix_when_header_is_unavailable():
    row = {"coinbase_scriptsig_hex": _scriptsig(BIP34_VERSION_2_HEIGHT)}
    assert bip34_height_error(row, BIP34_VERSION_2_HEIGHT) is None


def test_bip34_transition_requires_header_when_prefix_is_wrong():
    row = {"coinbase_scriptsig_hex": _scriptsig(BIP34_VERSION_2_HEIGHT + 1)}
    assert bip34_height_error(row, BIP34_VERSION_2_HEIGHT).startswith("UNKNOWN:")


def test_bip34_transition_missing_header_and_scriptsig_is_unknown():
    assert bip34_height_error({}, BIP34_VERSION_2_HEIGHT).startswith("UNKNOWN:")


def test_bip34_transition_missing_header_and_malformed_scriptsig_is_unknown():
    row = {"coinbase_scriptsig_hex": "not-hex"}
    assert bip34_height_error(row, BIP34_VERSION_2_HEIGHT).startswith("UNKNOWN:")


def test_bip34_universal_rule_rejects_version_1_even_with_exact_prefix():
    row = {
        "btc_header_hex": _header(1),
        "coinbase_scriptsig_hex": _scriptsig(BIP34_HEIGHT),
    }
    assert bip34_height_error(row, BIP34_HEIGHT).startswith(
        "REJECTED: Bitcoin block version below 2"
    )


def test_bip34_universal_rule_requires_header_even_with_exact_prefix():
    row = {"coinbase_scriptsig_hex": _scriptsig(BIP34_HEIGHT)}
    assert bip34_height_error(row, BIP34_HEIGHT).startswith("UNKNOWN:")


def test_historical_minimum_block_version_schedule():
    assert block_version_error({"btc_header_hex": _header(2)}, BIP66_HEIGHT - 1) is None
    assert block_version_error({"btc_header_hex": _header(2)}, BIP66_HEIGHT).startswith(
        "REJECTED: Bitcoin block version below historical minimum"
    )
    assert block_version_error({"btc_header_hex": _header(3)}, BIP66_HEIGHT) is None
    assert block_version_error({"btc_header_hex": _header(3)}, BIP65_HEIGHT).startswith(
        "REJECTED: Bitcoin block version below historical minimum"
    )
    assert block_version_error({"btc_header_hex": _header(4)}, BIP65_HEIGHT) is None


def test_signed_negative_version_fails_post_bip65_minimum():
    for version_word in (0xA0000000, 0xE0000000):
        row = {
            "btc_header_hex": _header(version_word),
            "coinbase_scriptsig_hex": _scriptsig(BIP65_HEIGHT),
        }
        error = stale_header_context_error(row, BIP65_HEIGHT)
        assert error is not None
        assert "required 4 after BIP65" in error


def test_positive_versionbits_word_passes_post_bip65_minimum():
    assert (
        block_version_error({"btc_header_hex": _header(0x20000000)}, BIP65_HEIGHT)
        is None
    )


def test_coinbase_scriptsig_length_gate_enforces_core_range():
    assert coinbase_scriptsig_length_error({"coinbase_scriptsig_hex": "00"}) == (
        "REJECTED: Bitcoin coinbase scriptSig length outside consensus range "
        "(got 1, required 2..100)"
    )
    assert (
        coinbase_scriptsig_length_error({"coinbase_scriptsig_hex": "00" * 100}) is None
    )
    assert coinbase_scriptsig_length_error(
        {"coinbase_scriptsig_hex": "00" * 101}
    ).startswith("REJECTED:")


def test_median_time_past_gate_requires_strictly_greater_time():
    assert median_time_past_error({"btc_time": "1001"}, 1000) is None
    assert median_time_past_error({"btc_time": "1000"}, 1000).startswith("REJECTED:")
    assert median_time_past_error({"btc_time": "999"}, 1000).startswith("REJECTED:")


def test_consensus_gate_overrides_matching_nbits_with_bip34_rejection():
    height = BIP34_HEIGHT
    canonical_hash = "11" * 32
    stales = [
        {
            "btc_height": str(height),
            "btc_prev_hash": "prev",
            "btc_time": "1001",
            "btc_bits": "1a0abbcc",
            "btc_bip34_height": str(height + 1),
            "coinbase_scriptsig_hex": _scriptsig(height + 1),
            "btc_header_hex": _header(2),
        }
    ]

    def rpc_batch(calls):
        responses = []
        for call in calls:
            if call["method"] == "getblockhash":
                result = canonical_hash
            elif call["params"] == ["prev"]:
                result = {
                    "hash": "prev",
                    "confirmations": 1,
                    "height": height - 1,
                    "mediantime": 1000,
                }
            else:
                result = {
                    "hash": canonical_hash,
                    "height": height,
                    "confirmations": 1,
                    "bits": "1a0abbcc",
                }
            responses.append({"id": call["id"], "result": result})
        return responses

    validate_stale_header_context(stales, rpc_batch)
    assert stales[0]["validation_status"].startswith(
        "REJECTED: BIP34 coinbase height mismatch"
    )
    assert stales[0]["expected_nbits"] == "1a0abbcc"


def _pre_bip34_stale() -> dict[str, str]:
    return {
        "btc_height": "100",
        "btc_prev_hash": "prev",
        "btc_time": "1001",
        "btc_bits": "1a0abbcc",
        "coinbase_scriptsig_hex": "abcd",
        "btc_header_hex": _header(1),
    }


def _rpc_with_parent_response(parent_response):
    canonical_hash = "11" * 32

    def rpc_batch(calls):
        call = calls[0]
        if call["method"] == "getblockhash":
            return [{"id": call["id"], "result": canonical_hash, "error": None}]
        if call["params"] == [canonical_hash]:
            return [
                {
                    "id": call["id"],
                    "result": {
                        "hash": canonical_hash,
                        "height": 100,
                        "confirmations": 1,
                        "bits": "1a0abbcc",
                    },
                    "error": None,
                }
            ]
        return parent_response

    return rpc_batch


def test_parent_rpc_transport_error_is_unknown_not_rejected():
    stale = _pre_bip34_stale()

    def rpc_batch(calls):
        call = calls[0]
        if call["method"] == "getblockhash":
            return [{"id": call["id"], "result": "canonical", "error": None}]
        if call["params"] == ["canonical"]:
            return [
                {
                    "id": call["id"],
                    "result": {"bits": "1a0abbcc"},
                    "error": None,
                }
            ]
        raise RuntimeError("transport failed")

    validate_stale_header_context([stale], rpc_batch)
    assert stale["validation_status"] == (
        "UNKNOWN: canonical parent context unavailable"
    )


def test_missing_parent_rpc_response_is_unknown_not_rejected():
    stale = _pre_bip34_stale()
    validate_stale_header_context([stale], _rpc_with_parent_response([]))
    assert stale["validation_status"].startswith("UNKNOWN:")


def test_parent_rpc_response_without_result_is_unknown_not_rejected():
    stale = _pre_bip34_stale()
    validate_stale_header_context(
        [stale],
        _rpc_with_parent_response([{"id": 0, "result": None, "error": None}]),
    )
    assert stale["validation_status"].startswith("UNKNOWN:")


def test_malformed_parent_rpc_response_is_unknown_not_rejected():
    stale = _pre_bip34_stale()
    validate_stale_header_context(
        [stale],
        _rpc_with_parent_response(
            [{"id": 0, "result": "not-an-object", "error": None}]
        ),
    )
    assert stale["validation_status"].startswith("UNKNOWN:")


def test_parent_rpc_error_is_unknown_not_rejected():
    stale = _pre_bip34_stale()
    validate_stale_header_context(
        [stale],
        _rpc_with_parent_response(
            [
                {
                    "id": 0,
                    "result": None,
                    "error": {"code": -28, "message": "Loading block index"},
                }
            ]
        ),
    )
    assert stale["validation_status"].startswith("UNKNOWN:")


def test_missing_parent_mediantime_is_unknown_not_rejected():
    stale = _pre_bip34_stale()
    validate_stale_header_context(
        [stale],
        _rpc_with_parent_response(
            [
                {
                    "id": 0,
                    "result": {
                        "hash": "prev",
                        "confirmations": 1,
                        "height": 99,
                    },
                    "error": None,
                }
            ]
        ),
    )
    assert stale["validation_status"].startswith("UNKNOWN:")


def test_later_unknown_context_does_not_erase_nbits_rejection():
    stale = _pre_bip34_stale()
    stale["btc_bits"] = "1a0abbbb"

    validate_stale_header_context(
        [stale],
        _rpc_with_parent_response(
            [
                {
                    "id": 0,
                    "result": {
                        "hash": "prev",
                        "confirmations": 1,
                        "height": 99,
                    },
                    "error": None,
                }
            ]
        ),
    )

    assert stale["validation_status"].startswith("REJECTED: nBits mismatch")


def test_parent_height_disagreement_is_unknown_not_rejected():
    stale = _pre_bip34_stale()
    validate_stale_header_context(
        [stale],
        _rpc_with_parent_response(
            [
                {
                    "id": 0,
                    "result": {
                        "hash": "prev",
                        "confirmations": 1,
                        "height": 98,
                        "mediantime": 1000,
                    },
                    "error": None,
                }
            ]
        ),
    )
    assert stale["validation_status"].startswith("UNKNOWN:")


def test_verified_absent_parent_is_rejected():
    stale = _pre_bip34_stale()
    validate_stale_header_context(
        [stale],
        _rpc_with_parent_response(
            [
                {
                    "id": 0,
                    "result": None,
                    "error": {"code": -5, "message": "Block not found"},
                }
            ]
        ),
    )
    assert stale["validation_status"].startswith("REJECTED:")


def test_verified_non_active_parent_is_rejected():
    stale = _pre_bip34_stale()
    validate_stale_header_context(
        [stale],
        _rpc_with_parent_response(
            [
                {
                    "id": 0,
                    "result": {
                        "hash": "prev",
                        "confirmations": -1,
                        "height": 99,
                        "mediantime": 1000,
                    },
                    "error": None,
                }
            ]
        ),
    )
    assert stale["validation_status"].startswith("REJECTED:")
