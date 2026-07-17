"""Unit tests for the nBits contamination gate (validate_stale_nbits).

This is the non-skippable gate that rejects post-2017 BCH/BSV-family parent
headers which share a BTC ancestor but use an easier target. The function takes
an injectable rpc_batch callable, so it is tested here with a fake RPC that maps
heights to canonical nBits without touching a node.
"""

from __future__ import annotations

from stale_blocks_analysis.btc_nbits_validation import validate_stale_nbits


def _make_rpc(height_to_bits, missing_heights=()):
    """Fake rpc_batch.

    getblockhash(height) -> a 64-hex hash (or None for *missing_heights*);
    getblockheader(hash) -> a corroborated active-chain header.
    """

    def rpc_batch(calls):
        out = []
        for c in calls:
            method, params = c["method"], c["params"]
            if method == "getblockhash":
                h = params[0]
                result = None if h in missing_heights else f"{h:064x}"
                out.append({"id": c["id"], "result": result, "error": None})
            elif method == "getblockheader":
                h = int(params[0], 16)
                out.append(
                    {
                        "id": c["id"],
                        "result": {
                            "hash": params[0],
                            "height": h,
                            "confirmations": 1,
                            "bits": height_to_bits[h],
                        },
                        "error": None,
                    }
                )
            else:  # pragma: no cover - defensive
                out.append({"id": c["id"], "result": None})
        return out

    return rpc_batch


def test_valid_when_bits_match_canonical():
    stales = [{"btc_height": "100", "btc_bits": "1a0abbcc"}]
    validate_stale_nbits(stales, _make_rpc({100: "1a0abbcc"}))
    assert stales[0]["validation_status"] == "VALID"
    assert stales[0]["expected_nbits"] == "1a0abbcc"


def test_rejected_when_bits_mismatch():
    stales = [{"btc_height": "100", "btc_bits": "1d00ffff"}]
    validate_stale_nbits(stales, _make_rpc({100: "1a0abbcc"}))
    assert stales[0]["validation_status"].startswith("REJECTED")
    assert stales[0]["expected_nbits"] == "1a0abbcc"


def test_unknown_when_height_missing():
    stales = [{"btc_bits": "1a0abbcc"}]  # no btc_height key
    validate_stale_nbits(stales, _make_rpc({}))
    assert stales[0]["validation_status"] == "UNKNOWN: missing btc_height"


def test_unknown_when_canonical_unavailable():
    stales = [{"btc_height": "999", "btc_bits": "1a0abbcc"}]
    validate_stale_nbits(stales, _make_rpc({}, missing_heights={999}))
    assert stales[0]["validation_status"] == "UNKNOWN: canonical nBits unavailable"


def test_bits_match_is_case_insensitive():
    stales = [{"btc_height": "100", "btc_bits": "1A0ABBCC"}]
    validate_stale_nbits(stales, _make_rpc({100: "1a0abbcc"}))
    assert stales[0]["validation_status"] == "VALID"


def test_custom_keys_are_honoured():
    stales = [{"h": "100", "bits": "1a0abbcc"}]
    validate_stale_nbits(
        stales, _make_rpc({100: "1a0abbcc"}), height_key="h", bits_key="bits"
    )
    assert stales[0]["validation_status"] == "VALID"


def test_empty_input_is_a_noop():
    stales: list[dict] = []
    validate_stale_nbits(stales, _make_rpc({}))
    assert stales == []


def test_mixed_batch_independent_verdicts():
    stales = [
        {"btc_height": "100", "btc_bits": "1a0abbcc"},  # valid
        {"btc_height": "101", "btc_bits": "1dffffff"},  # rejected
        {"btc_height": "102", "btc_bits": "1a0abbcc"},  # canonical unavailable
    ]
    rpc = _make_rpc({100: "1a0abbcc", 101: "1a0abbcc"}, missing_heights={102})
    validate_stale_nbits(stales, rpc)
    assert stales[0]["validation_status"] == "VALID"
    assert stales[1]["validation_status"].startswith("REJECTED")
    assert stales[2]["validation_status"] == "UNKNOWN: canonical nBits unavailable"


def test_malformed_or_incomplete_rpc_context_cannot_stamp_valid():
    stale = {"btc_height": "100", "btc_bits": "1a0abbcc"}

    def malformed_hash_batch(calls):
        return [{"id": calls[0]["id"], "result": "not-a-hash", "error": None}]

    validate_stale_nbits([stale], malformed_hash_batch)
    assert stale["validation_status"].startswith("UNKNOWN")

    stale = {"btc_height": "100", "btc_bits": "1a0abbcc"}

    def missing_batch(calls):
        return []

    validate_stale_nbits([stale], missing_batch)
    assert stale["validation_status"].startswith("UNKNOWN")


def test_header_must_match_hash_height_active_chain_and_bits():
    for mutation in (
        {"hash": "ff" * 32},
        {"height": 101},
        {"confirmations": -1},
        {"bits": "malformed"},
    ):
        stale = {"btc_height": "100", "btc_bits": "1a0abbcc"}

        def rpc_batch(calls, mutation=mutation):
            if calls[0]["method"] == "getblockhash":
                return [{"id": 0, "result": f"{100:064x}", "error": None}]
            header = {
                "hash": f"{100:064x}",
                "height": 100,
                "confirmations": 1,
                "bits": "1a0abbcc",
                **mutation,
            }
            return [{"id": 0, "result": header, "error": None}]

        validate_stale_nbits([stale], rpc_batch)
        assert stale["validation_status"].startswith("UNKNOWN")


def test_transport_failure_is_unknown_not_rejected():
    stale = {"btc_height": "100", "btc_bits": "1a0abbcc"}

    def rpc_batch(_calls):
        raise OSError("offline")

    validate_stale_nbits([stale], rpc_batch)
    assert stale["validation_status"].startswith("UNKNOWN")
