"""Unit tests for the shared per-chain classifier driver.

Exercises ``classify_candidates`` and ``run_classifier`` with a fully canned
fake RPC (no network). Verifies stale/unknown tagging, the prev-height+1
override, the non-skippable nBits gate (VALID/REJECTED), and the output column
order.
"""

from __future__ import annotations

import csv
import struct

import pytest

from stale_blocks_analysis.auxpow_chainid import (
    hash_from_header_bytes,
    hash_to_display_hex,
)
from stale_blocks_analysis.btc_classify import (
    _ordered_batch_responses,
    classify_candidates,
    normalize_bits_hex,
    output_columns,
    run_classifier,
    write_classifier_outputs,
)
from stale_blocks_analysis.config import ChainSpec
from stale_blocks_analysis.config import BIP34_HEIGHT

# Regtest-style easy target so synthetic headers pass the PoW filter roughly
# half the time; we pick nonces that pass.
REGTEST_BITS = 0x207FFFFF
OTHER_EASY_BITS = 0x207FFFFE


def _canonical_hash(height: int) -> str:
    return f"{height:064x}"


def _make_header(prev_display_hex: str, nonce: int, bits: int = REGTEST_BITS) -> str:
    """Build an 80-byte header hex with a chosen prev hash, nonce, and bits."""
    prev_internal = bytes.fromhex(prev_display_hex)[::-1]
    raw = (
        struct.pack("<i", 4)
        + prev_internal
        + b"\x11" * 32
        + struct.pack("<I", 1_700_000_000)
        + struct.pack("<I", bits)
        + struct.pack("<I", nonce)
    )
    return raw.hex()


def _meets(header_hex: str) -> bool:
    from stale_blocks_analysis.btc_classify import _meets_btc_difficulty

    return _meets_btc_difficulty(header_hex)


def _header_hash(header_hex: str) -> str:
    return hash_to_display_hex(hash_from_header_bytes(bytes.fromhex(header_hex)))


def _passing_header(prev_display_hex: str, bits: int = REGTEST_BITS) -> tuple[str, str]:
    """Return ``(header_hex, header_hash_display)`` for a PoW-passing header."""
    for nonce in range(10_000):
        hx = _make_header(prev_display_hex, nonce, bits=bits)
        if _meets(hx):
            return hx, _header_hash(hx)
    raise AssertionError("no passing header found")


class FakeRpc:
    """Canned getblockhash / getblockheader responder.

    ``headers`` maps a block-hash -> header dict (with at least ``height`` and
    ``bits``); a hash present here is "known to the node" (canonical or a
    canonical prev). ``height_to_hash`` maps a height -> canonical block hash,
    used by the nBits gate's getblockhash lookups.
    """

    def __init__(self, headers: dict[str, dict], height_to_hash: dict[int, str]):
        self.headers = headers
        self.height_to_hash = height_to_hash
        self.calls: list[dict] = []

    def batch(self, calls: list[dict]) -> list:
        self.calls.extend(calls)
        out = []
        for c in calls:
            method = c["method"]
            params = c.get("params", [])
            if method == "getblockheader":
                result = self.headers.get(params[0])
                if result is not None:
                    result = {
                        "hash": params[0],
                        "mediantime": 1_699_999_999,
                        **result,
                    }
            elif method == "getblockhash":
                result = self.height_to_hash.get(int(params[0]))
            elif method == "getblockcount":
                result = max(self.height_to_hash, default=0)
            else:
                result = None
            error = None
            if method == "getblockheader" and result is None:
                error = {"code": -5, "message": "Block not found"}
            out.append(
                {"jsonrpc": "1.0", "id": c["id"], "result": result, "error": error}
            )
        out.sort(key=lambda r: r["id"])
        return out


def _candidate(
    header_hex: str, header_hash: str, prev_hash: str, height: str, child_h: str
) -> dict:
    raw = bytes.fromhex(header_hex)
    bits = int.from_bytes(raw[72:76], "little")
    return {
        "btc_height": height,
        "btc_header_hash": header_hash,
        "btc_prev_hash": prev_hash,
        "btc_time": "1700000000",
        "btc_bits": f"{bits:08x}",
        "coinbase_scriptsig_hex": "abcd",
        "coinbase_outputs": "out",
        "btc_header_hex": header_hex,
        "ixc_height": child_h,
    }


# ---------------------------------------------------------------------------
# classify_candidates
# ---------------------------------------------------------------------------


def test_classify_candidates_tags_canonical_stale_unknown():
    # canonical header: known to node
    canon_hex, canon_hash = _passing_header("00" * 32)
    # stale header: prev is a known canonical block at height 499 -> override 500
    prev_known = "aa" * 32
    stale_hex, stale_hash = _passing_header(prev_known)
    # unknown header: prev unknown to node
    prev_unknown = "bb" * 32
    unknown_hex, unknown_hash = _passing_header(prev_unknown)

    headers = {
        canon_hash: {
            "height": 1000,
            "bits": "1a00ffff",
            "confirmations": 1,
        },  # canonical
        prev_known: {
            "height": 499,
            "bits": "1b0404cb",
            "confirmations": 2,
        },  # stale's prev
    }
    rpc = FakeRpc(headers, height_to_hash={})

    candidates = [
        _candidate(canon_hex, canon_hash, "00" * 32, "999", "10"),
        _candidate(stale_hex, stale_hash, prev_known, "12345", "20"),
        _candidate(unknown_hex, unknown_hash, prev_unknown, "0", "30"),
    ]
    results = classify_candidates(candidates, rpc)

    by_hash = {r["btc_header_hash"]: r for r in results}
    # canonical is a distinct output, with Core's height authoritative
    assert by_hash[canon_hash]["classification"] == "canonical"
    assert by_hash[canon_hash]["btc_height"] == "1000"  # overrides 999
    # stale tagged + prev+1 override
    assert by_hash[stale_hash]["classification"] == "stale"
    assert by_hash[stale_hash]["btc_height"] == "500"  # 499 + 1, overrides 12345
    # unknown tagged
    assert by_hash[unknown_hash]["classification"] == "unknown"


def test_classify_candidates_empty():
    rpc = FakeRpc({}, {})
    assert classify_candidates([], rpc) == []


def test_classify_candidates_active_parent_requires_height():
    import pytest

    prev_known = "cc" * 32
    stale_hex, stale_hash = _passing_header(prev_known)
    headers = {prev_known: {"bits": "1b0404cb", "confirmations": 1}}
    rpc = FakeRpc(headers, {})
    candidates = [_candidate(stale_hex, stale_hash, prev_known, "777", "1")]
    with pytest.raises(ValueError, match="lacks a valid height"):
        classify_candidates(candidates, rpc)


def test_classify_candidates_known_side_chain_header_is_not_canonical():
    prev_known = "dd" * 32
    stale_hex, stale_hash = _passing_header(prev_known)
    headers = {
        stale_hash: {"height": 500, "bits": "1b0404cb", "confirmations": -1},
        prev_known: {"height": 499, "bits": "1b0404cb", "confirmations": 2},
    }
    rpc = FakeRpc(headers, {})
    results = classify_candidates(
        [_candidate(stale_hex, stale_hash, prev_known, "500", "1")], rpc
    )
    assert results[0]["classification"] == "stale"
    assert results[0]["btc_height"] == "500"


def test_classify_candidates_side_chain_parent_is_unknown():
    side_parent = "ee" * 32
    candidate_hex, candidate_hash = _passing_header(side_parent)
    rpc = FakeRpc(
        {
            side_parent: {
                "height": 499,
                "bits": "1b0404cb",
                "confirmations": -1,
            }
        },
        {},
    )
    results = classify_candidates(
        [_candidate(candidate_hex, candidate_hash, side_parent, "500", "1")], rpc
    )
    assert results[0]["classification"] == "unknown"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("btc_header_hash", "ff" * 32),
        ("btc_prev_hash", "ee" * 32),
        ("btc_time", "1"),
        ("btc_bits", "1d00ffff"),
    ],
)
def test_classify_candidates_direct_call_corroborates_header(field, value):
    header_hex, header_hash = _passing_header("aa" * 32)
    candidate = _candidate(header_hex, header_hash, "aa" * 32, "500", "1")
    candidate[field] = value

    with pytest.raises(ValueError, match=f"{field} does not match"):
        classify_candidates([candidate], FakeRpc({}, {}))


def test_classify_candidates_direct_call_requires_self_pow():
    failing = next(
        header
        for nonce in range(10_000)
        if not _meets(header := _make_header("aa" * 32, nonce))
    )
    candidate = _candidate(failing, _header_hash(failing), "aa" * 32, "500", "1")

    with pytest.raises(ValueError, match="does not satisfy"):
        classify_candidates([candidate], FakeRpc({}, {}))


def test_classify_candidates_rejects_incomplete_batch_without_omission():
    first_hex, first_hash = _passing_header("aa" * 32)
    second_hex, second_hash = _passing_header("bb" * 32)

    class IncompleteRpc(FakeRpc):
        def batch(self, calls):
            return super().batch(calls)[:-1]

    candidates = [
        _candidate(first_hex, first_hash, "aa" * 32, "500", "1"),
        _candidate(second_hex, second_hash, "bb" * 32, "501", "2"),
    ]
    with pytest.raises(ValueError, match="missing ids"):
        classify_candidates(candidates, IncompleteRpc({}, {}))


@pytest.mark.parametrize(
    ("responses", "message"),
    [
        ([{"id": 0}, {"id": 0}], "duplicate id"),
        ([{"id": 0}, {"id": 2}], "invalid id"),
        ([{"id": 0}, {"id": True}], "invalid id"),
    ],
)
def test_batch_response_ids_must_be_unique_and_in_range(responses, message):
    with pytest.raises(ValueError, match=message):
        _ordered_batch_responses(responses, expected_count=2, method="getblockheader")


# ---------------------------------------------------------------------------
# output_columns
# ---------------------------------------------------------------------------


def test_output_columns_order_with_height_col():
    cols = output_columns("ixc_height")
    assert cols == [
        "btc_height",
        "btc_header_hash",
        "btc_prev_hash",
        "btc_time",
        "btc_bits",
        "coinbase_scriptsig_hex",
        "coinbase_outputs",
        "btc_header_hex",
        "ixc_height",
        "classification",
        "validation_status",
        "expected_nbits",
    ]


def test_output_columns_without_height_col():
    cols = output_columns(None)
    assert "ixc_height" not in cols
    assert cols[-3:] == ["classification", "validation_status", "expected_nbits"]


# ---------------------------------------------------------------------------
# run_classifier
# ---------------------------------------------------------------------------


def _spec(tmp_path, in_path, out_path) -> ChainSpec:
    from pathlib import Path

    return ChainSpec(
        key="ixcoin",
        display_name="ixcoin",
        height_column="ixc_height",
        chain_id=3,
        activation_height=45_001,
        attribution_mode="coinbase",
        input_csv=Path(in_path),
        output_csv=Path(out_path),
        validated_csv=Path(tmp_path) / "validated.csv",
    )


def _write_input(path, rows):
    fields = list(rows[0].keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def test_run_classifier_full_pipeline_with_nbits_gate(tmp_path):
    # Two stale candidates sharing a known prev at height 499 (=> btc_height 500).
    # One stale uses the canonical nBits (VALID), one uses a mismatched nBits
    # (REJECTED by the gate). One unknown and one canonical header are mixed in.
    prev_known = "aa" * 32
    prev_unknown = "bb" * 32

    canon_hex, canon_hash = _passing_header("00" * 32)
    stale_valid_hex, stale_valid_hash = _passing_header(prev_known)
    # second stale: valid self-PoW at a different encoded target
    stale_rej_hex, stale_rej_hash = _passing_header(prev_known, bits=OTHER_EASY_BITS)
    unknown_hex, unknown_hash = _passing_header(prev_unknown)

    # A header that does NOT meet difficulty is filtered out in Phase 1.
    fail_hex = None
    for nonce in range(10_000):
        hx = _make_header("dd" * 32, nonce)
        if not _meets(hx):
            fail_hex = hx
            break
    assert fail_hex is not None

    # The valid stale's btc_bits must equal the canonical nBits at height 500.
    canonical_bits = f"{REGTEST_BITS:08x}"

    rows = [
        # canonical (distinct output, written to the canonical artifact)
        {**_candidate(canon_hex, canon_hash, "00" * 32, "1000", "10")},
        # stale VALID: btc_bits matches canonical
        {**_candidate(stale_valid_hex, stale_valid_hash, prev_known, "9", "20")},
        # stale REJECTED: btc_bits mismatched below
        {**_candidate(stale_rej_hex, stale_rej_hash, prev_known, "9", "21")},
        # unknown
        {**_candidate(unknown_hex, unknown_hash, prev_unknown, "0", "30")},
        # PoW-failing row, must be filtered
        {**_candidate(fail_hex, _header_hash(fail_hex), "dd" * 32, "0", "99")},
    ]
    in_path = tmp_path / "in.csv"
    out_path = tmp_path / "out.csv"
    _write_input(in_path, rows)

    canon_500 = _canonical_hash(500)
    height_to_hash = {500: canon_500}
    headers = {
        canon_hash: {"height": 1000, "bits": "1a00ffff", "confirmations": 1},
        prev_known: {"height": 499, "bits": canonical_bits, "confirmations": 2},
        canon_500: {"height": 500, "bits": canonical_bits, "confirmations": 1},
    }
    rpc = FakeRpc(headers, height_to_hash)

    spec = _spec(tmp_path, in_path, out_path)
    summary = run_classifier(spec, rpc=rpc)

    assert summary["total"] == 5
    assert summary["btc_valid"] == 4  # fail_hex dropped
    assert summary["canonical"] == 1
    assert summary["stale"] == 2
    assert summary["unknown"] == 1
    assert summary["valid"] == 1
    assert summary["rejected"] == 1
    assert summary["validation_unknown"] == 0

    # Stale file: stale rows only now (2), sorted ascending; unknown is split
    # into its own file and canonical into the canonical artifact.
    with open(out_path, newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == output_columns("ixc_height")
        out_rows = list(reader)

    assert len(out_rows) == 2
    assert all(r["classification"] == "stale" for r in out_rows)
    heights = [int(r["btc_height"]) for r in out_rows]
    assert heights == sorted(heights)

    stale_rows = {r["btc_header_hash"]: r for r in out_rows}
    assert stale_rows[stale_valid_hash]["btc_height"] == "500"  # prev+1 override
    assert stale_rows[stale_valid_hash]["validation_status"] == "VALID"
    assert stale_rows[stale_valid_hash]["expected_nbits"] == canonical_bits
    assert stale_rows[stale_rej_hash]["validation_status"].startswith("REJECTED")

    # Unknown file: the single unknown row, split out of the stale inventory.
    with open(summary["unknown_output_path"], newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == output_columns("ixc_height")
        unknown_rows = list(reader)
    assert len(unknown_rows) == 1
    assert unknown_rows[0]["btc_header_hash"] == unknown_hash
    assert unknown_rows[0]["classification"] == "unknown"

    # Canonical artifact: canonical rows with Core's height authoritative.
    with open(summary["canonical_output_path"], newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == output_columns("ixc_height")
        canonical_rows = list(reader)
    assert len(canonical_rows) == 1
    assert canonical_rows[0]["btc_header_hash"] == canon_hash
    assert canonical_rows[0]["classification"] == "canonical"
    assert canonical_rows[0]["btc_height"] == "1000"


def test_run_classifier_nbits_gate_is_not_skippable(tmp_path):
    # Even with a single stale, the gate must run and annotate the row.
    prev_known = "aa" * 32
    stale_hex, stale_hash = _passing_header(prev_known)
    canonical_bits = f"{REGTEST_BITS:08x}"
    row = _candidate(stale_hex, stale_hash, prev_known, "9", "20")

    in_path = tmp_path / "in.csv"
    out_path = tmp_path / "out.csv"
    _write_input(in_path, [row])

    headers = {
        prev_known: {"height": 499, "bits": canonical_bits, "confirmations": 2},
        _canonical_hash(500): {
            "height": 500,
            "bits": canonical_bits,
            "confirmations": 1,
        },
    }
    rpc = FakeRpc(headers, {500: _canonical_hash(500)})
    spec = _spec(tmp_path, in_path, out_path)
    summary = run_classifier(spec, rpc=rpc)

    assert summary["stale"] == 1
    assert summary["valid"] == 1
    # getblockhash was issued by the gate (proves it ran).
    assert any(c["method"] == "getblockhash" for c in rpc.calls)


def test_run_classifier_bip34_gate_excludes_mismatched_stale(tmp_path):
    prev_known = "af" * 32
    stale_hex, stale_hash = _passing_header(prev_known)
    row = _candidate(
        stale_hex,
        stale_hash,
        prev_known,
        str(BIP34_HEIGHT + 1),
        "20",
    )
    row["coinbase_scriptsig_hex"] = (
        b"\x03" + (BIP34_HEIGHT + 1).to_bytes(3, "little") + b"pool"
    ).hex()
    canonical_bits = row["btc_bits"]

    in_path = tmp_path / "in.csv"
    out_path = tmp_path / "out.csv"
    _write_input(in_path, [row])
    headers = {
        prev_known: {
            "height": BIP34_HEIGHT - 1,
            "bits": canonical_bits,
            "confirmations": 2,
        },
        _canonical_hash(BIP34_HEIGHT): {
            "height": BIP34_HEIGHT,
            "bits": canonical_bits,
            "confirmations": 1,
        },
    }
    rpc = FakeRpc(headers, {BIP34_HEIGHT: _canonical_hash(BIP34_HEIGHT)})

    summary = run_classifier(_spec(tmp_path, in_path, out_path), rpc=rpc)

    assert summary["stale"] == 1
    assert summary["valid"] == 0
    assert summary["rejected"] == 1
    with open(out_path, newline="") as f:
        stale = list(csv.DictReader(f))
    assert stale[0]["validation_status"] == (
        "REJECTED: BIP34 coinbase height mismatch "
        f"(got {BIP34_HEIGHT + 1}, expected {BIP34_HEIGHT})"
    )
    with open(summary["validated_output_path"], newline="") as f:
        assert list(csv.DictReader(f)) == []


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("btc_header_hash", "ff" * 32, "btc_header_hash does not match"),
        ("btc_prev_hash", "ee" * 32, "btc_prev_hash does not match"),
        ("btc_time", "1699999999", "btc_time does not match"),
        ("btc_bits", f"{OTHER_EASY_BITS:08x}", "btc_bits does not match"),
    ],
)
def test_run_classifier_rejects_header_metadata_mismatch(
    tmp_path, field, replacement, message
):
    header_hex, header_hash = _passing_header("aa" * 32)
    row = _candidate(header_hex, header_hash, "aa" * 32, "500", "1")
    row[field] = replacement
    in_path = tmp_path / f"{field}.csv"
    _write_input(in_path, [row])

    with pytest.raises(ValueError, match=message):
        run_classifier(
            _spec(tmp_path, in_path, tmp_path / "out.csv"),
            rpc=FakeRpc({}, {}),
        )


# ---------------------------------------------------------------------------
# normalize_bits_hex (D2b)
# ---------------------------------------------------------------------------


def test_normalize_bits_hex_decimal_source_converts():
    # Legacy bitcoin-vault decimal value -> canonical hex.
    assert normalize_bits_hex("386924253", source_is_decimal=True) == "170ffedd"
    assert int("170ffedd", 16) == 386924253


def test_normalize_bits_hex_all_digit_hex_passes_through_unchanged():
    # An 8-char all-digit string is HEX (e.g. devcoin 19548732); with
    # source_is_decimal False it must NOT be decimal-converted.
    assert normalize_bits_hex("19548732", source_is_decimal=False) == "19548732"


def test_normalize_bits_hex_lowercases_hex():
    assert normalize_bits_hex("1D00FFFF", source_is_decimal=False) == "1d00ffff"


def test_normalize_bits_hex_rejects_non_8_char_hex():
    import pytest

    with pytest.raises(ValueError):
        normalize_bits_hex(
            "386924253", source_is_decimal=False
        )  # 9 chars, would be decimal
    with pytest.raises(ValueError):
        normalize_bits_hex("zzzz", source_is_decimal=False)


# ---------------------------------------------------------------------------
# run_classifier keystone extensions: validated_csv, preflight, batch fallback
# ---------------------------------------------------------------------------


def test_run_classifier_writes_valid_only_validated_csv(tmp_path):
    # One VALID stale, one REJECTED stale, one unknown. The validated_csv must
    # contain ONLY the VALID stale; the full inventory keeps all three.
    prev_known = "aa" * 32
    prev_unknown = "bb" * 32
    canonical_bits = f"{REGTEST_BITS:08x}"

    stale_valid_hex, stale_valid_hash = _passing_header(prev_known)
    stale_rej_hex, stale_rej_hash = _passing_header(prev_known, bits=OTHER_EASY_BITS)
    unknown_hex, unknown_hash = _passing_header(prev_unknown)

    rows = [
        {**_candidate(stale_valid_hex, stale_valid_hash, prev_known, "9", "20")},
        {**_candidate(stale_rej_hex, stale_rej_hash, prev_known, "9", "21")},
        {**_candidate(unknown_hex, unknown_hash, prev_unknown, "0", "30")},
    ]
    in_path = tmp_path / "in.csv"
    out_path = tmp_path / "out.csv"
    _write_input(in_path, rows)
    headers = {
        prev_known: {"height": 499, "bits": canonical_bits, "confirmations": 2},
        _canonical_hash(500): {
            "height": 500,
            "bits": canonical_bits,
            "confirmations": 1,
        },
    }
    rpc = FakeRpc(headers, {500: _canonical_hash(500)})
    spec = _spec(tmp_path, in_path, out_path)

    summary = run_classifier(spec, rpc=rpc)

    # validated_csv = VALID-only stale rows.
    with open(spec.validated_csv, newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == output_columns("ixc_height")
        validated = list(reader)
    assert len(validated) == 1
    assert validated[0]["btc_header_hash"] == stale_valid_hash
    assert validated[0]["validation_status"] == "VALID"
    assert summary["validated_output_path"] == str(spec.validated_csv)

    # Stale file now holds stale-only (2); the unknown row is split into its own file.
    with open(out_path, newline="") as f:
        assert len(list(csv.DictReader(f))) == 2
    with open(summary["unknown_output_path"], newline="") as f:
        assert len(list(csv.DictReader(f))) == 1


def test_run_classifier_preflight_fails_on_unreachable_node(tmp_path):
    import pytest

    class DeadRpc(FakeRpc):
        def batch(self, calls):
            # getblockcount preflight returns no result (node unreachable).
            return [
                {"jsonrpc": "1.0", "id": c["id"], "result": None, "error": None}
                for c in calls
            ]

    row = _candidate(*_passing_header("aa" * 32), "aa" * 32, "9", "1")
    in_path = tmp_path / "in.csv"
    _write_input(in_path, [row])
    spec = _spec(tmp_path, in_path, tmp_path / "out.csv")

    with pytest.raises(RuntimeError, match="preflight"):
        run_classifier(spec, rpc=DeadRpc({}, {}))


def test_run_classifier_preserves_outputs_when_validation_is_unknown(tmp_path):
    prev_known = "aa" * 32
    stale_hex, stale_hash = _passing_header(prev_known)
    row = _candidate(stale_hex, stale_hash, prev_known, "9", "20")
    in_path = tmp_path / "in.csv"
    out_path = tmp_path / "out.csv"
    _write_input(in_path, [row])
    spec = _spec(tmp_path, in_path, out_path)
    spec.validated_csv.write_text("sentinel\n")

    # Classification can establish a canonical predecessor, but the later
    # canonical-at-height lookup is unavailable. Regeneration must abort before
    # replacing either the stale inventory or the committed VALID-only file.
    headers = {
        prev_known: {
            "height": 499,
            "bits": f"{REGTEST_BITS:08x}",
            "confirmations": 2,
        }
    }

    with pytest.raises(RuntimeError, match="validation is incomplete"):
        run_classifier(spec, rpc=FakeRpc(headers, {}))

    assert spec.validated_csv.read_text() == "sentinel\n"
    assert not out_path.exists()


def test_run_classifier_batch_fallback_retries_individually(tmp_path):
    # A transient failure on the first multi-call batch must be recovered by
    # retrying each candidate singly, not abort the run.
    prev_known = "aa" * 32
    prev_unknown = "bb" * 32
    canonical_bits = f"{REGTEST_BITS:08x}"
    stale_hex, stale_hash = _passing_header(prev_known)
    unknown_hex, unknown_hash = _passing_header(prev_unknown)

    rows = [
        {**_candidate(stale_hex, stale_hash, prev_known, "9", "20")},
        {**_candidate(unknown_hex, unknown_hash, prev_unknown, "0", "30")},
    ]

    class FlakyRpc(FakeRpc):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._raised = False

        def batch(self, calls):
            # Fail once on the first multi-call batch (Phase 2's batch of 2),
            # forcing the per-candidate fallback; later batches succeed.
            if len(calls) > 1 and not self._raised:
                self._raised = True
                raise RuntimeError("transient batch error")
            return super().batch(calls)

    in_path = tmp_path / "in.csv"
    out_path = tmp_path / "out.csv"
    _write_input(in_path, rows)
    headers = {
        prev_known: {"height": 499, "bits": canonical_bits, "confirmations": 2},
        _canonical_hash(500): {
            "height": 500,
            "bits": canonical_bits,
            "confirmations": 1,
        },
    }
    rpc = FlakyRpc(headers, {500: _canonical_hash(500)})
    spec = _spec(tmp_path, in_path, out_path)

    summary = run_classifier(spec, rpc=rpc)

    assert rpc._raised  # the transient failure was exercised
    assert summary["stale"] == 1
    assert summary["unknown"] == 1
    assert summary["valid"] == 1


def test_run_classifier_does_not_write_partial_outputs(tmp_path):
    first_hex, first_hash = _passing_header("aa" * 32)
    second_hex, second_hash = _passing_header("bb" * 32)
    rows = [
        _candidate(first_hex, first_hash, "aa" * 32, "500", "1"),
        _candidate(second_hex, second_hash, "bb" * 32, "501", "2"),
    ]

    class IncompleteRpc(FakeRpc):
        def batch(self, calls):
            responses = super().batch(calls)
            if calls and calls[0]["method"] == "getblockheader":
                return responses[:-1]
            return responses

    in_path = tmp_path / "in.csv"
    out_path = tmp_path / "out.csv"
    _write_input(in_path, rows)

    with pytest.raises(ValueError, match="missing ids"):
        run_classifier(_spec(tmp_path, in_path, out_path), rpc=IncompleteRpc({}, {}))
    assert not out_path.exists()


# ---------------------------------------------------------------------------
# write_classifier_outputs: the shared bucket-split writer
# ---------------------------------------------------------------------------


def _cls_row(cls, height, status="", nbits=""):
    """Minimal classified row for the writer test."""
    return {
        "btc_height": str(height),
        "btc_header_hash": f"{height:064x}",
        "classification": cls,
        "validation_status": status,
        "expected_nbits": nbits,
        "ixc_height": str(height),
    }


def test_write_classifier_outputs_splits_by_bucket_and_validated(tmp_path):
    cols = output_columns("ixc_height")
    all_results = [
        _cls_row("canonical", 1000),
        _cls_row("stale", 500, status="VALID", nbits="1b0404cb"),
        _cls_row("stale", 501, status="REJECTED_NBITS"),
        _cls_row("unknown", 30),
        _cls_row("unknown", 20),
    ]
    paths = {
        k: tmp_path / f"{k}.csv" for k in ("canonical", "stale", "unknown", "validated")
    }
    counts = write_classifier_outputs(
        all_results,
        columns=cols,
        canonical_path=str(paths["canonical"]),
        stale_path=str(paths["stale"]),
        unknown_path=str(paths["unknown"]),
        validated_path=str(paths["validated"]),
    )

    def read(p):
        with open(p, newline="") as f:
            r = csv.DictReader(f)
            assert r.fieldnames == cols  # identical schema across all four files
            return list(r)

    canon, stale, unknown, validated = (
        read(paths[k]) for k in ("canonical", "stale", "unknown", "validated")
    )

    # Each file is bucket-pure (no commingling).
    assert [r["classification"] for r in canon] == ["canonical"]
    assert {r["classification"] for r in stale} == {"stale"}
    assert {r["classification"] for r in unknown} == {"unknown"}
    # stale file has NO canonical/unknown rows; unknown file has NO stale rows.
    assert all(r["classification"] == "stale" for r in stale)
    assert all(r["classification"] == "unknown" for r in unknown)
    # validated = the VALID stale subset only.
    assert len(validated) == 1
    assert validated[0]["btc_height"] == "500"
    assert validated[0]["validation_status"] == "VALID"
    # sorted by height ascending within each file.
    assert [int(r["btc_height"]) for r in unknown] == [20, 30]
    # returned counts.
    assert counts == {
        "canonical": 1,
        "stale": 2,
        "unknown": 2,
        "valid": 1,
        "rejected": 1,
        "validation_unknown": 0,
    }


def test_write_classifier_outputs_writes_header_for_empty_bucket(tmp_path):
    cols = output_columns("ixc_height")
    paths = {
        k: tmp_path / f"{k}.csv" for k in ("canonical", "stale", "unknown", "validated")
    }
    write_classifier_outputs(
        [_cls_row("stale", 500, status="VALID")],
        columns=cols,
        canonical_path=str(paths["canonical"]),
        stale_path=str(paths["stale"]),
        unknown_path=str(paths["unknown"]),
        validated_path=str(paths["validated"]),
    )
    # empty unknown file still has the header row, no data rows.
    with open(paths["unknown"], newline="") as f:
        r = csv.DictReader(f)
        assert r.fieldnames == cols
        assert list(r) == []
