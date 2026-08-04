"""Offline unit tests for the rejected-row error-block sweep.

The sweep's inventory reading is injectable; these tests run fully offline
with synthetic in-memory inventories.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_sweep():
    spec = importlib.util.spec_from_file_location(
        "sweep_error_blocks_rejected_rows_under_test",
        REPO / "scripts" / "analysis" / "sweep_error_blocks_rejected_rows.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


sweep = _load_sweep()

from _sweep_test_helpers import _bip34_scriptsig  # noqa: E402

# A bits value whose target is so large any header hash passes (exp 0x21).
EASY_BITS = "2100ffff"
# A bits value whose target is zero: nothing passes.
IMPOSSIBLE_BITS = "01003456"
# Harder than EASY_BITS but still easy enough to grind in tests (~2^8 tries).
HARDER_BITS = "2000ffff"
# Nonce for which _header_hex(EASY_BITS, nonce) meets the HARDER_BITS target.
HARDER_NONCE = 771

FIELDS = [
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "coinbase_scriptsig_hex",
    "btc_header_hex",
    "classification",
    "validation_status",
    "expected_nbits",
    "btc_bip34_height",
]


def _header_hex(bits: str, nonce: int = 42, version: int = 2) -> str:
    header = (
        version.to_bytes(4, "little", signed=True)
        + b"\x11" * 32
        + b"\x22" * 32
        + (1_400_000_000).to_bytes(4, "little")
        + bytes.fromhex(bits)[::-1]  # nBits is little-endian in the header
        + nonce.to_bytes(4, "little")
    )
    assert len(header) == 80
    return header.hex()


def _display_hash(header_hex: str) -> str:
    digest = hashlib.sha256(hashlib.sha256(bytes.fromhex(header_hex)).digest()).digest()
    return digest[::-1].hex()


def _row(
    height: int,
    bits: str,
    status: str,
    header_hex: str | None = None,
    scriptsig_hex: str = "03abcdef",
    bip34_height: str = "",
) -> dict[str, str]:
    header_hex = header_hex or _header_hex(bits)
    return {
        "btc_height": str(height),
        "btc_header_hash": _display_hash(header_hex),
        "btc_prev_hash": "11" * 32,
        "btc_time": "1400000000",
        "btc_bits": bits,
        "coinbase_scriptsig_hex": scriptsig_hex,
        "btc_header_hex": header_hex,
        "classification": "stale",
        "validation_status": status,
        "expected_nbits": bits,
        "btc_bip34_height": bip34_height,
    }


def _inventory(rows: list[dict[str, str]]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def _reader(mapping: dict[str, str]):
    def read(chain: str, path: str) -> str:
        if path not in mapping:
            raise OSError(f"no such inventory: {path}")
        return mapping[path]

    return read


def _synthetic_nbits_by_epoch(rows: list[dict[str, str]]) -> dict[int, int]:
    """An epoch table agreeing with the synthetic rows' EASY_BITS target.

    The contextual-row canonical-target check corroborates a row's
    ``expected_nbits`` against the epoch table at the claimed height's epoch
    start and fails closed on a disagreement. The synthetic rows use the
    trivially-met EASY_BITS, which disagrees with the REAL (hard) epoch-table
    value at these heights; map each row's epoch start to EASY_BITS so the
    canonical-target check can pass for a full-PoW finding.
    """
    table: dict[int, int] = {}
    for row in rows:
        try:
            height = int(row["btc_height"])
        except ValueError:
            continue  # no parseable height: no epoch-start entry needed
        table[(height // 2016) * 2016] = int(EASY_BITS, 16)
    return table


def _sweep(
    chain: str,
    path: str,
    mapping: dict[str, str],
    dataset_keys=None,
    nbits_by_epoch=None,
):
    rows = list(csv.DictReader(io.StringIO(mapping[path]))) if path in mapping else []
    return sweep.sweep_chain(
        chain,
        path,
        _reader(mapping),
        dataset_keys or set(),
        nbits_by_epoch
        if nbits_by_epoch is not None
        else _synthetic_nbits_by_epoch(rows),
    )


# ---------------------------------------------------------------------------
# Reason classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected_class"),
    [
        (
            "REJECTED: BIP34 coinbase height mismatch (got 436459339, expected 225013)",
            "contextual",
        ),
        (
            "REJECTED: Bitcoin block version below historical minimum (got 2, need >= 3)",
            "contextual",
        ),
        (
            "REJECTED: Bitcoin coinbase scriptSig length outside consensus range (got 103)",
            "contextual",
        ),
        (
            "REJECTED: Bitcoin header time not greater than parent median-time-past",
            "contextual",
        ),
        ("REJECTED: nBits mismatch (got 1a1bf2d4, expected 1a03d74b)", "target"),
        (
            "REJECTED: nBits mismatch with canonical BTC height (got 170b98ab, expected 1705dd01)",
            "target",
        ),
        ("REJECTED: something never seen before", "unrecognized"),
    ],
)
def test_classify_reason(status: str, expected_class: str) -> None:
    reason, reason_class = sweep.classify_reason(status)
    assert reason_class == expected_class
    assert reason
    # "nBits mismatch with canonical BTC height" must not be swallowed by the
    # shorter "nBits mismatch" prefix.
    if "canonical" in status:
        assert reason.startswith("nBits mismatch with canonical BTC height")


def test_classify_reason_rejects_non_rejected_status() -> None:
    with pytest.raises(ValueError, match="not a REJECTED status"):
        sweep.classify_reason("VALID")


# ---------------------------------------------------------------------------
# PoW re-verification gate
# ---------------------------------------------------------------------------


def test_reverify_full_pow_pass_and_fail() -> None:
    assert sweep.reverify_full_pow(_header_hex(EASY_BITS)) is True
    assert sweep.reverify_full_pow(_header_hex(IMPOSSIBLE_BITS)) is False


def test_reverify_full_pow_malformed_is_none() -> None:
    assert sweep.reverify_full_pow("not-hex") is None
    assert sweep.reverify_full_pow(("00" * 79)) is None


def test_reverify_full_pow_ignores_bits_column() -> None:
    # The own-target PoW check decodes nBits from the header bytes: a
    # mismatched btc_bits column can neither create nor hide a finding.
    row = _row(
        225013,
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch",
        scriptsig_hex=_bip34_scriptsig(436459339),  # wrong height: re-derives
    )
    row["btc_bits"] = IMPOSSIBLE_BITS  # column disagrees with the header
    mapping = {"/fake/devcoin_stale_blocks.csv": _inventory([row])}

    report = _sweep("devcoin", "/fake/devcoin_stale_blocks.csv", mapping)

    # The header's embedded (easy) bits win: full PoW passes and the
    # contextual row is a finding despite the impossible bits column.
    assert report.pow_pass == 1
    assert len(report.new_findings) == 1


def test_reverify_pow_against_target_uses_supplied_target() -> None:
    # The canonical-target anomaly check is the one place an externally
    # supplied target (expected_nbits) applies.
    header_hex = _header_hex(EASY_BITS, nonce=HARDER_NONCE)
    assert sweep.reverify_pow_against_target(header_hex, HARDER_BITS) is True
    assert sweep.reverify_pow_against_target(header_hex, IMPOSSIBLE_BITS) is False
    assert sweep.reverify_pow_against_target(header_hex, "not-hex") is None
    assert sweep.reverify_pow_against_target("not-hex", HARDER_BITS) is None


# ---------------------------------------------------------------------------
# End-to-end sweep over synthetic inventories
# ---------------------------------------------------------------------------


def test_sweep_contextual_full_pow_row_is_candidate() -> None:
    contextual_row = _row(
        225013,
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch (got 436459339, expected 225013)",
        scriptsig_hex=_bip34_scriptsig(436459339),  # wrong height: re-derives
    )
    target_row = _row(
        225014,
        IMPOSSIBLE_BITS,
        "REJECTED: nBits mismatch (got 01003456, expected 1a03d74b)",
    )
    valid_row = _row(225015, EASY_BITS, "VALID")
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory(
            [contextual_row, target_row, valid_row]
        )
    }

    report = _sweep("devcoin", "/fake/devcoin_stale_blocks.csv", mapping)

    assert report.reachable is True
    assert report.total_rows == 3
    assert report.rejected_rows == 2
    assert report.contextual == 1
    assert report.target == 1
    assert report.pow_pass == 1
    assert report.pow_fail == 1
    # The contextual full-PoW row is a NEW finding (dataset keys are empty).
    assert len(report.new_findings) == 1
    assert report.new_findings[0].height == 225013
    assert report.already_in_dataset == 0
    # The nBits-failure row fails PoW: not a candidate, not an anomaly.
    assert report.target_anomalies == []


def test_sweep_membership_dedupes_against_dataset() -> None:
    row = _row(
        225013,
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch (got 436459339, expected 225013)",
        scriptsig_hex=_bip34_scriptsig(436459339),  # wrong height: re-derives
    )
    mapping = {"/fake/devcoin_stale_blocks.csv": _inventory([row])}
    dataset_keys = {(225013, row["btc_header_hash"])}

    report = _sweep("devcoin", "/fake/devcoin_stale_blocks.csv", mapping, dataset_keys)

    assert report.already_in_dataset == 1
    assert report.new_findings == []


def test_sweep_contextual_row_confirmed_only_when_failure_rederives() -> None:
    # BIP34-labelled row whose scriptSig actually has the WRONG height
    # prefix: the named failure re-derives from the bytes, so the row is a
    # confirmed error-block candidate.
    row = _row(
        225013,
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch (got 436459339, expected 225013)",
        scriptsig_hex=_bip34_scriptsig(436459339),
    )
    mapping = {"/fake/devcoin_stale_blocks.csv": _inventory([row])}

    report = _sweep("devcoin", "/fake/devcoin_stale_blocks.csv", mapping)

    assert report.contextual == 1
    assert report.pow_pass == 1
    assert len(report.new_findings) == 1
    assert report.contextual_not_rederived == 0


def test_sweep_contextual_row_not_confirmed_when_failure_does_not_rederive() -> None:
    # BIP34-labelled row whose scriptSig actually has the CORRECT height
    # prefix: the named failure does NOT re-derive from the bytes, so the row
    # is NOT confirmed on the label alone — it is tallied separately.
    row = _row(
        225013,
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch (got 225013, expected 225013)",
        scriptsig_hex=_bip34_scriptsig(225013),
    )
    mapping = {"/fake/devcoin_stale_blocks.csv": _inventory([row])}

    report = _sweep("devcoin", "/fake/devcoin_stale_blocks.csv", mapping)

    assert report.contextual == 1
    assert report.pow_pass == 1
    assert report.new_findings == []
    assert report.contextual_not_rederived == 1
    assert report.contextual_not_offline_rederivable == 0


def test_sweep_bip34_labelled_v1_header_is_not_confirmed() -> None:
    # A BIP34-labelled contextual row whose header is version 1 at a post-BIP34
    # height: bip34_height_error rejects it for the VERSION rule (a post-BIP34
    # v1 header is invalid regardless of its coinbase prefix), not for a
    # coinbase-height serialization failure. The row's real problem is its
    # version, so it must NOT be confirmed as a BIP34 coinbase-height error
    # block on the label alone.
    row = _row(
        300000,  # post-BIP34_HEIGHT: version 1 is invalid here
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch (got 300005, expected 300000)",
        header_hex=_header_hex(EASY_BITS, version=1),
        scriptsig_hex=_bip34_scriptsig(300005),  # wrong height, but version gates first
    )
    mapping = {"/fake/devcoin_stale_blocks.csv": _inventory([row])}

    report = _sweep("devcoin", "/fake/devcoin_stale_blocks.csv", mapping)

    assert report.contextual == 1
    assert report.pow_pass == 1
    assert report.new_findings == []
    assert report.contextual_not_rederived == 1


def test_sweep_bip34_labelled_metadata_disagreement_is_not_confirmed() -> None:
    # A BIP34-labelled contextual row whose scriptSig encodes the height
    # CORRECTLY but whose optional btc_bip34_height column disagrees with it:
    # bip34_height_error rejects it on the metadata cross-check ("decoded BIP34
    # coinbase height disagrees with btc_bip34_height"), which is an
    # inconsistent-metadata observation, NOT a genuine raw coinbase-height
    # consensus failure. It must NOT be confirmed as an error block.
    row = _row(
        300000,
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch (got 300000, expected 300000)",
        scriptsig_hex=_bip34_scriptsig(300000),  # correct raw prefix
        bip34_height="300005",  # column disagrees with the correct scriptSig
    )
    mapping = {"/fake/devcoin_stale_blocks.csv": _inventory([row])}

    report = _sweep("devcoin", "/fake/devcoin_stale_blocks.csv", mapping)

    assert report.contextual == 1
    assert report.pow_pass == 1
    assert report.new_findings == []
    assert report.contextual_not_rederived == 1


def test_sweep_contextual_row_failing_canonical_target_is_not_confirmed() -> None:
    # A contextual row that meets its own (easy self-declared) embedded target
    # and re-derives its named failure, but whose digest does NOT meet the
    # canonical expected-nBits target, is a share/contamination observation —
    # never a confirmed error block (the same rule the validator enforces).
    row = _row(
        225013,
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch (got 436459339, expected 225013)",
        scriptsig_hex=_bip34_scriptsig(436459339),  # wrong height: re-derives
    )
    row["expected_nbits"] = IMPOSSIBLE_BITS  # canonical target: not met
    mapping = {"/fake/devcoin_stale_blocks.csv": _inventory([row])}

    report = _sweep("devcoin", "/fake/devcoin_stale_blocks.csv", mapping)

    assert report.contextual == 1
    assert report.pow_pass == 1  # meets its own embedded target...
    assert report.contextual_not_rederived == 0  # ...and the rule re-derives...
    assert report.contextual_canonical_target_fail == 1  # ...but not canonical
    assert report.new_findings == []
    assert report.already_in_dataset == 0


def test_sweep_contextual_row_expected_nbits_disagreeing_with_epoch_table() -> None:
    # A contextual row whose inventory ``expected_nbits`` DISAGREES with the
    # committed epoch table at the claimed height's epoch start must NOT be
    # confirmed: the canonical-target check corroborates the inventory value
    # against the epoch table and fails closed on a disagreement, so a
    # malformed/artificially-easy inventory ``expected_nbits`` cannot make the
    # row pass ``meets_expected_pow`` into ``new_findings``. Here the REAL
    # epoch table at 225013's epoch start (223776) is the hard 1a03d74b,
    # which disagrees with the row's easy expected_nbits.
    row = _row(
        225013,
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch (got 436459339, expected 225013)",
        scriptsig_hex=_bip34_scriptsig(436459339),  # wrong height: re-derives
    )
    assert row["expected_nbits"] == EASY_BITS  # parseable, not the epoch value
    mapping = {"/fake/devcoin_stale_blocks.csv": _inventory([row])}

    report = _sweep(
        "devcoin",
        "/fake/devcoin_stale_blocks.csv",
        mapping,
        nbits_by_epoch=sweep.load_nbits_by_epoch(),
    )

    assert report.contextual == 1
    assert report.pow_pass == 1  # meets its own embedded target...
    assert report.contextual_not_rederived == 0  # ...and the rule re-derives...
    assert report.contextual_canonical_target_fail == 1  # ...but unevaluable
    assert report.new_findings == []
    assert report.already_in_dataset == 0


def test_sweep_mtp_row_is_not_offline_rederivable() -> None:
    # The median-time-past rejection needs canonical parent context that is
    # not committed in the inventory: the row is tallied separately and never
    # confirmed as an error block by this sweep.
    row = _row(
        225013,
        EASY_BITS,
        "REJECTED: Bitcoin header time not greater than parent median-time-past "
        "(got 1400000000, required > 1400000001)",
        scriptsig_hex=_bip34_scriptsig(225013),
    )
    mapping = {"/fake/devcoin_stale_blocks.csv": _inventory([row])}

    report = _sweep("devcoin", "/fake/devcoin_stale_blocks.csv", mapping)

    assert report.contextual == 1
    assert report.pow_pass == 1
    assert report.new_findings == []
    assert report.contextual_not_rederived == 0
    assert report.contextual_not_offline_rederivable == 1


def test_sweep_scratch_chain_contextual_row_is_not_promoted() -> None:
    # Height-trust model: a full-PoW contextual row from a canonical-fill-
    # scratch inventory (syscoin, or any chain in _SCRATCH_CHAINS) re-derives
    # its named failure and meets the canonical expected-nBits target, but its
    # btc_height is NOT canonical-verified — it must NOT be promoted to a
    # confirmed new_findings error block on an unverified height. It is
    # tallied separately as untrustworthy_height.
    row = _row(
        225013,
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch (got 436459339, expected 225013)",
        scriptsig_hex=_bip34_scriptsig(436459339),  # wrong height: re-derives
    )
    mapping = {"/fake/syscoin_stale_blocks.csv": _inventory([row])}

    report = _sweep("syscoin", "/fake/syscoin_stale_blocks.csv", mapping)

    assert report.contextual == 1
    assert report.pow_pass == 1
    assert report.contextual_not_rederived == 0  # the rule re-derives...
    assert report.contextual_canonical_target_fail == 0  # ...canonical target met...
    assert report.new_findings == []  # ...but NOT promoted (unverified height)
    assert report.already_in_dataset == 0
    assert report.untrustworthy_height == 1

    rendered = sweep.render_report([report], "2026-07-30 00:00 UTC")
    assert "not promoted): 1" in rendered
    assert "NOT promoted on an unverified height" in rendered


def test_sweep_regen_chain_contextual_row_is_still_promoted() -> None:
    # Control: the SAME full-PoW contextual row from a regen-chain
    # (authoritative-height) inventory IS promoted to new_findings — the
    # scratch-chain gate does not suppress authoritative findings.
    row = _row(
        225013,
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch (got 436459339, expected 225013)",
        scriptsig_hex=_bip34_scriptsig(436459339),  # wrong height: re-derives
    )
    mapping = {"/fake/devcoin_stale_blocks.csv": _inventory([row])}

    report = _sweep("devcoin", "/fake/devcoin_stale_blocks.csv", mapping)

    assert report.untrustworthy_height == 0
    assert len(report.new_findings) == 1
    assert report.new_findings[0].height == 225013


def test_sweep_target_row_passing_pow_is_anomaly_not_finding() -> None:
    # nBits-mismatch row whose digest meets the *canonical expected* target:
    # an error-block candidate for manual review, never auto-promoted.
    header_hex = _header_hex(EASY_BITS, nonce=HARDER_NONCE)
    row = _row(
        700000,
        EASY_BITS,
        "REJECTED: nBits mismatch with canonical BTC height "
        f"(got {EASY_BITS}, expected {HARDER_BITS})",
        header_hex=header_hex,
    )
    row["expected_nbits"] = HARDER_BITS  # harder than EASY_BITS but still met
    mapping = {"/fake/syscoin_stale_blocks.csv": _inventory([row])}

    report = _sweep("syscoin", "/fake/syscoin_stale_blocks.csv", mapping)

    assert report.new_findings == []
    assert len(report.target_anomalies) == 1
    assert report.target_anomalies[0].height == 700000


def test_sweep_target_anomaly_in_dataset_is_reported_as_catalogued() -> None:
    # Regression: a target-class anomaly whose (height, hash) key is ALREADY
    # in the committed dataset must be reported as catalogued/promoted, not
    # as an un-promoted manual candidate (the 717696 case: once promoted, a
    # regeneration must not re-report it as awaiting manual review).
    header_hex = _header_hex(EASY_BITS, nonce=HARDER_NONCE)
    row = _row(
        717696,
        EASY_BITS,
        "REJECTED: nBits mismatch with canonical BTC height "
        f"(got {EASY_BITS}, expected {HARDER_BITS})",
        header_hex=header_hex,
    )
    row["expected_nbits"] = HARDER_BITS
    mapping = {"/fake/emercoin_stale_blocks.csv": _inventory([row])}
    dataset_keys = {(717696, row["btc_header_hash"])}

    report = _sweep(
        "emercoin", "/fake/emercoin_stale_blocks.csv", mapping, dataset_keys
    )

    assert len(report.target_anomalies) == 1
    assert report.target_anomalies[0].in_dataset is True

    rendered = sweep.render_report([report], "2026-07-30 00:00 UTC")
    # The in-dataset anomaly is marked catalogued/promoted, and the summary
    # counts 0 un-promoted candidates.
    assert "ALREADY IN THE DATASET (catalogued/promoted)" in rendered
    assert "(0 un-promoted, 1 already in the dataset)" in rendered

    # Control: the same anomaly NOT in the dataset is an un-promoted
    # candidate (no catalogued marker).
    report = _sweep("emercoin", "/fake/emercoin_stale_blocks.csv", mapping)
    assert report.target_anomalies[0].in_dataset is False
    rendered = sweep.render_report([report], "2026-07-30 00:00 UTC")
    assert "ALREADY IN THE DATASET" not in rendered
    assert "(1 un-promoted, 0 already in the dataset)" in rendered


def test_sweep_target_row_meeting_only_own_bits_is_not_anomaly() -> None:
    # Re-verifying an nBits-mismatch row against its own (wrong) bits is
    # circular: it trivially passes. The decisive check is the canonical
    # expected target; a row meeting only its own bits is a share.
    header_hex = _header_hex(EASY_BITS)
    row = _row(
        376385,
        EASY_BITS,
        "REJECTED: nBits mismatch (got 2100ffff, expected 01003456)",
        header_hex=header_hex,
    )
    row["expected_nbits"] = IMPOSSIBLE_BITS  # canonical target: not met
    mapping = {"/fake/i0coin_stale_blocks.csv": _inventory([row])}

    report = _sweep("i0coin", "/fake/i0coin_stale_blocks.csv", mapping)

    assert report.target == 1
    assert report.pow_pass == 1  # meets its own bits...
    assert report.target_anomalies == []  # ...but not the canonical target
    assert report.new_findings == []


def test_sweep_unreachable_inventory_fails_soft() -> None:
    report = sweep.sweep_chain("devcoin", "/missing.csv", _reader({}), set())
    assert report.reachable is False
    assert report.error


def test_main_fails_closed_when_no_inventory_reachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader({}))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_rejected_rows.py",
            "--allow-partial",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert sweep.main() == 1
    assert not list(tmp_path.iterdir())


def test_main_writes_report_with_negative_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contextual_row = _row(
        225013,
        EASY_BITS,
        "REJECTED: BIP34 coinbase height mismatch (got 436459339, expected 225013)",
        scriptsig_hex=_bip34_scriptsig(225013),
    )
    target_row = _row(
        225014,
        IMPOSSIBLE_BITS,
        "REJECTED: nBits mismatch (got 01003456, expected 1a03d74b)",
    )
    inventories = {
        chain: _inventory(rows)
        for chain, rows in {
            "devcoin": [contextual_row],
            "ixcoin": [],
            "i0coin": [target_row],
            "groupcoin": [],
            "emercoin": [],
            "unobtanium": [],
            "syscoin": [],
        }.items()
    }
    mapping = {
        sweep.CHAIN_INVENTORIES[chain]: text for chain, text in inventories.items()
    }
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(mapping))
    out_dir = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_rejected_rows.py",
            "--allow-partial",
            "--output-dir",
            str(out_dir),
        ],
    )

    assert sweep.main() == 0

    report = (out_dir / sweep.DEFAULT_REPORT.name).read_text()
    assert "REJECTED rows examined: 2" in report
    # The contextual row's BIP34 label does not re-derive (its scriptSig has
    # the correct height prefix), so it is NOT a confirmed error block.
    assert (
        "NEW confirmed error blocks (full PoW + canonical target + contextual "
        "re-derived, not in dataset): 0" in report
    )
    assert "named failure did NOT re-derive (not confirmed): 1" in report
    assert "Chains with zero REJECTED rows" in report
    assert "every target-class rejection failed the canonical" in report


def test_load_dataset_keys_fails_closed_on_empty_dataset(tmp_path: Path) -> None:
    # Regression: an empty or header-only committed dataset must fail closed.
    # The sweeps treat any rediscovered catalogued row absent from the key set
    # as NEW, so an empty key set would make every sweep report every
    # catalogued error block as a NEW finding (fail-open). This mirrors the
    # gate loader / builder / validator empty-dataset checks.
    for name, text in (
        ("header_only.csv", "height,hash,classification\n"),
        ("empty.csv", ""),
    ):
        path = tmp_path / name
        path.write_text(text)
        with pytest.raises(ValueError, match="no error block rows"):
            sweep.load_dataset_keys(path)


@pytest.mark.parametrize(
    ("name", "text", "match"),
    [
        # A blank classification (not the error_block token).
        (
            "blank_classification.csv",
            "height,hash,classification\n225013," + "ab" * 32 + ",\n",
            "invalid error block row",
        ),
        # A non-error_block classification.
        (
            "wrong_classification.csv",
            "height,hash,classification\n225013," + "ab" * 32 + ",stale\n",
            "invalid error block row",
        ),
        # A malformed hash (not 32 bytes of hex).
        (
            "malformed_hash.csv",
            "height,hash,classification\n225013,zz,error_block\n",
            "invalid error block row",
        ),
        # A duplicate (height, hash) key.
        (
            "duplicate_key.csv",
            "height,hash,classification\n"
            + "225013,"
            + "ab" * 32
            + ",error_block\n"
            + "225013,"
            + "ab" * 32
            + ",error_block\n",
            "duplicate error block key",
        ),
    ],
    ids=["blank-classification", "wrong-classification", "malformed-hash", "duplicate-key"],
)
def test_load_dataset_keys_fails_closed_on_invalid_catalog_row(
    tmp_path: Path, name: str, text: str, match: str
) -> None:
    # Regression: the sweep loader applies the same fail-closed validation as
    # the publication gate loader — a blank/wrong classification, a malformed
    # height/hash, or a duplicate key must raise, not be silently tolerated.
    path = tmp_path / name
    path.write_text(text)
    with pytest.raises(ValueError, match=match):
        sweep.load_dataset_keys(path)


def test_load_dataset_keys_loads_committed_dataset() -> None:
    # The committed 33-row dataset loads fine.
    assert len(sweep.load_dataset_keys()) == 33


def test_main_refuses_partial_write_to_committed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mapping = {path: _inventory([]) for path in sweep.CHAIN_INVENTORIES.values()}
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(mapping))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_rejected_rows.py",
            "--allow-partial",
            "--output-dir",
            str(sweep.DEFAULT_REPORT.parent),
        ],
    )
    assert sweep.main() == 2


@pytest.mark.parametrize(
    "output_dir",
    [
        # The committed report directory itself...
        Path("results/analysis/error-blocks"),
        # ...a subdirectory of it...
        Path("results/analysis/error-blocks") / "nested",
        # ...and the committed dataset directory.
        Path("data/error-blocks"),
    ],
    ids=["report-dir", "report-dir-nested", "dataset-dir"],
)
def test_main_refuses_partial_output_dir_in_committed_artifact_locations(
    output_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A partial sweep's --output-dir must be a genuinely disposable location:
    # pointing it at (or inside) a committed artifact directory would let a
    # partial report overwrite a DIFFERENT committed report or the committed
    # dataset, so it is refused (exit 2, no write) even with --output naming
    # an innocent filename.
    mapping = {path: _inventory([]) for path in sweep.CHAIN_INVENTORIES.values()}
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(mapping))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_rejected_rows.py",
            "--allow-partial",
            "--output-dir",
            str(output_dir),
            "--output",
            "scratch-partial-report.md",
        ],
    )
    assert sweep.main() == 2
    assert not (output_dir / "scratch-partial-report.md").exists()


def _partial_mapping() -> dict[str, str]:
    """All but one inventory reachable (devcoin's path is omitted)."""
    return {
        path: _inventory([])
        for chain, path in sweep.CHAIN_INVENTORIES.items()
        if chain != "devcoin"
    }


def test_main_partial_sweep_refuses_committed_write_without_allow_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One reachable + one unreachable inventory, writing to the (committed)
    # default path WITHOUT --allow-partial: fail closed, no write.
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(_partial_mapping()))
    out = tmp_path / "committed-report.md"
    monkeypatch.setattr(
        sys,
        "argv",
        ["sweep_error_blocks_rejected_rows.py", "--output", str(out)],
    )
    assert sweep.main() == 1
    assert not out.exists()


def test_main_partial_sweep_writes_partial_with_allow_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The diagnostic escape hatch: --allow-partial --output-dir writes the
    # partial report to the disposable dir.
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(_partial_mapping()))
    out_dir = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_rejected_rows.py",
            "--allow-partial",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert sweep.main() == 0
    report = (out_dir / sweep.DEFAULT_REPORT.name).read_text()
    assert "Unreachable inventories" in report
