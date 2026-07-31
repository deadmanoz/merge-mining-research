"""Offline unit tests for the time-rule error-block sweep.

The sweep's inventory reading and canonical MTP fetching are injectable;
these tests run fully offline with synthetic in-memory inventories and an
injected MTP context.
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
        "sweep_error_blocks_time_rule_under_test",
        REPO / "scripts" / "analysis" / "sweep_error_blocks_time_rule.py",
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

FIELDS = [
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "classification",
    "validation_status",
    "expected_nbits",
]

# Realistic parent context: the median-time-past is about an hour before the
# parent's block time (a real MTP trails the block time by roughly the median
# of the preceding 11 blocks, not days). Tests that place a candidate nTime
# relative to these exercise the time rules within the plausibility window.
PARENT_TIME = 1_400_000_000
PARENT_MTP = PARENT_TIME - 3600
# Canonical context for the parent of height 225013 (i.e. height 225012).
MTP_CONTEXT = {225012: {"time": PARENT_TIME, "mediantime": PARENT_MTP}}


def _header_hex(bits: str, n_time: int, nonce: int = 42) -> str:
    header = (
        (2).to_bytes(4, "little")
        + b"\x11" * 32
        + b"\x22" * 32
        + n_time.to_bytes(4, "little")
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
    n_time: int,
    *,
    scriptsig_height: int | None = None,
) -> dict[str, str]:
    header_hex = _header_hex(bits, n_time)
    return {
        "btc_height": str(height),
        "btc_header_hash": _display_hash(header_hex),
        "btc_prev_hash": "11" * 32,
        "btc_time": str(n_time),
        "btc_bits": bits,
        "coinbase_scriptsig_hex": (
            "" if scriptsig_height is None else _bip34_scriptsig(scriptsig_height)
        ),
        "coinbase_outputs": "",
        "btc_header_hex": header_hex,
        "classification": "stale",
        "validation_status": "VALID",
        "expected_nbits": bits,
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


def _synthetic_nbits_by_epoch(mapping: dict[str, str]) -> dict[int, int]:
    """An epoch table agreeing with the synthetic rows' EASY_BITS target.

    The shared canonical-target check corroborates a row's ``expected_nbits``
    against the epoch table at the claimed height's epoch start and fails
    closed on a disagreement. The synthetic rows use the trivially-met
    EASY_BITS, which disagrees with the REAL (hard) epoch-table value at
    these heights; map each row's epoch start to EASY_BITS so the
    canonical-target check can pass for a full-PoW finding.
    """
    table: dict[int, int] = {}
    for text in mapping.values():
        for row in csv.DictReader(io.StringIO(text)):
            try:
                height = int((row.get("btc_height") or "").strip())
            except ValueError:
                continue  # no parseable height: no epoch-start entry needed
            table[(height // 2016) * 2016] = int(EASY_BITS, 16)
    return table


def _sweep(mapping: dict[str, str], dataset_keys=None, nbits_by_epoch=None):
    return sweep.sweep_chain(
        "devcoin",
        "/fake/devcoin_stale_blocks.csv",
        "/fake/devcoin_unknown_blocks.csv",
        _reader(mapping),
        MTP_CONTEXT,
        dataset_keys or set(),
        nbits_by_epoch
        if nbits_by_epoch is not None
        else _synthetic_nbits_by_epoch(mapping),
    )


# ---------------------------------------------------------------------------
# Time-rule logic
# ---------------------------------------------------------------------------


def test_apply_time_rules_below_mtp() -> None:
    assert (
        sweep.apply_time_rules(PARENT_MTP, PARENT_MTP, PARENT_TIME) == "time_below_mtp"
    )
    assert (
        sweep.apply_time_rules(PARENT_MTP - 1, PARENT_MTP, PARENT_TIME)
        == "time_below_mtp"
    )


def test_apply_time_rules_above_mtp_passes() -> None:
    assert sweep.apply_time_rules(PARENT_MTP + 1, PARENT_MTP, PARENT_TIME) == ""


def test_apply_time_rules_beyond_future_limit() -> None:
    future = PARENT_TIME + sweep.MAX_FUTURE_BLOCK_TIME + 1
    assert (
        sweep.apply_time_rules(future, PARENT_MTP, PARENT_TIME)
        == "time_beyond_future_limit"
    )
    # Exactly at the bound passes (the rule is strictly greater-than).
    at_bound = PARENT_TIME + sweep.MAX_FUTURE_BLOCK_TIME
    assert sweep.apply_time_rules(at_bound, PARENT_MTP, PARENT_TIME) == ""


# ---------------------------------------------------------------------------
# Claimed-height trust
# ---------------------------------------------------------------------------


def test_claimed_height_accepts_column_matching_bip34() -> None:
    row = _row(225013, EASY_BITS, PARENT_TIME, scriptsig_height=225013)
    height, why = sweep.claimed_height(row)
    assert height == 225013
    assert why == ""


def test_claimed_height_rejects_bip34_disagreement() -> None:
    # At a BIP34-era height the coinbase-height prefix IS a consensus height
    # commitment, so a first-push integer disagreeing with btc_height
    # contradicts it: the claimed height is not trustworthy.
    row = _row(300000, EASY_BITS, PARENT_TIME, scriptsig_height=436459339)
    height, why = sweep.claimed_height(row)
    assert height is None
    assert "BIP34" in why


def test_claimed_height_pre_bip34_prefix_mismatch_is_not_rejected() -> None:
    # Before BIP34 activation the scriptSig's first push was NOT a consensus
    # height commitment, so a pre-BIP34 row whose first pushed integer differs
    # from btc_height is not a contradiction: the authoritative stale
    # inventory's btc_height is trustworthy on its own and the row is kept.
    # (225013 < BIP34_HEIGHT = 227931.)
    assert 225013 < sweep.BIP34_HEIGHT
    row = _row(225013, EASY_BITS, PARENT_TIME, scriptsig_height=436459339)
    height, why = sweep.claimed_height(row)
    assert height == 225013
    assert why == ""


def test_claimed_height_rejects_missing_or_malformed() -> None:
    row = _row(225013, EASY_BITS, PARENT_TIME)
    row["btc_height"] = ""
    assert sweep.claimed_height(row)[0] is None
    row["btc_height"] = "not-a-number"
    assert sweep.claimed_height(row)[0] is None


# ---------------------------------------------------------------------------
# PoW re-verification
# ---------------------------------------------------------------------------


def test_reverify_full_pow_rederives_time_and_bits() -> None:
    header_hex = _header_hex(EASY_BITS, 1_400_000_123)
    meets, n_time, bits = sweep.reverify_full_pow(header_hex)
    assert meets is True
    assert n_time == 1_400_000_123
    assert bits == int(EASY_BITS, 16)


def test_reverify_full_pow_matches_reference_digest() -> None:
    # Regression: the digest must be sha256d of the header exactly once.
    # sha256d applied twice is a different value; a target strictly between
    # the two digests is met by the smaller only. EASY_BITS passes either
    # way, so it cannot catch a double hash — this test patches the header's
    # bits field to a discriminating target.
    from stale_blocks_analysis.auxpow_parse import nbits_to_target

    header_hex = _header_hex(EASY_BITS, PARENT_TIME)
    header = bytes.fromhex(header_hex)
    single = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    double = hashlib.sha256(single).digest()  # sha256d applied a second time
    single_int = int.from_bytes(single, "little")
    double_int = int.from_bytes(double, "little")
    assert single_int != double_int
    low, high = sorted((single_int, double_int))
    # Scan for an exactly-representable nBits target in (low, high]: at the
    # exponent where a 3-byte mantissa reaches `high`, walk the mantissa down
    # from high's top bytes until the target drops at/below `high`. The
    # function must agree with the SINGLE-hash digest, and the two digests
    # must land on opposite sides of the target for it to discriminate.
    target = None
    for exponent in range(32, 2, -1):
        top = high >> (8 * (exponent - 3))
        for mantissa in range(min(top, 0x7FFFFF), 0, -1):
            candidate = mantissa << (8 * (exponent - 3))
            if low < candidate <= high:
                target = candidate
                bits = (exponent << 24) | mantissa
                break
        if target is not None:
            break
    assert target is not None, "no representable target between the digests"
    assert nbits_to_target(bits) == target
    assert (single_int <= target) != (double_int <= target)
    raw = bytearray(header)
    raw[72:76] = bits.to_bytes(4, "little")
    assert sweep.reverify_full_pow(raw.hex())[0] is (single_int <= target)


def test_reverify_full_pow_failure_and_malformed() -> None:
    assert (
        sweep.reverify_full_pow(_header_hex(IMPOSSIBLE_BITS, PARENT_TIME))[0] is False
    )
    assert sweep.reverify_full_pow("not-hex") is None
    assert sweep.reverify_full_pow("00" * 79) is None


# ---------------------------------------------------------------------------
# End-to-end sweep over synthetic inventories
# ---------------------------------------------------------------------------


def test_sweep_time_below_mtp_row_is_new_finding() -> None:
    # nTime below the parent MTP: a time-too-old error block.
    stale_row = _row(225013, EASY_BITS, PARENT_MTP - 100)
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    report = _sweep(mapping)
    assert report.reachable is True
    assert report.stale_rows == 1
    assert report.candidates == 1
    assert report.time_below_mtp == 1
    assert report.time_beyond_future_limit == 0
    assert len(report.new_findings) == 1
    assert report.new_findings[0].violation == "time_below_mtp"
    assert report.already_in_dataset == 0


def test_sweep_row_above_mtp_is_not_a_violation() -> None:
    stale_row = _row(225013, EASY_BITS, PARENT_MTP + 100)
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    report = _sweep(mapping)
    assert report.candidates == 1
    assert report.time_below_mtp == 0
    assert report.time_beyond_future_limit == 0
    assert report.new_findings == []


def test_sweep_time_below_mtp_failing_canonical_target_is_not_confirmed() -> None:
    # A time_below_mtp candidate whose digest meets only its easy self-declared
    # embedded target but NOT the canonical expected-nBits target at the
    # claimed height is a share/contamination observation, never a confirmed
    # error block — the same rule the offline validator enforces.
    stale_row = _row(225013, EASY_BITS, PARENT_MTP - 100)
    stale_row["expected_nbits"] = IMPOSSIBLE_BITS  # canonical target: not met
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    report = _sweep(mapping)
    assert report.candidates == 1
    assert report.time_below_mtp == 1  # the time violation is observed...
    assert report.canonical_target_fail == 1  # ...but tallied separately
    assert report.new_findings == []
    assert report.already_in_dataset == 0

    # The epoch-table fallback: an unparseable expected_nbits column falls
    # back to the committed epoch table at the claimed height's epoch start,
    # whose real target the synthetic easy header cannot meet either. This
    # sub-case passes the REAL epoch table (the default synthetic table would
    # agree with the easy header and let the fallback pass).
    stale_row["expected_nbits"] = "not-hex"
    mapping["/fake/devcoin_stale_blocks.csv"] = _inventory([stale_row])
    report = _sweep(mapping, nbits_by_epoch=sweep.load_nbits_by_epoch())
    assert report.time_below_mtp == 1
    assert report.canonical_target_fail == 1
    assert report.new_findings == []


def test_sweep_expected_nbits_disagreeing_with_epoch_table_is_not_confirmed() -> None:
    # A parseable inventory expected_nbits that DISAGREES with the committed
    # epoch table at the claimed height's epoch start is suspect (a stale
    # inventory could carry an erroneous/artificially-easy value): the
    # canonical target is unevaluable, so the row fails closed and is NOT a
    # confirmed error block. Here the REAL epoch table at 225013's epoch
    # start (223776) is a hard target that disagrees with the row's easy
    # expected_nbits.
    stale_row = _row(225013, EASY_BITS, PARENT_MTP - 100)
    assert stale_row["expected_nbits"] == EASY_BITS  # parseable, not the epoch value
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    report = _sweep(mapping, nbits_by_epoch=sweep.load_nbits_by_epoch())
    assert report.candidates == 1
    assert report.time_below_mtp == 1  # the time violation is observed...
    assert report.canonical_target_fail == 1  # ...but unevaluable: not confirmed
    assert report.new_findings == []
    assert report.already_in_dataset == 0


def test_sweep_future_limit_row_is_review_flag_not_promoted() -> None:
    # A modest future-limit excess on a trustworthy height is a manual-review
    # flag (approximate reference, deferred in the validator), never a
    # promoted NEW finding.
    future = PARENT_TIME + sweep.MAX_FUTURE_BLOCK_TIME + 1
    stale_row = _row(225013, EASY_BITS, future)
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    report = _sweep(mapping)
    assert report.time_beyond_future_limit == 1
    assert report.new_findings == []  # not promoted
    assert len(report.future_limit_flags) == 1
    assert report.future_limit_flags[0].violation == "time_beyond_future_limit"


def test_sweep_large_future_gap_on_authoritative_height_is_flagged() -> None:
    # An authoritative-height stale row (regen chain) with a large future
    # excess IS interpretable — its height was verified against the canonical
    # chain — so it is flagged for review, not discarded as untrustworthy.
    # (The unobtanium 379924 row is the real instance: nTime ~125h beyond its
    # canonical parent.)
    large = PARENT_TIME + 125 * 3600
    stale_row = _row(225013, EASY_BITS, large)
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    report = _sweep(mapping)
    assert report.untrustworthy_height == 0
    assert report.time_beyond_future_limit == 1
    assert len(report.future_limit_flags) == 1
    assert report.new_findings == []  # review flag, never promoted


def test_sweep_pow_failure_is_excluded() -> None:
    # A share/near row failing its own target is never an error block, even
    # with a time-rule-violating nTime.
    stale_row = _row(225013, IMPOSSIBLE_BITS, PARENT_MTP - 100)
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    report = _sweep(mapping)
    assert report.pow_fail == 1
    assert report.candidates == 0
    assert report.new_findings == []


def test_sweep_pre_bip34_stale_row_with_prefix_mismatch_is_kept() -> None:
    # An authoritative pre-BIP34 stale row whose scriptSig first push differs
    # from btc_height: the prefix was NOT a consensus height commitment before
    # BIP34 activation, so the row is NOT rejected on the mismatch — its
    # authoritative btc_height is trustworthy and it is evaluated normally.
    # (225013 < BIP34_HEIGHT; its parent 225012 is in MTP_CONTEXT.)
    assert 225013 < sweep.BIP34_HEIGHT
    stale_row = _row(225013, EASY_BITS, PARENT_MTP - 100, scriptsig_height=999)
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    report = _sweep(mapping)
    # Kept (not rejected for the prefix): collected as a candidate and
    # evaluated as a time_below_mtp violation on its authoritative height.
    assert report.candidates == 1
    assert report.untrustworthy_height == 0
    assert report.time_below_mtp == 1


def test_sweep_bip34_era_stale_row_with_prefix_mismatch_is_rejected() -> None:
    # A BIP34-era stale row whose scriptSig first push differs from btc_height:
    # the prefix IS a consensus height commitment here, so the claimed height
    # is not trustworthy and the row is rejected (never a candidate).
    stale_row = _row(300000, EASY_BITS, PARENT_MTP - 100, scriptsig_height=999)
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    report = _sweep(mapping)
    assert report.candidates == 0
    assert report.time_below_mtp == 0
    assert report.new_findings == []


def test_sweep_unknown_row_is_not_authoritative_height() -> None:
    # Unknown-row btc_height is not verified against the canonical chain (the
    # classifier leaves it from child-chain evidence), so even a full-PoW
    # unknown row with a BIP34 coinbase height is tallied as an untrustworthy
    # height, never evaluated as a time-rule violation.
    unknown_row = _row(225013, EASY_BITS, PARENT_MTP - 100, scriptsig_height=225013)
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([unknown_row]),
    }
    report = _sweep(mapping)
    assert report.unknown_rows == 1
    assert report.candidates == 1  # full-PoW candidate collected...
    assert report.untrustworthy_height == 1  # ...but not authoritative
    assert report.new_findings == []
    assert report.time_below_mtp == 0


def test_sweep_unknown_row_without_height_is_skipped() -> None:
    no_height = _row(225013, EASY_BITS, PARENT_MTP - 100)
    no_height["btc_height"] = ""
    # A BIP34-era unknown row whose first-push coinbase height disagrees with
    # its btc_height: the claimed height is not trustworthy, so it is skipped.
    mismatch = _row(300000, EASY_BITS, PARENT_MTP - 100, scriptsig_height=999)
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([no_height, mismatch]),
    }
    report = _sweep(mapping)
    assert report.unknown_rows == 2
    assert report.unknown_no_height == 2
    assert report.candidates == 0


def test_sweep_membership_dedupes_against_dataset() -> None:
    stale_row = _row(225013, EASY_BITS, PARENT_MTP - 100)
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    dataset_keys = {(225013, stale_row["btc_header_hash"])}
    report = _sweep(mapping, dataset_keys)
    assert report.already_in_dataset == 1
    assert report.new_findings == []


def test_sweep_uses_header_derived_hash_not_column() -> None:
    # The btc_header_hash column disagrees with the header bytes: candidate
    # identity and dataset membership must use the header-derived display
    # hash, not the (fabricated/stale) column value.
    stale_row = _row(225013, EASY_BITS, PARENT_MTP - 100)
    header_derived = stale_row["btc_header_hash"]  # the _row helper sets this
    stale_row["btc_header_hash"] = "ff" * 32  # fabricated column value
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    # Membership keyed on the header-derived hash matches despite the wrong
    # column, so the row is deduped (already in dataset), not a NEW finding.
    dataset_keys = {(225013, header_derived)}
    report = _sweep(mapping, dataset_keys)
    assert report.candidates == 1
    assert report.already_in_dataset == 1
    assert report.new_findings == []
    # And with an empty dataset the finding carries the header-derived hash,
    # not the fabricated column value.
    report = _sweep(mapping)
    assert len(report.new_findings) == 1
    assert report.new_findings[0].block_hash == header_derived


def test_sweep_missing_mtp_context_is_not_evaluated() -> None:
    stale_row = _row(225013, EASY_BITS, PARENT_MTP - 100)
    mapping = {
        "/fake/devcoin_stale_blocks.csv": _inventory([stale_row]),
        "/fake/devcoin_unknown_blocks.csv": _inventory([]),
    }
    report = sweep.sweep_chain(
        "devcoin",
        "/fake/devcoin_stale_blocks.csv",
        "/fake/devcoin_unknown_blocks.csv",
        _reader(mapping),
        {},  # no canonical context at all
        set(),
    )
    assert report.no_mtp_context == 1
    assert report.new_findings == []


def test_sweep_unreachable_inventory_fails_soft() -> None:
    report = _sweep({})
    assert report.reachable is False
    assert report.error


# ---------------------------------------------------------------------------
# Resolution-section preservation across regeneration
# ---------------------------------------------------------------------------


def _empty_report(chain: str = "devcoin") -> "sweep.ChainReport":
    return sweep.ChainReport(chain=chain, stale_inventory="/fake/stale.csv")


def test_extract_resolution_section_returns_followup_to_eof() -> None:
    text = (
        "# Error-blocks time-rule sweep\n\n... generated body ...\n\n"
        "## Follow-up investigation (2026-07-30): future-limit flags resolved\n\n"
        "The 15 flags were resolved as late-mined, 0 violations.\n"
    )
    section = sweep.extract_resolution_section(text)
    assert section.startswith("## Follow-up investigation")
    assert "0 violations" in section
    assert "generated body" not in section
    # No follow-up section -> empty.
    assert sweep.extract_resolution_section("# no follow-up here\n") == ""


def test_render_report_preserves_existing_resolution_section() -> None:
    # A prior report carrying the manually-written follow-up investigation:
    # regenerating must carry the section forward verbatim, not drop it.
    resolution = (
        "## Follow-up investigation (2026-07-30): future-limit flags resolved\n\n"
        "All 15 flags resolved as late-mined, 0 violations.\n"
    )
    prior = f"# old report\n\nold body\n\n{resolution}"
    rendered = sweep.render_report([_empty_report()], "2026-01-01 00:00 UTC", prior)
    assert "## Follow-up investigation" in rendered
    assert "All 15 flags resolved as late-mined, 0 violations." in rendered
    # The section is appended after the generated body, exactly once.
    assert rendered.count("## Follow-up investigation") == 1
    assert rendered.index("Row-level candidate detail") < rendered.index(
        "## Follow-up investigation"
    )


def test_render_report_without_prior_text_has_no_resolution_section() -> None:
    rendered = sweep.render_report([_empty_report()], "2026-01-01 00:00 UTC")
    assert "## Follow-up investigation" not in rendered


# ---------------------------------------------------------------------------
# MTP cache + main() fail-closed behavior
# ---------------------------------------------------------------------------


def test_fetch_mtp_context_uses_cache_and_fetches_missing(tmp_path: Path) -> None:
    cache = tmp_path / "mtp.json"
    cache.write_text('{"100": {"time": 10, "mediantime": 9}}')
    calls: list[list[int]] = []

    def fetcher(heights: list[int]) -> dict[int, dict[str, int]]:
        calls.append(heights)
        return {h: {"time": h * 10, "mediantime": h * 9} for h in heights}

    ctx = sweep.fetch_mtp_context({100, 200}, fetcher, cache)
    assert calls == [[200]]  # only the missing height was fetched
    assert ctx[100] == {"time": 10, "mediantime": 9}
    assert ctx[200] == {"time": 2000, "mediantime": 1800}
    # The cache now carries both heights.
    reloaded = sweep.load_mtp_cache(cache)
    assert set(reloaded) == {100, 200}


def test_main_fails_closed_when_no_inventory_reachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader({}))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_time_rule.py",
            "--allow-partial",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert sweep.main() == 1
    assert not list(tmp_path.iterdir())


def test_main_fails_closed_when_mtp_fetch_returns_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stale_row = _row(225013, EASY_BITS, PARENT_MTP - 100)
    mapping = {
        path: _inventory([stale_row] if "stale" in path else [])
        for path in sweep.STALE_INVENTORIES.values()
    }
    mapping.update(
        {path: _inventory([]) for path in sweep.UNKNOWN_INVENTORY_GLOB.values()}
    )
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(mapping))
    monkeypatch.setattr(sweep, "ssh_mtp_fetcher", lambda heights: {})
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_time_rule.py",
            "--mtp-cache",
            str(tmp_path / "mtp.json"),
            "--allow-partial",
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert sweep.main() == 1
    assert not (tmp_path / "out").exists()


def test_main_writes_report_with_negative_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    below = _row(225013, EASY_BITS, PARENT_MTP - 100)
    clean = _row(225014, EASY_BITS, PARENT_MTP + 100)
    mapping = {}
    for chain, path in sweep.STALE_INVENTORIES.items():
        if chain == "devcoin":
            rows = [below, clean]
        elif chain == "ixcoin":
            rows = [clean]  # candidates but zero violations: negative result
        else:
            rows = []
        mapping[path] = _inventory(rows)
    mapping.update(
        {path: _inventory([]) for path in sweep.UNKNOWN_INVENTORY_GLOB.values()}
    )
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(mapping))

    def fetcher(heights: list[int]) -> dict[int, dict[str, int]]:
        return {h: {"time": PARENT_TIME, "mediantime": PARENT_MTP} for h in heights}

    monkeypatch.setattr(sweep, "ssh_mtp_fetcher", fetcher)
    # The synthetic rows use the trivially-met EASY_BITS, which disagrees with
    # the REAL epoch-table value at these heights; the canonical-target check
    # corroborates expected_nbits against the epoch table and fails closed on
    # a disagreement, so inject a synthetic epoch table that agrees with
    # EASY_BITS to let the full-PoW finding confirm.
    monkeypatch.setattr(
        sweep,
        "load_nbits_by_epoch",
        lambda: _synthetic_nbits_by_epoch(mapping),
    )
    out_dir = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_time_rule.py",
            "--mtp-cache",
            str(tmp_path / "mtp.json"),
            "--allow-partial",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert sweep.main() == 0

    report = (out_dir / sweep.DEFAULT_REPORT.name).read_text()
    assert "NEW confirmed error blocks: 1" in report
    assert "`time_below_mtp` violations (trustworthy heights): 1" in report
    assert "Chains with full-PoW candidates but no time-rule violation" in report


def test_main_fetches_mtp_only_for_authoritative_height_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Unknown-row candidates (and scratch-inventory stale rows) carry a
    # non-authoritative claimed height: evaluate_candidate tallies them as
    # untrustworthy and never MTP-evaluates them. Their heights must NOT be
    # requested from the canonical node — only authoritative-height
    # candidates' parent heights are fetched.
    authoritative = _row(225013, EASY_BITS, PARENT_MTP - 100)
    untrustworthy = _row(700001, EASY_BITS, PARENT_MTP - 100)
    mapping = {}
    for chain, path in sweep.STALE_INVENTORIES.items():
        mapping[path] = _inventory([authoritative] if chain == "devcoin" else [])
    mapping.update(
        {
            path: _inventory([untrustworthy] if "devcoin" in path else [])
            for path in sweep.UNKNOWN_INVENTORY_GLOB.values()
        }
    )
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(mapping))
    fetched: list[list[int]] = []

    def fetcher(heights: list[int]) -> dict[int, dict[str, int]]:
        fetched.append(heights)
        return {h: {"time": PARENT_TIME, "mediantime": PARENT_MTP} for h in heights}

    monkeypatch.setattr(sweep, "ssh_mtp_fetcher", fetcher)
    out_dir = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_time_rule.py",
            "--mtp-cache",
            str(tmp_path / "mtp.json"),
            "--allow-partial",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert sweep.main() == 0
    # Only the authoritative candidate's parent height (225012) was fetched;
    # the untrustworthy unknown-row candidate's parent height (700000) was not.
    assert fetched == [[225012]]
    report = (out_dir / sweep.DEFAULT_REPORT.name).read_text()
    assert "untrustworthy height" in report


def test_main_refuses_partial_write_to_committed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mapping = {path: _inventory([]) for path in sweep.STALE_INVENTORIES.values()}
    mapping.update(
        {path: _inventory([]) for path in sweep.UNKNOWN_INVENTORY_GLOB.values()}
    )
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(mapping))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_time_rule.py",
            "--mtp-cache",
            str(tmp_path / "mtp.json"),
            "--allow-partial",
            "--output-dir",
            str(sweep.DEFAULT_REPORT.parent),
        ],
    )
    assert sweep.main() == 2


def _partial_mapping() -> dict[str, str]:
    """All but one stale inventory reachable (devcoin's path is omitted)."""
    mapping = {
        path: _inventory([])
        for chain, path in sweep.STALE_INVENTORIES.items()
        if chain != "devcoin"
    }
    mapping.update(
        {path: _inventory([]) for path in sweep.UNKNOWN_INVENTORY_GLOB.values()}
    )
    return mapping


def test_main_partial_sweep_refuses_committed_write_without_allow_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One reachable + one unreachable inventory, writing to the (committed)
    # default path WITHOUT --allow-partial: fail closed, no write.
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(_partial_mapping()))
    monkeypatch.setattr(
        sweep,
        "ssh_mtp_fetcher",
        lambda heights: {
            h: {"time": PARENT_TIME, "mediantime": PARENT_MTP} for h in heights
        },
    )
    out = tmp_path / "committed-report.md"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_time_rule.py",
            "--mtp-cache",
            str(tmp_path / "mtp.json"),
            "--output",
            str(out),
        ],
    )
    assert sweep.main() == 1
    assert not out.exists()


def test_main_partial_sweep_writes_partial_with_allow_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The diagnostic escape hatch: --allow-partial --output-dir writes the
    # partial report to the disposable dir.
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(_partial_mapping()))
    monkeypatch.setattr(
        sweep,
        "ssh_mtp_fetcher",
        lambda heights: {
            h: {"time": PARENT_TIME, "mediantime": PARENT_MTP} for h in heights
        },
    )
    out_dir = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_time_rule.py",
            "--mtp-cache",
            str(tmp_path / "mtp.json"),
            "--allow-partial",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert sweep.main() == 0
    report = (out_dir / sweep.DEFAULT_REPORT.name).read_text()
    assert "Unreachable inventories" in report


def _full_mapping_with_candidate() -> dict[str, str]:
    """Every inventory reachable, with full-PoW candidates on devcoin.

    Two candidates at distinct claimed heights (225013 and 225014) so the
    requested parent heights are {225012, 225013}: an MTP fetcher can then
    omit one while still returning a non-empty context.
    """
    below = _row(225013, EASY_BITS, PARENT_MTP - 100)
    clean = _row(225014, EASY_BITS, PARENT_MTP + 100)
    mapping = {}
    for chain, path in sweep.STALE_INVENTORIES.items():
        mapping[path] = _inventory([below, clean] if chain == "devcoin" else [])
    mapping.update(
        {path: _inventory([]) for path in sweep.UNKNOWN_INVENTORY_GLOB.values()}
    )
    return mapping


def _fetcher_omitting(missing_height: int):
    """An MTP fetcher that returns context for every requested height but one."""

    def fetcher(heights: list[int]) -> dict[int, dict[str, int]]:
        return {
            h: {"time": PARENT_TIME, "mediantime": PARENT_MTP}
            for h in heights
            if h != missing_height
        }

    return fetcher


def test_main_incomplete_mtp_context_refuses_committed_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # All inventories reachable (the full-coverage guard passes), but the
    # canonical MTP context omits the one requested parent height (225012).
    # Writing the committed report from an incomplete context would present
    # an incomplete sweep as complete, so it must fail closed: non-zero exit,
    # no write, naming the missing height.
    monkeypatch.setattr(
        sweep, "ssh_inventory_reader", _reader(_full_mapping_with_candidate())
    )
    monkeypatch.setattr(sweep, "ssh_mtp_fetcher", _fetcher_omitting(225012))
    out = tmp_path / "committed-report.md"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_time_rule.py",
            "--mtp-cache",
            str(tmp_path / "mtp.json"),
            "--output",
            str(out),
        ],
    )
    assert sweep.main() == 1
    assert not out.exists()


def test_main_incomplete_mtp_context_writes_partial_with_allow_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The diagnostic escape hatch: with --allow-partial --output-dir the
    # incomplete-MTP sweep writes the partial report to the disposable dir.
    monkeypatch.setattr(
        sweep, "ssh_inventory_reader", _reader(_full_mapping_with_candidate())
    )
    monkeypatch.setattr(sweep, "ssh_mtp_fetcher", _fetcher_omitting(225012))
    out_dir = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_time_rule.py",
            "--mtp-cache",
            str(tmp_path / "mtp.json"),
            "--allow-partial",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert sweep.main() == 0
    report = (out_dir / sweep.DEFAULT_REPORT.name).read_text()
    assert "no canonical parent context available" in report
