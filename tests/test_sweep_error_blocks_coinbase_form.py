"""Offline unit tests for the coinbase-form error-block sweep.

The sweep's inventory reading is injectable; these tests run fully offline
with synthetic in-memory inventories and injected readers.
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
        "sweep_error_blocks_coinbase_form_under_test",
        REPO / "scripts" / "analysis" / "sweep_error_blocks_coinbase_form.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


sweep = _load_sweep()

from _sweep_test_helpers import _bip34_scriptsig, _header_hex  # noqa: E402

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
    "btc_bip34_height",
]

# A post-BIP34 height (mandatory coinbase-height prefix), inside the
# plausible range.
BIP34_ERA_HEIGHT = 300_000
PRE_BIP34_HEIGHT = 100_000


def _display_hash(header_hex: str) -> str:
    digest = hashlib.sha256(hashlib.sha256(bytes.fromhex(header_hex)).digest()).digest()
    return digest[::-1].hex()


def _row(
    height: int,
    version: int,
    bits: str,
    *,
    scriptsig_hex: str | None = None,
    bip34_height: str = "",
) -> dict[str, str]:
    header_hex = _header_hex(version, bits)
    return {
        "btc_height": str(height),
        "btc_header_hash": _display_hash(header_hex),
        "btc_prev_hash": "11" * 32,
        "btc_time": "1500000000",
        "btc_bits": bits,
        "coinbase_scriptsig_hex": (
            _bip34_scriptsig(height) if scriptsig_hex is None else scriptsig_hex
        ),
        "coinbase_outputs": "",
        "btc_header_hex": header_hex,
        "classification": "stale",
        "validation_status": "VALID",
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

    The shared canonical-target check corroborates a row's ``expected_nbits``
    against the epoch table at the claimed height's epoch start and fails
    closed on a disagreement. The synthetic rows use the trivially-met
    EASY_BITS, which disagrees with the REAL (hard) epoch-table value at
    these heights; map each row's epoch start to EASY_BITS so the
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
    rows: list[dict[str, str]],
    *,
    authoritative: bool = True,
    source: str = "stale",
    dataset_keys=None,
    nbits_by_epoch=None,
):
    return sweep.sweep_inventory(
        "devcoin",
        source,
        "/fake/devcoin_stale_blocks.csv",
        authoritative,
        _reader({"/fake/devcoin_stale_blocks.csv": _inventory(rows)}),
        dataset_keys or set(),
        nbits_by_epoch
        if nbits_by_epoch is not None
        else _synthetic_nbits_by_epoch(rows),
    )


# ---------------------------------------------------------------------------
# Gate application
# ---------------------------------------------------------------------------


def test_length_gate_above_100_is_violation() -> None:
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab" * 103)
    verdict = sweep.apply_length_gate(row)
    assert verdict is not None
    token, detail = verdict
    assert token == "coinbase_scriptsig_length_above_100"
    assert detail.startswith("REJECTED:")


def test_length_gate_below_2_is_violation() -> None:
    # The gate enforces the full 2..100 bound: a 1-byte scriptSig is a
    # violation, labelled with the distinct below-2 token (not above_100).
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab")
    verdict = sweep.apply_length_gate(row)
    assert verdict is not None
    assert verdict[0] == "coinbase_scriptsig_length_below_2"


def test_length_gate_valid_row_passes() -> None:
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS)
    assert sweep.apply_length_gate(row) is None


def test_bip34_gate_height_mismatch_is_violation() -> None:
    # Version 4 with a coinbase height prefix that disagrees with the
    # claimed height.
    row = _row(
        BIP34_ERA_HEIGHT,
        4,
        EASY_BITS,
        scriptsig_hex=_bip34_scriptsig(BIP34_ERA_HEIGHT + 5),
    )
    verdict = sweep.apply_bip34_gate(row, BIP34_ERA_HEIGHT)
    assert verdict is not None
    assert verdict[0] == "bip34_coinbase_height_mismatch"


def test_bip34_gate_v2_window_mismatch_uses_v2_token() -> None:
    # A version-2 block in the transition window
    # [BIP34_VERSION_2_HEIGHT, BIP34_HEIGHT) with a wrong serialized height
    # push: the v2 token, not the mandatory-era plain token.
    v2_height = sweep.BIP34_VERSION_2_HEIGHT + 100
    assert v2_height < sweep.BIP34_HEIGHT
    row = _row(
        v2_height,
        2,
        EASY_BITS,
        scriptsig_hex=_bip34_scriptsig(v2_height + 5),
    )
    verdict = sweep.apply_bip34_gate(row, v2_height)
    assert verdict is not None
    assert verdict[0] == "bip34_v2_coinbase_height_mismatch"


def test_bip34_gate_mandatory_era_mismatch_uses_plain_token() -> None:
    # From BIP34_HEIGHT the prefix is mandatory for every block: the plain
    # token, not the v2-window token.
    row = _row(
        sweep.BIP34_HEIGHT,
        2,
        EASY_BITS,
        scriptsig_hex=_bip34_scriptsig(sweep.BIP34_HEIGHT + 5),
    )
    verdict = sweep.apply_bip34_gate(row, sweep.BIP34_HEIGHT)
    assert verdict is not None
    assert verdict[0] == "bip34_coinbase_height_mismatch"


def test_bip34_gate_valid_row_passes() -> None:
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS)
    assert sweep.apply_bip34_gate(row, BIP34_ERA_HEIGHT) is None


def test_bip34_gate_v1_header_at_post_bip34_height_is_not_a_coinbase_token() -> None:
    # A version-1 header at a post-BIP34 height with a VALID coinbase height
    # prefix: bip34_height_error rejects it for its VERSION before examining
    # the coinbase prefix, so the gate fires for the wrong reason. The sweep
    # must NOT token it bip34_coinbase_height_mismatch — the real violation
    # is the version, owned and reported by the version/BIP sweep (the same
    # consistency rule the offline validator enforces).
    row = _row(BIP34_ERA_HEIGHT, 1, EASY_BITS)  # valid prefix for the height
    assert sweep.apply_bip34_gate(row, BIP34_ERA_HEIGHT) is None


def test_bip34_gate_pre_bip34_height_passes() -> None:
    # Below BIP34 activation the rule does not apply, even to a version 1
    # block with no coinbase-height prefix.
    row = _row(PRE_BIP34_HEIGHT, 1, EASY_BITS, scriptsig_hex="abcd1234")
    assert sweep.apply_bip34_gate(row, PRE_BIP34_HEIGHT) is None


def test_bip34_gate_metadata_disagreement_is_not_a_bip34_finding() -> None:
    # A row whose scriptSig encodes the height CORRECTLY but whose optional
    # btc_bip34_height column disagrees with it: bip34_height_error rejects on
    # the metadata cross-check ("decoded BIP34 coinbase height disagrees with
    # btc_bip34_height"), an inconsistent-metadata observation, NOT a genuine
    # raw coinbase-height consensus failure (the raw coinbase bytes are valid).
    # It must NOT be tokened bip34_coinbase_height_mismatch.
    row = _row(
        BIP34_ERA_HEIGHT,
        4,
        EASY_BITS,
        scriptsig_hex=_bip34_scriptsig(BIP34_ERA_HEIGHT),  # correct raw prefix
        bip34_height=str(BIP34_ERA_HEIGHT + 5),  # column disagrees
    )
    assert sweep.apply_bip34_gate(row, BIP34_ERA_HEIGHT) is None

    # Control: a well-formed scriptSig with the wrong height prefix (and an
    # agreeing/absent column) IS the genuine raw-prefix failure and is tokened.
    row["coinbase_scriptsig_hex"] = _bip34_scriptsig(BIP34_ERA_HEIGHT + 5)
    row["btc_bip34_height"] = ""
    verdict = sweep.apply_bip34_gate(row, BIP34_ERA_HEIGHT)
    assert verdict is not None
    assert verdict[0] == "bip34_coinbase_height_mismatch"


# ---------------------------------------------------------------------------
# PoW re-verification
# ---------------------------------------------------------------------------


def test_reverify_full_pow_rederives_bits_from_header() -> None:
    assert sweep.reverify_full_pow(_header_hex(4, EASY_BITS)) is True
    assert sweep.reverify_full_pow(_header_hex(4, IMPOSSIBLE_BITS)) is False
    assert sweep.reverify_full_pow("not-hex") is None
    assert sweep.reverify_full_pow("00" * 79) is None


# ---------------------------------------------------------------------------
# End-to-end sweep over synthetic inventories
# ---------------------------------------------------------------------------


def test_sweep_pow_passing_103_byte_scriptsig_is_length_finding() -> None:
    # Full-PoW pass with a 103-byte scriptSig: an error block.
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab" * 103)
    report = _sweep([row])
    assert report.reachable is True
    assert report.pow_pass == 1
    assert report.length_violations_above_100 == 1
    assert report.length_violations_below_2 == 0
    assert report.bip34_violations == 0
    assert len(report.new_findings) == 1
    finding = report.new_findings[0]
    assert finding.violation == "coinbase_scriptsig_length_above_100"
    assert finding.scriptsig_length == 103
    assert report.already_in_dataset == 0


def test_sweep_pow_passing_below_2_scriptsig_is_length_finding() -> None:
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab")
    report = _sweep([row])
    assert report.length_violations_below_2 == 1
    assert report.length_violations_above_100 == 0
    assert len(report.new_findings) == 1


def test_sweep_pow_passing_bad_bip34_serialization_is_bip34_finding() -> None:
    # Trustworthy height, valid length, wrong serialized height push.
    row = _row(
        BIP34_ERA_HEIGHT,
        4,
        EASY_BITS,
        scriptsig_hex=_bip34_scriptsig(BIP34_ERA_HEIGHT + 5),
    )
    report = _sweep([row])
    assert report.bip34_violations == 1
    assert report.length_violations_above_100 == 0
    assert report.length_violations_below_2 == 0
    assert len(report.new_findings) == 1
    assert report.new_findings[0].violation == "bip34_coinbase_height_mismatch"


def test_sweep_v1_header_at_post_bip34_height_is_not_a_bip34_finding() -> None:
    # A full-PoW version-1 header at a post-BIP34 height with a valid
    # coinbase height prefix: the BIP34 gate fires for its VERSION, so the
    # coinbase-form sweep must NOT report it as a bip34_coinbase_height_mismatch
    # finding (the version/BIP sweep owns the version violation).
    row = _row(BIP34_ERA_HEIGHT, 1, EASY_BITS)
    report = _sweep([row])
    assert report.pow_pass == 1
    assert report.bip34_violations == 0
    assert report.length_violations_above_100 == 0
    assert report.length_violations_below_2 == 0
    assert report.new_findings == []


def test_sweep_pow_failing_row_is_excluded() -> None:
    # A share/near row failing its own target is never an error block, even
    # with a 103-byte scriptSig.
    row = _row(BIP34_ERA_HEIGHT, 4, IMPOSSIBLE_BITS, scriptsig_hex="ab" * 103)
    report = _sweep([row])
    assert report.pow_fail == 1
    assert report.pow_pass == 0
    assert report.length_violations_above_100 == 0
    assert report.new_findings == []


def test_sweep_length_violation_failing_canonical_target_is_not_confirmed() -> None:
    # A length violation whose digest meets only its easy self-declared
    # embedded target but NOT the canonical expected-nBits target at the
    # claimed height is a share/contamination observation, never a confirmed
    # error block — the same rule the offline validator enforces.
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab" * 103)
    row["expected_nbits"] = IMPOSSIBLE_BITS  # canonical target: not met
    report = _sweep([row])
    assert report.pow_pass == 1
    assert report.length_violations_above_100 == 1  # the gate violation is seen...
    assert report.canonical_target_fail == 1  # ...but tallied separately
    assert report.length_canonical_target_fail == 1  # ...(the length subset)
    assert report.new_findings == []
    assert report.already_in_dataset == 0

    # The epoch-table fallback: an unparseable expected_nbits column falls
    # back to the committed epoch table at the claimed height's epoch start,
    # whose real target the synthetic easy header cannot meet either. This
    # sub-case passes the REAL epoch table (the default synthetic table would
    # agree with the easy header and let the fallback pass).
    row["expected_nbits"] = "not-hex"
    report = _sweep([row], nbits_by_epoch=sweep.load_nbits_by_epoch())
    assert report.length_violations_above_100 == 1
    assert report.canonical_target_fail == 1
    assert report.new_findings == []


def test_sweep_bip34_violation_failing_canonical_target_is_not_confirmed() -> None:
    # Same canonical-target rule on the BIP34-form path: a BIP34 violation
    # meeting only its easy embedded target is not a confirmed error block.
    row = _row(
        BIP34_ERA_HEIGHT,
        4,
        EASY_BITS,
        scriptsig_hex=_bip34_scriptsig(BIP34_ERA_HEIGHT + 5),
    )
    row["expected_nbits"] = IMPOSSIBLE_BITS  # canonical target: not met
    report = _sweep([row])
    assert report.pow_pass == 1
    assert report.bip34_violations == 1
    assert report.canonical_target_fail == 1
    # A BIP34-path canonical-target failure is NOT a length violation: it
    # must not enter the length subset the single-member conclusion uses.
    assert report.length_canonical_target_fail == 0
    assert report.new_findings == []
    assert report.already_in_dataset == 0


def test_sweep_expected_nbits_disagreeing_with_epoch_table_is_not_confirmed() -> None:
    # A parseable inventory expected_nbits that DISAGREES with the committed
    # epoch table at the claimed height's epoch start is suspect (a stale
    # inventory could carry an erroneous/artificially-easy value): the
    # canonical target is unevaluable, so the row fails closed and is NOT a
    # confirmed error block. Here the REAL epoch table at 300000's epoch
    # start (298368) is a hard target that disagrees with the row's easy
    # expected_nbits.
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab" * 103)
    assert row["expected_nbits"] == EASY_BITS  # parseable, but not the epoch value
    report = _sweep([row], nbits_by_epoch=sweep.load_nbits_by_epoch())
    assert report.pow_pass == 1
    assert report.length_violations_above_100 == 1  # the gate violation is seen...
    assert report.canonical_target_fail == 1  # ...but unevaluable: not confirmed
    assert report.new_findings == []
    assert report.already_in_dataset == 0


def test_sweep_valid_row_is_not_a_finding() -> None:
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS)
    report = _sweep([row])
    assert report.pow_pass == 1
    assert report.length_violations_above_100 == 0
    assert report.length_violations_below_2 == 0
    assert report.bip34_violations == 0
    assert report.new_findings == []


def test_sweep_scratch_row_is_length_checked_but_not_bip34_checked() -> None:
    # A canonical-fill-scratch inventory row (untrustworthy height): the
    # height-independent length check runs, the BIP34-form check does not.
    bad_bip34 = _row(
        BIP34_ERA_HEIGHT,
        4,
        EASY_BITS,
        scriptsig_hex=_bip34_scriptsig(BIP34_ERA_HEIGHT + 5),
    )
    report = _sweep([bad_bip34], authoritative=False)
    assert report.pow_pass == 1
    assert report.untrustworthy_height == 1
    assert report.bip34_violations == 0
    assert report.new_findings == []

    # ...and a length violation in the same scratch inventory IS observed —
    # but with an untrusted claimed height it is an unresolved observation,
    # never a dataset-keyed NEW finding.
    long_scriptsig = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab" * 103)
    report = _sweep([long_scriptsig], authoritative=False)
    assert report.length_violations_above_100 == 1
    assert report.untrustworthy_height == 0
    assert report.new_findings == []
    assert len(report.unresolved_length_observations) == 1
    obs = report.unresolved_length_observations[0]
    assert obs.violation == "coinbase_scriptsig_length_above_100"
    assert obs.height == BIP34_ERA_HEIGHT  # carried for context, not trusted
    assert obs.block_hash == long_scriptsig["btc_header_hash"]


def test_sweep_membership_dedupes_against_dataset() -> None:
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab" * 103)
    dataset_keys = {(BIP34_ERA_HEIGHT, row["btc_header_hash"])}
    report = _sweep([row], dataset_keys=dataset_keys)
    assert report.length_violations_above_100 == 1
    assert report.already_in_dataset == 1
    assert report.new_findings == []


def test_sweep_uses_header_derived_hash_not_btc_header_hash_column() -> None:
    # Candidate identity and dataset membership are keyed on the display hash
    # derived from the header bytes, never the inventory's btc_header_hash
    # column. A row whose column disagrees with its header must be reported
    # and deduplicated under the header-derived hash.
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab" * 103)
    header_derived = row["btc_header_hash"]  # _row sets it correctly
    row["btc_header_hash"] = "ff" * 32  # column now disagrees with the header

    # Length-violation path: the finding carries the header-derived hash...
    report = _sweep([row])
    assert len(report.new_findings) == 1
    assert report.new_findings[0].block_hash == header_derived
    # ...and membership against the dataset keys on the header-derived hash,
    # so a dataset entry under that hash dedupes despite the lying column.
    report = _sweep([row], dataset_keys={(BIP34_ERA_HEIGHT, header_derived)})
    assert report.already_in_dataset == 1
    assert report.new_findings == []

    # BIP34 path: same header-derived identity for a BIP34-form violation.
    bip34_row = _row(
        BIP34_ERA_HEIGHT,
        4,
        EASY_BITS,
        scriptsig_hex=_bip34_scriptsig(BIP34_ERA_HEIGHT + 5),
    )
    bip34_header_derived = bip34_row["btc_header_hash"]
    bip34_row["btc_header_hash"] = "ff" * 32
    report = _sweep([bip34_row])
    assert report.bip34_violations == 1
    assert len(report.new_findings) == 1
    assert report.new_findings[0].block_hash == bip34_header_derived
    report = _sweep(
        [bip34_row], dataset_keys={(BIP34_ERA_HEIGHT, bip34_header_derived)}
    )
    assert report.already_in_dataset == 1
    assert report.new_findings == []


def test_sweep_length_violation_without_height_is_unresolved_not_finding() -> None:
    # A full-PoW length violation with no usable claimed height has no
    # (height, hash) key: it cannot be deduplicated against the dataset or
    # promoted, so it is tallied as an unresolved observation, never a NEW
    # finding.
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab" * 103)
    row["btc_height"] = ""
    report = _sweep([row])
    assert report.length_violations_above_100 == 1
    assert report.new_findings == []
    assert report.already_in_dataset == 0
    assert len(report.unresolved_length_observations) == 1
    obs = report.unresolved_length_observations[0]
    assert obs.violation == "coinbase_scriptsig_length_above_100"
    assert obs.block_hash == row["btc_header_hash"]
    assert obs.scriptsig_length == 103

    # Same for a malformed height value.
    row["btc_height"] = "not-a-height"
    report = _sweep([row])
    assert report.new_findings == []
    assert len(report.unresolved_length_observations) == 1


def test_sweep_scratch_length_violation_with_height_is_unresolved_not_finding() -> None:
    # A length violation from a non-authoritative-height (canonical-fill-
    # scratch) source must NOT be promoted to new_findings even when its
    # claimed height parses: the untrusted placement cannot key a
    # dataset-keyed, validator-facing finding. It stays an unresolved
    # observation, same as the no-usable-height case.
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab" * 103)
    report = _sweep([row], authoritative=False)
    assert report.length_violations_above_100 == 1
    assert report.new_findings == []
    assert report.already_in_dataset == 0
    assert len(report.unresolved_length_observations) == 1
    obs = report.unresolved_length_observations[0]
    assert obs.violation == "coinbase_scriptsig_length_above_100"
    assert obs.authoritative_height is False
    assert obs.block_hash == row["btc_header_hash"]


def test_sweep_row_without_evidence_is_not_usable() -> None:
    # A row missing the committed header/coinbase bytes (RSK does not expose
    # the real parent coinbase) is not a usable candidate.
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS)
    row["coinbase_scriptsig_hex"] = ""
    report = _sweep([row])
    assert report.total_rows == 1
    assert report.pow_pass == 0
    assert report.no_usable_rows is True
    assert report.new_findings == []


def test_sweep_empty_scriptsig_is_skipped_not_a_below_2_violation() -> None:
    # Pin the intentional evidence semantics: an EMPTY coinbase_scriptsig_hex
    # means "this chain's proof does not expose the real parent coinbase"
    # (missing evidence — RSK, and unrecovered rows), NOT "the coinbase
    # scriptSig was zero bytes". A true zero-byte scriptSig (a below-2
    # violation) cannot be distinguished from missing evidence in these
    # inventories, so the row is skipped as unusable and must NOT be flagged
    # as a below-2 violation (which would false-positive on RSK rows).
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS)
    row["coinbase_scriptsig_hex"] = ""
    report = _sweep([row])
    assert report.total_rows == 1
    assert report.no_usable_rows is True
    assert report.length_violations_below_2 == 0
    assert report.length_violations_above_100 == 0
    assert report.bip34_violations == 0
    assert report.new_findings == []
    assert report.unresolved_length_observations == []


def test_sweep_unreachable_inventory_fails_soft() -> None:
    report = sweep.sweep_inventory(
        "devcoin", "stale", "/fake/missing.csv", True, _reader({}), set()
    )
    assert report.reachable is False
    assert report.error


# ---------------------------------------------------------------------------
# The single-member conclusion
# ---------------------------------------------------------------------------


def test_conclusion_holds_when_a_length_violation_fails_canonical_target() -> None:
    # A full-PoW length violation that FAILS canonical-target verification
    # increments the length-violation tally but NOT length_in_dataset, and
    # produces no NEW finding (it is a share/contamination observation,
    # excluded from the error-block set). It must NOT select the
    # "coverage incomplete" conclusion branch (which points to a
    # NEW-findings section that does not exist for it): the single-member
    # conclusion compares only length violations meeting the canonical
    # target against the catalogued length violations.
    report = sweep.ChainReport(chain="devcoin", source="stale", inventory="/fake")
    report.total_rows = 2
    report.pow_pass = 2
    # One catalogued length violation (meets the canonical target)...
    report.length_violations_above_100 = 2
    report.already_in_dataset = 1
    report.length_in_dataset = 1
    report.in_dataset_keys.add((300_000, "ab" * 32))
    # ...and one length violation that failed the canonical target.
    report.canonical_target_fail = 1
    report.length_canonical_target_fail = 1

    text = sweep.render_report([report], "2026-01-01 00:00 UTC")
    assert "the single-member situation is REAL" in text
    assert "prior coverage was incomplete" not in text

    # Control: an UNCATALOGUED length violation meeting the canonical target
    # (length_in_dataset below the meeting-target tally) still selects the
    # coverage-incomplete branch.
    report.length_canonical_target_fail = 0
    report.canonical_target_fail = 0
    text = sweep.render_report([report], "2026-01-01 00:00 UTC")
    assert "prior coverage was incomplete" in text


def test_conclusion_holds_when_only_a_bip34_finding_is_new() -> None:
    # The single-member conclusion is about scriptSig-LENGTH coverage: it
    # gates on new LENGTH findings, not total_new (which also mixes in
    # BIP34-form findings). A sweep whose only NEW finding is a BIP34-form
    # violation (no new length violation) has every observed length violation
    # already catalogued, so the conclusion must still report the
    # single-member situation as REAL — not "coverage incomplete".
    report = sweep.ChainReport(chain="devcoin", source="stale", inventory="/fake")
    report.total_rows = 2
    report.pow_pass = 2
    # One catalogued length violation (meets the canonical target)...
    report.length_violations_above_100 = 1
    report.already_in_dataset = 1
    report.length_in_dataset = 1
    report.in_dataset_keys.add((300_000, "ab" * 32))
    # ...and one NEW BIP34-form finding (not a length violation).
    report.bip34_violations = 1
    report.new_findings.append(
        sweep.Candidate(
            chain="devcoin",
            source="stale",
            inventory="/fake",
            height=300_000,
            block_hash="cd" * 32,
            scriptsig_length=5,
            meets_full_pow=True,
            authoritative_height=True,
            meets_expected_pow=True,
            violation="bip34_coinbase_height_mismatch",
        )
    )

    text = sweep.render_report([report], "2026-01-01 00:00 UTC")
    assert "the single-member situation is REAL" in text
    assert "prior coverage was incomplete" not in text


# ---------------------------------------------------------------------------
# main() fail-closed behavior
# ---------------------------------------------------------------------------


def test_main_fails_closed_when_no_inventory_reachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader({}))
    monkeypatch.setattr(sweep, "local_validated_reader", _reader({}))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_coinbase_form.py",
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
    violating = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_hex="ab" * 103)
    clean = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS)
    mapping = {}
    for chain, path in sweep.STALE_INVENTORIES.items():
        if chain == "devcoin":
            rows = [violating, clean]
        elif chain == "ixcoin":
            rows = [clean]  # candidates but zero violations: negative result
        else:
            rows = []
        mapping[path] = _inventory(rows)
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(mapping))
    monkeypatch.setattr(
        sweep,
        "validated_stales_inventories",
        lambda glob_pattern: {},
    )
    # The synthetic rows use the trivially-met EASY_BITS, which disagrees with
    # the REAL epoch-table value at these heights; the canonical-target check
    # corroborates expected_nbits against the epoch table and fails closed on
    # a disagreement, so inject a synthetic epoch table that agrees with
    # EASY_BITS to let the full-PoW finding confirm.
    monkeypatch.setattr(
        sweep,
        "load_nbits_by_epoch",
        lambda: _synthetic_nbits_by_epoch([violating, clean]),
    )
    out_dir = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_coinbase_form.py",
            "--allow-partial",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert sweep.main() == 0

    report = (out_dir / sweep.DEFAULT_REPORT.name).read_text()
    assert "NEW confirmed error blocks: 1" in report
    assert "scriptSig length violations above 100 bytes: 1" in report
    assert "no coinbase-form violation" in report


def test_main_refuses_partial_write_to_committed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mapping = {path: _inventory([]) for path in sweep.STALE_INVENTORIES.values()}
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(mapping))
    monkeypatch.setattr(sweep, "validated_stales_inventories", lambda g: {})
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_coinbase_form.py",
            "--allow-partial",
            "--output-dir",
            str(sweep.DEFAULT_REPORT.parent),
        ],
    )
    assert sweep.main() == 2


def _partial_mapping() -> dict[str, str]:
    """All but one stale inventory reachable (devcoin's path is omitted)."""
    return {
        path: _inventory([])
        for chain, path in sweep.STALE_INVENTORIES.items()
        if chain != "devcoin"
    }


def test_main_partial_sweep_refuses_committed_write_without_allow_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One reachable + one unreachable inventory, writing to the (committed)
    # default path WITHOUT --allow-partial: fail closed, no write.
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(_partial_mapping()))
    monkeypatch.setattr(sweep, "validated_stales_inventories", lambda g: {})
    out = tmp_path / "committed-report.md"
    monkeypatch.setattr(
        sys,
        "argv",
        ["sweep_error_blocks_coinbase_form.py", "--output", str(out)],
    )
    assert sweep.main() == 1
    assert not out.exists()


def test_main_partial_sweep_writes_partial_with_allow_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The diagnostic escape hatch: --allow-partial --output-dir writes the
    # partial report to the disposable dir.
    monkeypatch.setattr(sweep, "ssh_inventory_reader", _reader(_partial_mapping()))
    monkeypatch.setattr(sweep, "validated_stales_inventories", lambda g: {})
    out_dir = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sweep_error_blocks_coinbase_form.py",
            "--allow-partial",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert sweep.main() == 0
    report = (out_dir / sweep.DEFAULT_REPORT.name).read_text()
    assert "Unreachable inventories" in report
