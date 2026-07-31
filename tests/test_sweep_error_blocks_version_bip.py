"""Offline unit tests for the version/BIP error-block sweep.

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
        "sweep_error_blocks_version_bip_under_test",
        REPO / "scripts" / "analysis" / "sweep_error_blocks_version_bip.py",
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

# A post-BIP65 height (min version 4) and a post-BIP34 height (mandatory
# coinbase-height prefix), both inside the plausible range.
BIP65_ERA_HEIGHT = 400_000
BIP34_ERA_HEIGHT = 300_000


def _display_hash(header_hex: str) -> str:
    digest = hashlib.sha256(hashlib.sha256(bytes.fromhex(header_hex)).digest()).digest()
    return digest[::-1].hex()


def _row(
    height: int,
    version: int,
    bits: str,
    *,
    scriptsig_height: int | None = None,
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
            "" if scriptsig_height is None else _bip34_scriptsig(scriptsig_height)
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


def test_gates_version_below_4_at_bip65_height_is_violation() -> None:
    row = _row(BIP65_ERA_HEIGHT, 3, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    verdict = sweep.apply_version_bip_gates(row, BIP65_ERA_HEIGHT)
    assert verdict is not None
    token, detail = verdict
    assert token == "bip65_block_version_below_4"
    assert detail.startswith("REJECTED:")


def test_gates_version_below_3_at_bip66_height_is_violation() -> None:
    height = 370_000  # post-BIP66, pre-BIP65
    row = _row(height, 2, EASY_BITS, scriptsig_height=height)
    verdict = sweep.apply_version_bip_gates(row, height)
    assert verdict is not None
    assert verdict[0] == "bip66_block_version_below_3"


def test_gates_version_below_2_at_bip34_height_is_bip34_token() -> None:
    # A v1 header at a BIP34-era height [BIP34_HEIGHT, BIP66_HEIGHT) violates
    # the v2 minimum (the gate message says "required 2 after BIP34"), so it
    # must be tokened bip34_block_version_below_2, not
    # bip66_block_version_below_3 (the wrong enforcement).
    height = 300_000  # post-BIP34, pre-BIP66
    row = _row(height, 1, EASY_BITS, scriptsig_height=height)
    verdict = sweep.apply_version_bip_gates(row, height)
    assert verdict is not None
    token, detail = verdict
    assert token == "bip34_block_version_below_2"
    assert detail.startswith("REJECTED:")


def test_gates_bip34_height_mismatch_is_violation() -> None:
    # Version 4 (passes the min-version gate) but the coinbase height prefix
    # disagrees with the claimed height.
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_height=BIP34_ERA_HEIGHT + 5)
    verdict = sweep.apply_version_bip_gates(row, BIP34_ERA_HEIGHT)
    assert verdict is not None
    assert verdict[0] == "bip34_coinbase_height_mismatch"


def test_gates_bip34_v2_window_token() -> None:
    # Between BIP34_VERSION_2_HEIGHT and BIP34_HEIGHT a version >= 2 block
    # with a wrong coinbase height is the v2 rule, not the mandatory rule.
    height = 225_000
    row = _row(height, 2, EASY_BITS, scriptsig_height=height + 5)
    verdict = sweep.apply_version_bip_gates(row, height)
    assert verdict is not None
    assert verdict[0] == "bip34_v2_coinbase_height_mismatch"


def test_gates_valid_row_passes() -> None:
    row = _row(BIP65_ERA_HEIGHT, 4, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    assert sweep.apply_version_bip_gates(row, BIP65_ERA_HEIGHT) is None


def test_gates_malformed_scriptsig_is_not_a_bip34_mismatch() -> None:
    # A malformed but non-empty scriptSig makes bip34_height_error return
    # "REJECTED: malformed coinbase scriptSig hex" — unusable evidence, not a
    # BIP34 height violation. It must NOT be tokened
    # bip34_coinbase_height_mismatch (which would report a NEW confirmed
    # error block for unparseable evidence).
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_height=BIP34_ERA_HEIGHT)
    row["coinbase_scriptsig_hex"] = "zz"  # malformed non-empty hex
    assert sweep.apply_version_bip_gates(row, BIP34_ERA_HEIGHT) is None
    # End to end: the sweep reports no BIP34 violation and no NEW finding.
    report = _sweep([row])
    assert report.pow_pass == 1
    assert report.bip34_violations == 0
    assert report.version_violations == 0
    assert report.new_findings == []

    # Control: a well-formed scriptSig with the wrong height prefix IS the
    # expected BIP34-failure form and is still tokened.
    row["coinbase_scriptsig_hex"] = _bip34_scriptsig(BIP34_ERA_HEIGHT + 5)
    verdict = sweep.apply_version_bip_gates(row, BIP34_ERA_HEIGHT)
    assert verdict is not None
    assert verdict[0] == "bip34_coinbase_height_mismatch"


def test_gates_pre_bip34_height_passes() -> None:
    # Below BIP34_VERSION_2_HEIGHT neither rule applies, even to a version 1
    # block with no coinbase-height prefix.
    row = _row(100_000, 1, EASY_BITS, scriptsig_height=100_000)
    assert sweep.apply_version_bip_gates(row, 100_000) is None


def test_gates_bip34_metadata_disagreement_is_not_a_bip34_finding() -> None:
    # A row whose scriptSig encodes the height CORRECTLY but whose optional
    # btc_bip34_height column disagrees with it: bip34_height_error rejects on
    # the metadata cross-check ("decoded BIP34 coinbase height disagrees with
    # btc_bip34_height"), an inconsistent-metadata observation, NOT a genuine
    # raw coinbase-height consensus failure. It must NOT be tokened
    # bip34_coinbase_height_mismatch.
    row = _row(
        BIP34_ERA_HEIGHT,
        4,
        EASY_BITS,
        scriptsig_height=BIP34_ERA_HEIGHT,  # correct raw prefix
        bip34_height=str(BIP34_ERA_HEIGHT + 5),  # column disagrees
    )
    assert sweep.apply_version_bip_gates(row, BIP34_ERA_HEIGHT) is None
    # End to end: no BIP34 violation and no NEW finding.
    report = _sweep([row])
    assert report.pow_pass == 1
    assert report.bip34_violations == 0
    assert report.version_violations == 0
    assert report.new_findings == []

    # Control: a well-formed scriptSig with the wrong height prefix (and a
    # agreeing/absent column) IS the genuine raw-prefix failure and is tokened.
    row["coinbase_scriptsig_hex"] = _bip34_scriptsig(BIP34_ERA_HEIGHT + 5)
    row["btc_bip34_height"] = ""
    verdict = sweep.apply_version_bip_gates(row, BIP34_ERA_HEIGHT)
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


def test_sweep_pow_passing_version_violation_is_new_finding() -> None:
    # Full-PoW pass, version 3 at a BIP65-era height: an error block.
    row = _row(BIP65_ERA_HEIGHT, 3, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    report = _sweep([row])
    assert report.reachable is True
    assert report.pow_pass == 1
    assert report.version_violations == 1
    assert report.bip34_violations == 0
    assert len(report.new_findings) == 1
    finding = report.new_findings[0]
    assert finding.violation == "bip65_block_version_below_4"
    assert finding.header_version == 3
    assert report.already_in_dataset == 0


def test_sweep_pow_passing_bip34_violation_is_new_finding() -> None:
    row = _row(BIP34_ERA_HEIGHT, 4, EASY_BITS, scriptsig_height=BIP34_ERA_HEIGHT + 5)
    report = _sweep([row])
    assert report.bip34_violations == 1
    assert report.version_violations == 0
    assert len(report.new_findings) == 1
    assert report.new_findings[0].violation == "bip34_coinbase_height_mismatch"


def test_sweep_pow_failing_row_is_excluded() -> None:
    # A share/near row failing its own target is never an error block, even
    # with a rule-violating version.
    row = _row(BIP65_ERA_HEIGHT, 3, IMPOSSIBLE_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    report = _sweep([row])
    assert report.pow_fail == 1
    assert report.pow_pass == 0
    assert report.version_violations == 0
    assert report.new_findings == []


def test_sweep_violation_failing_canonical_target_is_not_confirmed() -> None:
    # A gate violation whose digest meets only its easy self-declared embedded
    # target but NOT the canonical expected-nBits target at the claimed height
    # is a share/contamination observation, never a confirmed error block —
    # the same rule the offline validator enforces.
    row = _row(BIP65_ERA_HEIGHT, 3, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    row["expected_nbits"] = IMPOSSIBLE_BITS  # canonical target: not met
    report = _sweep([row])
    assert report.pow_pass == 1
    assert report.version_violations == 1  # the gate violation is observed...
    assert report.canonical_target_fail == 1  # ...but tallied separately
    assert report.new_findings == []
    assert report.already_in_dataset == 0

    # The epoch-table fallback: an unparseable expected_nbits column falls
    # back to the committed epoch table at the claimed height's epoch start,
    # whose real target the synthetic easy header cannot meet either. This
    # sub-case passes the REAL epoch table (the default synthetic table would
    # agree with the easy header and let the fallback pass).
    row["expected_nbits"] = "not-hex"
    report = _sweep([row], nbits_by_epoch=sweep.load_nbits_by_epoch())
    assert report.version_violations == 1
    assert report.canonical_target_fail == 1
    assert report.new_findings == []


def test_sweep_expected_nbits_disagreeing_with_epoch_table_is_not_confirmed() -> None:
    # A parseable inventory expected_nbits that DISAGREES with the committed
    # epoch table at the claimed height's epoch start is suspect (a stale
    # inventory could carry an erroneous/artificially-easy value): the
    # canonical target is unevaluable, so the row fails closed and is NOT a
    # confirmed error block. Here the REAL epoch table at 400000's epoch
    # start (399168) is a hard target that disagrees with the row's easy
    # expected_nbits.
    row = _row(BIP65_ERA_HEIGHT, 3, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    assert row["expected_nbits"] == EASY_BITS  # parseable, but not the epoch value
    report = _sweep([row], nbits_by_epoch=sweep.load_nbits_by_epoch())
    assert report.pow_pass == 1
    assert report.version_violations == 1  # the gate violation is observed...
    assert report.canonical_target_fail == 1  # ...but unevaluable: not confirmed
    assert report.new_findings == []
    assert report.already_in_dataset == 0


def test_sweep_valid_row_is_not_a_finding() -> None:
    row = _row(BIP65_ERA_HEIGHT, 4, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    report = _sweep([row])
    assert report.pow_pass == 1
    assert report.version_violations == 0
    assert report.bip34_violations == 0
    assert report.new_findings == []


def test_sweep_membership_dedupes_against_dataset() -> None:
    row = _row(BIP65_ERA_HEIGHT, 3, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    dataset_keys = {(BIP65_ERA_HEIGHT, row["btc_header_hash"])}
    report = _sweep([row], dataset_keys=dataset_keys)
    assert report.version_violations == 1
    assert report.already_in_dataset == 1
    assert report.new_findings == []


def test_sweep_identity_uses_header_derived_hash_not_column() -> None:
    # A blank/stale btc_header_hash column must not give a finding the wrong
    # identity or make a known dataset member appear NEW: the display hash is
    # derived from the header bytes, never trusted from the column.
    row = _row(BIP65_ERA_HEIGHT, 3, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    header_hash = row["btc_header_hash"]
    row["btc_header_hash"] = "ff" * 32  # column disagrees with the header
    report = _sweep([row], dataset_keys={(BIP65_ERA_HEIGHT, header_hash)})
    assert report.version_violations == 1
    # The header-derived hash matches the dataset key: already catalogued,
    # not a NEW finding under the fabricated column hash.
    assert report.already_in_dataset == 1
    assert report.new_findings == []
    # And with an empty dataset the finding carries the header-derived hash.
    report = _sweep([row])
    assert len(report.new_findings) == 1
    assert report.new_findings[0].block_hash == header_hash


def test_sweep_untrustworthy_height_is_not_evaluated() -> None:
    # The canonical-fill-scratch stale inventories carry a btc_height that is
    # not canonical-verified, so even a full-PoW rule-violating row is an
    # untrustworthy-height negative, never a violation.
    row = _row(BIP65_ERA_HEIGHT, 3, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    report = _sweep([row], authoritative=False)
    assert report.pow_pass == 1
    assert report.untrustworthy_height == 1
    assert report.version_violations == 0
    assert report.new_findings == []


def test_sweep_row_without_header_is_not_usable() -> None:
    # A row missing the committed header bytes cannot be re-verified or gated
    # at all; it is not a usable candidate.
    row = _row(BIP65_ERA_HEIGHT, 3, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    row["btc_header_hex"] = ""
    report = _sweep([row])
    assert report.total_rows == 1
    assert report.pow_pass == 0
    assert report.no_usable_rows is True
    assert report.new_findings == []


def test_sweep_header_only_row_is_version_checked_but_bip34_unevaluable() -> None:
    # An RSK-style row: authoritative height, valid full-PoW header, EMPTY
    # coinbase scriptSig (RSK's proof does not expose the real parent
    # coinbase). The version gate is coinbase-independent, so a version below
    # the minimum for the height IS reported as a version violation (not
    # skipped); the same row is correctly NOT evaluated for BIP34 (no
    # coinbase evidence).
    row = _row(BIP65_ERA_HEIGHT, 3, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    row["coinbase_scriptsig_hex"] = ""
    # The gate-level split: the version violation fires, no BIP34 token.
    verdict = sweep.apply_version_bip_gates(row, BIP65_ERA_HEIGHT)
    assert verdict is not None
    assert verdict[0] == "bip65_block_version_below_4"
    # End to end: the header-only row is usable, version-checked, and
    # reported as a NEW version-violation finding with zero BIP34 violations.
    report = _sweep([row])
    assert report.total_rows == 1
    assert report.no_usable_rows is False
    assert report.pow_pass == 1
    assert report.version_violations == 1
    assert report.bip34_violations == 0
    assert len(report.new_findings) == 1
    assert report.new_findings[0].violation == "bip65_block_version_below_4"

    # Control: a version-PASSING header-only row is a clean negative — no
    # version violation, and no spurious BIP34 finding from the missing
    # coinbase (bip34_height_error's "missing coinbase scriptSig" verdict is
    # not a BIP34 height mismatch).
    row = _row(BIP65_ERA_HEIGHT, 4, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    row["coinbase_scriptsig_hex"] = ""
    assert sweep.apply_version_bip_gates(row, BIP65_ERA_HEIGHT) is None
    report = _sweep([row])
    assert report.pow_pass == 1
    assert report.version_violations == 0
    assert report.bip34_violations == 0
    assert report.new_findings == []


def test_sweep_implausible_height_is_skipped() -> None:
    row = _row(BIP65_ERA_HEIGHT, 3, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    row["btc_height"] = "99999999"
    report = _sweep([row])
    assert report.no_height == 1
    assert report.pow_pass == 0
    assert report.new_findings == []


def test_sweep_unreachable_inventory_fails_soft() -> None:
    report = sweep.sweep_inventory(
        "devcoin", "stale", "/fake/missing.csv", True, _reader({}), set()
    )
    assert report.reachable is False
    assert report.error


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
            "sweep_error_blocks_version_bip.py",
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
    violating = _row(BIP65_ERA_HEIGHT, 3, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
    clean = _row(BIP65_ERA_HEIGHT, 4, EASY_BITS, scriptsig_height=BIP65_ERA_HEIGHT)
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
            "sweep_error_blocks_version_bip.py",
            "--allow-partial",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert sweep.main() == 0

    report = (out_dir / sweep.DEFAULT_REPORT.name).read_text()
    assert "NEW confirmed error blocks: 1" in report
    assert "Version-rule violation observations (BIP66/BIP65): 1" in report
    assert "no version/BIP34 violation" in report


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
            "sweep_error_blocks_version_bip.py",
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
        ["sweep_error_blocks_version_bip.py", "--output", str(out)],
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
            "sweep_error_blocks_version_bip.py",
            "--allow-partial",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert sweep.main() == 0
    report = (out_dir / sweep.DEFAULT_REPORT.name).read_text()
    assert "Unreachable inventories" in report
