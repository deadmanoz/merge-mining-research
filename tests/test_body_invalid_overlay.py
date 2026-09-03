"""Tests for the body-invalid-stales overlay validator.

The overlay annotates accepted VALID direct stales whose full body is known
consensus-invalid from an externally observed complete block. These tests pin
the committed dataset (exactly the two F2Pool blocks), the fail-closed
behaviour of every invariant, and the legacy sigop counter the byte
cross-check relies on.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from stale_blocks_analysis import body_invalid_overlay
from stale_blocks_analysis.config import BLOCKS_DIR, BODY_INVALID_STALES_CSV

F2POOL_783426 = (
    783426,
    "00000000000000000002ec935e245f8ae70fc68cc828f05bf4cfa002668599e4",
)
F2POOL_784121 = (
    784121,
    "000000000000000000046a2698233ed93bb5e74ba7d2146a68ddb0c2504c980d",
)

_blocks_fetched = pytest.mark.skipif(
    not BLOCKS_DIR.is_dir(), reason="stale-blocks clone not fetched"
)


def _committed_rows() -> tuple[list[str], list[dict[str, str]]]:
    with BODY_INVALID_STALES_CSV.open(newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames is not None
        return list(reader.fieldnames), list(reader)


def _write_overlay(
    path: Path, fieldnames: list[str], rows: list[dict[str, str]]
) -> Path:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return path


def _validate(path: Path, tmp_path: Path, **overrides) -> list[str]:
    """Validate with byte checks off by default (missing blocks dir)."""
    overrides.setdefault("blocks_dir", tmp_path / "no-blocks-fetched")
    failures, _rows, _byte_checked = body_invalid_overlay.validate_dataset(
        path, **overrides
    )
    return failures


def test_committed_overlay_validates() -> None:
    failures, row_count, _byte_checked = body_invalid_overlay.validate_dataset()
    assert failures == [], f"overlay rows failed validation: {failures}"
    assert row_count == 2


def test_committed_overlay_is_exactly_the_f2pool_pair() -> None:
    _fieldnames, rows = _committed_rows()
    keys = {(int(row["height"]), row["hash"]) for row in rows}
    assert keys == {F2POOL_783426, F2POOL_784121}
    assert {row["rule"] for row in rows} == {"bad-blk-sigops"}


@_blocks_fetched
def test_committed_overlay_byte_checks_run() -> None:
    failures, _row_count, byte_checked = body_invalid_overlay.validate_dataset()
    assert failures == []
    assert byte_checked == 2


def test_empty_overlay_fails_closed(tmp_path: Path) -> None:
    fieldnames, _rows = _committed_rows()
    path = _write_overlay(tmp_path / "empty.csv", fieldnames, [])
    failures = _validate(path, tmp_path)
    assert any("dataset is empty" in failure for failure in failures)


def test_unexpected_schema_fails(tmp_path: Path) -> None:
    path = tmp_path / "wrong_schema.csv"
    path.write_text("height,hash,rule\n1,ab,x\n")
    failures = _validate(path, tmp_path)
    assert any("unexpected columns" in failure for failure in failures)


def test_duplicate_key_fails(tmp_path: Path) -> None:
    fieldnames, rows = _committed_rows()
    path = _write_overlay(
        tmp_path / "duplicate.csv", fieldnames, [rows[0], dict(rows[0])]
    )
    failures = _validate(path, tmp_path)
    assert any("duplicate overlay key" in failure for failure in failures)


def test_catalogue_rule_token_rejected(tmp_path: Path) -> None:
    """A byte-recheckable catalogue rule belongs in error_blocks.csv."""
    fieldnames, rows = _committed_rows()
    for token in ("bip34_coinbase_height_mismatch", "time_below_mtp"):
        mutated = dict(rows[0], rule=token)
        path = _write_overlay(tmp_path / f"{token}.csv", fieldnames, [mutated])
        failures = _validate(path, tmp_path)
        assert any("catalogue vocabulary" in failure for failure in failures)


def test_key_absent_from_validated_stales_fails(tmp_path: Path) -> None:
    fieldnames, rows = _committed_rows()
    mutated = dict(rows[0], height="783427")
    path = _write_overlay(tmp_path / "not_a_stale.csv", fieldnames, [mutated])
    failures = _validate(path, tmp_path)
    assert any("not an accepted direct stale" in failure for failure in failures)


def test_error_catalogue_overlap_rejected(tmp_path: Path) -> None:
    """The overlay and the exclusion gate must stay disjoint."""
    fieldnames, rows = _committed_rows()
    overlay = _write_overlay(tmp_path / "overlap.csv", fieldnames, [rows[0]])
    catalogue = tmp_path / "error_blocks.csv"
    catalogue.write_text(
        "height,hash,classification\n"
        f"{rows[0]['height']},{rows[0]['hash']},error_block\n"
    )
    failures = _validate(overlay, tmp_path, error_blocks_path=catalogue)
    assert any(
        "already in the error-block catalogue" in failure for failure in failures
    )


def test_attested_cost_at_or_below_limit_rejected(tmp_path: Path) -> None:
    fieldnames, rows = _committed_rows()
    mutated = dict(rows[0], attested_sigop_cost="80000")
    path = _write_overlay(tmp_path / "not_over.csv", fieldnames, [mutated])
    failures = _validate(path, tmp_path)
    assert any("does not exceed" in failure for failure in failures)


def test_byte_derivable_excess_rejected(tmp_path: Path) -> None:
    """A scaled legacy count over the limit would be a catalogue matter."""
    fieldnames, rows = _committed_rows()
    mutated = dict(rows[0], legacy_sigops_from_bytes="20001")
    path = _write_overlay(tmp_path / "derivable.csv", fieldnames, [mutated])
    failures = _validate(path, tmp_path)
    assert any("already exceeds the limit" in failure for failure in failures)


@_blocks_fetched
def test_wrong_block_sha256_detected(tmp_path: Path) -> None:
    fieldnames, rows = _committed_rows()
    sha = rows[0]["block_sha256"]
    mutated = dict(rows[0], block_sha256=("0" if sha[0] != "0" else "1") + sha[1:])
    path = _write_overlay(tmp_path / "bad_sha.csv", fieldnames, [mutated])
    failures = _validate(path, tmp_path, blocks_dir=BLOCKS_DIR)
    assert any(
        "block_sha256 does not match the pinned block file" in failure
        for failure in failures
    )


@_blocks_fetched
def test_wrong_legacy_count_detected(tmp_path: Path) -> None:
    fieldnames, rows = _committed_rows()
    mutated = dict(rows[0], legacy_sigops_from_bytes="12345")
    path = _write_overlay(tmp_path / "bad_count.csv", fieldnames, [mutated])
    failures = _validate(path, tmp_path, blocks_dir=BLOCKS_DIR)
    assert any("does not match the count re-derived" in failure for failure in failures)


def test_missing_block_file_reported_when_fetched(tmp_path: Path) -> None:
    """A fetched clone that lacks the referenced bin is a failure, not a skip."""
    fieldnames, rows = _committed_rows()
    empty_blocks_dir = tmp_path / "blocks"
    empty_blocks_dir.mkdir()
    path = _write_overlay(tmp_path / "missing_bin.csv", fieldnames, [rows[0]])
    failures = _validate(path, tmp_path, blocks_dir=empty_blocks_dir)
    assert any("is missing from the fetched" in failure for failure in failures)


def test_main_reports_failures(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        body_invalid_overlay,
        "validate_dataset",
        lambda *_args, **_kwargs: (["783426:668599e4: boom"], 1, 0),
    )
    assert body_invalid_overlay.main() == 1
    assert "boom" in capsys.readouterr().out


def test_legacy_sigop_counter_known_scripts() -> None:
    p2pkh = bytes.fromhex("76a914c825a1ecf2a6830c4401620c3a16f1995057c2ab88ac")
    assert body_invalid_overlay.count_legacy_sigops_in_script(p2pkh) == 1
    # OP_CHECKMULTISIG counts the 20-key maximum in inaccurate mode.
    assert body_invalid_overlay.count_legacy_sigops_in_script(b"\x51\x51\xae") == 20
    assert body_invalid_overlay.count_legacy_sigops_in_script(b"\xac\xad") == 2
    # A truncated push ends the walk with the count so far, like Core's GetOp.
    assert body_invalid_overlay.count_legacy_sigops_in_script(b"\xac\x4c") == 1


def test_block_counter_rejects_malformed_bytes() -> None:
    with pytest.raises(ValueError):
        body_invalid_overlay.count_block_legacy_sigops(b"\x00" * 40)
    with pytest.raises(ValueError):
        # 80-byte header + zero tx count.
        body_invalid_overlay.count_block_legacy_sigops(b"\x00" * 80 + b"\x00")
