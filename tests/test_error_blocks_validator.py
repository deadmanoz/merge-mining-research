from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

from stale_blocks_analysis.config import ERROR_BLOCKS_CSV

REPO = Path(__file__).resolve().parents[1]

from _sweep_test_helpers import _bip34_scriptsig  # noqa: E402


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_error_blocks",
        REPO / "scripts" / "analysis" / "validate_error_blocks.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_committed_row_revalidates() -> None:
    mod = _load_validator()
    failures = mod.validate_dataset(ERROR_BLOCKS_CSV)
    assert failures == [], f"rows failed re-derivation: {failures}"


def test_946213_time_below_mtp_revalidates() -> None:
    import csv as _csv

    mod = _load_validator()
    with ERROR_BLOCKS_CSV.open(newline="") as f:
        row = next(r for r in _csv.DictReader(f) if r["height"] == "946213")
    assert "time_below_mtp" in row["rules_violated"]
    assert row["provenance"].startswith("monitor-live-capture:")
    assert mod.validate_row(row) == []


def test_380992_median_time_past_violation_revalidates() -> None:
    import csv as _csv

    mod = _load_validator()
    with ERROR_BLOCKS_CSV.open(newline="") as f:
        row = next(r for r in _csv.DictReader(f) if r["height"] == "380992")
    assert "median_time_past_violation" in row["rules_violated"]
    assert mod.validate_row(row) == []
    # The rule re-derives from the committed MTP context: the header's nTime
    # (1446052047) is at or below the canonical parent's median-time-past
    # (1446068449). Stripping the sidecar context breaks re-derivation.
    assert any(
        "median_time_past_violation has no committed MTP context" in f
        for f in mod.validate_row(row, mtp_context={})
    )
    # The candidate nTime is derived from the header bytes, never the
    # btc_time column: raising the column above the parent MTP does NOT
    # break re-derivation, because the header's nTime still violates. But
    # the derived-column cross-check DOES flag the tampered column: a
    # btc_time that disagrees with the header's embedded nTime is an audit
    # failure independent of the time-rule re-derivation.
    raised = dict(row, btc_time="1446068450")
    raised_failures = mod.validate_row(raised)
    assert not any("did not re-derive" in f for f in raised_failures)
    assert any("btc_time column does not match" in f for f in raised_failures)
    # Raising the header's own nTime above the parent MTP breaks it.
    header = bytearray(bytes.fromhex(row["btc_header_hex"]))
    header[68:72] = (1446068450).to_bytes(4, "little")
    import hashlib as _hashlib

    digest = _hashlib.sha256(_hashlib.sha256(bytes(header)).digest()).digest()
    raised_header = dict(
        row, btc_header_hex=bytes(header).hex(), hash=digest[::-1].hex()
    )
    mtp_context = {(380992, raised_header["hash"]): 1446068449}
    assert any(
        "median_time_past_violation did not re-derive" in f
        for f in mod.validate_row(raised_header, mtp_context=mtp_context)
    )


def test_717696_nbits_retarget_not_applied_revalidates() -> None:
    import csv as _csv

    mod = _load_validator()
    with ERROR_BLOCKS_CSV.open(newline="") as f:
        row = next(r for r in _csv.DictReader(f) if r["height"] == "717696")
    assert "nbits_retarget_not_applied" in row["rules_violated"]
    assert row["provenance"].startswith("sweep-rejected-rows:")
    # The row used the previous epoch's bits at an epoch-start height.
    assert row["btc_bits"] == "170b98ab"
    assert row["expected_nbits"] == "170b8c8b"
    assert mod.validate_row(row) == []


def _retarget_row(height: str, bits: str) -> dict[str, str]:
    return {
        "height": height,
        "hash": "00" * 32,
        "btc_bits": bits,
        "rules_violated": "nbits_retarget_not_applied",
    }


def test_retarget_rule_fails_at_non_boundary_height() -> None:
    mod = _load_validator()
    nbits_by_epoch = mod._load_nbits_by_epoch()
    # 717697 is mid-epoch: the retarget-not-applied claim cannot re-derive
    # (a mid-epoch nBits mismatch is the contamination gate's target class).
    row = _retarget_row("717697", "170b98ab")
    assert mod.nbits_retarget_not_applied_error(row, nbits_by_epoch) is None
    assert any(
        "nbits_retarget_not_applied did not re-derive" in f
        for f in mod.validate_row(row, nbits_by_epoch=nbits_by_epoch, mtp_context={})
    )


def test_retarget_rule_fails_when_bits_match_neither_epoch() -> None:
    mod = _load_validator()
    nbits_by_epoch = mod._load_nbits_by_epoch()
    # Epoch-start height but bits from neither the current nor previous epoch.
    row = _retarget_row("717696", "170b0000")
    assert mod.nbits_retarget_not_applied_error(row, nbits_by_epoch) is None
    assert any(
        "nbits_retarget_not_applied did not re-derive" in f
        for f in mod.validate_row(row, nbits_by_epoch=nbits_by_epoch, mtp_context={})
    )


def test_retarget_rule_fails_when_retarget_was_applied() -> None:
    mod = _load_validator()
    nbits_by_epoch = mod._load_nbits_by_epoch()
    # Bits equal to the epoch table value at the boundary: no violation.
    row = _retarget_row("717696", "170b8c8b")
    assert mod.nbits_retarget_not_applied_error(row, nbits_by_epoch) is None


def test_retarget_rule_fails_closed_when_epoch_table_lacks_height() -> None:
    mod = _load_validator()
    # An epoch-start height beyond the committed table's coverage cannot be
    # evaluated: the helper raises and the validator records a failure.
    row = _retarget_row("9999360", "170b98ab")  # 2016 * 4960, an epoch start
    with pytest.raises(ValueError, match="epoch table lacks"):
        mod.nbits_retarget_not_applied_error(row, {})
    assert any(
        "rule nbits_retarget_not_applied: epoch table lacks" in f
        for f in mod.validate_row(row, nbits_by_epoch={}, mtp_context={})
    )


def _retarget_pow_header(old_bits: str) -> tuple[str, str, int]:
    """An 80-byte header embedding ``old_bits``.

    Returns (header hex, display hash, digest as a little-endian integer).
    """
    header = (
        (2).to_bytes(4, "little")
        + b"\x11" * 32
        + b"\x22" * 32
        + (1_600_000_000).to_bytes(4, "little")
        + bytes.fromhex(old_bits)[::-1]  # nBits is little-endian
        + (42).to_bytes(4, "little")
    )
    assert len(header) == 80
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return header.hex(), digest[::-1].hex(), int.from_bytes(digest, "little")


def test_retarget_rule_requires_meeting_canonical_target() -> None:
    mod = _load_validator()
    # Synthetic epoch boundary at height 4032 (2016*2): the previous epoch's
    # bits are the trivially-easy 2100ffff (the digest meets the embedded
    # target, so the general PoW check passes), while the new epoch's bits —
    # and hence the row's expected_nbits — are set just below the header's
    # digest integer, so the digest does NOT meet the canonical target. The
    # row is a share at the canonical difficulty, not a full-PoW error block.
    old_bits = "2100ffff"
    header_hex, display_hash, digest_int = _retarget_pow_header(old_bits)
    # Craft a canonical target strictly below the digest: nBits with the
    # digest's own top bytes minus one in the mantissa at the same exponent.
    from stale_blocks_analysis.auxpow_parse import nbits_to_target

    exponent = 32
    mantissa = (digest_int >> (8 * (exponent - 3))) & 0x7FFFFF
    assert mantissa > 0
    canonical_bits = (exponent << 24) | (mantissa - 1)
    assert nbits_to_target(canonical_bits) < digest_int
    canonical_hex = f"{canonical_bits:08x}"
    nbits_by_epoch = {4032: canonical_bits, 2016: int(old_bits, 16)}
    row = {
        "height": "4032",
        "hash": display_hash,
        "btc_bits": old_bits,
        "expected_nbits": canonical_hex,
        "btc_header_hex": header_hex,
        "coinbase_scriptsig_hex": "02" + "00" * 30,
        "rules_violated": "nbits_retarget_not_applied",
    }
    # The epoch conditions re-derive (the helper fires)...
    assert mod.nbits_retarget_not_applied_error(row, nbits_by_epoch) is not None
    # ...and the digest meets the embedded old target (no own-target failure)...
    failures = mod.validate_row(row, nbits_by_epoch=nbits_by_epoch, mtp_context={})
    assert not any("not full PoW" in f and "canonical" not in f for f in failures)
    # ...but the digest does not meet the canonical target, so the row fails.
    assert any(
        "does not meet the canonical expected_nbits target" in f for f in failures
    ), failures


def test_pow_target_failure_is_not_an_error_block() -> None:
    mod = _load_validator()
    # A header that does not meet its own target must be flagged (a share, not
    # an error block). All-zero header hash will not meet the 0x1d00ffff target.
    row = {
        "height": "100000",
        "hash": "ff" * 32,
        "btc_bits": "1d00ffff",
        "expected_nbits": "1d00ffff",
        "btc_header_hex": "00" * 80,
        "coinbase_scriptsig_hex": "02" + "00" * 30,
        "rules_violated": "bip66_block_version_below_3",
    }
    assert any("not full PoW" in f for f in mod.validate_row(row))


def test_digest_must_meet_canonical_expected_nbits_target() -> None:
    mod = _load_validator()
    # Finding: a row whose digest meets its easy EMBEDDED btc_bits (so the
    # self-target PoW check passes) but NOT the canonical expected_nbits
    # target must be flagged — an error block is full-PoW at the Bitcoin
    # difficulty in force at the claimed position, not at some easy
    # non-Bitcoin embedded target (the BCH/BSV-contamination concern).
    header = (
        (2).to_bytes(4, "little")
        + b"\x11" * 32
        + b"\x22" * 32
        + (1_400_000_000).to_bytes(4, "little")
        + bytes.fromhex("2100ffff")[::-1]  # easy embedded nBits (little-endian)
        + (42).to_bytes(4, "little")
    )
    assert len(header) == 80
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    row = {
        "height": "100000",
        "hash": digest[::-1].hex(),
        "btc_bits": "2100ffff",  # easy embedded bits: self-target PoW passes
        # The canonical target is the much harder 1d00ffff: the digest does
        # NOT meet it.
        "expected_nbits": "1d00ffff",
        "btc_header_hex": header.hex(),
        "coinbase_scriptsig_hex": "02" + "00" * 30,
        "rules_violated": "bip66_block_version_below_3",
    }
    failures = mod.validate_row(row)
    # The self-target check passes (no "its own target" failure)...
    assert not any("its own target" in f for f in failures)
    # ...but the digest does not meet the canonical expected_nbits target.
    assert any(
        "does not meet the canonical expected_nbits target" in f for f in failures
    ), failures


def test_digest_meeting_both_targets_is_not_canonical_flagged() -> None:
    mod = _load_validator()
    # Control: when expected_nbits equals the embedded bits (both trivially
    # easy), the digest meets both targets and the canonical-target check does
    # NOT fire. (Section (c) may still flag an epoch-table mismatch; that is
    # not under test here.)
    header = (
        (2).to_bytes(4, "little")
        + b"\x11" * 32
        + b"\x22" * 32
        + (1_400_000_000).to_bytes(4, "little")
        + bytes.fromhex("2100ffff")[::-1]
        + (42).to_bytes(4, "little")
    )
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    row = {
        "height": "100000",
        "hash": digest[::-1].hex(),
        "btc_bits": "2100ffff",
        "expected_nbits": "2100ffff",
        "btc_header_hex": header.hex(),
        "coinbase_scriptsig_hex": "02" + "00" * 30,
        "rules_violated": "bip66_block_version_below_3",
    }
    failures = mod.validate_row(row)
    assert not any(
        "does not meet the canonical expected_nbits target" in f for f in failures
    ), failures


def _stricter_wrong_bits_row() -> dict[str, str]:
    """A row whose embedded btc_bits is stricter-but-wrong.

    The embedded bits 2100fff0 have a target just below the canonical
    expected_nbits 2100ffff (stricter), so the digest meets BOTH targets: the
    own-target and canonical-target PoW checks both pass. But the embedded
    bits field != expected_nbits, which is itself a consensus violation.
    """
    header = (
        (2).to_bytes(4, "little")
        + b"\x11" * 32
        + b"\x22" * 32
        + (1_400_000_000).to_bytes(4, "little")
        + bytes.fromhex("2100fff0")[::-1]  # stricter-than-canonical embedded nBits
        + (42).to_bytes(4, "little")
    )
    assert len(header) == 80
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return {
        "height": "100000",
        "hash": digest[::-1].hex(),
        "btc_bits": "2100fff0",  # stricter-but-wrong embedded bits
        "expected_nbits": "2100ffff",  # canonical (easier) bits
        "btc_header_hex": header.hex(),
        "coinbase_scriptsig_hex": "02" + "00" * 30,
        "rules_violated": "bip66_block_version_below_3",
    }


def test_embedded_bits_must_equal_expected_nbits_for_non_retarget_row() -> None:
    mod = _load_validator()
    # Finding: a non-retarget row whose embedded btc_bits is stricter-but-wrong
    # (the digest meets both the stricter embedded target and the easier
    # canonical target, so both PoW checks pass) must still be flagged: the
    # embedded nBits field must equal the canonical expected_nbits.
    row = _stricter_wrong_bits_row()
    failures = mod.validate_row(row)
    # Both PoW checks pass (no own-target or canonical-target failure)...
    assert not any("not full PoW" in f or "not full Bitcoin PoW" in f for f in failures)
    # ...but the embedded bits field does not match expected_nbits.
    assert any(
        "embedded btc_bits 2100fff0 does not match canonical expected_nbits "
        "2100ffff" in f
        for f in failures
    ), failures


def test_embedded_bits_check_not_applied_to_retarget_row() -> None:
    mod = _load_validator()
    # The nbits_retarget_not_applied rule is the deliberate exception: its
    # embedded bits are the previous epoch's by design, so the
    # embedded-bits-vs-expected_nbits check is skipped for that token. The
    # committed 717696 row carries btc_bits 170b98ab != expected_nbits
    # 170b8c8b and must NOT be flagged by this check.
    import csv as _csv

    with ERROR_BLOCKS_CSV.open(newline="") as f:
        row = next(r for r in _csv.DictReader(f) if r["height"] == "717696")
    assert "nbits_retarget_not_applied" in row["rules_violated"]
    assert row["btc_bits"] != row["expected_nbits"]
    failures = mod.validate_row(row)
    assert not any("embedded btc_bits" in f for f in failures), failures


def _full_pow_row() -> dict[str, str]:
    """A minimal row whose header meets its own (trivial) embedded target.

    The audit columns (btc_header_version, btc_time, coinbase_height) agree
    with the committed bytes so the derived-column cross-checks pass; the
    scriptSig decodes to BIP34 height 0.
    """
    header = (
        (2).to_bytes(4, "little")
        + b"\x11" * 32
        + b"\x22" * 32
        + (1_400_000_000).to_bytes(4, "little")
        + bytes.fromhex("2100ffff")[::-1]  # nBits is little-endian
        + (42).to_bytes(4, "little")
    )
    assert len(header) == 80
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return {
        "height": "100000",
        "hash": digest[::-1].hex(),
        "btc_header_version": "2",
        "btc_time": "1400000000",
        "btc_bits": "2100ffff",
        "expected_nbits": "1d00ffff",
        "btc_header_hex": header.hex(),
        "coinbase_height": "0",
        "coinbase_scriptsig_hex": "02" + "00" * 30,
        "rules_violated": "bip66_block_version_below_3",
    }


def test_hash_column_must_match_header_digest() -> None:
    mod = _load_validator()
    row = _full_pow_row()
    assert not any(
        "hash column" in f or "btc_bits column" in f for f in mod.validate_row(row)
    )
    row["hash"] = "ff" * 32
    assert any("hash column does not match" in f for f in mod.validate_row(row))


def test_btc_bits_column_must_match_header_bits() -> None:
    mod = _load_validator()
    row = _full_pow_row()
    row["btc_bits"] = "2100fffe"
    assert any("btc_bits column does not match" in f for f in mod.validate_row(row))


def test_btc_header_version_column_must_match_header_version() -> None:
    mod = _load_validator()
    row = _full_pow_row()
    # Control: the consistent column is NOT flagged.
    assert not any("btc_header_version" in f for f in mod.validate_row(row))
    # A tampered column that disagrees with the header's embedded nVersion.
    row["btc_header_version"] = "3"
    assert any(
        "btc_header_version column does not match" in f for f in mod.validate_row(row)
    )
    # A malformed column value is flagged as malformed.
    row["btc_header_version"] = "not-a-version"
    assert any("malformed btc_header_version value" in f for f in mod.validate_row(row))


def test_btc_time_column_must_match_header_ntime() -> None:
    mod = _load_validator()
    row = _full_pow_row()
    # Control: the consistent column is NOT flagged.
    assert not any("btc_time" in f for f in mod.validate_row(row))
    # A tampered column that disagrees with the header's embedded nTime.
    row["btc_time"] = "1400000001"
    assert any("btc_time column does not match" in f for f in mod.validate_row(row))
    # A malformed column value is flagged as malformed.
    row["btc_time"] = "not-a-time"
    assert any("malformed btc_time value" in f for f in mod.validate_row(row))


def test_coinbase_height_column_must_match_scriptsig_prefix() -> None:
    mod = _load_validator()
    # A row whose scriptSig carries a decodable BIP34 height prefix: the
    # coinbase_height column must agree with the decoded value.
    row = _version_row("300000", 4, _bip34_scriptsig(300000))
    assert row["coinbase_height"] == "300000"
    assert not any("coinbase_height" in f for f in mod.validate_row(row))
    # A tampered column that disagrees with the scriptSig's decoded height.
    row["coinbase_height"] = "300001"
    assert any(
        "coinbase_height column does not match" in f for f in mod.validate_row(row)
    )
    # A malformed column value is flagged as malformed.
    row["coinbase_height"] = "not-a-height"
    assert any("malformed coinbase_height value" in f for f in mod.validate_row(row))


def test_coinbase_height_check_skipped_when_no_prefix_derivable() -> None:
    mod = _load_validator()
    # A scriptSig with no decodable BIP34 height push (a 1-byte scriptSig
    # whose push opcode exceeds its length): there is no derivable value to
    # compare against, so the coinbase_height cross-check is skipped and an
    # arbitrary column value is NOT flagged. The 1-byte scriptSig is itself a
    # real length violation, so it must be claimed (the unclaimed-violation
    # check); the assertions below target the coinbase_height cross-check
    # messages specifically, not the length token.
    row = _version_row("400000", 4, "02")
    row["rules_violated"] = "coinbase_scriptsig_length_below_2"
    assert row["coinbase_height"] == ""
    assert not any(
        "coinbase_height column" in f or "malformed coinbase_height" in f
        for f in mod.validate_row(row)
    )


def test_coinbase_scriptsig_length_below_2_rederives() -> None:
    mod = _load_validator()
    # A row claiming coinbase_scriptsig_length_below_2 with a 1-byte
    # scriptSig must re-derive: the same length gate as
    # coinbase_scriptsig_length_above_100 enforces the full 2..100 bound, so
    # it returns a REJECTED string (non-None) for the below-2 case.
    row = _full_pow_row()
    row["coinbase_scriptsig_hex"] = "02"  # 1 byte, below the 2-byte minimum
    row["rules_violated"] = "coinbase_scriptsig_length_below_2"
    assert not any(
        "no gate registered" in f
        or "coinbase_scriptsig_length_below_2 did not re-derive" in f
        for f in mod.validate_row(row)
    )


def _version_row(height: str, version: int, scriptsig_hex: str) -> dict[str, str]:
    """A full-PoW row at ``height`` with the given header version.

    Both btc_bits and expected_nbits use the trivially-met 2100ffff target so
    the own-target and canonical-target PoW checks pass; section (c) may still
    flag an epoch-table mismatch, which is not under test here. The audit
    columns (btc_header_version, btc_time, coinbase_height) agree with the
    committed bytes so the derived-column cross-checks pass; coinbase_height
    is decoded from the scriptSig's BIP34 prefix (absent when the scriptSig
    carries no decodable push, in which case the cross-check is skipped).
    """
    header = (
        version.to_bytes(4, "little", signed=True)
        + b"\x11" * 32
        + b"\x22" * 32
        + (1_400_000_000).to_bytes(4, "little")
        + bytes.fromhex("2100ffff")[::-1]  # nBits is little-endian
        + (42).to_bytes(4, "little")
    )
    assert len(header) == 80
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    from stale_blocks_analysis.auxpow_parse import parse_coinbase_height

    decoded_height = parse_coinbase_height(bytes.fromhex(scriptsig_hex))
    return {
        "height": height,
        "hash": digest[::-1].hex(),
        "btc_header_version": str(version),
        "btc_time": "1400000000",
        "btc_bits": "2100ffff",
        "expected_nbits": "2100ffff",
        "btc_header_hex": header.hex(),
        "coinbase_height": "" if decoded_height is None else str(decoded_height),
        "coinbase_scriptsig_hex": scriptsig_hex,
        "rules_violated": "",
    }


def test_version_rule_token_must_match_actual_violation() -> None:
    mod = _load_validator()
    # A BIP65-era version-2 header: the version gate fires (v2 < required v4),
    # but the CORRECT token for that height is bip65_block_version_below_4.
    # Labelling it bip66_block_version_below_3 must be flagged as inconsistent
    # even though the same gate fires.
    row = _version_row("400000", 2, "02" + "00" * 30)  # BIP65-era (>= 388381)
    row["rules_violated"] = "bip66_block_version_below_3"
    failures = mod.validate_row(row)
    assert any(
        "declared rule bip66_block_version_below_3 inconsistent with actual "
        "violation bip65_block_version_below_4" in f
        for f in failures
    ), failures

    # Control: the correct token for the same violation is NOT flagged.
    row["rules_violated"] = "bip65_block_version_below_4"
    assert not any(
        "inconsistent with actual violation" in f for f in mod.validate_row(row)
    )


def test_length_rule_token_must_match_actual_violation() -> None:
    mod = _load_validator()
    # A 1-byte scriptSig fires the length gate, but the CORRECT token is
    # below_2, not above_100. Labelling it above_100 must be flagged.
    row = _version_row("400000", 4, "02")  # 1-byte scriptSig
    row["rules_violated"] = "coinbase_scriptsig_length_above_100"
    failures = mod.validate_row(row)
    assert any(
        "declared rule coinbase_scriptsig_length_above_100 inconsistent with "
        "actual violation coinbase_scriptsig_length_below_2" in f
        for f in failures
    ), failures

    # Control: the correct token for the same violation is NOT flagged.
    row["rules_violated"] = "coinbase_scriptsig_length_below_2"
    assert not any(
        "inconsistent with actual violation" in f for f in mod.validate_row(row)
    )


def test_unclaimed_length_violation_alongside_claimed_version() -> None:
    mod = _load_validator()
    # A BIP65-era version-2 header with an over-100-byte scriptSig: BOTH the
    # version violation and the length violation are derivable from the bytes.
    # Claiming only the version violation omits a real secondary violation and
    # must be flagged as an unclaimed violation.
    row = _version_row(
        "400000", 2, "03" + (400000).to_bytes(3, "little").hex() + "00" * 97
    )
    row["rules_violated"] = "bip65_block_version_below_4"
    failures = mod.validate_row(row)
    assert any(
        "unclaimed violation: coinbase_scriptsig_length_above_100" in f
        for f in failures
    ), failures

    # Control: claiming BOTH derivable violations is NOT flagged.
    row["rules_violated"] = (
        "bip65_block_version_below_4|coinbase_scriptsig_length_above_100"
    )
    assert not any("unclaimed violation" in f for f in mod.validate_row(row))


def test_row_with_only_the_claimed_violation_is_not_unclaimed_flagged() -> None:
    mod = _load_validator()
    # A BIP65-era version-2 header with a VALID-length scriptSig: the version
    # violation is the only derivable violation, so claiming it alone is
    # complete and passes with no unclaimed-violation failure.
    row = _version_row("400000", 2, "02" + "00" * 30)
    row["rules_violated"] = "bip65_block_version_below_4"
    failures = mod.validate_row(row)
    assert not any("unclaimed violation" in f for f in failures), failures


def test_unclaimed_version_violation_alongside_claimed_length() -> None:
    mod = _load_validator()
    # The reverse omission: a BIP65-era version-2 header with an over-100-byte
    # scriptSig claiming only the length violation must be flagged for the
    # unclaimed version violation.
    row = _version_row(
        "400000", 2, "03" + (400000).to_bytes(3, "little").hex() + "00" * 97
    )
    row["rules_violated"] = "coinbase_scriptsig_length_above_100"
    failures = mod.validate_row(row)
    assert any(
        "unclaimed violation: bip65_block_version_below_4" in f for f in failures
    ), failures


def test_unclaimed_bip34_coinbase_height_violation() -> None:
    mod = _load_validator()
    # A version-2 header at a BIP34+ height whose scriptSig carries the WRONG
    # BIP34 height prefix but a valid length: the coinbase-height violation is
    # derivable, so an empty rules_violated is flagged for the unclaimed
    # bip34_coinbase_height_mismatch (the version passes, so no version token
    # is derived).
    height = 300_000  # BIP34+ era (>= BIP34_HEIGHT, < BIP66_HEIGHT)
    row = _version_row(str(height), 2, _bip34_scriptsig(height + 5))
    row["rules_violated"] = "bip66_block_version_below_3"  # does not re-derive
    failures = mod.validate_row(row)
    assert any(
        "unclaimed violation: bip34_coinbase_height_mismatch" in f for f in failures
    ), failures

    # Control: claiming the coinbase-height violation is NOT flagged.
    row["rules_violated"] = "bip34_coinbase_height_mismatch"
    assert not any("unclaimed violation" in f for f in mod.validate_row(row))


def test_version_violation_suppresses_unclaimed_bip34_height_token() -> None:
    mod = _load_validator()
    # A version-1 header at a BIP34+ height with a WRONG coinbase height
    # prefix: bip34_height_error rejects it for its VERSION before examining
    # the coinbase prefix, so the real violation is the version. Only the
    # version token is derived — no unclaimed bip34 coinbase-height token.
    height = 300_000
    row = _version_row(str(height), 1, _bip34_scriptsig(height + 5))
    row["rules_violated"] = "bip34_block_version_below_2"
    failures = mod.validate_row(row)
    assert not any("unclaimed violation" in f for f in failures), failures


def test_bip34_coinbase_height_token_requires_passing_version() -> None:
    mod = _load_validator()
    # A version-1 header at a BIP34+ height (>= 227931) with a VALID coinbase
    # height prefix: bip34_height_error rejects it for its VERSION before
    # examining the coinbase prefix, so labelling it
    # bip34_coinbase_height_mismatch passes the gate for the wrong reason.
    # The declared coinbase-height token must be flagged as inconsistent: the
    # real/primary violation is the version, not the coinbase height.
    height = 300_000  # BIP34+ era (>= BIP34_HEIGHT, < BIP66_HEIGHT)
    row = _version_row(str(height), 1, _bip34_scriptsig(height))
    row["rules_violated"] = "bip34_coinbase_height_mismatch"
    failures = mod.validate_row(row)
    assert any(
        "declared rule bip34_coinbase_height_mismatch inconsistent with "
        "actual violation" in f
        for f in failures
    ), failures

    # Control: a version-2 header at the same height with a WRONG coinbase
    # height prefix (the version passes, so the coinbase height is the only
    # remaining failure) is NOT flagged as inconsistent.
    row = _version_row(str(height), 2, _bip34_scriptsig(height + 5))
    row["rules_violated"] = "bip34_coinbase_height_mismatch"
    assert not any(
        "inconsistent with actual violation" in f for f in mod.validate_row(row)
    )


def _mtp_row(header_time: int, column_time: str) -> dict[str, str]:
    """A full-PoW row claiming a time rule, with a header/column nTime split.

    The btc_time column deliberately disagrees with the header's nTime (the
    split exercises that the MTP rule re-derives from the header bytes, never
    the column); the derived-column cross-check therefore flags the column,
    which the test accounts for. The remaining audit columns agree with the
    bytes.
    """
    header = (
        (4).to_bytes(4, "little")
        + b"\x11" * 32
        + b"\x22" * 32
        + header_time.to_bytes(4, "little")
        + bytes.fromhex("2100ffff")[::-1]  # nBits is little-endian
        + (42).to_bytes(4, "little")
    )
    assert len(header) == 80
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return {
        "height": "500000",
        "hash": digest[::-1].hex(),
        "btc_header_version": "4",
        "btc_time": column_time,
        "btc_bits": "2100ffff",
        "expected_nbits": "1d00ffff",
        "btc_header_hex": header.hex(),
        "coinbase_height": "0",
        "coinbase_scriptsig_hex": "02" + "00" * 30,
        "rules_violated": "median_time_past_violation",
    }


def test_gate_unknown_verdict_is_not_proof_of_the_declared_rule() -> None:
    mod = _load_validator()
    # A row claiming coinbase_scriptsig_length_above_100 whose scriptSig is
    # MISSING: coinbase_scriptsig_length_error returns "UNKNOWN: missing
    # coinbase scriptSig for length validation" — unusable evidence, not a
    # proven violation. The validator must fail closed: an UNKNOWN verdict
    # is not proof of the declared rule.
    row = _full_pow_row()
    row["coinbase_scriptsig_hex"] = ""
    row["rules_violated"] = "coinbase_scriptsig_length_above_100"
    failures = mod.validate_row(row)
    assert any(
        "rule coinbase_scriptsig_length_above_100 could not be evaluated "
        "(gate returned UNKNOWN)" in f
        for f in failures
    ), failures


def test_gate_malformed_evidence_rejected_is_not_proof_of_the_declared_rule() -> None:
    mod = _load_validator()
    # A row claiming a BIP34 coinbase-height rule whose scriptSig hex is
    # MALFORMED (non-empty but unparseable): bip34_height_error returns
    # "REJECTED: malformed coinbase scriptSig hex" — a malformed-evidence
    # verdict, not a proven consensus violation. The validator must fail
    # closed: it is not proof of the declared rule.
    height = 300_000  # BIP34+ era, version 4 passes the version requirement
    row = _version_row(str(height), 4, _bip34_scriptsig(height))
    row["coinbase_scriptsig_hex"] = "zz"  # malformed non-empty hex
    row["rules_violated"] = "bip34_coinbase_height_mismatch"
    failures = mod.validate_row(row)
    assert any(
        "rule bip34_coinbase_height_mismatch could not be evaluated" in f
        for f in failures
    ), failures
    # Control: the same row with a genuine height mismatch (a well-formed
    # scriptSig carrying the wrong height) re-derives and is NOT flagged.
    row["coinbase_scriptsig_hex"] = _bip34_scriptsig(height + 5)
    row["coinbase_height"] = str(height + 5)
    assert not any("could not be evaluated" in f for f in mod.validate_row(row))


def test_gate_missing_coinbase_evidence_is_not_proof_of_a_bip34_violation() -> None:
    mod = _load_validator()
    # A row claiming a BIP34 coinbase-height rule whose scriptSig is EMPTY
    # (missing evidence, e.g. an export that does not expose the parent
    # coinbase): bip34_height_error returns "REJECTED: missing coinbase
    # scriptSig for BIP34 validation" — a missing-evidence verdict, not a
    # proven consensus violation. A genuine BIP34 violation requires the
    # scriptSig to be PRESENT and wrongly-encoded, so the validator must
    # fail closed: missing evidence is not proof of the declared rule.
    height = 300_000  # BIP34+ era, version 4 passes the version requirement
    row = _version_row(str(height), 4, _bip34_scriptsig(height))
    row["coinbase_scriptsig_hex"] = ""
    row["coinbase_height"] = ""
    row["rules_violated"] = "bip34_coinbase_height_mismatch"
    failures = mod.validate_row(row)
    assert any(
        "rule bip34_coinbase_height_mismatch could not be evaluated" in f
        for f in failures
    ), failures
    # The reverse direction agrees: missing evidence derives NO BIP34
    # coinbase-height violation, so the row must NOT be flagged for an
    # unclaimed bip34 token either.
    assert not any("unclaimed violation: bip34" in f for f in failures), failures

    # Control: the same row with a genuine height mismatch (a well-formed
    # scriptSig carrying the wrong height) re-derives and is NOT flagged.
    row["coinbase_scriptsig_hex"] = _bip34_scriptsig(height + 5)
    row["coinbase_height"] = str(height + 5)
    assert not any("could not be evaluated" in f for f in mod.validate_row(row))


def test_empty_scriptsig_derives_no_length_violation() -> None:
    mod = _load_validator()
    # A header-only row (an EMPTY scriptSig — the source does not expose the
    # parent coinbase, e.g. RSK) with a valid version: the length gate returns
    # UNKNOWN for missing evidence, which is NOT a violation. The reverse
    # direction must NOT derive an unclaimed coinbase_scriptsig_length_below_2
    # token from the empty string (empty means "not exposed", not "zero-byte").
    height = 400_000  # BIP65 era; version 4 passes the version requirement
    row = _version_row(str(height), 4, _bip34_scriptsig(height))
    row["coinbase_scriptsig_hex"] = ""
    row["coinbase_height"] = ""
    row["rules_violated"] = "median_time_past_violation"  # unrelated claim
    failures = mod.validate_row(row, mtp_context={})
    assert not any(
        "unclaimed violation: coinbase_scriptsig_length" in f for f in failures
    ), failures

    # Control: a PRESENT 1-byte scriptSig is a genuine below-2 violation and
    # MUST be derived (flagged as unclaimed when not claimed).
    row["coinbase_scriptsig_hex"] = "02"  # 1 byte, below the 2-byte minimum
    failures = mod.validate_row(row, mtp_context={})
    assert any(
        "unclaimed violation: coinbase_scriptsig_length_below_2" in f for f in failures
    ), failures


def test_bip34_metadata_crosscheck_is_not_proof_of_a_coinbase_height_violation() -> (
    None
):
    mod = _load_validator()
    # A row whose scriptSig encodes the height CORRECTLY but whose optional
    # btc_bip34_height metadata column disagrees: bip34_height_error returns
    # "REJECTED: decoded BIP34 coinbase height disagrees with
    # btc_bip34_height". That is inconsistent metadata, NOT a Bitcoin
    # consensus violation (the raw coinbase bytes are correct), so it must NOT
    # be accepted as proof of a declared bip34 coinbase-height rule.
    height = 300_000  # BIP34+ era, version 4 passes the version requirement
    row = _version_row(str(height), 4, _bip34_scriptsig(height))
    row["btc_bip34_height"] = str(height + 7)  # stale/disagreeing metadata
    row["rules_violated"] = "bip34_coinbase_height_mismatch"
    failures = mod.validate_row(row)
    assert any(
        "rule bip34_coinbase_height_mismatch could not be evaluated (gate "
        "returned a metadata cross-check rejection" in f
        for f in failures
    ), failures
    # The reverse direction agrees: a metadata disagreement derives NO BIP34
    # coinbase-height violation, so the row must NOT be flagged for an
    # unclaimed bip34 token either.
    assert not any("unclaimed violation: bip34" in f for f in failures), failures

    # Control: a genuine raw-prefix mismatch (a well-formed scriptSig carrying
    # the WRONG height) re-derives and is NOT flagged as a metadata cross-check.
    row2 = _version_row(str(height), 4, _bip34_scriptsig(height + 5))
    row2["rules_violated"] = "bip34_coinbase_height_mismatch"
    assert not any("could not be evaluated" in f for f in mod.validate_row(row2))


def test_time_beyond_future_limit_is_rejected_not_deferred() -> None:
    mod = _load_validator()
    # A self-contained row claiming time_beyond_future_limit: the rule needs
    # network-adjusted time that is not committed, so it is not
    # offline-recheckable and can never be a valid committed error block. The
    # validator must FAIL closed on the token, not silently accept the row.
    row = _mtp_row(header_time=1_500_000_000, column_time="1500000000")
    row["rules_violated"] = "time_beyond_future_limit"
    row["rejection_reason"] = "time_beyond_future_limit"
    failures = mod.validate_row(row, mtp_context={})
    assert any(
        "rule time_beyond_future_limit is not offline-recheckable and cannot "
        "be a committed error block" in f
        for f in failures
    ), failures


def test_mtp_rule_uses_header_ntime_not_btc_time_column() -> None:
    mod = _load_validator()
    parent_mtp = 1_500_000_000
    # The header's nTime (1_500_000_000) is at the parent MTP, so the header
    # violates the time rule; the btc_time column (1_500_000_100) would pass.
    # The header's nTime must govern: the rule re-derives (no failure).
    row = _mtp_row(header_time=1_500_000_000, column_time="1500000100")
    mtp_context = {(500000, row["hash"]): parent_mtp}
    assert not any(
        "median_time_past_violation did not re-derive" in f
        for f in mod.validate_row(row, mtp_context=mtp_context)
    )
    # The reverse split: the header's nTime (1_500_000_100) is above the
    # parent MTP, so the header does NOT violate; the btc_time column
    # (1_500_000_000) would. The header's nTime must govern: the claimed
    # violation does not re-derive.
    row = _mtp_row(header_time=1_500_000_100, column_time="1500000000")
    mtp_context = {(500000, row["hash"]): parent_mtp}
    assert any(
        "median_time_past_violation did not re-derive" in f
        for f in mod.validate_row(row, mtp_context=mtp_context)
    )


def test_mtp_rule_invalid_sidecar_value_is_not_proof() -> None:
    mod = _load_validator()
    # A time_below_mtp row whose committed sidecar parent_median_time_past is
    # INVALID (-1, or above the uint32 max): median_time_past_error returns
    # "UNKNOWN: canonical parent median-time-past unavailable", not a
    # rule-specific REJECTED verdict. The MTP-rule path must fail closed —
    # an UNKNOWN result is not a proven re-derivation, so the row must NOT
    # validate. The header's nTime is at/below any plausible parent MTP, so a
    # valid sidecar value WOULD re-derive the violation; only the invalid
    # sidecar value stands between this row and a (wrong) pass.
    for invalid_mtp in (-1, 0x1_0000_0000):
        row = _mtp_row(header_time=1_500_000_000, column_time="1500000000")
        row["rules_violated"] = "time_below_mtp"
        mtp_context = {(500000, row["hash"]): invalid_mtp}
        assert any(
            "rule time_below_mtp could not be evaluated (gate returned UNKNOWN)" in f
            for f in mod.validate_row(row, mtp_context=mtp_context)
        ), invalid_mtp


def test_rejection_reason_must_be_primary_rule_of_rules_violated() -> None:
    mod = _load_validator()
    # A BIP65-era version-2 header with an over-100-byte scriptSig: BOTH
    # bip65_block_version_below_4 and coinbase_scriptsig_length_above_100
    # re-derive from the bytes, so the multi-rule rules_violated is fully
    # re-derivable. The dataset contract makes rejection_reason the PRIMARY
    # (first) rule of the pipe-joined set.
    row = _version_row(
        "400000", 2, "03" + (400000).to_bytes(3, "little").hex() + "00" * 97
    )
    row["rules_violated"] = (
        "bip65_block_version_below_4|coinbase_scriptsig_length_above_100"
    )

    # A consistent multi-rule row: rejection_reason is the first token.
    row["rejection_reason"] = "bip65_block_version_below_4"
    assert not any("rejection_reason" in f for f in mod.validate_row(row))

    # rejection_reason naming the SECONDARY rule: flagged even though every
    # rule in rules_violated re-derives.
    row["rejection_reason"] = "coinbase_scriptsig_length_above_100"
    assert any(
        "rejection_reason coinbase_scriptsig_length_above_100 is not the "
        "primary (first) rule" in f
        for f in mod.validate_row(row)
    )

    # rejection_reason naming a rule not in the set at all: flagged.
    row["rejection_reason"] = "bip66_block_version_below_3"
    assert any(
        "rejection_reason bip66_block_version_below_3 is not the primary "
        "(first) rule" in f
        for f in mod.validate_row(row)
    )

    # An empty/missing rejection_reason: flagged.
    row["rejection_reason"] = ""
    assert any("rejection_reason is empty" in f for f in mod.validate_row(row))
