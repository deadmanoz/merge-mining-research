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
from stale_blocks_analysis.auxpow_chainid import (
    hash_from_header_bytes,
    hash_to_display_hex,
)
from stale_blocks_analysis.bitcoin_binary import sha256d
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


def test_committed_overlay_pins_the_externally_attested_fields() -> None:
    """Pin the values the validator cannot re-derive from committed bytes.

    The attested sigop cost is the overlay's central externally sourced
    measurement (b10c counted exactly 80,003 for BOTH blocks), and the
    evidence URL is the citation the claim rests on. The validator can only
    check ``> 80000``, so a silently corrupted value would otherwise pass CI;
    this test pins the exact figures per key.
    """
    _fieldnames, rows = _committed_rows()
    by_height = {int(row["height"]): row for row in rows}
    evidence_url = "https://b10c.me/observations/11-invalid-blocks-783426-and-784121/"
    for height, legacy in ((783426, "18630"), (784121, "18051")):
        row = by_height[height]
        assert row["attested_sigop_cost"] == "80003"
        assert row["legacy_sigops_from_bytes"] == legacy
        assert row["evidence_source"] == "b10c"
        assert row["evidence_url"] == evidence_url


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


def _craft_one_tx_block() -> bytes:
    """Serialize a minimal 1-transaction block whose header commits to its tx."""
    tx = (
        b"\x01\x00\x00\x00"  # nVersion
        + b"\x01"  # vin count
        + b"\x00" * 32
        + b"\xff\xff\xff\xff"  # coinbase outpoint
        + b"\x00"  # empty scriptSig
        + b"\xff\xff\xff\xff"  # nSequence
        + b"\x01"  # vout count
        + b"\x00" * 8  # value
        + b"\x01\xac"  # scriptPubKey: OP_CHECKSIG (1 legacy sigop)
        + b"\x00" * 4  # nLockTime
    )
    header = b"\x01\x00\x00\x00" + b"\x00" * 32 + sha256d(tx) + b"\x00" * 12
    return header + b"\x01" + tx


def test_parse_block_body_derives_matching_merkle_root() -> None:
    raw = _craft_one_tx_block()
    sigops, merkle_root = body_invalid_overlay.parse_block_body(raw)
    assert sigops == 1
    assert merkle_root == raw[36:68]


def test_merkle_fold_rejects_cve_2012_2459_duplication() -> None:
    """A duplicated final leaf yields the same root; it must fail, not match."""
    a, b, c = (sha256d(bytes([seed])) for seed in (1, 2, 3))
    odd_root = body_invalid_overlay._merkle_root([a, b, c])
    assert odd_root  # the legitimate odd-length fold still derives a root
    with pytest.raises(ValueError, match="CVE-2012-2459"):
        body_invalid_overlay._merkle_root([a, b, c, c])


def test_substituted_body_fails_merkle_authentication(tmp_path: Path) -> None:
    """A genuine header over a tampered body must not count as byte-checked."""
    import hashlib

    fieldnames, _rows = _committed_rows()
    raw = _craft_one_tx_block()
    tampered = raw[:-1] + bytes([raw[-1] ^ 0x01])  # flip a tx locktime byte
    block_hash = hash_to_display_hex(hash_from_header_bytes(tampered[:80]))
    blocks_dir = tmp_path / "blocks"
    blocks_dir.mkdir()
    (blocks_dir / f"999999-{block_hash}.bin").write_bytes(tampered)
    row = {
        "height": "999999",
        "hash": block_hash,
        "rule": "bad-blk-sigops",
        "attested_sigop_cost": "80003",
        "legacy_sigops_from_bytes": "1",
        "evidence_source": "test",
        "evidence_url": "https://example.com/",
        "block_file": f"blocks/999999-{block_hash}.bin",
        "block_sha256": hashlib.sha256(tampered).hexdigest(),
        "notes": "",
    }
    path = _write_overlay(tmp_path / "tampered.csv", fieldnames, [row])
    failures = _validate(path, tmp_path, blocks_dir=blocks_dir)
    assert any("do not merkle-authenticate" in failure for failure in failures)


def _craft_segwit_block(
    tamper_witness: bool = False, extra_coinbase_witness_item: bool = False
) -> bytes:
    """Serialize a 2-tx segwit block with a valid BIP141 witness commitment."""
    witness_item = b"\xab" if tamper_witness else b"\xaa"
    spend = (
        b"\x01\x00\x00\x00"  # nVersion
        + b"\x00\x01"  # segwit marker + flag
        + b"\x01"  # vin count
        + b"\x11" * 32
        + b"\x00\x00\x00\x00"  # outpoint
        + b"\x00"  # empty scriptSig
        + b"\xff\xff\xff\xff"  # nSequence
        + b"\x01"  # vout count
        + b"\x00" * 8  # value
        + b"\x01\xac"  # scriptPubKey: OP_CHECKSIG
        + b"\x01\x01"  # witness: one 1-byte item
        + witness_item
        + b"\x00" * 4  # nLockTime
    )
    spend_txid = sha256d(
        spend[:4] + spend[6 : len(spend) - 7] + spend[len(spend) - 4 :]
    )
    # For the COMMITMENT the untampered wtxid is used, so a tampered witness
    # byte makes the derived commitment disagree with the committed one.
    committed_spend = spend if not tamper_witness else spend.replace(b"\xab", b"\xaa")
    spend_wtxid = sha256d(committed_spend)
    reserved = b"\x00" * 32
    witness_root = body_invalid_overlay._merkle_root([b"\x00" * 32, spend_wtxid])
    commitment = sha256d(witness_root + reserved)
    coinbase = (
        b"\x01\x00\x00\x00"
        + b"\x00\x01"
        + b"\x01"
        + b"\x00" * 32
        + b"\xff\xff\xff\xff"  # null outpoint
        + b"\x01\x51"  # scriptSig: OP_1
        + b"\xff\xff\xff\xff"
        + b"\x02"  # vout count
        + b"\x00" * 8
        + b"\x01\xac"
        + b"\x00" * 8
        + b"\x26"  # 38-byte commitment script
        + b"\x6a\x24\xaa\x21\xa9\xed"
        + commitment
        + (
            # An appended second item is NOT covered by the commitment (the
            # coinbase wtxid leaf is zeroed), so it must be rejected outright.
            b"\x02\x20" + reserved + b"\x01\xff"
            if extra_coinbase_witness_item
            else b"\x01\x20" + reserved  # exactly one 32-byte reserved value
        )
        + b"\x00" * 4
    )
    witness_bytes = 36 if extra_coinbase_witness_item else 34
    coinbase_txid = sha256d(
        coinbase[:4]
        + coinbase[6 : len(coinbase) - witness_bytes - 4]
        + coinbase[len(coinbase) - 4 :]
    )
    merkle_root = body_invalid_overlay._merkle_root([coinbase_txid, spend_txid])
    header = b"\x01\x00\x00\x00" + b"\x00" * 32 + merkle_root + b"\x00" * 12
    return header + b"\x02" + coinbase + spend


def test_segwit_block_witness_commitment_authenticates() -> None:
    raw = _craft_segwit_block()
    sigops, failures = body_invalid_overlay.authenticate_block_body(raw)
    assert failures == []
    assert sigops == 2


def test_tampered_witness_data_fails_commitment_authentication() -> None:
    """Altered witness bytes leave the txid tree intact but must still fail."""
    raw = _craft_segwit_block(tamper_witness=True)
    _sigops, failures = body_invalid_overlay.authenticate_block_body(raw)
    assert any("coinbase commitment" in failure for failure in failures)


def test_surplus_coinbase_witness_item_rejected() -> None:
    """The zeroed coinbase leaf never covers extra items; BIP141 allows one."""
    raw = _craft_segwit_block(extra_coinbase_witness_item=True)
    _sigops, failures = body_invalid_overlay.authenticate_block_body(raw)
    assert any("bad-witness-nonce-size" in failure for failure in failures)


def _strip_witnesses(raw: bytes) -> bytes:
    """Rebuild the crafted 2-tx segwit block with all witness data stripped.

    Legacy txids (and so the header merkle root) are unchanged; only the
    marker, flag, and witness sections disappear. The coinbase's commitment
    output stays in place, exactly the incomplete-body shape the validator
    must reject rather than skip.
    """
    pos = 80
    tx_count, pos = body_invalid_overlay._read_compact_size(raw, pos)
    stripped_txs = []
    for _ in range(tx_count):
        count, txid, wtxid, _outputs, _witness, new_pos = (
            body_invalid_overlay._transaction_at(raw, pos)
        )
        tx = raw[pos:new_pos]
        # version + body (between marker/flag and witness) + locktime.
        is_segwit = tx[4] == 0x00 and tx[5] == 0x01
        if is_segwit:
            # Recompute the body span exactly as the txid derivation does.
            legacy = _legacy_tx_bytes(tx)
        else:
            legacy = tx
        assert sha256d(legacy) == txid
        stripped_txs.append(legacy)
        pos = new_pos
    return raw[:81] + b"".join(stripped_txs)


def _legacy_tx_bytes(tx: bytes) -> bytes:
    """Strip marker/flag/witness from one serialized segwit transaction."""
    pos = 6  # version + marker + flag
    body_start = pos
    vin_count, pos = body_invalid_overlay._read_compact_size(tx, pos)
    for _ in range(vin_count):
        pos += 36
        script_len, pos = body_invalid_overlay._read_compact_size(tx, pos)
        pos += script_len + 4
    vout_count, pos = body_invalid_overlay._read_compact_size(tx, pos)
    for _ in range(vout_count):
        pos += 8
        script_len, pos = body_invalid_overlay._read_compact_size(tx, pos)
        pos += script_len
    body_end = pos
    return tx[:4] + tx[body_start:body_end] + tx[len(tx) - 4 :]


def test_witness_stripped_body_still_fails_commitment_check() -> None:
    """Stripping every witness must not silently skip commitment validation."""
    raw = _strip_witnesses(_craft_segwit_block())
    _sigops, failures = body_invalid_overlay.authenticate_block_body(raw)
    assert any("bad-witness-nonce-size" in failure for failure in failures)


def test_non_canonical_compact_size_rejected() -> None:
    """A widened-but-equal count encoding must fail, as Core refuses it."""
    raw = _craft_one_tx_block()
    assert raw[80] == 0x01
    widened = raw[:80] + b"\xfd\x01\x00" + raw[81:]
    with pytest.raises(ValueError, match="non-canonical CompactSize"):
        body_invalid_overlay.count_block_legacy_sigops(widened)


def test_surplus_csv_field_fails_closed(tmp_path: Path) -> None:
    """An unquoted comma in the final column must not validate as conformant."""
    fieldnames, rows = _committed_rows()
    line = ",".join(rows[0][name] for name in fieldnames) + ",surplus"
    path = tmp_path / "surplus.csv"
    path.write_text(",".join(fieldnames) + "\n" + line + "\n")
    failures = _validate(path, tmp_path)
    assert any("does not have exactly" in failure for failure in failures)


def test_missing_csv_field_fails_closed(tmp_path: Path) -> None:
    fieldnames, rows = _committed_rows()
    line = ",".join(rows[0][name] for name in fieldnames[:-1])
    path = tmp_path / "short.csv"
    path.write_text(",".join(fieldnames) + "\n" + line + "\n")
    failures = _validate(path, tmp_path)
    assert any("does not have exactly" in failure for failure in failures)
