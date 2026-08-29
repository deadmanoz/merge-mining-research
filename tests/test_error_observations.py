"""Tests for the fail-closed error-block witness export."""

import csv
import shutil

import pytest

from stale_blocks_analysis.auxpow_chainid import (
    hash_from_display_hex,
    hash_from_header_bytes,
    hash_to_internal_hex,
)
from stale_blocks_analysis.config import DATA_DIR
from stale_blocks_analysis.error_observations import (
    ERROR_OBSERVATION_FIELDS,
    ERROR_OBSERVATION_LEDGER,
    RSK_SIDECAR_EXPORT_FIELDS,
    build_error_observation_rows,
    load_error_blocks,
    validate_rsk_sidecar_cells,
)
from stale_blocks_analysis.evidence_hydration import load_child_identity
from stale_blocks_analysis.monitor_exports import MONITOR_EVIDENCE_FIELDS


def _copy_error_observation_inputs(data_dir) -> None:
    shutil.copytree(DATA_DIR / "error-blocks", data_dir / "error-blocks")
    shutil.copytree(DATA_DIR / "child-identity", data_dir / "child-identity")


def _rewrite_ledger(ledger_path, rows, fieldnames) -> None:
    with ledger_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _rewrite_rsk_identity(data_dir, mutate) -> None:
    path = data_dir / "child-identity" / "rsk_child_identity.csv"
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    mutate(rows)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_catalogue_preserves_an_expected_target_that_differs_from_header_bits() -> None:
    row = next(block for block in load_error_blocks() if block.height == 717696)

    assert row.btc_bits == "170b98ab"
    assert row.expected_nbits == "170b8c8b"


def test_recovered_witness_ledger_exactly_covers_the_current_catalogue() -> None:
    rows, inventory = build_error_observation_rows()
    blocks = load_error_blocks()
    expected = {
        (chain, child_height, block.block_hash)
        for block in blocks
        for chain, child_height in block.observations
    }

    assert {
        (row["chain"], int(row["child_height"]), row["btc_header_hash"]) for row in rows
    } == expected
    assert inventory["rows"] == len(expected)
    assert len(blocks) == 39
    assert inventory["rows"] == 86


def test_error_observation_ledger_rejects_wrong_catalogue_row_number(tmp_path) -> None:
    data_dir = tmp_path / "data"
    _copy_error_observation_inputs(data_dir)
    ledger_path = data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER
    with ledger_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rows[0]["catalogue_row_number"] = "999"
    _rewrite_ledger(ledger_path, rows, fieldnames)

    with pytest.raises(ValueError, match="wrong catalogue_row_number"):
        build_error_observation_rows(data_dir=data_dir)


def test_error_observation_header_is_the_34_column_union() -> None:
    rows, _inventory = build_error_observation_rows()

    assert list(ERROR_OBSERVATION_FIELDS) == list(MONITOR_EVIDENCE_FIELDS) + list(
        RSK_SIDECAR_EXPORT_FIELDS
    )
    assert list(rows[0]) == list(ERROR_OBSERVATION_FIELDS)


def test_non_rsk_error_observations_leave_sidecar_cells_blank() -> None:
    rows, _inventory = build_error_observation_rows()

    for row in rows:
        if row["chain"] == "rsk":
            continue
        extra = [
            field
            for field in RSK_SIDECAR_EXPORT_FIELDS
            if (row.get(field) or "").strip()
        ]
        assert extra == []


def test_rsk_error_observations_carry_semantic_sidecars() -> None:
    rows, _inventory = build_error_observation_rows()
    rsk_rows = [row for row in rows if row["chain"] == "rsk"]

    assert len(rsk_rows) == 5
    for row in rsk_rows:
        validate_rsk_sidecar_cells(row, row_id=f"rsk {row['btc_header_hash']}")


def test_rsk_display_order_witness_hashes_are_exported_unchanged() -> None:
    rows, _inventory = build_error_observation_rows()
    with (DATA_DIR / "error-blocks" / ERROR_OBSERVATION_LEDGER).open(
        newline=""
    ) as handle:
        ledger = list(csv.DictReader(handle))

    ledger_rsk = {
        row["btc_header_hash"]: row["child_block_hash"]
        for row in ledger
        if row["chain"] == "rsk"
    }
    exported_rsk = {
        row["btc_header_hash"]: row["child_block_hash"]
        for row in rows
        if row["chain"] == "rsk"
    }
    reversed_ledger = {
        parent: hash_to_internal_hex(hash_from_display_hex(child))
        for parent, child in ledger_rsk.items()
    }

    assert exported_rsk == ledger_rsk
    assert exported_rsk != reversed_ledger


def test_bitcoin_family_display_order_hashes_are_exported_in_internal_order(
    tmp_path,
) -> None:
    data_dir = tmp_path / "data"
    _copy_error_observation_inputs(data_dir)
    ledger_path = data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER
    with ledger_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    witness = next(row for row in rows if row["chain"] == "namecoin")
    internal = witness["child_block_hash"]
    witness["child_block_hash_order"] = "display"
    witness["child_block_hash"] = hash_to_internal_hex(hash_from_display_hex(internal))
    _rewrite_ledger(ledger_path, rows, fieldnames)

    output_rows, _inventory = build_error_observation_rows(data_dir=data_dir)
    exported = next(
        row
        for row in output_rows
        if row["chain"] == witness["chain"]
        and row["child_height"] == witness["child_height"]
        and row["btc_header_hash"] == witness["btc_header_hash"]
    )
    assert exported["child_block_hash"] == internal


def test_error_observation_ledger_rejects_unmatched_child_header_hash(tmp_path) -> None:
    data_dir = tmp_path / "data"
    _copy_error_observation_inputs(data_dir)
    ledger_path = data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER

    with ledger_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)

    assert fieldnames is not None
    next(row for row in rows if row["child_header_hex"])["child_block_hash"] = "00" * 32
    _rewrite_ledger(ledger_path, rows, fieldnames)

    with pytest.raises(
        ValueError, match="child_header_hex does not match child_block_hash"
    ):
        build_error_observation_rows(data_dir=data_dir)


def test_error_observation_ledger_derives_missing_child_hash_from_header(
    tmp_path,
) -> None:
    data_dir = tmp_path / "data"
    _copy_error_observation_inputs(data_dir)
    ledger_path = data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER

    with ledger_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)

    assert fieldnames is not None
    witness = next(row for row in rows if row["child_header_hex"])
    expected_hash = hash_from_header_bytes(
        bytes.fromhex(witness["child_header_hex"])
    ).hex()
    witness["child_block_hash"] = ""
    _rewrite_ledger(ledger_path, rows, fieldnames)

    output_rows, _inventory = build_error_observation_rows(data_dir=data_dir)
    exported = next(
        row
        for row in output_rows
        if row["chain"] == witness["chain"]
        and row["child_height"] == witness["child_height"]
        and row["btc_header_hash"] == witness["btc_header_hash"]
    )
    assert exported["child_block_hash"] == expected_hash


def test_error_observation_ledger_rejects_missing_child_identity(tmp_path) -> None:
    data_dir = tmp_path / "data"
    _copy_error_observation_inputs(data_dir)
    ledger_path = data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER

    with ledger_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)

    assert fieldnames is not None
    rows[0]["child_block_hash"] = ""
    rows[0]["child_header_hex"] = ""
    _rewrite_ledger(ledger_path, rows, fieldnames)

    with pytest.raises(
        ValueError, match="missing child_block_hash and child_header_hex"
    ):
        build_error_observation_rows(data_dir=data_dir)


def test_error_observation_ledger_rejects_duplicate_child_identity(tmp_path) -> None:
    data_dir = tmp_path / "data"
    _copy_error_observation_inputs(data_dir)
    ledger_path = data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER

    with ledger_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)

    assert fieldnames is not None
    headerless = [row for row in rows if not row["child_header_hex"]]
    first, second = headerless[:2]
    assert first["chain"] == second["chain"]
    second["child_block_hash"] = first["child_block_hash"]
    _rewrite_ledger(ledger_path, rows, fieldnames)

    with pytest.raises(ValueError, match="duplicate child identity"):
        build_error_observation_rows(data_dir=data_dir)


def test_error_observation_rejects_missing_rsk_child_identity(tmp_path) -> None:
    data_dir = tmp_path / "data"
    _copy_error_observation_inputs(data_dir)
    identity = data_dir / "child-identity" / "rsk_child_identity.csv"
    identity.write_text("chain,btc_header_hash,child_height,child_block_hash\n")

    with pytest.raises(ValueError, match="missing child-identity"):
        build_error_observation_rows(data_dir=data_dir)


def test_error_observation_corroborates_rsk_child_timestamp(tmp_path) -> None:
    data_dir = tmp_path / "data"
    _copy_error_observation_inputs(data_dir)
    ledger_path = data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER
    with ledger_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rsk = next(row for row in rows if row["chain"] == "rsk")
    rsk["child_block_time"] = "1"
    _rewrite_ledger(ledger_path, rows, fieldnames)
    with pytest.raises(ValueError, match="child_block_time disagrees"):
        build_error_observation_rows(data_dir=data_dir)

    rsk["child_block_time"] = ""
    _rewrite_ledger(ledger_path, rows, fieldnames)
    identity = load_child_identity(data_dir)[("rsk", rsk["btc_header_hash"])]
    exported = next(
        row
        for row in build_error_observation_rows(data_dir=data_dir)[0]
        if row["chain"] == "rsk" and row["btc_header_hash"] == rsk["btc_header_hash"]
    )
    assert exported["child_block_time"] == identity["child_block_time"]


def test_error_observation_rejects_reversed_rsk_hash_without_overwriting(
    tmp_path,
) -> None:
    data_dir = tmp_path / "data"
    _copy_error_observation_inputs(data_dir)
    ledger_path = data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER
    with ledger_path.open(newline="") as handle:
        rsk_witness = next(
            row for row in csv.DictReader(handle) if row["chain"] == "rsk"
        )
    rsk_parent = rsk_witness["btc_header_hash"]
    ledger_hash = rsk_witness["child_block_hash"]
    assert not (rsk_witness.get("child_header_hex") or "").strip()

    def reverse_hash(rows) -> None:
        for row in rows:
            if row["btc_header_hash"] == rsk_parent:
                assert not (row.get("child_header_hex") or "").strip()
                row["child_block_hash"] = hash_to_internal_hex(
                    hash_from_display_hex(row["child_block_hash"])
                )

    _rewrite_rsk_identity(data_dir, reverse_hash)

    with pytest.raises(ValueError, match="child_block_hash disagrees"):
        build_error_observation_rows(data_dir=data_dir)

    identity_after = load_child_identity(data_dir)
    assert identity_after[("rsk", rsk_parent)]["child_block_hash"] != ledger_hash


def test_rsk_sidecar_rejects_0x_prefix_and_i32_overflow() -> None:
    row = {
        "rsk_miner": "07c5446adb392be116f4859a722589f3fa8223e4",
        "merge_mining_hash": "6381b3a089cfdd2852ac0edba8e3c234b16321167e8b71c45a75db1148c11c2f",
        "is_uncle": "1",
        "uncle_index": "0",
        "uncle_parent_height": "789984",
        "rsk_merkle_proof": "04",
        "rsk_coinbase_tail": "05",
    }
    validate_rsk_sidecar_cells(row, row_id="ok")

    prefixed = dict(row)
    prefixed["rsk_miner"] = "0x" + row["rsk_miner"]
    with pytest.raises(ValueError, match="unprefixed 20-byte hex"):
        validate_rsk_sidecar_cells(prefixed, row_id="prefixed")

    overflow = dict(row)
    overflow["uncle_parent_height"] = "2147483648"
    with pytest.raises(ValueError, match="signed 32-bit"):
        validate_rsk_sidecar_cells(overflow, row_id="overflow")

    spaced = dict(row)
    spaced["rsk_miner"] = row["rsk_miner"][:4] + "  " + row["rsk_miner"][4:]
    with pytest.raises(ValueError, match="unprefixed 20-byte hex"):
        validate_rsk_sidecar_cells(spaced, row_id="spaced")

    underscored = dict(row)
    underscored["uncle_index"] = "1_0"
    with pytest.raises(ValueError, match="signed 32-bit"):
        validate_rsk_sidecar_cells(underscored, row_id="underscore")
