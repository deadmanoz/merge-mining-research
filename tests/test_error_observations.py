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
    ERROR_OBSERVATION_LEDGER,
    build_error_observation_rows,
    load_error_blocks,
)


def test_catalogue_preserves_an_expected_target_that_differs_from_header_bits() -> None:
    row = next(block for block in load_error_blocks() if block.height == 717696)

    assert row.btc_bits == "170b98ab"
    assert row.expected_nbits == "170b8c8b"


def test_recovered_witness_ledger_exactly_covers_the_current_catalogue() -> None:
    rows, inventory = build_error_observation_rows()
    expected = {
        (chain, child_height, block.block_hash)
        for block in load_error_blocks()
        for chain, child_height in block.observations
    }

    assert {
        (row["chain"], int(row["child_height"]), row["btc_header_hash"]) for row in rows
    } == expected
    assert inventory["rows"] == len(expected)


def test_display_order_witness_hashes_are_exported_in_internal_order() -> None:
    rows, _inventory = build_error_observation_rows()
    with (DATA_DIR / "error-blocks" / ERROR_OBSERVATION_LEDGER).open(
        newline=""
    ) as handle:
        ledger = list(csv.DictReader(handle))

    display_hashes = {
        hash_to_internal_hex(hash_from_display_hex(row["child_block_hash"]))
        for row in ledger
        if row["child_block_hash_order"] == "display"
    }
    rsk_hashes = {row["child_block_hash"] for row in rows if row["chain"] == "rsk"}

    assert len(display_hashes) == 5
    assert rsk_hashes == display_hashes


def test_error_observation_ledger_rejects_unmatched_child_header_hash(tmp_path) -> None:
    data_dir = tmp_path / "data"
    shutil.copytree(DATA_DIR / "error-blocks", data_dir / "error-blocks")
    ledger_path = data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER

    with ledger_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)

    assert fieldnames is not None
    next(row for row in rows if row["child_header_hex"])["child_block_hash"] = "00" * 32

    with ledger_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(
        ValueError, match="child_header_hex does not match child_block_hash"
    ):
        build_error_observation_rows(data_dir=data_dir)


def test_error_observation_ledger_derives_missing_child_hash_from_header(
    tmp_path,
) -> None:
    data_dir = tmp_path / "data"
    shutil.copytree(DATA_DIR / "error-blocks", data_dir / "error-blocks")
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

    with ledger_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

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
    shutil.copytree(DATA_DIR / "error-blocks", data_dir / "error-blocks")
    ledger_path = data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER

    with ledger_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)

    assert fieldnames is not None
    rows[0]["child_block_hash"] = ""
    rows[0]["child_header_hex"] = ""

    with ledger_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(
        ValueError, match="missing child_block_hash and child_header_hex"
    ):
        build_error_observation_rows(data_dir=data_dir)
