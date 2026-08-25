"""Tests for the fail-closed error-block witness export."""

from stale_blocks_analysis.error_observations import (
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
