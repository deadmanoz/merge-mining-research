from __future__ import annotations

import hashlib
import csv
import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "reports"))

from emit_auxpow_chainid_sidecar import (  # noqa: E402
    CAUXPOW_PARSE_ERRORS,
    infer_row,
    main as sidecar_main,
    parse_auxpow_tail_for_sidecar,
)
from extract_auxpow_from_blkdat import (  # noqa: E402
    CHAINS as BLKDAT_CHAINS,
    _deobfuscate,
    block_data_files,
    chain_scope_rejection,
    child_chain_id,
    parse_block,
    provisional_child_fields,
)

from stale_blocks_analysis.auxpow_chainid import (  # noqa: E402
    LEGACY_SINGLE_SLOT_UNVERIFIED,
    LEGACY_SINGLE_SLOT_VERIFIED,
    NON_POWER_OF_TWO_SIZE,
    ParentCommitment,
    SIZE_BRANCH_MISMATCH,
    SIZE_MATCHED,
    auxpow_lcg_index,
    candidate_chains_for_residue,
    commitment_from_embedded_scriptsig,
    commitment_size_status,
    fold_merkle_branch,
    hash_from_display_hex,
    hash_from_display_bytes,
    hash_from_header_bytes,
    hash_from_internal_bytes,
    hash_from_internal_hex,
    hash_to_display_hex,
    lcg_chain_id_residue,
    parent_commitment_for_proof,
    size_status_allows_inference,
)
from stale_blocks_analysis.coinbase_markers import parse_auxpow_marker  # noqa: E402


BTC_800000_HEADER_HEX = (
    "00601d3455bb9fbd966b3ea2dc42d0c22722e4c0c1729fad172101000000000000000000"
    "55087fab0c8f3f89f8bcfd4df26c504d81b0a88e04907161838c0c53001af09135edbd"
    "64943805175e955e06"
)
BTC_800000_DISPLAY_HASH = (
    "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"
)
BTC_800000_INTERNAL_HASH_HEX = (
    "54a02827d7a8b75601275a160279a3c5768de4c1c4a702000000000000000000"
)


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def test_hash_helpers_have_explicit_byte_order_for_btc_800000():
    raw_header = bytes.fromhex(BTC_800000_HEADER_HEX)
    expected_internal = bytes.fromhex(BTC_800000_INTERNAL_HASH_HEX)

    assert hash_from_header_bytes(raw_header) == expected_internal
    assert hash_from_display_hex(BTC_800000_DISPLAY_HASH) == expected_internal
    assert (
        hash_from_display_bytes(bytes.fromhex(BTC_800000_DISPLAY_HASH))
        == expected_internal
    )
    assert hash_from_internal_hex(BTC_800000_INTERNAL_HASH_HEX) == expected_internal
    assert hash_from_internal_bytes(expected_internal) == expected_internal
    assert hash_to_display_hex(expected_internal) == BTC_800000_DISPLAY_HASH

    # The display hash is not auto-detected as display-order by the internal
    # helper.  Callers must choose the convention explicitly.
    assert hash_from_internal_hex(BTC_800000_DISPLAY_HASH) != expected_internal


def test_blkdat_deobfuscation_round_trips_repeating_xor_key():
    raw = bytes(range(251)) * 3
    key = bytes.fromhex("7236e5a503d2dc27")

    encoded = _deobfuscate(raw, key)

    assert encoded != raw
    assert _deobfuscate(encoded, key) == raw


def test_blkdat_discovery_excludes_legacy_index_file(tmp_path: Path):
    expected = [tmp_path / "blk0001.dat", tmp_path / "blk0002.dat"]
    for path in [*expected, tmp_path / "blkindex.dat", tmp_path / "blocks.dat"]:
        path.touch()

    assert block_data_files(tmp_path) == expected


def test_ixcoin_blkdat_magic_matches_remote_archive_bytes():
    assert BLKDAT_CHAINS["ixcoin"]["magic"] == bytes.fromhex("f1bab6db")


def test_namecoin_blkdat_scope_enforces_consensus_chain_id():
    config = BLKDAT_CHAINS["namecoin"]
    namecoin_auxpow = (1 << 16) | 0x100 | 2

    assert config["magic"] == bytes.fromhex("f9beb4fe")
    assert config["auxpow_start"] == 19_200
    assert config["chain_id"] == 1
    assert config["enforce_chain_id"] is True
    assert chain_scope_rejection(namecoin_auxpow, config) is None
    assert chain_scope_rejection((2 << 16) | 0x100 | 2, config) == "chain_id_mismatch"


@pytest.mark.parametrize(
    ("chain", "magic", "auxpow_start", "chain_id", "auxpow_end"),
    [
        ("lyncoin", "52030e2f", 0, 0x0B0D, 260_499),
        ("sixeleven", "f9beb611", 19_200, 1, None),
    ],
)
def test_catalogued_chain_blkdat_parameters(
    chain: str,
    magic: str,
    auxpow_start: int,
    chain_id: int,
    auxpow_end: int | None,
):
    config = BLKDAT_CHAINS[chain]

    assert config["magic"] == bytes.fromhex(magic)
    assert config["auxpow_start"] == auxpow_start
    assert config["chain_id"] == chain_id
    assert config.get("auxpow_end") == auxpow_end
    assert config["enforce_chain_id"] is True


def test_catalogued_chain_version_scope_enforces_chain_id_and_flex_boundary():
    lyncoin = BLKDAT_CHAINS["lyncoin"]
    sixeleven = BLKDAT_CHAINS["sixeleven"]
    lyncoin_auxpow = (0x0B0D << 16) | 0x100 | 2
    lyncoin_flex = lyncoin_auxpow | 0x8000
    sixeleven_auxpow = (1 << 16) | 0x100 | 2

    assert child_chain_id(lyncoin_auxpow) == 0x0B0D
    assert chain_scope_rejection(lyncoin_auxpow, lyncoin) is None
    assert chain_scope_rejection(lyncoin_flex, lyncoin) == "excluded_version"
    assert chain_scope_rejection(sixeleven_auxpow, sixeleven) is None
    assert (
        chain_scope_rejection((2 << 16) | 0x100 | 2, sixeleven) == "chain_id_mismatch"
    )


def test_blkdat_child_hash_has_explicit_importer_compatible_byte_order():
    parsed = parse_block(bytes.fromhex(BTC_800000_HEADER_HEX))

    assert parsed is not None
    assert parsed["child_block_hash"] == BTC_800000_INTERNAL_HASH_HEX
    assert parsed["child_hash"] == BTC_800000_DISPLAY_HASH
    assert parsed["child_version"] == int.from_bytes(
        bytes.fromhex(BTC_800000_HEADER_HEX)[:4], "little", signed=True
    )

    provisional = provisional_child_fields(parsed, child_sequence=17)
    assert provisional == {
        "child_sequence": 17,
        "child_height": "",
        "child_block_hash": BTC_800000_INTERNAL_HASH_HEX,
        "child_block_hash_display": BTC_800000_DISPLAY_HASH,
        "child_header_hex": BTC_800000_HEADER_HEX,
        "child_version": parsed["child_version"],
        "child_chain_id": child_chain_id(parsed["child_version"]),
        "child_block_time": int.from_bytes(
            bytes.fromhex(BTC_800000_HEADER_HEX)[68:72], "little"
        ),
        "child_nbits": "17053894",
    }

    historical = provisional_child_fields(
        parsed,
        child_sequence=17,
        child_height_from_sequence=True,
    )
    assert historical["child_sequence"] == 17
    assert historical["child_height"] == 17


def test_offline_historical_chains_preserve_sequence_height_contract():
    assert BLKDAT_CHAINS["i0coin"]["child_height_from_sequence"] is True
    assert BLKDAT_CHAINS["coiledcoin"]["child_height_from_sequence"] is True
    assert "child_height_from_sequence" not in BLKDAT_CHAINS["lyncoin"]


def test_blast_blkdat_scope_accepts_both_consensus_chain_ids():
    blast = BLKDAT_CHAINS["blast"]
    launch = (0x1940 << 16) | 0x100 | 2
    rotated = (0x00A4 << 16) | 0x100 | 2

    assert blast["magic"] == bytes.fromhex("b3c4fda2")
    assert blast["auxpow_start"] == 1
    assert blast["chain_ids"] == (0x1940, 0x00A4)
    assert chain_scope_rejection(launch, blast) is None
    assert chain_scope_rejection(rotated, blast) is None
    assert chain_scope_rejection((0x00BA << 16) | 0x100 | 2, blast) == (
        "chain_id_mismatch"
    )


def test_census_join_uses_internal_order_hash_for_btc_800000():
    db = REPO_ROOT / "data" / "coinbase_mergemining_v1.db"
    if not db.exists():
        pytest.skip("coinbase_mergemining_v1.db not present")

    raw_header = bytes.fromhex(BTC_800000_HEADER_HEX)
    parent_internal = hash_from_header_bytes(raw_header)

    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT block_hash FROM coinbase_mergemining_v1 WHERE block_height = 800000"
        ).fetchone()

    assert row is not None
    assert bytes(row[0]) == parent_internal


@pytest.mark.parametrize("branch_len", [0, 1, 2, 3, 4, 7, 8])
def test_lcg_residue_round_trips(branch_len: int):
    nonce = 0x9F909FF0
    chain_id = 1638
    index = auxpow_lcg_index(nonce, chain_id, branch_len)
    residue = lcg_chain_id_residue(nonce, index, branch_len)
    assert residue == chain_id % (1 << branch_len)


def test_lcg_candidate_lookup_is_residue_filter_only():
    nonce = 0
    branch_len = 4
    index = auxpow_lcg_index(nonce, 1, branch_len)
    residue = lcg_chain_id_residue(nonce, index, branch_len)
    candidates = candidate_chains_for_residue(residue, branch_len)
    assert "namecoin" in {chain.slug for chain in candidates}
    assert all(chain.chain_id % (1 << branch_len) == residue for chain in candidates)


def test_commitment_size_statuses_gate_inference():
    assert commitment_size_status(0, 0) == LEGACY_SINGLE_SLOT_VERIFIED
    assert size_status_allows_inference(LEGACY_SINGLE_SLOT_VERIFIED)

    assert commitment_size_status(0, None) == LEGACY_SINGLE_SLOT_UNVERIFIED
    assert not size_status_allows_inference(LEGACY_SINGLE_SLOT_UNVERIFIED)

    assert commitment_size_status(4, 2) == SIZE_MATCHED
    assert size_status_allows_inference(SIZE_MATCHED)

    assert commitment_size_status(3, 2) == NON_POWER_OF_TWO_SIZE
    assert not size_status_allows_inference(NON_POWER_OF_TWO_SIZE)

    assert commitment_size_status(4, 1) == SIZE_BRANCH_MISMATCH
    assert not size_status_allows_inference(SIZE_BRANCH_MISMATCH)


def test_no_magic_embedded_coinbase_skips_inference():
    commitment = commitment_from_embedded_scriptsig(b"\x03abc/no-auxpow-here")
    assert commitment.source == "embedded_no_magic_unparsed"
    assert commitment.merkle_root is None
    assert commitment_size_status(commitment.merkle_size, 0) != SIZE_MATCHED


def test_embedded_auxpow_commitment_root_is_converted_to_internal_order():
    scriptsig = bytes.fromhex(
        "044b6d0b1a03c6de01522cfabe6d6d"
        "8d681259b58321d3fbe72bb4616301d1a0f6bec5562fe75fcbf0e0cf14f61c5a"
        "0100000000000000"
    )
    marker = parse_auxpow_marker(scriptsig)
    assert marker is not None

    commitment = commitment_from_embedded_scriptsig(scriptsig)

    assert commitment.merkle_root == marker.merkle_root[::-1]


def test_parent_commitment_prefers_census_over_embedded_marker():
    db = REPO_ROOT / "data" / "coinbase_mergemining_v1.db"
    if not db.exists():
        pytest.skip("coinbase_mergemining_v1.db not present")

    raw_header = bytes.fromhex(BTC_800000_HEADER_HEX)
    parent_internal = hash_from_header_bytes(raw_header)
    embedded = (
        b"\x03abc"
        + bytes.fromhex("fabe6d6d")
        + b"\x11" * 32
        + (1).to_bytes(4, "little")
        + (2).to_bytes(4, "little")
    )

    with sqlite3.connect(db) as conn:
        commitment = parent_commitment_for_proof(conn, parent_internal, embedded)

    # Height 800,000 has no AuxPoW marker in the census.  Because the parent is
    # canonical and present in the census, the embedded fallback is deliberately
    # not used.
    assert commitment.source == "census_no_auxpow"
    assert commitment.merkle_root is None


def test_parent_commitment_can_use_preloaded_census_mapping():
    raw_header = bytes.fromhex(BTC_800000_HEADER_HEX)
    parent_internal = hash_from_header_bytes(raw_header)
    expected = ParentCommitment(
        merkle_root=b"\x11" * 32,
        merkle_size=1,
        merkle_nonce=2,
        source="census",
    )

    commitment = parent_commitment_for_proof(
        {parent_internal: expected},
        parent_internal,
        b"\x03abc/no-auxpow-here",
    )

    assert commitment == expected


def test_merkle_folding_namecoin_single_slot_fixture():
    # First row in data/validated-stales/namecoin_validated_stales.csv.  The parent coinbase
    # scriptSig commits a single-slot AuxPoW tree.  The committed root is
    # serialized in display order and converted before merkle comparison.
    scriptsig = bytes.fromhex(
        "044b6d0b1a03c6de01522cfabe6d6d"
        "8d681259b58321d3fbe72bb4616301d1a0f6bec5562fe75fcbf0e0cf14f61c5a"
        "0100000000000000"
    )
    marker = parse_auxpow_marker(scriptsig)
    assert marker is not None
    assert marker.merkle_size == 1

    child_hash_internal = hash_from_display_bytes(marker.merkle_root)
    computed = fold_merkle_branch(child_hash_internal, [], 0)
    assert computed == hash_from_display_bytes(marker.merkle_root)


def test_merkle_folding_two_slot_branch_exercises_both_directions():
    leaf = bytes.fromhex("01" * 32)
    sibling = bytes.fromhex("02" * 32)

    assert fold_merkle_branch(leaf, [sibling], 0) == sha256d(leaf + sibling)
    assert fold_merkle_branch(leaf, [sibling], 1) == sha256d(sibling + leaf)


def test_merkle_folding_deeper_branch_matches_manual_tree_root():
    leaves = [bytes([i]) * 32 for i in range(1, 5)]
    left_root = sha256d(leaves[0] + leaves[1])
    right_root = sha256d(leaves[2] + leaves[3])
    root = sha256d(left_root + right_root)

    assert fold_merkle_branch(leaves[3], [leaves[2], left_root], 3) == root
    assert fold_merkle_branch(leaves[1], [leaves[0], right_root], 1) == root


def test_parse_auxpow_tail_for_sidecar_raises_typed_error_on_truncated_payload():
    with pytest.raises(CAUXPOW_PARSE_ERRORS):
        parse_auxpow_tail_for_sidecar(b"\x00" * 80)


def test_sidecar_cli_does_not_require_unshipped_census_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "emit_auxpow_chainid_sidecar.py",
            "--blocks-dir",
            str(tmp_path),
            "--output",
            str(tmp_path / "sidecar.csv"),
        ],
    )

    with pytest.raises(SystemExit, match=r"no blk\*\.dat files found"):
        sidecar_main()


def test_sidecar_chain_merkle_root_ok_is_empty_when_not_compared():
    auxpow = {
        "parent_header_raw": bytes.fromhex(BTC_800000_HEADER_HEX),
        "coinbase_tx": {
            "vin": [{"scriptsig": b"\x03abc/no-auxpow-here"}],
        },
        "chain_merkle_branch": [],
        "chain_index": 0,
    }

    row = infer_row(
        chain_slug="namecoin",
        child_sequence=1,
        child_header_raw=b"\x01" * 80,
        child_version=0x10100,
        auxpow=auxpow,
        census_conn=None,
    )

    assert row["commitment_source"] == "embedded_no_magic_unparsed"
    assert row["chain_merkle_root_ok"] == ""
    assert row["inference_status"] == "skip:embedded_no_magic_unparsed"
