from __future__ import annotations

import csv
import hashlib
from pathlib import Path

import pytest

from stale_blocks_analysis.reconciled_error_blocks import (
    IDENTITY_FIELDS,
    LEDGER_FIELDS,
    build_reconciled_import,
    merge_ledger_rows,
    write_ledger,
)


PARENT_HASH = "11" * 32
PREV_HASH = "22" * 32
CHILD_HEADER_BYTES = (
    bytes.fromhex("01000000")
    + bytes(64)
    + (1234).to_bytes(4, "little")
    + int("1d00ffff", 16).to_bytes(4, "little")
    + bytes(4)
)
CHILD_HEADER_HEX = CHILD_HEADER_BYTES.hex()
CHILD_HASH = hashlib.sha256(hashlib.sha256(CHILD_HEADER_BYTES).digest()).digest().hex()


def _write_csv(path: Path, fieldnames: tuple[str, ...] | list[str], rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _fixture(
    tmp_path: Path,
    *,
    source_btc_height: str = "101",
    source_classification: str = "orphan",
    source_token: str = "namecoin:data/namecoin_stale_blocks.csv:2",
    duplicate_source_row: bool = False,
) -> tuple[Path, Path, Path]:
    data_dir = tmp_path / "data"
    source = data_dir / "namecoin_stale_blocks.csv"
    _write_csv(
        source,
        [
            "btc_bip34_height",
            "btc_hash",
            "btc_prev_hash",
            "nmc_height",
            "classification",
            "coinbase_scriptsig_hex",
            "btc_header_hex",
        ],
        [
            {
                "btc_bip34_height": source_btc_height,
                "btc_hash": PARENT_HASH,
                "btc_prev_hash": PREV_HASH,
                "nmc_height": "200",
                "classification": source_classification,
                "coinbase_scriptsig_hex": "0165",
                "btc_header_hex": "00" * 80,
            }
        ]
        * (2 if duplicate_source_row else 1),
    )
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    identity = data_dir / "error-blocks" / "reconciled_child_identities.csv"
    _write_csv(
        identity,
        IDENTITY_FIELDS,
        [
            {
                "btc_height": "100",
                "btc_header_hash": PARENT_HASH,
                "chain": "namecoin",
                "child_height": "200",
                "child_block_hash": CHILD_HASH,
                "child_block_hash_order": "internal",
                "child_header_hex": CHILD_HEADER_HEX,
                "child_block_time": "1234",
                "child_nbits": "1d00ffff",
                "source_path": "data/namecoin_stale_blocks.csv",
                "source_row_number": "2",
                "source_sha256": source_sha256,
                "source_classification": "orphan",
                "identity_provenance": "node-verified-rpc:namecoin",
            }
        ],
    )
    peer = data_dir / "stale_descendants_error_blocks.csv"
    peer_row = {
        "classification": "error_block",
        "validation_status": "REJECTED_bip34_height_mismatch",
        "btc_height": "100",
        "btc_header_hash": PARENT_HASH,
        "btc_prev_hash": PREV_HASH,
        "expected_nbits": "1d00ffff",
        "btc_header_hex": "00" * 80,
        "observed_btc_heights": "101",
        "observed_chains": "namecoin",
        "source_rows": source_token,
        "coinbase_scriptsig_hex": "0165",
        "rules_violated": "bip34_coinbase_height_mismatch",
    }
    _write_csv(peer, list(peer_row), [peer_row])
    return data_dir, peer, identity


def _update_first_row(path: Path, **updates: str) -> None:
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or ())
        rows = list(reader)
    rows[0].update(updates)
    _write_csv(path, fieldnames, rows)


def test_build_reconciled_import_authenticates_source_and_height_semantics(
    tmp_path: Path,
) -> None:
    data_dir, peer, identity = _fixture(tmp_path)

    imported = build_reconciled_import(
        peer_path=peer, identity_path=identity, data_dir=data_dir
    )

    assert len(imported.catalogue_rows) == 1
    assert len(imported.ledger_rows) == 1
    parent = imported.catalogue_rows[0]
    assert parent["height"] == "100"
    assert parent["coinbase_height"] == "101"
    assert parent["source_child_observations"] == "namecoin:200"
    assert parent["first_observed_child_time"] == "1234"
    witness = imported.ledger_rows[0]
    assert witness["source_btc_height"] == "101"
    assert (
        witness["source_sha256"]
        == hashlib.sha256(
            (data_dir / "namecoin_stale_blocks.csv").read_bytes()
        ).hexdigest()
    )


@pytest.mark.parametrize(
    ("source_btc_height", "source_classification", "message"),
    [
        ("102", "orphan", "encoded coinbase height"),
        ("101", "canonical", "source classification"),
    ],
)
def test_build_reconciled_import_rejects_wrong_source_bucket_or_height(
    tmp_path: Path,
    source_btc_height: str,
    source_classification: str,
    message: str,
) -> None:
    data_dir, peer, identity = _fixture(
        tmp_path,
        source_btc_height=source_btc_height,
        source_classification=source_classification,
    )

    with pytest.raises(ValueError, match=message):
        build_reconciled_import(
            peer_path=peer, identity_path=identity, data_dir=data_dir
        )


def test_build_reconciled_import_rejects_unpinned_source_bytes(tmp_path: Path) -> None:
    data_dir, peer, identity = _fixture(tmp_path)
    source = data_dir / "namecoin_stale_blocks.csv"
    source.write_text(source.read_text() + "\n")

    with pytest.raises(ValueError, match="sha256"):
        build_reconciled_import(
            peer_path=peer, identity_path=identity, data_dir=data_dir
        )


def test_build_reconciled_import_rejects_tampered_peer_coinbase_scriptsig(
    tmp_path: Path,
) -> None:
    data_dir, peer, identity = _fixture(tmp_path)
    _update_first_row(peer, coinbase_scriptsig_hex="0166")

    with pytest.raises(ValueError, match="coinbase_scriptsig_hex disagrees"):
        build_reconciled_import(
            peer_path=peer, identity_path=identity, data_dir=data_dir
        )


def test_build_reconciled_import_rejects_missing_source_coinbase_scriptsig(
    tmp_path: Path,
) -> None:
    data_dir, peer, identity = _fixture(tmp_path)
    _update_first_row(data_dir / "namecoin_stale_blocks.csv", coinbase_scriptsig_hex="")

    with pytest.raises(ValueError, match="missing coinbase_scriptsig_hex"):
        build_reconciled_import(
            peer_path=peer, identity_path=identity, data_dir=data_dir
        )


def test_build_reconciled_import_rejects_tampered_peer_header_when_source_has_it(
    tmp_path: Path,
) -> None:
    data_dir, peer, identity = _fixture(tmp_path)
    _update_first_row(peer, btc_header_hex="01" + "00" * 79)

    with pytest.raises(ValueError, match="source btc_header_hex disagrees"):
        build_reconciled_import(
            peer_path=peer, identity_path=identity, data_dir=data_dir
        )


def test_build_reconciled_import_rejects_source_path_escape(tmp_path: Path) -> None:
    data_dir, peer, identity = _fixture(
        tmp_path, source_token="namecoin:data/../outside.csv:2"
    )

    with pytest.raises(ValueError, match="escapes data"):
        build_reconciled_import(
            peer_path=peer, identity_path=identity, data_dir=data_dir
        )


def test_build_reconciled_import_rejects_same_source_payload_at_alternate_path(
    tmp_path: Path,
) -> None:
    data_dir, peer, identity = _fixture(tmp_path)
    source = data_dir / "namecoin_stale_blocks.csv"
    alternate = data_dir / "alternate_namecoin_stale_blocks.csv"
    alternate.write_bytes(source.read_bytes())
    _update_first_row(
        peer,
        source_rows="namecoin:data/alternate_namecoin_stale_blocks.csv:2",
    )

    with pytest.raises(ValueError, match="source path .* identity manifest"):
        build_reconciled_import(
            peer_path=peer, identity_path=identity, data_dir=data_dir
        )


def test_build_reconciled_import_rejects_matching_duplicate_source_row(
    tmp_path: Path,
) -> None:
    data_dir, peer, identity = _fixture(
        tmp_path,
        duplicate_source_row=True,
        source_token="namecoin:data/namecoin_stale_blocks.csv:3",
    )

    with pytest.raises(ValueError, match="source row .* identity manifest"):
        build_reconciled_import(
            peer_path=peer, identity_path=identity, data_dir=data_dir
        )


@pytest.mark.parametrize("field", ["child_header_hex", "child_nbits"])
def test_build_reconciled_import_requires_complete_child_header_identity(
    tmp_path: Path, field: str
) -> None:
    data_dir, peer, identity = _fixture(tmp_path)
    _update_first_row(identity, **{field: ""})

    with pytest.raises(ValueError, match=f"missing {field}"):
        build_reconciled_import(
            peer_path=peer, identity_path=identity, data_dir=data_dir
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "child_header_hex",
            CHILD_HEADER_HEX[:8] + "01" + CHILD_HEADER_HEX[10:],
            "child_header_hex does not match",
        ),
        ("child_block_hash", "33" * 32, "child_header_hex does not match"),
        ("child_block_time", "1235", "child_header_hex does not match"),
        ("child_nbits", "1d00fffe", "child header does not match child_nbits"),
    ],
)
def test_build_reconciled_import_rederives_child_identity_from_header(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    data_dir, peer, identity = _fixture(tmp_path)
    _update_first_row(identity, **{field: value})

    with pytest.raises(ValueError, match=message):
        build_reconciled_import(
            peer_path=peer, identity_path=identity, data_dir=data_dir
        )


def test_build_reconciled_import_rejects_cross_chain_identity_provenance(
    tmp_path: Path,
) -> None:
    data_dir, peer, identity = _fixture(tmp_path)
    _update_first_row(identity, identity_provenance="node-verified-rpc:devcoin")

    with pytest.raises(ValueError, match="malformed source authentication"):
        build_reconciled_import(
            peer_path=peer, identity_path=identity, data_dir=data_dir
        )


def test_merge_ledger_rows_is_idempotent_after_catalogue_number_refresh(
    tmp_path: Path,
) -> None:
    data_dir, peer, identity = _fixture(tmp_path)
    imported = build_reconciled_import(
        peer_path=peer, identity_path=identity, data_dir=data_dir
    )
    ledger_path = data_dir / "error-blocks" / "error_block_observations.csv"
    existing = {**imported.ledger_rows[0], "catalogue_row_number": "999"}
    _write_csv(ledger_path, LEDGER_FIELDS, [existing])
    catalogue = [{"height": "100", "hash": PARENT_HASH}]

    first = merge_ledger_rows(
        ledger_path=ledger_path,
        imported_rows=imported.ledger_rows,
        catalogue_rows=catalogue,
    )
    write_ledger(first, ledger_path)
    second = merge_ledger_rows(
        ledger_path=ledger_path,
        imported_rows=imported.ledger_rows,
        catalogue_rows=catalogue,
    )

    assert first == second
    assert second[0]["catalogue_row_number"] == "2"
