from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from stale_blocks_analysis.auxpow_parse import ChildHeaderValidationError
from stale_blocks_analysis.auxpow_chainid import hash_from_header_bytes
from stale_blocks_analysis.full_evidence import (
    EVIDENCE_FIELDS,
    EvidenceSource,
    SourceStats,
    build_full_evidence_exports,
    discover_canonical_sources,
    discover_evidence_sources,
    discover_unknown_sources,
    hydrate_child_identity,
    load_child_identity,
    note_child_height_availability,
    normalize_evidence_row,
    safe_path,
    stale_descendant_parent_verdict_source,
    write_csv,
)

REPO = Path(__file__).resolve().parents[1]
P2PKH_SPK = bytes.fromhex("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f18")
P2PKH_SPK += bytes.fromhex("88ac")
EXCLUDED_HASH = "000000000000000010d43fb3f8d02cab156f333f2bfc172de9e6d87359118a1a"


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def test_write_csv_uses_lf_line_endings(tmp_path: Path) -> None:
    output = tmp_path / "evidence.csv"

    assert write_csv(output, [{"chain": "namecoin"}], ["chain"]) == 1
    assert output.read_bytes() == b"chain\nnamecoin\n"


def test_child_height_unavailable_note_depends_on_emitted_values() -> None:
    unavailable = SourceStats()
    note_child_height_availability(unavailable, [{"child_height": ""}])
    assert unavailable.notes == {"child_height=unavailable"}

    available = SourceStats()
    note_child_height_availability(available, [{"child_height": "42"}])
    assert not available.notes

    partial = SourceStats()
    note_child_height_availability(
        partial,
        [{"child_height": "42"}, {"child_height": ""}],
    )
    assert partial.notes == {"child_height=unavailable"}


def test_stale_btc_height_uses_legacy_bip34_height_fallback(tmp_path: Path) -> None:
    source = EvidenceSource(
        chain="namecoin",
        display_name="Namecoin",
        path=tmp_path / "source.csv",
        source_kind="full_inventory",
        artifact_scope="full_classifier_inventory",
        provenance="test",
    )
    row = {
        "btc_hash": "11" * 32,
        "btc_prev_hash": "22" * 32,
        "btc_bip34_height": "656478",
        "classification": "stale",
    }

    normalized, _errors = normalize_evidence_row(source, row, list(row), 2)

    assert normalized["btc_height"] == "656478"


@pytest.mark.parametrize("classification", ["canonical", "unknown"])
def test_non_stale_evidence_clears_stale_gate_annotations(
    tmp_path: Path, classification: str
) -> None:
    source = EvidenceSource(
        chain="elastos",
        display_name="Elastos",
        path=tmp_path / "elastos_canonical_blocks.csv",
        source_kind="canonical_blocks",
        artifact_scope="canonical_blocks",
        provenance="test",
    )
    row = {field: "" for field in EVIDENCE_FIELDS}
    row.update(
        {
            "btc_header_hash": "11" * 32,
            "classification": classification,
            "validation_status": "UNKNOWN",
            "expected_nbits": "170b8c8b",
            "rejection_reason": "legacy annotation",
        }
    )

    normalized, _errors = normalize_evidence_row(
        source, row, EVIDENCE_FIELDS, row_number=2
    )

    assert normalized["validation_status"] == ""
    assert normalized["expected_nbits"] == ""
    assert normalized["rejection_reason"] == ""


def test_normalized_evidence_preserves_original_source_metadata(tmp_path: Path) -> None:
    source = EvidenceSource(
        chain="namecoin",
        display_name="Namecoin",
        path=tmp_path / "namecoin_evidence.csv",
        source_kind="full_inventory",
        artifact_scope="full_classifier_inventory",
        provenance="archive",
    )
    row = {field: "" for field in EVIDENCE_FIELDS}
    row.update(
        {
            "chain": "namecoin",
            "source_kind": "validated_stales",
            "source_path": "data/validated-stales/argentum_validated_stales.csv",
            "source_row_number": "17",
            "artifact_scope": "stale_only_publication",
            "provenance": "repo-data",
            "btc_header_hash": "11" * 32,
            "classification": "stale",
        }
    )

    normalized, _errors = normalize_evidence_row(
        source, row, EVIDENCE_FIELDS, row_number=2
    )

    assert normalized["source_kind"] == "validated_stales"
    assert normalized["source_path"] == (
        "data/validated-stales/argentum_validated_stales.csv"
    )
    assert normalized["source_row_number"] == "17"
    assert normalized["artifact_scope"] == "stale_only_publication"
    assert normalized["provenance"] == "repo-data"

    row["source_path"] = str(
        tmp_path / "private" / "namecoin" / "classified" / "input.csv"
    )
    normalized, _errors = normalize_evidence_row(
        source, row, EVIDENCE_FIELDS, row_number=2
    )
    assert normalized["source_path"] == (
        "<chain-archive>/namecoin/classified/input.csv"
    )


def test_child_identity_requires_nonnegative_height(tmp_path: Path) -> None:
    btc_hash = "11" * 32
    identity_path = tmp_path / "child-identity" / "namecoin_child_identity.csv"
    _write_csv(
        identity_path,
        [
            {
                "chain": "namecoin",
                "btc_header_hash": btc_hash,
                "child_height": "",
                "child_block_hash": "22" * 32,
                "child_block_time": "1322540063",
                "verification": "auxpow_parent_match",
                "note": "",
            }
        ],
    )
    assert load_child_identity(tmp_path) == {}

    row = {
        "chain": "namecoin",
        "btc_header_hash": btc_hash,
        "child_height": "",
        "child_block_hash": "",
        "classification": "stale",
    }
    stats = hydrate_child_identity(
        [row],
        {
            ("namecoin", btc_hash): {
                "child_height": "",
                "child_block_hash": "22" * 32,
                "child_block_time": "1322540063",
            }
        },
    )
    assert stats.hydrated == 0
    assert stats.height_mismatch == 1
    assert row["child_block_hash"] == ""


def test_safe_path_resolves_repo_relative_inputs() -> None:
    assert safe_path(Path("data/example.csv")) == "data/example.csv"


def test_safe_path_preserves_repo_paths_through_symlinked_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from stale_blocks_analysis import evidence_normalization

    real_root = tmp_path / "repository"
    real_root.mkdir()
    linked_root = tmp_path / "linked-repository"
    linked_root.symlink_to(real_root, target_is_directory=True)
    monkeypatch.setattr(evidence_normalization, "PROJECT_ROOT", linked_root)

    assert (
        evidence_normalization.safe_path(Path("data/example.csv")) == "data/example.csv"
    )
    assert (
        evidence_normalization.safe_path(linked_root / "data" / "example.csv")
        == "data/example.csv"
    )


def test_safe_path_redacts_repo_local_archive_staging() -> None:
    assert (
        safe_path(
            Path("staging/chains/devcoin/classified/devcoin_stale_blocks.csv"),
            chain="devcoin",
        )
        == "<chain-archive>/devcoin/classified/devcoin_stale_blocks.csv"
    )


def test_safe_path_preserves_repo_paths_with_chain_named_directories() -> None:
    assert (
        safe_path(Path("node-infra/devcoin/README.md"), chain="devcoin")
        == "node-infra/devcoin/README.md"
    )


def test_safe_path_redacts_relative_paths_outside_repository() -> None:
    assert (
        safe_path(
            Path("../private-host/chains/devcoin/classified/input.csv"),
            chain="devcoin",
        )
        == "<chain-archive>/devcoin/classified/input.csv"
    )


def test_full_evidence_can_report_a_logical_output_directory(tmp_path: Path) -> None:
    summary = build_full_evidence_exports(
        data_dir=tmp_path / "data",
        output_dir=tmp_path / "staging",
        reported_output_dir=Path("/published/full-evidence"),
    )

    assert summary["output_dir"] == "<external>/full-evidence"
    assert summary["counts_csv"] == "<external>/auxpow-full-evidence-counts.csv"


def test_discovery_prefers_authoritative_doichain_full_inventory(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "archive"
    publication = archive / "doichain/classified/doichain_stale_blocks.csv"
    publication.parent.mkdir(parents=True)
    publication.write_text("classification\n")
    full_inventory = archive / "doichain/2026-06-24-redo/doichain_stale_blocks.csv"
    full_inventory.parent.mkdir(parents=True)
    full_inventory.write_text("classification\norphan\n")

    sources = discover_evidence_sources(tmp_path / "data", [archive])

    assert sources["doichain"].path == full_inventory
    assert sources["doichain"].source_kind == "full_inventory"


def test_namecoin_classifier_sources_declare_scan_order_height_untrusted(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "archive"
    classified = archive / "namecoin" / "classified"
    for suffix in ("stale_blocks", "unknown_blocks", "canonical_blocks"):
        _write_csv(
            classified / f"namecoin_{suffix}.csv",
            [
                {
                    "child_height": "19255",
                    "btc_hash": "11" * 32,
                    "classification": "canonical",
                }
            ],
        )

    primary = discover_evidence_sources(tmp_path / "data", [archive])["namecoin"]
    unknown = discover_unknown_sources(tmp_path / "data", [archive])["namecoin"]
    canonical = discover_canonical_sources(tmp_path / "data", [archive])["namecoin"]

    assert primary.child_height_semantics == "unauthenticated_scan_order"
    assert unknown.child_height_semantics == "unauthenticated_scan_order"
    assert canonical.child_height_semantics == "unauthenticated_scan_order"

    validated_data = tmp_path / "validated-data"
    _write_csv(
        validated_data / "validated-stales/namecoin_validated_stales.csv",
        [
            {
                "nmc_height": "207157",
                "btc_hash": "22" * 32,
                "classification": "stale",
            }
        ],
    )
    validated = discover_evidence_sources(validated_data)["namecoin"]
    assert validated.source_kind == "validated_stales"
    assert validated.child_height_semantics == "authenticated_consensus"


@pytest.mark.parametrize("chain", ("coiledcoin", "i0coin"))
def test_offline_classifier_sources_declare_scan_order_height_untrusted(
    tmp_path: Path,
    chain: str,
) -> None:
    archive = tmp_path / "archive"
    classified = archive / chain / "classified"
    for suffix in ("stale_blocks", "unknown_blocks", "canonical_blocks"):
        _write_csv(
            classified / f"{chain}_{suffix}.csv",
            [
                {
                    "child_height": "19255",
                    "btc_hash": "11" * 32,
                    "classification": "canonical",
                }
            ],
        )

    primary = discover_evidence_sources(tmp_path / "data", [archive])[chain]
    unknown = discover_unknown_sources(tmp_path / "data", [archive])[chain]
    canonical = discover_canonical_sources(tmp_path / "data", [archive])[chain]

    assert primary.child_height_semantics == "unauthenticated_scan_order"
    assert unknown.child_height_semantics == "unauthenticated_scan_order"
    assert canonical.child_height_semantics == "unauthenticated_scan_order"


def test_namecoin_scan_order_is_blank_before_verified_identity_hydration(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "archive"
    source_path = archive / "namecoin/classified/namecoin_stale_blocks.csv"
    btc_hash = "11" * 32
    row = {
        "child_height": "19255",
        "btc_hash": btc_hash,
        "classification": "orphan",
    }
    _write_csv(source_path, [row])
    source = discover_evidence_sources(tmp_path / "data", [archive])["namecoin"]

    normalized, _errors = normalize_evidence_row(source, row, list(row), 2)

    assert normalized["child_height"] == ""
    stats = hydrate_child_identity(
        [normalized],
        {
            ("namecoin", btc_hash): {
                "child_height": "207157",
                "child_block_hash": "22" * 32,
                "child_block_time": "1416990212",
            }
        },
    )
    assert stats.hydrated == 1
    assert stats.height_mismatch == 0
    assert normalized["child_height"] == "207157"
    assert normalized["child_block_hash"] == "22" * 32
    assert normalized["child_block_time"] == "1416990212"


def test_authenticated_child_height_is_never_overridden_by_identity(
    tmp_path: Path,
) -> None:
    btc_hash = "11" * 32
    source = EvidenceSource(
        chain="syscoin",
        display_name="Syscoin",
        path=tmp_path / "syscoin_stale_blocks.csv",
        source_kind="full_inventory",
        artifact_scope="full_classifier_inventory",
        provenance="test",
    )
    row = {
        "sys_height": "400",
        "btc_hash": btc_hash,
        "classification": "orphan",
    }
    normalized, _errors = normalize_evidence_row(source, row, list(row), 2)

    stats = hydrate_child_identity(
        [normalized],
        {
            ("syscoin", btc_hash): {
                "child_height": "999",
                "child_block_hash": "22" * 32,
                "child_block_time": "1562940120",
            }
        },
    )

    assert stats.hydrated == 0
    assert stats.height_mismatch == 1
    assert normalized["child_height"] == "400"
    assert normalized["child_block_hash"] == ""


def _header(prev_hash: str = "11" * 32) -> tuple[str, str]:
    raw = (
        (0x20000000).to_bytes(4, "little")
        + bytes.fromhex(prev_hash)[::-1]
        + b"\x22" * 32
        + (1_700_000_000).to_bytes(4, "little")
        + bytes.fromhex("ffff001d")
        + (42).to_bytes(4, "little")
    )
    display_hash = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
    return raw.hex(), display_hash


def test_serialized_parent_header_fills_every_missing_audit_field(
    tmp_path: Path,
) -> None:
    header_hex, header_hash = _header(prev_hash="11" * 32)
    source = EvidenceSource(
        chain="namecoin",
        display_name="Namecoin",
        path=tmp_path / "source.csv",
        source_kind="full_inventory",
        artifact_scope="full_classifier_inventory",
        provenance="test",
    )

    normalized, _errors = normalize_evidence_row(
        source,
        {"btc_header_hex": header_hex, "classification": "unknown"},
        ("btc_header_hex", "classification"),
        2,
    )

    assert normalized["btc_header_hash"] == header_hash
    assert normalized["btc_prev_hash"] == "11" * 32
    assert normalized["btc_time"] == "1700000000"
    assert normalized["btc_bits"] == "1d00ffff"
    assert normalized["btc_nonce"] == "42"


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("btc_header_hash", "ff" * 32),
        ("btc_prev_hash", "22" * 32),
        ("btc_time", "1700000001"),
        ("btc_bits", "1d00fffe"),
        ("btc_nonce", "43"),
    ],
)
def test_serialized_parent_header_rejects_populated_audit_disagreement(
    tmp_path: Path,
    field: str,
    wrong_value: str,
) -> None:
    header_hex, header_hash = _header(prev_hash="11" * 32)
    source = EvidenceSource(
        chain="namecoin",
        display_name="Namecoin",
        path=tmp_path / "source.csv",
        source_kind="full_inventory",
        artifact_scope="full_classifier_inventory",
        provenance="test",
    )
    row = {
        "btc_header_hash": header_hash,
        "btc_prev_hash": "11" * 32,
        "btc_time": "1700000000",
        "btc_bits": "1d00ffff",
        "btc_nonce": "42",
        "btc_header_hex": header_hex,
        "classification": "unknown",
    }
    row[field] = wrong_value

    with pytest.raises(
        ValueError,
        match=rf"namecoin evidence row 2: {field} disagrees with serialized",
    ):
        normalize_evidence_row(source, row, row.keys(), 2)


def _child_header(prev_hash: str = "33" * 32) -> tuple[str, str]:
    raw = (
        (0x20000000).to_bytes(4, "little")
        + bytes.fromhex(prev_hash)[::-1]
        + b"\x22" * 32
        + (1_700_000_000).to_bytes(4, "little")
        + bytes.fromhex("ffff001d")
        + (42).to_bytes(4, "little")
    )
    internal_hash = hashlib.sha256(hashlib.sha256(raw).digest()).digest().hex()
    return raw.hex(), internal_hash


def _child_fields(prev_hash: str = "33" * 32) -> dict[str, str]:
    header_hex, child_hash = _child_header(prev_hash)
    return {
        "child_block_hash": child_hash,
        "child_header_hex": header_hex,
        "child_block_time": "1700000000",
        "child_nbits": "1d00ffff",
    }


def _coinbase_tx() -> str:
    raw = (
        bytes.fromhex("01000000")
        + b"\x01"
        + b"\x00" * 32
        + bytes.fromhex("ffffffff")
        + b"\x03\xaa\xbb\xcc"
        + bytes.fromhex("ffffffff")
        + b"\x01"
        + (5000000000).to_bytes(8, "little")
        + bytes([len(P2PKH_SPK)])
        + P2PKH_SPK
        + bytes.fromhex("00000000")
    )
    return raw.hex()


@pytest.mark.parametrize(
    ("chain", "hash_field"),
    [
        ("devcoin", "devcoin_block_hash"),
        ("bitcoin-vault", "bitcoin-vault_block_hash"),
        ("bitcoin-vault", "bitcoin_vault_block_hash"),
        ("devcoin", "child_block_hash"),
        ("devcoin", "block_hash"),
    ],
)
def test_child_header_authentication_uses_every_supported_hash_alias(
    tmp_path: Path,
    chain: str,
    hash_field: str,
) -> None:
    child_header_hex, child_hash = _child_header()
    row = {
        hash_field: child_hash,
        "child_header_hex": child_header_hex,
        "child_block_time": "1700000000",
        "child_nbits": "1d00ffff",
    }
    source = EvidenceSource(
        chain=chain,
        display_name=chain,
        path=tmp_path / "source.csv",
        source_kind="classified_inventory",
        artifact_scope="full_historical",
        provenance="test",
    )

    normalized, _ = normalize_evidence_row(source, row, list(row), 2)

    assert normalized["child_block_hash"] == child_hash


def test_child_header_hash_alias_is_normalized_to_lowercase(tmp_path: Path) -> None:
    child_header_hex, child_hash = _child_header()
    row = {
        "devcoin_block_hash": child_hash.upper(),
        "child_header_hex": child_header_hex,
        "child_block_time": "1700000000",
        "child_nbits": "1d00ffff",
    }
    source = EvidenceSource(
        chain="devcoin",
        display_name="Devcoin",
        path=tmp_path / "source.csv",
        source_kind="classified_inventory",
        artifact_scope="full_historical",
        provenance="test",
    )

    normalized, _ = normalize_evidence_row(source, row, list(row), 2)

    assert normalized["child_block_hash"] == child_hash


def test_live_partial_child_identity_rejects_malformed_hash(tmp_path: Path) -> None:
    row = {
        "child_block_hash": "not-a-hash",
        "child_block_time": "1700000000",
    }
    source = EvidenceSource(
        chain="namecoin",
        display_name="Namecoin",
        path=tmp_path / "source.csv",
        source_kind="classified_inventory",
        artifact_scope="full_historical",
        provenance="test",
    )

    with pytest.raises(
        ChildHeaderValidationError,
        match="namecoin evidence row 2: child_block_hash must be exactly",
    ):
        normalize_evidence_row(source, row, list(row), 2)


def test_live_partial_child_identity_rejects_header_hash_mismatch(
    tmp_path: Path,
) -> None:
    child_header_hex, _child_hash = _child_header()
    row = {
        "child_block_hash": "11" * 32,
        "child_header_hex": child_header_hex,
    }
    source = EvidenceSource(
        chain="namecoin",
        display_name="Namecoin",
        path=tmp_path / "source.csv",
        source_kind="classified_inventory",
        artifact_scope="full_historical",
        provenance="test",
    )

    with pytest.raises(
        ChildHeaderValidationError,
        match="namecoin evidence row 2: child_header_hex does not match",
    ):
        normalize_evidence_row(source, row, list(row), 2)


def test_hathor_style_canonical_rows_are_exported(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    header_hex, header_hash = _header()
    _write_csv(
        data_dir / "hathor_stale_blocks.csv",
        [
            {
                "hathor_height": "100",
                "child_block_hash": hash_from_header_bytes(
                    bytes.fromhex(header_hex)
                ).hex(),
                "child_block_time": "1700000001",
                "btc_prev_hash": "11" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "btc_nonce": "42",
                "btc_header_hex": header_hex,
                "full_coinbase_hex": _coinbase_tx(),
                "btc_rpc_match": "true",
                "btc_header_hash": header_hash,
                "classification": "canonical",
                "btc_canonical_height": "800000",
                "btc_confirmations": "1",
                "btc_parent_height": "",
                "expected_nbits": "",
                "validation_status": "",
            }
        ],
    )

    summary = build_full_evidence_exports(data_dir=data_dir, output_dir=output_dir)

    rows = _read_csv(output_dir / "hathor_evidence.csv")
    assert rows[0]["classification"] == "canonical"
    assert rows[0]["btc_height"] == "800000"
    assert (
        rows[0]["child_block_hash"]
        == hash_from_header_bytes(bytes.fromhex(header_hex)).hex()
    )
    assert rows[0]["child_block_time"] == "1700000001"
    assert rows[0]["coinbase_scriptsig_hex"] == "aabbcc"
    assert (
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa:5000000000" in rows[0]["coinbase_outputs"]
    )

    manifest = _read_csv(output_dir / "auxpow-full-evidence-manifest.csv")
    hathor = next(row for row in manifest if row["chain"] == "hathor")
    assert hathor["canonical"] == "1"
    assert hathor["canonical_evidence_status"] == "canonical_retained"
    assert summary["status_counts"]["canonical_retained"] == 1


def test_hathor_child_hash_must_match_reconstructed_header(tmp_path: Path) -> None:
    source = EvidenceSource(
        chain="hathor",
        display_name="Hathor",
        path=tmp_path / "hathor_stale_blocks.csv",
        source_kind="full_inventory",
        artifact_scope="full_classifier_inventory",
        provenance="test",
    )
    header_hex, _header_hash = _header()
    row = {
        "btc_header_hex": header_hex,
        "child_block_hash": "aa" * 32,
        "classification": "canonical",
    }

    with pytest.raises(
        ChildHeaderValidationError,
        match="hathor evidence row 2: child_block_hash does not match",
    ):
        normalize_evidence_row(source, row, list(row), 2)


def test_validated_stales_are_marked_as_stale_only_publication(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    header_hex, header_hash = _header()
    _write_csv(
        data_dir / "validated-stales" / "namecoin_validated_stales.csv",
        [
            {
                "btc_stale_height": "150000",
                "btc_hash": header_hash,
                "btc_prev_hash": "11" * 32,
                "btc_time": "1700000000",
                "btc_bits_hex": "1d00ffff",
                "coinbase_scriptsig_hex": "abcd",
                "coinbase_outputs": "76a91400",
                "btc_header_hex": header_hex,
                "nmc_height": "200",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            }
        ],
    )

    build_full_evidence_exports(data_dir=data_dir, output_dir=output_dir)

    rows = _read_csv(output_dir / "namecoin_evidence.csv")
    assert rows[0]["artifact_scope"] == "stale_only_publication"
    assert rows[0]["classification"] == "stale"

    manifest = _read_csv(output_dir / "auxpow-full-evidence-manifest.csv")
    namecoin = next(row for row in manifest if row["chain"] == "namecoin")
    assert namecoin["stale"] == "1"
    assert (
        namecoin["canonical_evidence_status"]
        == "canonical_rows_not_represented_stale_only_publication_path"
    )


def test_child_header_fields_survive_full_evidence_normalization(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    btc_header_hex, btc_header_hash = _header()
    child_header_hex, child_hash_internal = _child_header()
    _write_csv(
        data_dir / "validated-stales" / "devcoin_validated_stales.csv",
        [
            {
                "btc_height": "500000",
                "btc_header_hash": btc_header_hash,
                "btc_prev_hash": "11" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "coinbase_scriptsig_hex": "abcd",
                "coinbase_outputs": "76a91400",
                "btc_header_hex": btc_header_hex,
                "dvc_height": "300000",
                "child_block_hash": child_hash_internal,
                "child_header_hex": child_header_hex,
                "child_block_time": "1700000000",
                "child_nbits": "1d00ffff",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            }
        ],
    )

    build_full_evidence_exports(data_dir=data_dir, output_dir=output_dir)

    row = _read_csv(output_dir / "devcoin_evidence.csv")[0]
    assert row["child_block_hash"] == child_hash_internal
    assert row["child_header_hex"] == child_header_hex
    assert row["child_block_time"] == "1700000000"
    assert row["child_nbits"] == "1d00ffff"


def test_target_child_header_contradiction_stops_full_evidence_export(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    btc_header_hex, btc_header_hash = _header()
    child_header_hex, _child_hash_internal = _child_header()
    _write_csv(
        data_dir / "validated-stales" / "devcoin_validated_stales.csv",
        [
            {
                "btc_height": "500000",
                "btc_header_hash": btc_header_hash,
                "btc_header_hex": btc_header_hex,
                "dvc_height": "300000",
                "child_block_hash": "00" * 32,
                "child_header_hex": child_header_hex,
                "child_block_time": "1700000000",
                "child_nbits": "1d00ffff",
                "classification": "stale",
                "validation_status": "VALID",
            }
        ],
    )

    with pytest.raises(ChildHeaderValidationError, match="devcoin evidence row 2"):
        build_full_evidence_exports(data_dir=data_dir, output_dir=output_dir)


def test_target_partial_child_header_bundle_stops_full_evidence_export(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    btc_header_hex, btc_header_hash = _header()
    _write_csv(
        data_dir / "validated-stales" / "devcoin_validated_stales.csv",
        [
            {
                "btc_height": "500000",
                "btc_header_hash": btc_header_hash,
                "btc_header_hex": btc_header_hex,
                "dvc_height": "300000",
                "child_block_hash": "11" * 32,
                "classification": "stale",
                "validation_status": "VALID",
            }
        ],
    )

    with pytest.raises(
        ChildHeaderValidationError,
        match=(
            "devcoin evidence row 2: historical source requires regeneration "
            "with a complete child header bundle; incomplete child header evidence"
        ),
    ):
        build_full_evidence_exports(data_dir=data_dir, output_dir=output_dir)


def test_target_empty_child_header_bundle_stops_full_evidence_export(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    btc_header_hex, btc_header_hash = _header()
    _write_csv(
        data_dir / "validated-stales" / "devcoin_validated_stales.csv",
        [
            {
                "btc_height": "500000",
                "btc_header_hash": btc_header_hash,
                "btc_header_hex": btc_header_hex,
                "dvc_height": "300000",
                "classification": "stale",
                "validation_status": "VALID",
            }
        ],
    )

    with pytest.raises(
        ChildHeaderValidationError,
        match=(
            "devcoin evidence row 2: historical source requires regeneration "
            "with a complete child header bundle; incomplete child header evidence"
        ),
    ):
        build_full_evidence_exports(data_dir=data_dir, output_dir=output_dir)


def test_archive_full_inventory_overrides_repo_validated_file(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    archive_dir = tmp_path / "archive"
    output_dir = tmp_path / "out"
    header_hex, header_hash = _header()
    _write_csv(
        data_dir / "validated-stales" / "devcoin_validated_stales.csv",
        [
            {
                "btc_height": "1",
                "btc_header_hash": "aa" * 32,
                "btc_prev_hash": "bb" * 32,
                "btc_time": "1",
                "btc_bits": "1d00ffff",
                "coinbase_scriptsig_hex": "stale",
                "coinbase_outputs": "",
                "btc_header_hex": "",
                "dvc_height": "1",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            }
        ],
    )
    _write_csv(
        archive_dir / "chains" / "devcoin" / "classified" / "devcoin_stale_blocks.csv",
        [
            {
                **_child_fields(),
                "btc_height": "700000",
                "btc_header_hash": header_hash,
                "btc_prev_hash": "11" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "coinbase_scriptsig_hex": "canonical",
                "coinbase_outputs": "out",
                "btc_header_hex": header_hex,
                "dvc_height": "300",
                "classification": "canonical",
                "validation_status": "",
                "expected_nbits": "",
            }
        ],
    )

    build_full_evidence_exports(
        data_dir=data_dir,
        output_dir=output_dir,
        chain_archive_dirs=[archive_dir],
    )

    rows = _read_csv(output_dir / "devcoin_evidence.csv")
    assert rows[0]["classification"] == "canonical"
    assert rows[0]["source_path"].endswith(
        "devcoin/classified/devcoin_stale_blocks.csv"
    )

    manifest = _read_csv(output_dir / "auxpow-full-evidence-manifest.csv")
    devcoin = next(row for row in manifest if row["chain"] == "devcoin")
    assert devcoin["source_kind"] == "full_inventory"
    assert devcoin["canonical"] == "1"
    assert devcoin["stale"] == "0"


def test_archive_full_inventory_applies_consensus_exclusion_overlay(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    archive_dir = tmp_path / "archive"
    output_dir = tmp_path / "out"
    _write_csv(
        archive_dir / "chains" / "devcoin" / "classified" / "devcoin_stale_blocks.csv",
        [
            {
                **_child_fields(),
                "btc_height": "331735",
                "btc_header_hash": EXCLUDED_HASH,
                "btc_prev_hash": "11" * 32,
                "classification": "stale",
                "validation_status": "VALID",
            }
        ],
    )

    build_full_evidence_exports(
        data_dir=data_dir,
        output_dir=output_dir,
        chain_archive_dirs=[archive_dir],
    )

    assert _read_csv(output_dir / "devcoin_evidence.csv") == []
    manifest = _read_csv(output_dir / "auxpow-full-evidence-manifest.csv")
    devcoin = next(row for row in manifest if row["chain"] == "devcoin")
    assert devcoin["source_rows"] == "0"
    assert "publication_exclusions=1" in devcoin["notes"]


def test_stale_descendant_parent_verdicts_get_own_artifact(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    header_hex, header_hash = _header()
    _write_csv(
        data_dir / "stale_descendants.csv",
        [
            {
                "classification": "stale_descendant",
                "ancestry_relation": "direct_stale_child",
                "validation_status": "VALID_STALE_DESCENDANT",
                "active_mainchain_status": "verified_not_active",
                "active_mainchain_hash_at_height": "aa" * 32,
                "root_active_mainchain_status": "verified_not_active",
                "root_active_mainchain_hash_at_height": "cc" * 32,
                "active_mainchain_verification_source": "bitcoin-core-rpc:test",
                "btc_height": "800001",
                "btc_header_hash": header_hash,
                "btc_prev_hash": "11" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "expected_nbits": "1d00ffff",
                "coinbase_scriptsig_hex": "abcd",
                "coinbase_outputs": "out",
                "btc_header_hex": header_hex,
                "observed_chains": "namecoin",
                "source_observation_count": "1",
                "root_stale_hash": "11" * 32,
                "root_stale_height": "800000",
                "stale_fork_depth": "1",
                "path_hashes": f"{header_hash}>{'11' * 32}",
            }
        ],
    )
    source = stale_descendant_parent_verdict_source(data_dir)
    assert source is not None
    assert source.child_height_semantics == "not_applicable"

    build_full_evidence_exports(data_dir=data_dir, output_dir=output_dir)

    rows = _read_csv(output_dir / "stale-descendants_evidence.csv")
    assert rows[0]["classification"] == "stale_descendant"
    assert rows[0]["child_height"] == ""
    assert rows[0]["child_block_hash"] == ""
    assert rows[0]["child_header_hex"] == ""
    assert rows[0]["child_block_time"] == ""
    assert rows[0]["child_nbits"] == ""

    manifest_json = json.loads(
        (output_dir / "auxpow-full-evidence-manifest.json").read_text()
    )
    parent_verdicts = next(
        row for row in manifest_json["counts"] if row["chain"] == "stale-descendants"
    )
    assert parent_verdicts["source_kind"] == "stale_descendant_parent_verdicts"
    assert parent_verdicts["artifact_scope"] == "stale_descendant_parent_verdicts"
    assert parent_verdicts["stale_descendant"] == 1


def test_stale_descendant_parent_projection_rejects_weak_parent_row(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    with (REPO / "data/stale_descendants.csv").open(newline="") as handle:
        parent = next(csv.DictReader(handle))
    parent["active_mainchain_status"] = "unverified"
    _write_csv(data_dir / "stale_descendants.csv", [parent])

    with pytest.raises(ValueError, match="parent lacks the active-mainchain gate"):
        build_full_evidence_exports(data_dir=data_dir, output_dir=output_dir)
