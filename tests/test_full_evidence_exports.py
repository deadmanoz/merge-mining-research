from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from stale_blocks_analysis.full_evidence import build_full_evidence_exports


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


def _header(prev_hash: str = "11" * 32) -> tuple[str, str]:
    raw = (
        (0x20000000).to_bytes(4, "little")
        + bytes.fromhex(prev_hash)[::-1]
        + b"\x22" * 32
        + (1_700_000_000).to_bytes(4, "little")
        + bytes.fromhex("ffff001d")[::-1]
        + (42).to_bytes(4, "little")
    )
    display_hash = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
    return raw.hex(), display_hash


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


def test_hathor_style_canonical_rows_are_exported(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    header_hex, header_hash = _header()
    _write_csv(
        data_dir / "hathor_stale_blocks.csv",
        [
            {
                "hathor_height": "100",
                "hathor_block_hash": "aa" * 32,
                "hathor_timestamp": "1700000001",
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
    assert rows[0]["coinbase_scriptsig_hex"] == "aabbcc"
    assert (
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa:5000000000" in rows[0]["coinbase_outputs"]
    )

    manifest = _read_csv(output_dir / "auxpow-full-evidence-manifest.csv")
    hathor = next(row for row in manifest if row["chain"] == "hathor")
    assert hathor["canonical"] == "1"
    assert hathor["canonical_evidence_status"] == "canonical_retained"
    assert summary["status_counts"]["canonical_retained"] == 1


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


def test_stale_descendant_sidecar_gets_own_artifact(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    header_hex, header_hash = _header()
    _write_csv(
        data_dir / "stale_descendants.csv",
        [
            {
                "classification": "stale_descendant",
                "promotion_subclass": "direct_stale_child",
                "validation_status": "VALID_STALE_DESCENDANT",
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
            }
        ],
    )

    build_full_evidence_exports(data_dir=data_dir, output_dir=output_dir)

    rows = _read_csv(output_dir / "stale-descendants_evidence.csv")
    assert rows[0]["classification"] == "stale_descendant"

    manifest_json = json.loads(
        (output_dir / "auxpow-full-evidence-manifest.json").read_text()
    )
    sidecar = next(
        row for row in manifest_json["counts"] if row["chain"] == "stale-descendants"
    )
    assert sidecar["stale_descendant"] == 1


def _monitor_fixture_rows(
    header_hexes: dict[str, tuple[str, str]],
) -> list[dict[str, str]]:
    """Full-inventory rows spanning every evidence state, keyed by label."""
    rows = []
    for label, (header_hex, header_hash) in header_hexes.items():
        classification, status = {
            "canonical": ("canonical", ""),
            "stale": ("stale", "VALID"),
            "rejected_stale": ("stale", "REJECTED: nBits mismatch"),
            "orphan_strict": ("unknown", ""),
            # legacy spelling on purpose: readers must normalize "orphan"
            "orphan_weak": ("orphan", ""),
            "orphan_excluded": ("unknown", ""),
            "near": ("near", ""),
        }[label]
        rows.append(
            {
                "btc_height": "800000",
                "btc_header_hash": header_hash,
                "btc_prev_hash": "11" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "btc_header_hex": header_hex,
                "coinbase_scriptsig_hex": "abcd",
                "coinbase_outputs": "76a91400",
                "nmc_height": "200",
                "classification": classification,
                "validation_status": status,
                "expected_nbits": "1d00ffff",
            }
        )
    return rows


def test_monitor_export_keeps_only_final_categories(tmp_path: Path) -> None:
    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    headers = {
        label: _header(prev_hash=f"{i:02x}" * 32)
        for i, label in enumerate(
            [
                "canonical",
                "stale",
                "rejected_stale",
                "orphan_strict",
                "orphan_weak",
                "orphan_excluded",
                "near",
            ],
            start=1,
        )
    }
    _write_csv(data_dir / "namecoin_stale_blocks.csv", _monitor_fixture_rows(headers))
    inventory = tmp_path / "inventory.csv"
    _write_csv(
        inventory,
        [
            {
                "btc_header_hash": headers["orphan_strict"][1],
                "btc_stale_relevance": "strict_btc_orphan",
                "relevance_reason": "strict_height_nbits_match",
            },
            {
                "btc_header_hash": headers["orphan_weak"][1],
                "btc_stale_relevance": "weak_btc_orphan",
                "relevance_reason": "timestamp_epoch_nbits_match",
            },
            {
                "btc_header_hash": headers["orphan_excluded"][1],
                "btc_stale_relevance": "excluded",
                "relevance_reason": "non_btc_epoch_bits",
            },
        ],
    )

    summary = build_monitor_evidence_exports(
        data_dir=data_dir, output_dir=output_dir, relevance_inventory=inventory
    )

    rows = _read_csv(output_dir / "namecoin_monitor_evidence.csv")
    by_hash = {row["btc_header_hash"]: row for row in rows}
    by_relevance = {row["btc_stale_relevance"]: row for row in rows}
    assert len(rows) == 4
    assert by_hash[headers["canonical"][1]]["btc_stale_relevance"] == ""
    assert by_hash[headers["canonical"][1]]["classification"] == "canonical"
    # confirmed stales/descendants also carry an empty derived relevance now
    # (the confirmation lives on the primary `classification` axis instead),
    # so they are distinguished by header hash, not by `btc_stale_relevance`.
    assert by_hash[headers["stale"][1]]["btc_stale_relevance"] == ""
    assert by_hash[headers["stale"][1]]["classification"] == "stale"
    assert by_hash[headers["stale"][1]]["relevance_reason"] == "valid_direct_stale"
    assert by_relevance["strict_btc_orphan"]["classification"] == "unknown"
    # the weak row was written with the legacy "orphan" spelling; the export
    # must normalize it to "unknown"
    assert by_relevance["weak_btc_orphan"]["classification"] == "unknown"
    exported_hashes = {row["btc_header_hash"] for row in rows}
    assert headers["rejected_stale"][1] not in exported_hashes
    assert headers["orphan_excluded"][1] not in exported_hashes
    assert headers["near"][1] not in exported_hashes

    counts = _read_csv(output_dir / "monitor-evidence-counts.csv")
    namecoin = next(row for row in counts if row["chain"] == "namecoin")
    assert namecoin["canonical"] == "1"
    assert namecoin["stale"] == "1"
    assert namecoin["strict_btc_orphan"] == "1"
    assert namecoin["weak_btc_orphan"] == "1"
    assert namecoin["monitor_rows"] == "4"
    assert summary["strict_weak_verdicts_loaded"] == 2


def test_monitor_export_skip_canonical_excludes_in_file_and_companion_rows(
    tmp_path: Path,
) -> None:
    # include_canonical=False is the committed --skip-canonical configuration
    # that produces the results/monitor-evidence/ CSVs. Every other monitor
    # test uses the default True path, so this pins the compact one: no
    # canonical rows survive, and the canonical-parent companion file is not
    # even discovered/merged.
    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    headers = {
        label: _header(prev_hash=f"{i:02x}" * 32)
        for i, label in enumerate(["canonical", "stale"], start=1)
    }
    _write_csv(data_dir / "namecoin_stale_blocks.csv", _monitor_fixture_rows(headers))
    companion_hex, companion_hash = _header(prev_hash="ee" * 32)
    _write_csv(
        data_dir / "namecoin_canonical_blocks.csv",
        [
            {
                "btc_height": "800001",
                "btc_header_hash": companion_hash,
                "btc_prev_hash": "ee" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "btc_header_hex": companion_hex,
                "nmc_height": "201",
                "classification": "canonical",
                "validation_status": "",
                "expected_nbits": "1d00ffff",
            }
        ],
    )

    build_monitor_evidence_exports(
        data_dir=data_dir,
        output_dir=output_dir,
        relevance_inventory=None,
        include_canonical=False,
    )

    rows = _read_csv(output_dir / "namecoin_monitor_evidence.csv")
    assert [r["classification"] for r in rows] == ["stale"]  # only the VALID stale
    exported_hashes = {r["btc_header_hash"] for r in rows}
    assert headers["canonical"][1] not in exported_hashes  # in-file canonical dropped
    assert companion_hash not in exported_hashes  # companion never merged

    counts = _read_csv(output_dir / "monitor-evidence-counts.csv")
    namecoin = next(row for row in counts if row["chain"] == "namecoin")
    assert namecoin["canonical"] == "0"
    assert namecoin["stale"] == "1"


def test_monitor_export_split_archive_uses_committed_validated_stales(
    tmp_path: Path,
) -> None:
    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    archive_dir = tmp_path / "archive"
    output_dir = tmp_path / "monitor"
    historical_hex, historical_hash = _header(prev_hash="11" * 32)
    validated_hex, validated_hash = _header(prev_hash="22" * 32)
    unknown_hex, unknown_hash = _header(prev_hash="33" * 32)
    common = {
        "btc_height": "800000",
        "btc_time": "1700000000",
        "btc_bits": "1d00ffff",
        "coinbase_scriptsig_hex": "abcd",
        "coinbase_outputs": "76a91400",
        "fb_height": "100",
        "expected_nbits": "1d00ffff",
    }
    _write_csv(
        archive_dir / "chains" / "fractal" / "classified" / "fractal_stale_blocks.csv",
        [
            common
            | {
                "btc_header_hash": historical_hash,
                "btc_prev_hash": "11" * 32,
                "btc_header_hex": historical_hex,
                "classification": "stale",
                "validation_status": "",
            }
        ],
    )
    _write_csv(
        archive_dir
        / "chains"
        / "fractal"
        / "classified"
        / "fractal_unknown_blocks.csv",
        [
            common
            | {
                "btc_header_hash": unknown_hash,
                "btc_prev_hash": "33" * 32,
                "btc_header_hex": unknown_hex,
                "classification": "unknown",
                "validation_status": "",
            }
        ],
    )
    _write_csv(
        data_dir / "validated-stales" / "fractal_validated_stales.csv",
        [
            common
            | {
                "btc_header_hash": validated_hash,
                "btc_prev_hash": "22" * 32,
                "btc_header_hex": validated_hex,
                "classification": "stale",
                "validation_status": "VALID",
            }
        ],
    )
    inventory = tmp_path / "inventory.csv"
    _write_csv(
        inventory,
        [
            {
                "btc_header_hash": unknown_hash,
                "btc_stale_relevance": "strict_btc_orphan",
                "relevance_reason": "strict_height_nbits_match",
            }
        ],
    )

    build_monitor_evidence_exports(
        data_dir=data_dir,
        output_dir=output_dir,
        chain_archive_dirs=[archive_dir],
        relevance_inventory=inventory,
        include_canonical=False,
    )

    rows = _read_csv(output_dir / "fractal_monitor_evidence.csv")
    assert {row["btc_header_hash"] for row in rows} == {validated_hash, unknown_hash}
    validated_row = next(row for row in rows if row["classification"] == "stale")
    assert validated_row["source_kind"] == "validated_stales"
    assert validated_row["artifact_scope"] == "stale_only_publication"
    assert validated_row["validation_status"] == "VALID"
    counts = _read_csv(output_dir / "monitor-evidence-counts.csv")
    fractal = next(row for row in counts if row["chain"] == "fractal")
    assert fractal["source_kind"] == "full_inventory"
    assert fractal["artifact_scope"] == "full_classifier_inventory"
    assert fractal["source_rows"] == "2"
    assert fractal["stale"] == "1"
    assert fractal["strict_btc_orphan"] == "1"


def test_monitor_export_flags_missing_relevance_inventory(tmp_path: Path) -> None:
    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    header_hex, header_hash = _header()
    _write_csv(
        data_dir / "namecoin_stale_blocks.csv",
        [
            {
                "btc_height": "800000",
                "btc_header_hash": header_hash,
                "btc_prev_hash": "11" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "btc_header_hex": header_hex,
                "coinbase_scriptsig_hex": "abcd",
                "coinbase_outputs": "76a91400",
                "nmc_height": "200",
                "classification": "orphan",
                "validation_status": "",
                "expected_nbits": "",
            }
        ],
    )

    summary = build_monitor_evidence_exports(
        data_dir=data_dir,
        output_dir=output_dir,
        relevance_inventory=tmp_path / "does-not-exist.csv",
    )

    rows = _read_csv(output_dir / "namecoin_monitor_evidence.csv")
    assert rows == []
    counts = _read_csv(output_dir / "monitor-evidence-counts.csv")
    namecoin = next(row for row in counts if row["chain"] == "namecoin")
    assert namecoin["notes"] == "unknown_rows_present_no_relevance_inventory"
    assert summary["relevance_inventory"] == "missing"


def test_relevance_verdicts_prefer_strict_over_weak_regardless_of_order(
    tmp_path: Path,
) -> None:
    from stale_blocks_analysis.full_evidence import load_orphan_relevance_verdicts

    inventory = tmp_path / "inventory.csv"
    hash_a = "aa" * 32
    hash_b = "bb" * 32
    inventory.write_text(
        "chain,btc_stale_relevance,relevance_reason,btc_header_hash\n"
        # weak first, strict later: strict must win
        f"rsk,weak_btc_orphan,timestamp_epoch_nbits_match,{hash_a}\n"
        f"namecoin,strict_btc_orphan,strict_height_nbits_match,{hash_a}\n"
        # strict first, weak later: strict must survive
        f"syscoin,strict_btc_orphan,strict_height_nbits_match,{hash_b}\n"
        f"rsk,weak_btc_orphan,timestamp_epoch_nbits_match,{hash_b}\n"
    )

    verdicts = load_orphan_relevance_verdicts(inventory)

    assert verdicts[hash_a] == ("strict_btc_orphan", "strict_height_nbits_match")
    assert verdicts[hash_b] == ("strict_btc_orphan", "strict_height_nbits_match")


def test_monitor_export_includes_valid_stale_descendants(tmp_path: Path) -> None:
    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    valid_hex, valid_hash = _header(prev_hash="aa" * 32)
    rejected_hex, rejected_hash = _header(prev_hash="bb" * 32)
    _write_csv(
        data_dir / "stale_descendants.csv",
        [
            {
                "btc_height": "800001",
                "btc_header_hash": valid_hash,
                "btc_prev_hash": "aa" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "btc_header_hex": valid_hex,
                "classification": "stale_descendant",
                "validation_status": "VALID_STALE_DESCENDANT",
            },
            {
                "btc_height": "800002",
                "btc_header_hash": rejected_hash,
                "btc_prev_hash": "bb" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "btc_header_hex": rejected_hex,
                "classification": "stale_descendant",
                "validation_status": "REJECTED_bip34_height_mismatch",
            },
        ],
    )

    build_monitor_evidence_exports(
        data_dir=data_dir,
        output_dir=output_dir,
        relevance_inventory=None,
    )

    rows = _read_csv(output_dir / "stale-descendants_monitor_evidence.csv")
    assert len(rows) == 1
    assert rows[0]["btc_header_hash"] == valid_hash
    assert rows[0]["btc_stale_relevance"] == ""
    assert rows[0]["relevance_reason"] == "valid_stale_descendant"


def test_canonical_companion_file_is_discovered_and_merged(tmp_path: Path) -> None:
    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    stale_hex, stale_hash = _header(prev_hash="aa" * 32)
    canon_hex, canon_hash = _header(prev_hash="bb" * 32)
    _write_csv(
        data_dir / "validated-stales" / "namecoin_validated_stales.csv",
        [
            {
                "btc_stale_height": "150000",
                "btc_hash": stale_hash,
                "btc_prev_hash": "aa" * 32,
                "btc_time": "1700000000",
                "btc_bits_hex": "1d00ffff",
                "coinbase_scriptsig_hex": "abcd",
                "coinbase_outputs": "76a91400",
                "btc_header_hex": stale_hex,
                "nmc_height": "200",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            }
        ],
    )
    _write_csv(
        data_dir / "namecoin_canonical_blocks.csv",
        [
            {
                "btc_height": "150001",
                "btc_header_hash": canon_hash,
                "btc_prev_hash": "bb" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "coinbase_scriptsig_hex": "beef",
                "coinbase_outputs": "76a91401",
                "btc_header_hex": canon_hex,
                "nmc_height": "201",
                "classification": "canonical",
                "validation_status": "",
                "expected_nbits": "",
            }
        ],
    )

    # Full-evidence export merges the companion and retains canonical status.
    summary = build_full_evidence_exports(data_dir=data_dir, output_dir=output_dir)
    rows = _read_csv(output_dir / "namecoin_evidence.csv")
    classifications = {row["classification"] for row in rows}
    assert classifications == {"stale", "canonical"}
    manifest = _read_csv(output_dir / "auxpow-full-evidence-manifest.csv")
    namecoin = next(row for row in manifest if row["chain"] == "namecoin")
    assert namecoin["canonical"] == "1"
    assert namecoin["canonical_evidence_status"] == "canonical_retained"
    assert summary["status_counts"]["canonical_retained"] == 1

    # Monitor export includes the canonical row with empty relevance.
    monitor_dir = tmp_path / "monitor"
    build_monitor_evidence_exports(
        data_dir=data_dir, output_dir=monitor_dir, relevance_inventory=None
    )
    monitor_rows = _read_csv(monitor_dir / "namecoin_monitor_evidence.csv")
    by_class = {row["classification"]: row for row in monitor_rows}
    assert set(by_class) == {"stale", "canonical"}
    assert by_class["canonical"]["btc_stale_relevance"] == ""
    counts = _read_csv(monitor_dir / "monitor-evidence-counts.csv")
    namecoin_counts = next(row for row in counts if row["chain"] == "namecoin")
    assert namecoin_counts["canonical"] == "1"
    assert namecoin_counts["stale"] == "1"


def test_canonical_companion_duplicate_rows_are_deduped(tmp_path: Path) -> None:
    # A never-split chain's inventory (e.g. i0coin) can already carry the
    # same canonical rows its companion file carries. The merge must skip
    # the companion's duplicate while keeping any row the companion alone
    # contributes.
    inventory_hex, inventory_hash = _header(prev_hash="aa" * 32)
    new_hex, new_hash = _header(prev_hash="bb" * 32)
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "out"
    _write_csv(
        data_dir / "namecoin_stale_blocks.csv",
        [
            {
                "btc_height": "800000",
                "btc_header_hash": inventory_hash,
                "btc_prev_hash": "aa" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "coinbase_scriptsig_hex": "abcd",
                "coinbase_outputs": "76a91400",
                "btc_header_hex": inventory_hex,
                "nmc_height": "200",
                "classification": "canonical",
                "validation_status": "",
                "expected_nbits": "",
            }
        ],
    )
    _write_csv(
        data_dir / "namecoin_canonical_blocks.csv",
        [
            {
                "btc_height": "800000",
                "btc_header_hash": inventory_hash,
                "btc_prev_hash": "aa" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "coinbase_scriptsig_hex": "abcd",
                "coinbase_outputs": "76a91400",
                "btc_header_hex": inventory_hex,
                "nmc_height": "200",
                "classification": "canonical",
                "validation_status": "",
                "expected_nbits": "",
            },
            {
                "btc_height": "800001",
                "btc_header_hash": new_hash,
                "btc_prev_hash": "bb" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "coinbase_scriptsig_hex": "beef",
                "coinbase_outputs": "76a91401",
                "btc_header_hex": new_hex,
                "nmc_height": "201",
                "classification": "canonical",
                "validation_status": "",
                "expected_nbits": "",
            },
        ],
    )

    build_full_evidence_exports(data_dir=data_dir, output_dir=output_dir)

    rows = _read_csv(output_dir / "namecoin_evidence.csv")
    canonical_hashes = [
        row["btc_header_hash"] for row in rows if row["classification"] == "canonical"
    ]
    assert sorted(canonical_hashes) == sorted([inventory_hash, new_hash])

    manifest = _read_csv(output_dir / "auxpow-full-evidence-manifest.csv")
    namecoin = next(row for row in manifest if row["chain"] == "namecoin")
    assert namecoin["canonical"] == "2"


def test_monitor_export_hydrates_empty_namecoin_header_from_prototype(
    tmp_path: Path,
) -> None:
    # A namecoin stale row whose commingled inventory never carried a
    # btc_header_hex must be hydrated from the data/prototype/ extract whose
    # header hashes to the row's btc_header_hash, and the coverage must show
    # up in the counts notes.
    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    header_hex, header_hash = _header(prev_hash="11" * 32)
    _write_csv(
        data_dir / "namecoin_stale_blocks.csv",
        [
            {
                "btc_height": "150000",
                "btc_header_hash": header_hash,
                "btc_prev_hash": "11" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "btc_header_hex": "",  # the gap: no header hex recovered
                "coinbase_scriptsig_hex": "abcd",
                "coinbase_outputs": "76a91400",
                "nmc_height": "200",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            }
        ],
    )
    # The prototype extract carries the full 80-byte header keyed by btc_hash.
    _write_csv(
        data_dir / "prototype" / "namecoin_blkdat_classified.csv",
        [{"btc_hash": header_hash, "btc_header_hex": header_hex}],
    )

    build_monitor_evidence_exports(
        data_dir=data_dir, output_dir=output_dir, relevance_inventory=None
    )

    rows = _read_csv(output_dir / "namecoin_monitor_evidence.csv")
    assert len(rows) == 1
    # the previously-empty header is now the verified prototype header
    assert rows[0]["btc_header_hex"] == header_hex
    assert rows[0]["classification"] == "stale"

    counts = _read_csv(output_dir / "monitor-evidence-counts.csv")
    namecoin = next(row for row in counts if row["chain"] == "namecoin")
    assert namecoin["notes"] == (
        "namecoin_header_hydration=hydrated:1/still_missing:0/hash_mismatch_rejected:0; "
        "child_identity_hydration=hydrated:0/missing_identity:1"
    )


def test_monitor_export_rejects_and_counts_wrong_namecoin_header(
    tmp_path: Path,
) -> None:
    # A prototype candidate whose header does NOT hash to the row's
    # btc_header_hash must never be written, and must be counted as a
    # hash-mismatch rejection in the coverage notes.
    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    _good_hex, good_hash = _header(prev_hash="11" * 32)
    wrong_hex, _wrong_hash = _header(prev_hash="99" * 32)  # hashes elsewhere
    _write_csv(
        data_dir / "namecoin_stale_blocks.csv",
        [
            {
                "btc_height": "150000",
                "btc_header_hash": good_hash,
                "btc_prev_hash": "11" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1d00ffff",
                "btc_header_hex": "",
                "coinbase_scriptsig_hex": "abcd",
                "coinbase_outputs": "76a91400",
                "nmc_height": "200",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            }
        ],
    )
    # The extract maps the row's hash to a DIFFERENT header.
    _write_csv(
        data_dir / "prototype" / "namecoin_blkdat_classified.csv",
        [{"btc_hash": good_hash, "btc_header_hex": wrong_hex}],
    )

    build_monitor_evidence_exports(
        data_dir=data_dir, output_dir=output_dir, relevance_inventory=None
    )

    rows = _read_csv(output_dir / "namecoin_monitor_evidence.csv")
    assert len(rows) == 1
    # the mismatching candidate was rejected: the header stays empty
    assert rows[0]["btc_header_hex"] == ""

    counts = _read_csv(output_dir / "monitor-evidence-counts.csv")
    namecoin = next(row for row in counts if row["chain"] == "namecoin")
    assert namecoin["notes"] == (
        "namecoin_header_hydration=hydrated:0/still_missing:1/hash_mismatch_rejected:1; "
        "child_identity_hydration=hydrated:0/missing_identity:1"
    )


def test_monitor_export_reports_consensus_exclusions(
    tmp_path: Path, monkeypatch
) -> None:
    from stale_blocks_analysis import full_evidence

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    excluded_hash = "11" * 32
    _write_csv(
        data_dir / "validated-stales" / "namecoin_validated_stales.csv",
        [
            {
                "btc_height": "331735",
                "btc_header_hash": excluded_hash,
                "classification": "stale",
                "validation_status": "VALID",
            }
        ],
    )
    monkeypatch.setattr(
        full_evidence,
        "load_stale_exclusion_keys",
        lambda: {(331735, excluded_hash)},
    )

    full_evidence.build_monitor_evidence_exports(
        data_dir=data_dir, output_dir=output_dir, relevance_inventory=None
    )

    counts = _read_csv(output_dir / "monitor-evidence-counts.csv")
    namecoin = next(row for row in counts if row["chain"] == "namecoin")
    assert namecoin["source_rows"] == "0"
    assert namecoin["notes"] == "publication_exclusions=1"

    manifest = json.loads((output_dir / "monitor-evidence-manifest.json").read_text())
    assert manifest["validation_contract"] == {
        "profile": "direct_stale_header_context_v1",
        "valid_token_scope": "publication_gate_accepted_not_full_block_validity",
        "full_block_consensus_validity_asserted": False,
        "required_checks": [
            "candidate_header_hash_and_self_pow",
            "active_chain_parent_and_expected_height",
            "expected_nbits",
            "median_time_past",
            "historical_minimum_block_version",
            "coinbase_scriptsig_length_when_available",
            "bip34_coinbase_height_when_available",
        ],
        "known_exception": {
            "rsk": "coinbase-dependent checks unavailable from compressed proof"
        },
        "documentation": "docs/data-validity.md",
    }


def test_monitor_export_reads_unknown_from_split_companion_file(tmp_path: Path) -> None:
    # After the bucket split, unknown rows live in <chain>_unknown_blocks.csv,
    # NOT the stale inventory. The monitor export must merge that companion
    # unconditionally, else every strict/weak orphan silently vanishes.
    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    headers = {
        label: _header(prev_hash=f"{i:02x}" * 32)
        for i, label in enumerate(
            [
                "canonical",
                "stale",
                "rejected_stale",
                "orphan_strict",
                "orphan_weak",
                "orphan_excluded",
                "near",
            ],
            start=1,
        )
    }
    all_rows = _monitor_fixture_rows(headers)
    stale_file_rows = [
        r for r in all_rows if r["classification"] in ("canonical", "stale", "near")
    ]
    unknown_file_rows = [
        r for r in all_rows if r["classification"] in ("unknown", "orphan")
    ]
    # split across the two files, exactly as the classifier now writes them
    _write_csv(data_dir / "devcoin_stale_blocks.csv", stale_file_rows)
    _write_csv(data_dir / "devcoin_unknown_blocks.csv", unknown_file_rows)
    # sanity: the stale inventory carries NO unknown rows now
    assert all(
        r["classification"] not in ("unknown", "orphan") for r in stale_file_rows
    )

    inventory = tmp_path / "inventory.csv"
    _write_csv(
        inventory,
        [
            {
                "btc_header_hash": headers["orphan_strict"][1],
                "btc_stale_relevance": "strict_btc_orphan",
                "relevance_reason": "strict_height_nbits_match",
            },
            {
                "btc_header_hash": headers["orphan_weak"][1],
                "btc_stale_relevance": "weak_btc_orphan",
                "relevance_reason": "timestamp_epoch_nbits_match",
            },
            {
                "btc_header_hash": headers["orphan_excluded"][1],
                "btc_stale_relevance": "excluded",
                "relevance_reason": "non_btc_epoch_bits",
            },
        ],
    )

    build_monitor_evidence_exports(
        data_dir=data_dir, output_dir=output_dir, relevance_inventory=inventory
    )

    rows = _read_csv(output_dir / "devcoin_monitor_evidence.csv")
    by_hash = {row["btc_header_hash"]: row for row in rows}
    by_relevance = {row["btc_stale_relevance"]: row for row in rows}
    # the strict/weak orphans came from the SEPARATE unknown file — they survive
    assert by_relevance["strict_btc_orphan"]["classification"] == "unknown"
    assert by_relevance["weak_btc_orphan"]["classification"] == "unknown"
    # confirmed stales carry an empty derived relevance now, so look them up
    # by header hash rather than via the (now-shared-with-canonical) "" bucket.
    assert by_hash[headers["stale"][1]]["classification"] == "stale"
    assert by_hash[headers["stale"][1]]["relevance_reason"] == "valid_direct_stale"
    counts = _read_csv(output_dir / "monitor-evidence-counts.csv")
    devcoin = next(row for row in counts if row["chain"] == "devcoin")
    assert devcoin["strict_btc_orphan"] == "1"
    assert devcoin["weak_btc_orphan"] == "1"
    assert devcoin["stale"] == "1"


def test_monitor_export_includes_normalized_supplemental_canonical_scope(
    tmp_path: Path,
) -> None:
    from stale_blocks_analysis.full_evidence import (
        EVIDENCE_FIELDS,
        build_monitor_evidence_exports,
    )

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    supplemental = tmp_path / "vcash_hydrated.csv"
    header_hex, header_hash = _header()
    row = {field: "" for field in EVIDENCE_FIELDS}
    row.update(
        {
            "chain": "vcash",
            "source_kind": "wayback_canonical_hydration",
            "source_path": "<chain-archive>/vcash/wayback_scrape/results.tsv",
            "source_row_number": "2",
            "artifact_scope": "partial_canonical_subset",
            "provenance": "wayback:vcash.tech/block + bitcoin-core:canonical",
            "child_height": "100",
            "child_block_hash": "22" * 32,
            "btc_height": "800000",
            "btc_header_hash": header_hash,
            "btc_prev_hash": "11" * 32,
            "btc_time": "1700000000",
            "btc_bits": "1d00ffff",
            "btc_header_hex": header_hex,
            "classification": "canonical",
            "validation_status": "CANONICAL_CONFIRMED",
        }
    )
    _write_csv(supplemental, [row])

    summary = build_monitor_evidence_exports(
        data_dir=data_dir,
        output_dir=output_dir,
        relevance_inventory=None,
        supplemental_evidence_paths=[supplemental],
    )

    exported = _read_csv(output_dir / "vcash_monitor_evidence.csv")
    assert len(exported) == 1
    assert exported[0]["btc_header_hash"] == header_hash
    assert exported[0]["source_path"].endswith("vcash/wayback_scrape/results.tsv")
    # A supplemental artifact predating the lag-tolerated columns still emits
    # them, filled empty, so every export shares one schema.
    assert exported[0]["child_block_time"] == ""
    counts = _read_csv(output_dir / "monitor-evidence-counts.csv")
    vcash = next(item for item in counts if item["chain"] == "vcash")
    assert vcash["canonical"] == "1"
    assert vcash["monitor_rows"] == "1"
    assert vcash["notes"] == "partial_canonical_subset_not_complete_coverage"
    assert summary["supplemental_evidence"] == ["<external>/vcash_hydrated.csv"]


def test_monitor_export_hydrates_child_identity_and_rsk_sidecar_columns(
    tmp_path: Path,
) -> None:
    # A verified data/child-identity/ row must fill the empty child identity
    # columns, the RSK export alone must carry the seven sidecar columns, and
    # the coverage must land in the counts notes.
    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    rsk_hex, rsk_hash = _header(prev_hash="11" * 32)
    nmc_hex, nmc_hash = _header(prev_hash="33" * 32)
    _write_csv(
        data_dir / "validated-stales" / "rsk_validated_stales.csv",
        [
            {
                "btc_height": "660000",
                "btc_header_hash": rsk_hash,
                "btc_header_hex": rsk_hex,
                "rsk_height": "200",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            }
        ],
    )
    _write_csv(
        data_dir / "validated-stales" / "namecoin_validated_stales.csv",
        [
            {
                "btc_height": "150000",
                "btc_header_hash": nmc_hash,
                "btc_header_hex": nmc_hex,
                "nmc_height": "300",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            }
        ],
    )
    _write_csv(
        data_dir / "child-identity" / "rsk_child_identity.csv",
        [
            {
                "chain": "rsk",
                "btc_header_hash": rsk_hash,
                "child_height": "200",
                "child_block_hash": "aa" * 32,
                "child_block_time": "1521456575",
                "verification": "merged_mining_header_match",
                "note": "",
                "rsk_miner": "bb" * 20,
                "merge_mining_hash": "cc" * 32,
                "is_uncle": "1",
                "uncle_index": "0",
                "uncle_parent_height": "202",
                "rsk_merkle_proof": "0405",
                "rsk_coinbase_tail": "",
            }
        ],
    )
    _write_csv(
        data_dir / "child-identity" / "namecoin_child_identity.csv",
        [
            {
                "chain": "namecoin",
                "btc_header_hash": nmc_hash,
                "child_height": "300",
                "child_block_hash": "dd" * 32,
                "child_block_time": "1322540063",
                "verification": "auxpow_parent_match",
                "note": "",
            }
        ],
    )

    build_monitor_evidence_exports(
        data_dir=data_dir, output_dir=output_dir, relevance_inventory=None
    )

    rsk_rows = _read_csv(output_dir / "rsk_monitor_evidence.csv")
    assert rsk_rows[0]["child_block_hash"] == "aa" * 32
    assert rsk_rows[0]["child_block_time"] == "1521456575"
    assert rsk_rows[0]["rsk_miner"] == "bb" * 20
    assert rsk_rows[0]["merge_mining_hash"] == "cc" * 32
    assert rsk_rows[0]["is_uncle"] == "1"
    assert rsk_rows[0]["uncle_index"] == "0"
    assert rsk_rows[0]["uncle_parent_height"] == "202"

    nmc_rows = _read_csv(output_dir / "namecoin_monitor_evidence.csv")
    assert nmc_rows[0]["child_block_hash"] == "dd" * 32
    assert nmc_rows[0]["child_block_time"] == "1322540063"
    # The sidecar columns are an RSK-only extension of the shared schema.
    assert "rsk_miner" not in nmc_rows[0]

    counts = _read_csv(output_dir / "monitor-evidence-counts.csv")
    for chain in ("rsk", "namecoin"):
        row = next(r for r in counts if r["chain"] == chain)
        assert row["notes"] == "child_identity_hydration=hydrated:1"


def test_monitor_export_refuses_unverified_or_mismatched_child_identity(
    tmp_path: Path,
) -> None:
    # An identity row without a verification never hydrates (missing), and a
    # verified identity recorded at a different child height is refused and
    # counted, so a stale identity file can never mislabel evidence.
    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    unverified_hex, unverified_hash = _header(prev_hash="55" * 32)
    mismatch_hex, mismatch_hash = _header(prev_hash="77" * 32)
    _write_csv(
        data_dir / "validated-stales" / "syscoin_validated_stales.csv",
        [
            {
                "btc_height": "584000",
                "btc_header_hash": unverified_hash,
                "btc_header_hex": unverified_hex,
                "sys_height": "400",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            },
            {
                "btc_height": "584001",
                "btc_header_hash": mismatch_hash,
                "btc_header_hex": mismatch_hex,
                "sys_height": "401",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            },
        ],
    )
    _write_csv(
        data_dir / "child-identity" / "syscoin_child_identity.csv",
        [
            {
                "chain": "syscoin",
                "btc_header_hash": unverified_hash,
                "child_height": "400",
                "child_block_hash": "aa" * 32,
                "child_block_time": "1562940119",
                "verification": "",  # unrecovered: must never hydrate
                "note": "parent_mismatch:deadbeef",
            },
            {
                "chain": "syscoin",
                "btc_header_hash": mismatch_hash,
                "child_height": "999",  # disagrees with the row's sys_height
                "child_block_hash": "bb" * 32,
                "child_block_time": "1562940120",
                "verification": "auxpow_parent_match",
                "note": "",
            },
        ],
    )

    build_monitor_evidence_exports(
        data_dir=data_dir, output_dir=output_dir, relevance_inventory=None
    )

    rows = _read_csv(output_dir / "syscoin_monitor_evidence.csv")
    assert all(row["child_block_hash"] == "" for row in rows)
    assert all(row["child_block_time"] == "" for row in rows)

    counts = _read_csv(output_dir / "monitor-evidence-counts.csv")
    syscoin = next(row for row in counts if row["chain"] == "syscoin")
    assert (
        syscoin["notes"]
        == "child_identity_hydration=hydrated:0/missing_identity:1/height_mismatch:1"
    )


def test_publication_flag_fails_on_unhydrated_live_chain_rows(tmp_path: Path) -> None:
    # With fail_on_missing_child_identity set (the publication default), a
    # live-chain row without a verified identity must abort the build: the
    # monitor importer deliberately skips such rows, so publishing them would
    # silently shrink the imported evidence.
    import pytest

    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    header_hex, header_hash = _header(prev_hash="88" * 32)
    _write_csv(
        data_dir / "validated-stales" / "fractal_validated_stales.csv",
        [
            {
                "btc_height": "860000",
                "btc_header_hash": header_hash,
                "btc_header_hex": header_hex,
                "fb_height": "500",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            }
        ],
    )
    # The chain has identity data, but not for this row.
    _write_csv(
        data_dir / "child-identity" / "fractal_child_identity.csv",
        [
            {
                "chain": "fractal",
                "btc_header_hash": "aa" * 32,
                "child_height": "1",
                "child_block_hash": "bb" * 32,
                "child_block_time": "1728590402",
                "verification": "auxpow_parent_match",
                "note": "",
            }
        ],
    )

    with pytest.raises(ValueError, match="fractal: missing_identity=1"):
        build_monitor_evidence_exports(
            data_dir=data_dir,
            output_dir=output_dir,
            relevance_inventory=None,
            fail_on_missing_child_identity=True,
        )


def test_publication_flag_fails_when_identity_file_is_absent(tmp_path: Path) -> None:
    # A live chain with NO identity file at all (missing, empty, or holding
    # no verified rows) must still trip the publication gate: the live set is
    # targeted unconditionally, so an absent sidecar can never bypass
    # fail_on_missing_child_identity by narrowing the target set.
    import pytest

    from stale_blocks_analysis.full_evidence import build_monitor_evidence_exports

    data_dir = tmp_path / "data"
    output_dir = tmp_path / "monitor"
    header_hex, header_hash = _header(prev_hash="99" * 32)
    _write_csv(
        data_dir / "validated-stales" / "hathor_validated_stales.csv",
        [
            {
                "btc_height": "710000",
                "btc_header_hash": header_hash,
                "btc_header_hex": header_hex,
                "hathor_height": "600",
                "classification": "stale",
                "validation_status": "VALID",
                "expected_nbits": "1d00ffff",
            }
        ],
    )

    with pytest.raises(ValueError, match="hathor: missing_identity=1"):
        build_monitor_evidence_exports(
            data_dir=data_dir,
            output_dir=output_dir,
            relevance_inventory=None,
            fail_on_missing_child_identity=True,
        )
