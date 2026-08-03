from __future__ import annotations

import csv
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pytest

from stale_blocks_analysis.config import (
    BIP34_HEIGHT,
    BIP34_VERSION_2_HEIGHT,
    BIP65_HEIGHT,
    BIP66_HEIGHT,
)
from stale_blocks_analysis.btc_stale_validation import (
    bip34_height_error,
    block_version_error,
    coinbase_scriptsig_length_error,
)
from stale_blocks_analysis.stale_exclusions import (
    exclude_consensus_invalid_rows,
    load_consensus_invalid_stale_keys,
    load_stale_exclusion_keys,
)
from stale_blocks_analysis.stale_blocks import load_stale_descendant_observation_keys


REPO = Path(__file__).resolve().parents[1]
EXCLUDED_HASH = "000000000000000010d43fb3f8d02cab156f333f2bfc172de9e6d87359118a1a"
INCLUDED_HASH = "11" * 32


def test_committed_exclusion_inventory_is_complete() -> None:
    path = REPO / "data" / "stale_block_exclusions.csv"
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 32
    assert len(load_stale_exclusion_keys(path)) == 32
    assert len(load_consensus_invalid_stale_keys(path)) == 31
    assert Counter(row["exclusion_scope"] for row in rows) == {
        "consensus_invalid": 31,
        "direct_stale_only": 1,
    }
    assert Counter(row["rejection_reason"] for row in rows) == {
        "bip34_v2_coinbase_height_mismatch": 12,
        "bip34_coinbase_height_mismatch": 9,
        "bip66_block_version_below_3": 3,
        "bip65_block_version_below_4": 5,
        "coinbase_scriptsig_length_above_100": 1,
        "median_time_past_violation": 1,
        "reclassified_stale_descendant": 1,
    }
    assert all(row["coinbase_height"] for row in rows)
    for row in rows:
        height = int(row["height"])
        version = int(row["btc_header_version"])
        reason = row["rejection_reason"]
        if reason == "bip66_block_version_below_3":
            assert BIP66_HEIGHT <= height < BIP65_HEIGHT
            assert version < 3
        elif reason == "bip65_block_version_below_4":
            assert height >= BIP65_HEIGHT
            assert version < 4


@pytest.mark.dataset
def test_excluded_keys_are_absent_from_committed_publication_csvs() -> None:
    excluded = load_stale_exclusion_keys()
    consensus_invalid = load_consensus_invalid_stale_keys()
    paths = [
        *sorted((REPO / "data" / "validated-stales").glob("*_validated_stales.csv")),
        *sorted((REPO / "results" / "per-chain-novelty").glob("*.csv")),
        *sorted((REPO / "results" / "monitor-evidence").glob("*_monitor_evidence.csv")),
    ]
    found: list[tuple[Path, tuple[int, str]]] = []
    for path in paths:
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                height_text = row.get("btc_height") or row.get("height") or ""
                block_hash = row.get("btc_header_hash") or row.get("btc_hash")
                block_hash = block_hash or row.get("hash") or ""
                if not height_text or not block_hash:
                    continue
                key = (int(height_text), block_hash.lower())
                classification = row.get("classification", "")
                if key in consensus_invalid or (
                    key in excluded and classification != "stale_descendant"
                ):
                    found.append((path.relative_to(REPO), key))

    assert found == []


@pytest.mark.dataset
def test_published_monitor_stales_pass_historical_consensus_checks() -> None:
    failures: list[tuple[Path, int, str, str]] = []
    for path in sorted(
        (REPO / "results" / "monitor-evidence").glob("*_monitor_evidence.csv")
    ):
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                if row.get("classification") != "stale":
                    continue
                height = int(row["btc_height"])
                version_error = block_version_error(row, height)
                if version_error is not None:
                    failures.append(
                        (
                            path.relative_to(REPO),
                            height,
                            row["btc_header_hash"],
                            version_error,
                        )
                    )
                if not row.get("coinbase_scriptsig_hex"):
                    continue
                length_error = coinbase_scriptsig_length_error(row)
                if length_error is not None:
                    failures.append(
                        (
                            path.relative_to(REPO),
                            height,
                            row["btc_header_hash"],
                            length_error,
                        )
                    )
                bip34_error = bip34_height_error(row, height)
                if bip34_error is not None:
                    failures.append(
                        (
                            path.relative_to(REPO),
                            height,
                            row["btc_header_hash"],
                            bip34_error,
                        )
                    )

    assert failures == []


@pytest.mark.dataset
def test_published_monitor_represents_every_stale_descendant_observation() -> None:
    expected = load_stale_descendant_observation_keys()
    represented: set[tuple[str, str]] = set()
    for path in sorted(
        (REPO / "results" / "monitor-evidence").glob("*_monitor_evidence.csv")
    ):
        with path.open(newline="") as handle:
            for row in csv.DictReader(handle):
                if row.get("relevance_reason") != "valid_stale_descendant":
                    continue
                observation_key = (row["chain"], row["btc_header_hash"].lower())
                if observation_key in expected:
                    assert len(row["child_block_hash"]) == 64, (path, observation_key)
                    assert row["child_block_time"].isdigit(), (path, observation_key)
                    represented.add(observation_key)

    assert represented == expected


def _load_script(relative_path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write_upstream(path: Path) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["height", "hash", "header"])
        writer.writeheader()
        writer.writerow(
            {"height": "331735", "hash": EXCLUDED_HASH, "header": "00" * 80}
        )
        writer.writerow(
            {"height": "331736", "hash": INCLUDED_HASH, "header": "00" * 80}
        )


def test_exclusion_file_rejects_duplicate_and_malformed_keys(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.csv"
    duplicate.write_text(
        "height,hash,exclusion_scope\n"
        f"331735,{EXCLUDED_HASH},consensus_invalid\n"
        f"331735,{EXCLUDED_HASH},consensus_invalid\n"
    )
    with pytest.raises(ValueError, match="duplicate stale exclusion key"):
        load_stale_exclusion_keys(duplicate)

    malformed = tmp_path / "malformed.csv"
    malformed.write_text(
        "height,hash,exclusion_scope\n331735,not-a-hash,consensus_invalid\n"
    )
    with pytest.raises(ValueError, match="invalid stale exclusion row"):
        load_stale_exclusion_keys(malformed)

    missing_scope = tmp_path / "missing-scope.csv"
    missing_scope.write_text(f"height,hash,exclusion_scope\n331735,{EXCLUDED_HASH},\n")
    with pytest.raises(ValueError, match="invalid stale exclusion row"):
        load_stale_exclusion_keys(missing_scope)
    with pytest.raises(ValueError, match="invalid stale exclusion row"):
        load_consensus_invalid_stale_keys(missing_scope)


def test_general_catalogue_keeps_direct_only_reclassification(tmp_path: Path) -> None:
    invalid_hash = "22" * 32
    descendant_hash = "33" * 32
    overlay = tmp_path / "overlay.csv"
    overlay.write_text(
        "height,hash,exclusion_scope\n"
        f"1,{invalid_hash},consensus_invalid\n"
        f"2,{descendant_hash},direct_stale_only\n"
    )
    rows = [
        {"height": 1, "hash": invalid_hash},
        {"height": 2, "hash": descendant_hash},
    ]

    assert exclude_consensus_invalid_rows(rows, path=overlay) == [rows[1]]


def test_upstream_sidecar_loader_applies_exclusion_overlay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script(
        "scripts/reports/build_upstream_stale_sidecar.py",
        "build_upstream_stale_sidecar_under_test",
    )
    upstream = tmp_path / "stale-blocks.csv"
    _write_upstream(upstream)
    monkeypatch.setattr(
        module,
        "load_consensus_invalid_stale_keys",
        lambda: {(331735, EXCLUDED_HASH)},
    )
    monkeypatch.setattr(
        module, "load_stale_exclusion_keys", lambda: {(331735, EXCLUDED_HASH)}
    )

    assert module.load_upstream_keys(upstream) == {(331736, INCLUDED_HASH)}


def test_upstream_sidecar_candidates_apply_exclusion_overlay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script(
        "scripts/reports/build_upstream_stale_sidecar.py",
        "build_upstream_stale_sidecar_candidates_under_test",
    )
    data_dir = tmp_path / "data"
    (data_dir / "validated-stales").mkdir(parents=True)
    candidate_path = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    with candidate_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "btc_height",
                "btc_header_hash",
                "btc_header_hex",
                "classification",
                "validation_status",
            ],
        )
        writer.writeheader()
        for height, block_hash in ((331735, EXCLUDED_HASH), (331736, INCLUDED_HASH)):
            writer.writerow(
                {
                    "btc_height": height,
                    "btc_header_hash": block_hash,
                    "btc_header_hex": "00" * 80,
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            )
    monkeypatch.setattr(
        module,
        "load_consensus_invalid_stale_keys",
        lambda: {(331735, EXCLUDED_HASH)},
    )
    monkeypatch.setattr(
        module, "load_stale_exclusion_keys", lambda: {(331735, EXCLUDED_HASH)}
    )

    candidates, missing, warnings = module.collect_candidates(data_dir, {})

    assert set(candidates) == {(331736, INCLUDED_HASH)}
    assert missing == {}
    assert warnings == {}


def test_unknown_ancestry_upstream_scan_applies_exclusion_overlay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script(
        "scripts/analysis/reconcile_unknown_stale_ancestry.py",
        "reconcile_unknown_stale_ancestry_under_test",
    )
    upstream = tmp_path / "stale-blocks.csv"
    _write_upstream(upstream)
    monkeypatch.setattr(
        module,
        "load_consensus_invalid_stale_keys",
        lambda: {(331735, EXCLUDED_HASH)},
    )
    stale_by_hash = defaultdict(list)
    all_hash_chains = defaultdict(set)
    prevs_by_hash = defaultdict(set)

    count = module.scan_upstream_stales(
        upstream,
        stale_by_hash,
        all_hash_chains,
        prevs_by_hash,
    )

    assert count == 1
    assert set(stale_by_hash) == {INCLUDED_HASH}
    assert all_hash_chains[INCLUDED_HASH] == {"upstream"}


def test_unknown_ancestry_inventory_identity_uses_parent_height_fallback() -> None:
    module = _load_script(
        "scripts/analysis/reconcile_unknown_stale_ancestry.py",
        "reconcile_unknown_stale_ancestry_identity_under_test",
    )
    row = {
        "btc_hash": EXCLUDED_HASH,
        "btc_parent_height": "331734",
        "btc_bip34_height": "331736",
    }

    assert module.stale_identity_key(row, list(row), "btc_hash") == (
        331735,
        EXCLUDED_HASH,
    )


def test_unknown_ancestry_inventory_identity_uses_bip34_height_fallback() -> None:
    module = _load_script(
        "scripts/analysis/reconcile_unknown_stale_ancestry.py",
        "reconcile_unknown_stale_ancestry_bip34_identity_under_test",
    )
    row = {
        "btc_hash": EXCLUDED_HASH,
        "btc_bip34_height": "331736",
    }

    assert module.stale_identity_key(row, list(row), "btc_hash") == (
        331736,
        EXCLUDED_HASH,
    )


@pytest.mark.parametrize(
    ("classification", "validation_status", "expected"),
    [
        ("stale", "", True),
        ("stale", "VALID", True),
        ("stale", "VALID (post-BCH, difficulty matches BTC)", True),
        ("stale", "REJECTED: nBits mismatch", False),
        ("stale", "UNKNOWN: missing header", False),
        ("unknown", "VALID", False),
    ],
)
def test_unknown_ancestry_admits_only_accepted_stale_roots(
    classification: str, validation_status: str, expected: bool
) -> None:
    module = _load_script(
        "scripts/analysis/reconcile_unknown_stale_ancestry.py",
        "reconcile_unknown_stale_ancestry_status_under_test",
    )

    assert (
        module.accepted_stale_root(
            {
                "classification": classification,
                "validation_status": validation_status,
            }
        )
        is expected
    )


def test_unknown_ancestry_does_not_treat_mixed_upstream_sidecar_as_roots(
    tmp_path: Path,
) -> None:
    module = _load_script(
        "scripts/analysis/reconcile_unknown_stale_ancestry.py",
        "reconcile_unknown_stale_ancestry_mixed_sidecar_under_test",
    )
    data_dir = tmp_path / "data"
    upstream_dir = data_dir / "stale-blocks"
    upstream_dir.mkdir(parents=True)
    (upstream_dir / "stale-blocks.csv").write_text("height,hash,header\n")

    derived_root = "22" * 32
    derived_child = "33" * 32
    (data_dir / "new_stale_blocks_for_upstream.csv").write_text(
        f"height,hash,header\n100,{derived_root},{'00' * 80}\n"
    )
    (data_dir / "namecoin_unknown_blocks.csv").write_text(
        "btc_header_hash,btc_prev_hash,classification\n"
        f"{derived_child},{derived_root},unknown\n"
    )
    results_dir = tmp_path / "results"
    promoted_csv = tmp_path / "stale_descendants.csv"

    module.main(
        [
            "--data-dir",
            str(data_dir),
            "--results-dir",
            str(results_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--promoted-csv",
            str(promoted_csv),
            "--allow-partial",
        ]
    )

    summary = json.loads((results_dir / module.OUTPUT_SUMMARY).read_text())
    assert summary["known_stale_hashes"] == 0
    assert "local_upstream_candidate_hashes" not in summary
    with promoted_csv.open(newline="") as handle:
        assert list(csv.DictReader(handle)) == []


def test_unknown_ancestry_full_and_validated_scans_cannot_restore_exclusions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script(
        "scripts/analysis/reconcile_unknown_stale_ancestry.py",
        "reconcile_unknown_stale_ancestry_inventory_under_test",
    )
    data_dir = tmp_path / "data"
    upstream_dir = data_dir / "stale-blocks"
    upstream_dir.mkdir(parents=True)
    (upstream_dir / "stale-blocks.csv").write_text("height,hash,header\n")

    accepted_hash = "22" * 32
    rejected_hash = "33" * 32
    fieldnames = [
        "btc_height",
        "btc_hash",
        "btc_prev_hash",
        "classification",
        "validation_status",
    ]
    rows = [
        {
            "btc_height": "331735",
            "btc_hash": EXCLUDED_HASH,
            "btc_prev_hash": "44" * 32,
            "classification": "stale",
            "validation_status": "VALID",
        },
        {
            "btc_height": "331736",
            "btc_hash": rejected_hash,
            "btc_prev_hash": "55" * 32,
            "classification": "stale",
            "validation_status": "REJECTED: nBits mismatch",
        },
        {
            "btc_height": "331737",
            "btc_hash": accepted_hash,
            "btc_prev_hash": "66" * 32,
            "classification": "stale",
            "validation_status": "VALID",
        },
    ]
    for name in (
        "namecoin_stale_blocks.csv",
        "validated-stales/namecoin_validated_stales.csv",
    ):
        dest = data_dir / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    results_dir = tmp_path / "results"
    promoted_csv = tmp_path / "stale_descendants.csv"
    monkeypatch.setattr(
        module, "load_stale_exclusion_keys", lambda: {(331735, EXCLUDED_HASH)}
    )
    monkeypatch.setattr(
        module,
        "load_consensus_invalid_stale_keys",
        lambda: {(331735, EXCLUDED_HASH)},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "reconcile_unknown_stale_ancestry.py",
            "--data-dir",
            str(data_dir),
            "--results-dir",
            str(results_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--promoted-csv",
            str(promoted_csv),
            "--allow-partial",
        ],
    )

    module.main()

    summary = json.loads((results_dir / module.OUTPUT_SUMMARY).read_text())
    assert summary["known_stale_hashes"] == 1
    assert summary["auxpow_stale_hashes"] == 1


def test_unknown_ancestry_reclassifies_direct_stale_only_as_descendant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script(
        "scripts/analysis/reconcile_unknown_stale_ancestry.py",
        "reconcile_unknown_stale_ancestry_direct_only_under_test",
    )
    data_dir = tmp_path / "data"
    upstream_dir = data_dir / "stale-blocks"
    upstream_dir.mkdir(parents=True)
    upstream = upstream_dir / "stale-blocks.csv"
    _write_upstream(upstream)

    descendant_hash = "77" * 32
    inventory = data_dir / "namecoin_stale_blocks.csv"
    with inventory.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "btc_height",
                "btc_hash",
                "btc_prev_hash",
                "classification",
                "validation_status",
                "coinbase_scriptsig_hex",
                "btc_header_hex",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "btc_height": "331737",
                "btc_hash": descendant_hash,
                "btc_prev_hash": INCLUDED_HASH,
                "classification": "stale",
                "validation_status": "VALID",
                "coinbase_scriptsig_hex": _scriptsig(331737),
                "btc_header_hex": "",
            }
        )

    rsk_inventory = data_dir / "rsk_stale_blocks.csv"
    with rsk_inventory.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "btc_height",
                "btc_hash",
                "btc_prev_hash",
                "classification",
                "validation_status",
                "coinbase_scriptsig_hex",
                "btc_header_hex",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "btc_height": "331737",
                "btc_hash": descendant_hash,
                "btc_prev_hash": INCLUDED_HASH,
                "classification": "stale",
                "validation_status": "VALID",
                "coinbase_scriptsig_hex": "",
                "btc_header_hex": "00" * 80,
            }
        )

    direct_only_key = (331737, descendant_hash)
    monkeypatch.setattr(module, "load_stale_exclusion_keys", lambda: {direct_only_key})
    monkeypatch.setattr(module, "load_consensus_invalid_stale_keys", set)
    bip34_calls: list[tuple[str, str, int]] = []

    def record_bip34(header_hex: str, scriptsig_hex: str, height: int):
        bip34_calls.append((header_hex, scriptsig_hex, height))
        return "match", None

    monkeypatch.setattr(module, "descendant_bip34_verdict", record_bip34)

    results_dir = tmp_path / "results"
    promoted_csv = tmp_path / "stale_descendants.csv"
    module.main(
        [
            "--data-dir",
            str(data_dir),
            "--results-dir",
            str(results_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--promoted-csv",
            str(promoted_csv),
            "--allow-partial",
        ]
    )

    with promoted_csv.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["classification"] == "stale_descendant"
    assert rows[0]["btc_header_hash"] == descendant_hash
    assert rows[0]["root_stale_hash"] == INCLUDED_HASH
    assert rows[0]["coinbase_scriptsig_hex"] == _scriptsig(331737)
    assert rows[0]["btc_header_hex"] == "00" * 80
    assert bip34_calls == [("00" * 80, _scriptsig(331737), 331737)]


def _header(version: int) -> str:
    return (version.to_bytes(4, "little", signed=True) + b"\x00" * 76).hex()


def _scriptsig(height: int) -> str:
    encoded = height.to_bytes((height.bit_length() + 7) // 8, "little")
    if encoded[-1] & 0x80:
        encoded += b"\x00"
    return (bytes([len(encoded)]) + encoded + b"pool").hex()


@pytest.mark.parametrize(
    ("version", "height", "scriptsig_height", "expected"),
    [
        (1, BIP34_VERSION_2_HEIGHT, None, ("not_applicable", None)),
        (2, BIP34_VERSION_2_HEIGHT, BIP34_VERSION_2_HEIGHT, ("match", None)),
        (
            2,
            BIP34_VERSION_2_HEIGHT,
            BIP34_VERSION_2_HEIGHT + 1,
            ("mismatch", "bip34_height_mismatch"),
        ),
        (
            1,
            BIP34_HEIGHT,
            BIP34_HEIGHT,
            ("mismatch", "btc_block_version_below_minimum"),
        ),
        (2, BIP34_HEIGHT, BIP34_HEIGHT, ("match", None)),
        (
            2,
            BIP66_HEIGHT,
            BIP66_HEIGHT,
            ("match", "btc_block_version_below_minimum"),
        ),
    ],
)
def test_descendant_reconciliation_uses_contemporaneous_bip34_rules(
    version: int,
    height: int,
    scriptsig_height: int | None,
    expected: tuple[str, str | None],
) -> None:
    module = _load_script(
        "scripts/analysis/reconcile_unknown_stale_ancestry.py",
        "reconcile_unknown_stale_ancestry_bip34_under_test",
    )
    scriptsig = "" if scriptsig_height is None else _scriptsig(scriptsig_height)

    assert (
        module.descendant_bip34_verdict(_header(version), scriptsig, height) == expected
    )
