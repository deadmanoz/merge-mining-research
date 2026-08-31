from __future__ import annotations

import csv
import hashlib
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
    ERROR_BLOCKS_CSV,
)
from stale_blocks_analysis.btc_stale_validation import (
    bip34_height_error,
    block_version_error,
    coinbase_scriptsig_length_error,
)
from stale_blocks_analysis.error_blocks import (
    exclude_error_block_rows,
    load_error_block_keys,
)
from stale_blocks_analysis.reconcile_observations import (
    accepted_stale_root,
    scan_upstream_stales,
)
from stale_blocks_analysis.reconcile_publication import (
    OUTPUT_SUMMARY,
    descendant_bip34_verdict,
)
from stale_blocks_analysis.stale_descendants import (
    load_stale_descendant_observations,
)

REPO = Path(__file__).resolve().parents[1]
EXCLUDED_HASH = "000000000000000010d43fb3f8d02cab156f333f2bfc172de9e6d87359118a1a"
INCLUDED_HASH = "11" * 32


def test_load_keys_from_committed_dataset() -> None:
    keys = load_error_block_keys(ERROR_BLOCKS_CSV)
    assert (
        363967,
        "00000000000000000954ed93eda1e79e8261137548fa9ccf4d516bb384a3660b",
    ) in keys


def test_missing_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_error_block_keys(tmp_path / "nope.csv")


def test_blank_classification_fails_closed(tmp_path: Path) -> None:
    p = tmp_path / "error_blocks.csv"
    p.write_text("height,hash,classification\n1," + "00" * 32 + ",\n")
    with pytest.raises(ValueError):
        load_error_block_keys(p)


def test_header_only_dataset_fails_closed(tmp_path: Path) -> None:
    # A header-only (or empty) dataset yields an empty gate, which is never
    # valid for this committed dataset: a truncated file must fail closed
    # rather than silently let every known error block re-enter publication
    # loaders.
    header_only = tmp_path / "header_only.csv"
    header_only.write_text("height,hash,classification\n")
    with pytest.raises(ValueError, match="no error block rows"):
        load_error_block_keys(header_only)

    empty = tmp_path / "empty.csv"
    empty.write_text("")
    with pytest.raises(ValueError, match="no error block rows"):
        load_error_block_keys(empty)


def test_committed_dataset_loads_39_rows() -> None:
    # The committed dataset is non-empty and loads fine.
    assert len(load_error_block_keys(ERROR_BLOCKS_CSV)) == 39


def test_exclude_rows_filters_exact_key() -> None:
    rows = [
        {
            "height": "363967",
            "hash": "00000000000000000954ed93eda1e79e8261137548fa9ccf4d516bb384a3660b",
        },
        {"height": "1", "hash": "11" * 32},
    ]
    kept = exclude_error_block_rows(rows, path=ERROR_BLOCKS_CSV)
    assert kept == [{"height": "1", "hash": "11" * 32}]


EXPECTED_COLUMNS = [
    "height",
    "hash",
    "btc_prev_hash",
    "btc_header_version",
    "btc_time",
    "btc_bits",
    "expected_nbits",
    "btc_header_hex",
    "coinbase_height",
    "coinbase_scriptsig_hex",
    "source_chains",
    "source_child_observations",
    "classification",
    "rejection_reason",
    "rules_violated",
    "first_observed_child_time",
    "provenance",
]


def test_committed_catalogue_schema_and_row_count() -> None:
    with ERROR_BLOCKS_CSV.open(newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == EXPECTED_COLUMNS
        rows = list(reader)
    assert len(rows) == 39
    assert all(r["classification"] == "error_block" for r in rows)
    assert all(r["rules_violated"] for r in rows)
    assert all(r["provenance"] for r in rows)
    assert all(len(r["btc_header_hex"]) == 160 for r in rows)
    # The 946213 and 957780 time-too-old rows from merge-mining-monitor live evidence.
    assert sum(1 for r in rows if r["rejection_reason"] == "time_below_mtp") == 2
    # The 717696 retarget-boundary row from the rejected-row sweep.
    assert (
        sum(1 for r in rows if r["rejection_reason"] == "nbits_retarget_not_applied")
        == 1
    )


def test_ancestry_derived_error_catalogue_claims_are_exact() -> None:
    expected = {
        "000000000000000010bcbb75dc17fce43da835bd26ccec95ed0d39570a51112a": {
            "height": "331673",
            "source_child_observations": "devcoin:163400|ixcoin:234208|namecoin:207157",
        },
        "00000000000000000d610e393ffeed6b9494d54121f05f7a3905f940f0e0cf69": {
            "height": "331674",
            "source_child_observations": "devcoin:163402|ixcoin:234210|namecoin:207159",
        },
        "000000000000000003a1ce220ae97419cc4bdb5d70b90189b8f8a06b0b37e3a2": {
            "height": "402610",
            "source_child_observations": "namecoin:276713",
        },
        "00000000000000000254ed1e8143f0bcd3c3564db07e7c35631e999d53e81fa7": {
            "height": "422059",
            "source_child_observations": "namecoin:296773",
        },
    }
    with ERROR_BLOCKS_CSV.open(newline="") as handle:
        rows = {
            row["hash"]: row
            for row in csv.DictReader(handle)
            if row["hash"] in expected
        }

    assert set(rows) == set(expected)
    for block_hash, claims in expected.items():
        row = rows[block_hash]
        assert row["height"] == claims["height"]
        assert row["source_child_observations"] == claims["source_child_observations"]
        assert row["rejection_reason"] == "bip34_coinbase_height_mismatch"
        assert row["provenance"] == "stale-ancestry-reconciliation:catalogue"


def test_committed_dataset_rejection_reasons_are_version_consistent() -> None:
    with ERROR_BLOCKS_CSV.open(newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 39
    assert len(load_error_block_keys(ERROR_BLOCKS_CSV)) == 39
    assert Counter(row["rejection_reason"] for row in rows) == {
        "bip34_v2_coinbase_height_mismatch": 12,
        "bip34_coinbase_height_mismatch": 13,
        "bip66_block_version_below_3": 3,
        "bip65_block_version_below_4": 5,
        "coinbase_scriptsig_length_above_100": 1,
        "median_time_past_violation": 1,
        "time_below_mtp": 2,
        "nbits_retarget_not_applied": 1,
        "bip34_coinbase_height_missing": 1,
    }
    missing_heights = [row for row in rows if not row["coinbase_height"]]
    assert len(missing_heights) == 1
    assert missing_heights[0]["rejection_reason"] == "bip34_coinbase_height_missing"
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


def test_error_block_keys_are_absent_from_committed_publication_csvs() -> None:
    excluded = load_error_block_keys()
    paths = [
        *sorted((REPO / "data" / "validated-stales").glob("*_validated_stales.csv")),
        *sorted((REPO / "results" / "per-chain-novelty").glob("*.csv")),
        *(
            path
            for path in sorted(
                (REPO / "results" / "monitor-evidence").glob("*_monitor_evidence.csv")
            )
            if path.name != "error-block-observations_monitor_evidence.csv"
        ),
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
                if key in excluded:
                    found.append((path.relative_to(REPO), key))

    assert found == []


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


def test_656478_absent_from_direct_stale_catalogues() -> None:
    # 656478 is a stale_descendant; it must not appear in any direct-stale CSV.
    target = "00000000000000000005f8f74e57aa4584aacfed509b8a6feb20bc22e7d60a34"
    for path in sorted(
        (REPO / "data" / "validated-stales").glob("*_validated_stales.csv")
    ):
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                assert row.get("btc_header_hash", "").lower() != target, path


def test_656478_remains_in_stale_descendants() -> None:
    target = "00000000000000000005f8f74e57aa4584aacfed509b8a6feb20bc22e7d60a34"
    with (REPO / "data" / "stale_descendants.csv").open(newline="") as f:
        hashes = {r["btc_header_hash"].lower() for r in csv.DictReader(f)}
    assert target in hashes


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


def _write_error_catalogue(data_dir: Path, keys: set[tuple[int, str]]) -> Path:
    path = data_dir / "error-blocks" / "error_blocks.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["height", "hash", "classification"],
            lineterminator="\n",
        )
        writer.writeheader()
        for height, block_hash in sorted(keys):
            writer.writerow(
                {
                    "height": height,
                    "hash": block_hash,
                    "classification": "error_block",
                }
            )
    return path


def test_dataset_rejects_duplicate_and_malformed_keys(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.csv"
    duplicate.write_text(
        "height,hash,classification\n"
        f"331735,{EXCLUDED_HASH},error_block\n"
        f"331735,{EXCLUDED_HASH},error_block\n"
    )
    with pytest.raises(ValueError, match="duplicate error block key"):
        load_error_block_keys(duplicate)

    malformed = tmp_path / "malformed.csv"
    malformed.write_text("height,hash,classification\n331735,not-a-hash,error_block\n")
    with pytest.raises(ValueError, match="invalid error block row"):
        load_error_block_keys(malformed)

    missing_classification = tmp_path / "missing-classification.csv"
    missing_classification.write_text(
        f"height,hash,classification\n331735,{EXCLUDED_HASH},\n"
    )
    with pytest.raises(ValueError, match="invalid error block row"):
        load_error_block_keys(missing_classification)


def test_upstream_sidecar_loader_applies_error_block_gate(
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
        "load_error_block_keys",
        lambda: {(331735, EXCLUDED_HASH)},
    )

    assert module.load_upstream_keys(upstream) == {(331736, INCLUDED_HASH)}


def test_upstream_sidecar_candidates_apply_error_block_gate(
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
        module, "load_error_block_keys", lambda: {(331735, EXCLUDED_HASH)}
    )

    candidates, missing, warnings = module.collect_candidates(data_dir)

    assert set(candidates) == {(331736, INCLUDED_HASH)}
    assert missing == {}
    assert warnings == {}


def test_upstream_sidecar_descendants_use_canonical_parent_loader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script(
        "scripts/reports/build_upstream_stale_sidecar.py",
        "build_upstream_stale_sidecar_descendants_under_test",
    )
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    parents_path = data_dir / "stale_descendants.csv"
    parents_path.write_bytes((REPO / "data/stale_descendants.csv").read_bytes())
    with parents_path.open(newline="") as handle:
        parent_rows = list(csv.DictReader(handle))
    expected = parent_rows[0]
    validated_dir = data_dir / "validated-stales"
    validated_dir.mkdir()
    (validated_dir / "roots_validated_stales.csv").write_text(
        "btc_height,btc_header_hash,classification,validation_status\n"
    )
    trust_upstream = tmp_path / "external-upstream.csv"
    trusted_roots = sorted(
        {(row["root_stale_height"], row["root_stale_hash"]) for row in parent_rows}
    )
    trust_upstream.write_text(
        "height,hash\n"
        + "".join(f"{height},{block_hash}\n" for height, block_hash in trusted_roots)
    )
    trust_errors = data_dir / "error-blocks" / "error_blocks.csv"
    trust_errors.parent.mkdir()
    trust_errors.write_text(f"height,hash,classification\n0,{'00' * 32},error_block\n")
    monkeypatch.setattr(module, "load_error_block_keys", lambda: set())

    candidates, missing, warnings = module.collect_candidates(
        data_dir,
        upstream_path=trust_upstream,
    )

    assert (
        int(expected["btc_height"]),
        expected["btc_header_hash"],
    ) in candidates
    assert missing == {}
    assert warnings == {}
    stats = module.build(tmp_path / "sidecar.csv", data_dir, trust_upstream)
    assert stats["committed_valid_candidates"] == len(parent_rows)

    with parents_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or ())
        rows = list(reader)
    rows[0]["validation_status"] = "REJECTED_bip34_height_mismatch"
    with parents_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="parent verdict is not accepted"):
        module.collect_candidates(data_dir, upstream_path=trust_upstream)


def test_unknown_ancestry_upstream_scan_applies_error_block_gate(
    tmp_path: Path,
) -> None:
    upstream = tmp_path / "stale-blocks.csv"
    _write_upstream(upstream)
    stale_by_hash = defaultdict(list)
    all_hash_chains = defaultdict(set)
    prevs_by_hash = defaultdict(set)

    count = scan_upstream_stales(
        upstream,
        stale_by_hash,
        all_hash_chains,
        prevs_by_hash,
        excluded_keys={(331735, EXCLUDED_HASH)},
    )

    assert count == 1
    assert set(stale_by_hash) == {INCLUDED_HASH}
    assert all_hash_chains[INCLUDED_HASH] == {"upstream"}


@pytest.mark.parametrize(
    ("classification", "validation_status", "expected"),
    [
        ("stale", "", False),
        ("stale", "VALID", True),
        ("stale", "VALID (post-BCH, difficulty matches BTC)", True),
        ("stale", "VALIDATION_FAILED", False),
        ("stale", "VALID_BOGUS", False),
        ("stale", "REJECTED: nBits mismatch", False),
        ("stale", "UNKNOWN: missing header", False),
        ("unknown", "VALID", False),
        ("", "VALID", False),
    ],
)
def test_unknown_ancestry_admits_only_accepted_stale_roots(
    classification: str, validation_status: str, expected: bool
) -> None:
    assert (
        accepted_stale_root(
            {
                "classification": classification,
                "validation_status": validation_status,
            }
        )
        is expected
    )


def test_unknown_ancestry_uses_selected_catalogue_for_all_inventory_scans(
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
    selected_excluded_hash = "aa" * 32
    _write_error_catalogue(data_dir, {(331735, selected_excluded_hash)})

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
            "btc_hash": selected_excluded_hash,
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
    parent_verdicts_csv = tmp_path / "stale_descendants.csv"
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
            "--parent-verdicts-csv",
            str(parent_verdicts_csv),
            "--observations-csv",
            str(tmp_path / "stale_descendant_observations.csv"),
            "--error-candidates-csv",
            str(tmp_path / "error_candidates.csv"),
            "--allow-partial",
        ],
    )

    module.main()

    summary = json.loads((results_dir / OUTPUT_SUMMARY).read_text())
    assert summary["known_stale_hashes"] == 1
    assert summary["auxpow_stale_hashes"] == 1


def test_unknown_ancestry_reports_missing_selected_error_catalogue(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_script(
        "scripts/analysis/reconcile_unknown_stale_ancestry.py",
        "reconcile_unknown_stale_ancestry_missing_catalogue_under_test",
    )
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    with pytest.raises(SystemExit):
        module.main(
            [
                "--data-dir",
                str(data_dir),
                "--results-dir",
                str(tmp_path / "results"),
                "--parent-verdicts-csv",
                str(tmp_path / "stale_descendants.csv"),
                "--observations-csv",
                str(tmp_path / "stale_descendant_observations.csv"),
                "--error-candidates-csv",
                str(tmp_path / "error_candidates.csv"),
                "--allow-partial",
            ]
        )

    expected = data_dir / "error-blocks" / "error_blocks.csv"
    assert f"error blocks dataset missing: {expected}" in capsys.readouterr().err


def _header(version: int) -> str:
    return (version.to_bytes(4, "little", signed=True) + b"\x00" * 76).hex()


def _scriptsig(height: int) -> str:
    encoded = height.to_bytes((height.bit_length() + 7) // 8, "little")
    if encoded[-1] & 0x80:
        encoded += b"\x00"
    return (bytes([len(encoded)]) + encoded + b"pool").hex()


def _easy_pow_header(prev_hash: str) -> tuple[str, str]:
    """Return a deterministic header/hash pair meeting compact target 207fffff."""
    prefix = (
        (4).to_bytes(4, "little", signed=True)
        + bytes.fromhex(prev_hash)[::-1]
        + b"\x22" * 32
        + (1_700_000_000).to_bytes(4, "little")
        + (0x207FFFFF).to_bytes(4, "little")
    )
    target = 0x7FFFFF << (8 * (0x20 - 3))
    for nonce in range(1000):
        header = prefix + nonce.to_bytes(4, "little")
        block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1]
        if int.from_bytes(block_hash, "big") <= target:
            return header.hex(), block_hash.hex()
    raise AssertionError("fixture could not mine an easy-target header")


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
    scriptsig = "" if scriptsig_height is None else _scriptsig(scriptsig_height)

    assert descendant_bip34_verdict(_header(version), scriptsig, height) == expected


def test_error_block_is_a_documented_classification() -> None:
    text = (REPO / "docs" / "data-reference.md").read_text()
    assert "`error_block`" in text
    assert "consensus-invalid" in text


# ── Child-header and ancestry dataset contracts ───────────────────────────────


@pytest.mark.dataset
def test_published_descendant_ledger_preserves_complete_child_identity() -> None:
    observations = load_stale_descendant_observations()

    assert len(observations) == 32
    assert all(len(observation.child_hash) == 64 for observation in observations)
    assert all(
        observation.row["child_block_time"].isdigit() for observation in observations
    )


@pytest.mark.dataset
def test_published_monitor_canonical_rows_have_no_stale_gate_verdict() -> None:
    for path in sorted(
        (REPO / "results" / "monitor-evidence").glob("*_monitor_evidence.csv")
    ):
        with path.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), 2):
                if row.get("classification") != "canonical":
                    continue
                assert row.get("validation_status") == "", (path, row_number)
                assert row.get("expected_nbits") == "", (path, row_number)
                assert row.get("rejection_reason") == "", (path, row_number)


@pytest.mark.dataset
def test_published_monitor_unknown_rows_only_use_descendant_verdict() -> None:
    for path in sorted(
        (REPO / "results" / "monitor-evidence").glob("*_monitor_evidence.csv")
    ):
        with path.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), 2):
                if row.get("classification") != "unknown":
                    continue
                assert row.get("validation_status") == "", (path, row_number)
                assert row.get("relevance_reason") != "valid_stale_descendant", (
                    path,
                    row_number,
                )
                assert row.get("expected_nbits") == "", (path, row_number)
                assert row.get("rejection_reason") == "", (path, row_number)


@pytest.mark.dataset
def test_unresolved_offline_child_heights_remain_blank() -> None:
    # These offline sources cannot authenticate consensus child height. Remove
    # a chain from this pin when its historical evidence is fully hydrated.
    for chain in ("coiledcoin", "i0coin"):
        path = REPO / "results" / "monitor-evidence" / f"{chain}_monitor_evidence.csv"
        with path.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), 2):
                assert row.get("child_height") == "", (path, row_number)


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
    _write_error_catalogue(data_dir, {(0, "00" * 32)})

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
    parent_verdicts_csv = tmp_path / "stale_descendants.csv"

    module.main(
        [
            "--data-dir",
            str(data_dir),
            "--results-dir",
            str(results_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--parent-verdicts-csv",
            str(parent_verdicts_csv),
            "--observations-csv",
            str(tmp_path / "stale_descendant_observations.csv"),
            "--error-candidates-csv",
            str(tmp_path / "error_candidates.csv"),
            "--allow-partial",
        ]
    )

    summary = json.loads((results_dir / OUTPUT_SUMMARY).read_text())
    assert summary["known_stale_hashes"] == 0
    assert "local_upstream_candidate_hashes" not in summary
    with parent_verdicts_csv.open(newline="") as handle:
        assert list(csv.DictReader(handle)) == []


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
    _write_error_catalogue(data_dir, {(0, "00" * 32)})

    header_hex, descendant_hash = _easy_pow_header(INCLUDED_HASH)
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
                "nmc_height",
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
                "nmc_height": "331737",
                "coinbase_scriptsig_hex": _scriptsig(331737),
                "btc_header_hex": header_hex,
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
                "rsk_height",
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
                "rsk_height": "331737",
                "coinbase_scriptsig_hex": "",
                "btc_header_hex": header_hex,
            }
        )

    identity_dir = data_dir / "child-identity"
    identity_dir.mkdir()
    for chain, child_hash in (("namecoin", "88" * 32), ("rsk", "99" * 32)):
        with (identity_dir / f"{chain}_child_identity.csv").open("w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "chain",
                    "btc_header_hash",
                    "child_height",
                    "child_block_hash",
                    "child_block_time",
                    "verification",
                    "note",
                ],
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerow(
                {
                    "chain": chain,
                    "btc_header_hash": descendant_hash,
                    "child_height": "331737",
                    "child_block_hash": child_hash,
                    "child_block_time": "1700000000",
                    "verification": "fixture-parent-match",
                    "note": "",
                }
            )

    monkeypatch.setattr(
        "stale_blocks_analysis.reconcile_publication.expected_bits_for_height",
        lambda *_args: "207fffff",
    )
    bip34_calls: list[tuple[str, str, int]] = []

    def record_bip34(header_hex: str, scriptsig_hex: str, height: int):
        bip34_calls.append((header_hex, scriptsig_hex, height))
        return "match", None

    monkeypatch.setattr(module, "descendant_bip34_verdict", record_bip34)

    results_dir = tmp_path / "results"
    parent_verdicts_csv = tmp_path / "stale_descendants.csv"
    module.main(
        [
            "--data-dir",
            str(data_dir),
            "--results-dir",
            str(results_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--parent-verdicts-csv",
            str(parent_verdicts_csv),
            "--observations-csv",
            str(tmp_path / "stale_descendant_observations.csv"),
            "--error-candidates-csv",
            str(tmp_path / "error_candidates.csv"),
            "--allow-partial",
        ]
    )

    with parent_verdicts_csv.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["classification"] == "stale_descendant"
    assert rows[0]["btc_header_hash"] == descendant_hash
    assert rows[0]["root_stale_hash"] == INCLUDED_HASH
    assert rows[0]["coinbase_scriptsig_hex"] == _scriptsig(331737)
    assert rows[0]["btc_header_hex"] == header_hex
    assert bip34_calls == [(header_hex, _scriptsig(331737), 331737)]
