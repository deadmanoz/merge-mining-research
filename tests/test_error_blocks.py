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
    exclude_consensus_invalid_rows,
    load_consensus_invalid_stale_keys,
    load_stale_exclusion_keys,
)
from stale_blocks_analysis.stale_blocks import (
    load_stale_descendant_correction_keys,
    load_stale_descendant_observation_keys,
)

REPO = Path(__file__).resolve().parents[1]
EXCLUDED_HASH = "000000000000000010d43fb3f8d02cab156f333f2bfc172de9e6d87359118a1a"
INCLUDED_HASH = "11" * 32


def test_load_keys_from_committed_dataset() -> None:
    keys = load_stale_exclusion_keys(ERROR_BLOCKS_CSV)
    assert (
        363967,
        "00000000000000000954ed93eda1e79e8261137548fa9ccf4d516bb384a3660b",
    ) in keys


def test_consensus_invalid_subset_equals_all_rows() -> None:
    # Every dataset row is an error block, so the two key sets are identical.
    assert load_stale_exclusion_keys(
        ERROR_BLOCKS_CSV
    ) == load_consensus_invalid_stale_keys(ERROR_BLOCKS_CSV)


def test_missing_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_stale_exclusion_keys(tmp_path / "nope.csv")


def test_blank_classification_fails_closed(tmp_path: Path) -> None:
    p = tmp_path / "error_blocks.csv"
    p.write_text("height,hash,classification\n1," + "00" * 32 + ",\n")
    with pytest.raises(ValueError):
        load_stale_exclusion_keys(p)


def test_header_only_dataset_fails_closed(tmp_path: Path) -> None:
    # A header-only (or empty) dataset yields an empty gate, which is never
    # valid for this committed dataset: a truncated file must fail closed
    # rather than silently let every known error block re-enter publication
    # loaders.
    header_only = tmp_path / "header_only.csv"
    header_only.write_text("height,hash,classification\n")
    with pytest.raises(ValueError, match="no error block rows"):
        load_stale_exclusion_keys(header_only)
    with pytest.raises(ValueError, match="no error block rows"):
        load_consensus_invalid_stale_keys(header_only)

    empty = tmp_path / "empty.csv"
    empty.write_text("")
    with pytest.raises(ValueError, match="no error block rows"):
        load_stale_exclusion_keys(empty)


def test_committed_dataset_loads_33_rows() -> None:
    # The committed dataset is non-empty and loads fine.
    assert len(load_stale_exclusion_keys(ERROR_BLOCKS_CSV)) == 33


def test_exclude_rows_filters_exact_key() -> None:
    rows = [
        {
            "height": "363967",
            "hash": "00000000000000000954ed93eda1e79e8261137548fa9ccf4d516bb384a3660b",
        },
        {"height": "1", "hash": "11" * 32},
    ]
    kept = exclude_consensus_invalid_rows(rows, path=ERROR_BLOCKS_CSV)
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


def test_committed_dataset_schema_and_seed_count() -> None:
    with ERROR_BLOCKS_CSV.open(newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == EXPECTED_COLUMNS
        rows = list(reader)
    assert len(rows) == 33
    assert all(r["classification"] == "error_block" for r in rows)
    assert all(r["rules_violated"] for r in rows)
    assert all(r["provenance"] for r in rows)
    assert all(len(r["btc_header_hex"]) == 160 for r in rows)
    # The 946213 time-too-old row from merge-mining-monitor live evidence.
    assert sum(1 for r in rows if r["rejection_reason"] == "time_below_mtp") == 1
    # The 717696 retarget-boundary row from the rejected-row sweep.
    assert (
        sum(1 for r in rows if r["rejection_reason"] == "nbits_retarget_not_applied")
        == 1
    )


def test_committed_dataset_rejection_reasons_are_version_consistent() -> None:
    with ERROR_BLOCKS_CSV.open(newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 33
    assert len(load_stale_exclusion_keys(ERROR_BLOCKS_CSV)) == 33
    assert len(load_consensus_invalid_stale_keys(ERROR_BLOCKS_CSV)) == 33
    assert Counter(row["rejection_reason"] for row in rows) == {
        "bip34_v2_coinbase_height_mismatch": 12,
        "bip34_coinbase_height_mismatch": 9,
        "bip66_block_version_below_3": 3,
        "bip65_block_version_below_4": 5,
        "coinbase_scriptsig_length_above_100": 1,
        "median_time_past_violation": 1,
        "time_below_mtp": 1,
        "nbits_retarget_not_applied": 1,
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


def test_error_block_keys_are_absent_from_committed_publication_csvs() -> None:
    excluded = load_stale_exclusion_keys()
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


def test_656478_has_an_explicit_direct_stale_correction_key() -> None:
    target = "00000000000000000005f8f74e57aa4584aacfed509b8a6feb20bc22e7d60a34"
    assert (656478, target) in load_stale_descendant_correction_keys()


def test_error_block_builder_writes_lf_terminated_csvs(tmp_path: Path) -> None:
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_lf_terminators_under_test",
    )
    output = tmp_path / "error_blocks.csv"
    row = {field: "" for field in module.COLUMNS}
    row.update(
        height="1",
        hash="00" * 32,
        classification="error_block",
    )
    module.write_csv([row], output)
    assert b"\r\n" not in output.read_bytes()

    mtp_context = tmp_path / "error_blocks_mtp_context.csv"
    module.update_mtp_context(
        {
            "height": "1",
            "hash": "00" * 32,
            "provenance": "monitor-live-capture:test",
            "_parent_median_time_past": "1",
        },
        mtp_context,
    )
    assert b"\r\n" not in mtp_context.read_bytes()


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


def test_dataset_rejects_duplicate_and_malformed_keys(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.csv"
    duplicate.write_text(
        "height,hash,classification\n"
        f"331735,{EXCLUDED_HASH},error_block\n"
        f"331735,{EXCLUDED_HASH},error_block\n"
    )
    with pytest.raises(ValueError, match="duplicate error block key"):
        load_stale_exclusion_keys(duplicate)

    malformed = tmp_path / "malformed.csv"
    malformed.write_text("height,hash,classification\n331735,not-a-hash,error_block\n")
    with pytest.raises(ValueError, match="invalid error block row"):
        load_stale_exclusion_keys(malformed)

    missing_classification = tmp_path / "missing-classification.csv"
    missing_classification.write_text(
        f"height,hash,classification\n331735,{EXCLUDED_HASH},\n"
    )
    with pytest.raises(ValueError, match="invalid error block row"):
        load_stale_exclusion_keys(missing_classification)
    with pytest.raises(ValueError, match="invalid error block row"):
        load_consensus_invalid_stale_keys(missing_classification)


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
        "load_consensus_invalid_stale_keys",
        lambda: {(331735, EXCLUDED_HASH)},
    )
    monkeypatch.setattr(
        module, "load_stale_exclusion_keys", lambda: {(331735, EXCLUDED_HASH)}
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
        module, "load_stale_exclusion_keys", lambda: {(331735, EXCLUDED_HASH)}
    )

    candidates, missing, warnings = module.collect_candidates(data_dir, {})

    assert set(candidates) == {(331736, INCLUDED_HASH)}
    assert missing == {}
    assert warnings == {}


def test_unknown_ancestry_upstream_scan_applies_error_block_gate(
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


_BUILDER_PRIVATE_INPUTS = [
    Path("~/dev/bitcoin/stale-blocks-research/results/full-evidence").expanduser(),
    Path(
        "~/dev/bitcoin/stale-blocks-research/data/stale-blocks/stale-blocks.csv"
    ).expanduser(),
    REPO / "cache" / "recovered_seed_headers.json",
]

# Compact committed fixtures mimicking the builder's four evidence-source
# groups for a handful of seed rows (one Group A full-evidence export, the
# upstream stale-blocks headers for the Group C heights, and the Group D
# recovered-headers cache). They let the builder's CORE tests run in a plain
# public checkout (CI), where the private evidence archives in
# _BUILDER_PRIVATE_INPUTS are absent. The private-input tests below remain as
# an additional integration layer over the full 33-row committed dataset.
_FIXTURE_DIR = REPO / "tests" / "fixtures" / "error_blocks"
_FIXTURE_SEED = _FIXTURE_DIR / "seed.csv"


def _normalized_bytes(path: Path) -> bytes:
    """Return a file's bytes with CRLF normalized to LF.

    The builder writes CRLF (Python csv module) while git checks out LF
    (`.gitattributes` `eol=lf`), so a byte-for-byte comparison between builder
    output and a checked-out file is line-ending-state-dependent. Compare
    content, not line-ending bytes.
    """
    return path.read_bytes().replace(b"\r\n", b"\n")


def _fixture_source_args() -> list[str]:
    """CLI args pointing the builder's evidence sources at the fixtures."""
    return [
        "--seed",
        str(_FIXTURE_SEED),
        "--full-evidence-dir",
        str(_FIXTURE_DIR),
        "--upstream-stale-blocks",
        str(_FIXTURE_DIR / "stale-blocks.csv"),
        "--recovered-headers",
        str(_FIXTURE_DIR / "recovered_seed_headers.json"),
    ]


def test_builder_reproduces_fixture_seed_without_private_archives(
    tmp_path: Path,
) -> None:
    # Core reproduction coverage for CI: with the evidence sources pointed at
    # the compact committed fixtures, the builder assembles every fixture seed
    # row (groups A, C, and D) and reproduces the seed byte-identically. Runs
    # without the private evidence archives.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_fixture_repro_under_test",
    )
    out = tmp_path / "error_blocks.csv"
    rc = module.main([*_fixture_source_args(), "--output", str(out)])
    assert rc == 0
    assert _normalized_bytes(out) == _normalized_bytes(_FIXTURE_SEED)


def test_builder_fixture_seed_covers_source_groups() -> None:
    # The fixture seed exercises the full-evidence (A), upstream (C), and
    # recovered-headers (D) source groups, so the fixture-based tests give
    # real coverage of every assembly branch that does not need the private
    # archives. (Group B, RSK, needs the private rsk_evidence.csv export and
    # stays covered by the private-input integration tests.)
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_fixture_groups_under_test",
    )
    seeds = module.load_seed_rows(_FIXTURE_SEED)
    groups = {module.group_for_seed(int(s["height"])) for s in seeds}
    assert groups == {"A", "C", "D"}


@pytest.mark.parametrize("bad_classification", ["", "stale"])
def test_builder_fails_closed_on_malformed_seed_classification(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], bad_classification: str
) -> None:
    # Regression: a seed row whose classification is blank or wrong (not
    # exactly "error_block") must fail the build closed (non-zero, no write)
    # rather than being silently dropped — silently dropping it would make a
    # normal rebuild write a SMALLER dataset, removing that exclusion key and
    # letting the known invalid block back into publications. This mirrors the
    # gate loader's fail-closed check. Runs without the private archives.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_bad_seed_classification_under_test",
    )
    bad_seed = tmp_path / "seed.csv"
    lines = _FIXTURE_SEED.read_text().splitlines(keepends=True)
    header = lines[0].strip().split(",")
    classification_index = header.index("classification")
    first_row = lines[1].strip().split(",")
    first_row[classification_index] = bad_classification
    bad_seed.write_text("".join(lines[:1]) + ",".join(first_row) + "\n")
    out = tmp_path / "error_blocks.csv"

    rc = module.main(
        [
            "--seed",
            str(bad_seed),
            "--full-evidence-dir",
            str(_FIXTURE_DIR),
            "--upstream-stale-blocks",
            str(_FIXTURE_DIR / "stale-blocks.csv"),
            "--recovered-headers",
            str(_FIXTURE_DIR / "recovered_seed_headers.json"),
            "--output",
            str(out),
        ]
    )

    assert rc == 1
    err = capsys.readouterr().err
    assert "invalid seed row 2" in err
    assert "error_block" in err
    assert not out.exists()


def test_builder_fails_closed_on_empty_seed_set(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Regression: a header-only (or empty) seed CSV yields zero valid
    # error_block seed rows. The default non-partial path must fail closed
    # (non-zero, no write) rather than overwrite the committed dataset with a
    # header-only file, which would silently destroy the exclusion gate and let
    # every known error block re-enter publication loaders. This mirrors the
    # gate loader's fail-closed empty-dataset check. Runs without the private
    # archives.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_empty_seed_under_test",
    )
    for name, text in (
        ("header_only.csv", _FIXTURE_SEED.read_text().splitlines(keepends=True)[0]),
        ("empty.csv", ""),
    ):
        seed = tmp_path / name
        seed.write_text(text)
        out = tmp_path / f"out_{name}"
        rc = module.main(
            [
                "--seed",
                str(seed),
                "--full-evidence-dir",
                str(_FIXTURE_DIR),
                "--upstream-stale-blocks",
                str(_FIXTURE_DIR / "stale-blocks.csv"),
                "--recovered-headers",
                str(_FIXTURE_DIR / "recovered_seed_headers.json"),
                "--output",
                str(out),
            ]
        )
        assert rc == 1, name
        assert not out.exists(), name
    err = capsys.readouterr().err
    assert "no error block seed rows" in err


def test_builder_fails_closed_on_missing_fixture_evidence(tmp_path: Path) -> None:
    # Core fail-closed coverage for CI: a seed row whose evidence is absent
    # from the pointed-at sources fails the build (non-zero, no write). Point
    # the upstream source at an empty CSV so the Group C rows have no header.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_fixture_missing_under_test",
    )
    empty_upstream = tmp_path / "stale-blocks.csv"
    with empty_upstream.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["height", "hash", "header"])
        writer.writeheader()
    out = tmp_path / "error_blocks.csv"
    rc = module.main(
        [
            "--seed",
            str(_FIXTURE_SEED),
            "--full-evidence-dir",
            str(_FIXTURE_DIR),
            "--upstream-stale-blocks",
            str(empty_upstream),
            "--recovered-headers",
            str(_FIXTURE_DIR / "recovered_seed_headers.json"),
            "--output",
            str(out),
        ]
    )
    assert rc == 1
    assert not out.exists()


def test_builder_fails_closed_on_prev_hash_mismatch_without_private_archives(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: a self-contained import whose btc_prev_hash disagrees with
    # the authoritative 80-byte header must NOT be copied verbatim into the
    # dataset. The builder derives the parent hash from the header bytes and
    # fails closed on a mismatch. Uses only fixture sources; the committed
    # output path is redirected to a tmp copy so the real CSV is untouched.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_prev_hash_mismatch_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _easy_header()
    export = _time_below_mtp_export(block_hash, header_hex)
    # The easy header's prev-hash bytes are b"\x11" * 32, so the derived
    # display prev hash is "11"*32; claim a different one.
    assert module.parse_header_prev_hash(header_hex) == "11" * 32
    export["btc_prev_hash"] = "22" * 32
    extra_path = tmp_path / "extra_rows.json"
    extra_path.write_text(json.dumps([export]))

    committed_copy = tmp_path / "error_blocks.csv"
    committed_copy.write_bytes(_FIXTURE_SEED.read_bytes())
    monkeypatch.setattr(module, "ERROR_BLOCKS_CSV", committed_copy)

    rc = module.main(
        [
            *_fixture_source_args(),
            "--extra-rows",
            str(extra_path),
            "--output",
            str(committed_copy),
        ]
    )

    assert rc == 1
    assert "btc_prev_hash mismatch" in capsys.readouterr().err
    # Fail closed: the tmp committed copy was not overwritten with the bad row.
    assert committed_copy.read_bytes() == _FIXTURE_SEED.read_bytes()


def test_merge_self_contained_row_canonicalizes_dedup_key() -> None:
    # Regression: an import that identifies an existing block with a
    # noncanonical height string ("0946213") or a mixed-case hash must dedup
    # against the seed's canonical "946213" / lowercase form, not write a
    # duplicate row. The merge canonicalizes the (height, hash) key (height as
    # int, hash lowercased) before comparing.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_merge_canonical_key_under_test",
    )
    seed = {"height": "946213", "hash": "ab" * 32}
    seeds = [seed, {"height": "225013", "hash": "cd" * 32}]

    # Noncanonical height string + uppercase hash: same block, one row out.
    imported = {"height": "0946213", "hash": ("ab" * 32).upper()}
    merged = module.merge_self_contained_row(seeds, imported)
    assert len(merged) == 2
    # The imported row replaced the matching seed (deduped, not duplicated).
    assert merged[-1] is imported
    assert sum(1 for r in merged if module._dedup_key(r) == (946213, "ab" * 32)) == 1

    # A genuinely different block is appended, not deduped away.
    other = {"height": "999999", "hash": "ef" * 32}
    merged = module.merge_self_contained_row(seeds, other)
    assert len(merged) == 3


@pytest.mark.parametrize("empty_key", ["source_chains", "source_child_observations"])
def test_self_contained_row_rejects_empty_witnessing_chain_fields(
    empty_key: str,
) -> None:
    # Regression: a self-contained import (monitor export or extra row) whose
    # source_chains / source_child_observations is present but EMPTY (or
    # whitespace-only) must fail closed at ingest. A row with no witnessing
    # chain is not merge-mining evidence; the text-field check rejects only a
    # missing key, so the empty string must be rejected explicitly.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_empty_source_fields_under_test",
    )
    header_hex, block_hash = _self_consistent_header()
    export = {
        "height": 999999,
        "hash": block_hash,
        "btc_prev_hash": "11" * 32,
        "btc_header_hex": header_hex,
        "expected_nbits": "17021369",
        "coinbase_height": 999999,
        "coinbase_scriptsig_hex": "03" + (999999).to_bytes(3, "little").hex() + "00",
        "source_chains": "namecoin",
        "source_child_observations": "namecoin:1",
        "rejection_reason": "bip65_block_version_below_4",
        "first_observed_child_time": 1700000100,
        "provenance": "monitor-live-capture:namecoin:1",
    }
    export[empty_key] = "   "

    with pytest.raises(ValueError, match=f"empty {empty_key!r}"):
        module._self_contained_row(export)


def _witnessing_export() -> dict[str, object]:
    """A minimal self-contained export with matching source chain fields."""
    header_hex, block_hash = _self_consistent_header()
    return {
        "height": 999999,
        "hash": block_hash,
        "btc_prev_hash": "11" * 32,
        "btc_header_hex": header_hex,
        "expected_nbits": "17021369",
        "coinbase_height": 999999,
        "coinbase_scriptsig_hex": "03" + (999999).to_bytes(3, "little").hex() + "00",
        "source_chains": "namecoin",
        "source_child_observations": "namecoin:1",
        "rejection_reason": "bip65_block_version_below_4",
        "first_observed_child_time": 1700000100,
        "provenance": "monitor-live-capture:namecoin:1",
    }


@pytest.mark.parametrize(
    ("source_chains", "source_child_observations"),
    [
        # Two source chains but only one observation.
        ("namecoin|syscoin", "namecoin:1"),
        # An observation naming a chain outside source_chains.
        ("namecoin", "syscoin:1"),
        # An observation without the chain:child_height form.
        ("namecoin", "namecoin"),
        # The same chain observed twice while the other source chain is
        # unobserved (a one-to-one mapping is required).
        ("namecoin|rsk", "namecoin:1|namecoin:2"),
        # The source declaration itself must be a set: two namecoin entries
        # could otherwise pass the equal-count/sorted-observations checks.
        ("namecoin|namecoin", "namecoin:1|namecoin:2"),
    ],
    ids=[
        "count-mismatch",
        "unknown-chain",
        "missing-child-height",
        "chain-twice",
        "duplicate-source-chain",
    ],
)
def test_self_contained_row_rejects_mismatched_child_observations(
    source_chains: str, source_child_observations: str
) -> None:
    # Regression: the child observations must correspond to the source chains —
    # exactly one chain:child_height observation per source chain, each naming
    # one of those chains, with no duplicate source/observation chain and no
    # chain left unobserved. A count mismatch, an observation naming a chain
    # outside source_chains, or a duplicated chain fails closed at ingest.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_observation_mismatch_under_test",
    )
    export = _witnessing_export()
    export["source_chains"] = source_chains
    export["source_child_observations"] = source_child_observations

    with pytest.raises(ValueError, match="does not match source_chains"):
        module._self_contained_row(export)


@pytest.mark.parametrize(
    ("source_chains", "source_child_observations"),
    [
        ("namecoin|syscoin", "namecoin:1|syscoin:2"),
        ("namecoin|rsk", "namecoin:1|rsk:2"),
    ],
    ids=["namecoin-syscoin", "namecoin-rsk"],
)
def test_self_contained_row_accepts_matching_child_observations(
    source_chains: str, source_child_observations: str
) -> None:
    # A matching one-to-one set — one chain:child_height observation per source
    # chain, each naming a distinct source chain — is accepted.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_observation_match_under_test",
    )
    export = _witnessing_export()
    export["source_chains"] = source_chains
    export["source_child_observations"] = source_child_observations

    row = module._self_contained_row(export)

    assert row["source_chains"] == source_chains
    assert row["source_child_observations"] == source_child_observations


def test_builder_self_contained_validation_without_private_archives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Core self-contained validation coverage for CI: a monitor export whose
    # claimed rule does NOT re-derive from its own bytes fails the committed
    # -dataset write closed, using only fixture sources. The committed output
    # path is the fixture seed copy in tmp_path (not the real committed CSV).
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_fixture_selfval_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _easy_header()
    export = _time_below_mtp_export(block_hash, header_hex)
    # False claim: time_below_mtp requires the header nTime <= parent MTP, but
    # the export's parent MTP is below the header nTime, so it does not
    # re-derive.
    export["parent_median_time_past"] = 1699999999
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))
    # Redirect the committed-dataset target to a tmp copy of the fixture seed
    # so the committed-write validation path runs without touching the real
    # committed CSV.
    committed_copy = tmp_path / "error_blocks.csv"
    committed_copy.write_bytes(_FIXTURE_SEED.read_bytes())
    monkeypatch.setattr(module, "ERROR_BLOCKS_CSV", committed_copy)

    rc = module.main(
        [
            *_fixture_source_args(),
            "--monitor-export",
            str(export_path),
            "--output",
            str(committed_copy),
        ]
    )

    assert rc == 1
    # Fail closed: the tmp committed copy was not overwritten with the bad row.
    assert committed_copy.read_bytes() == _FIXTURE_SEED.read_bytes()


def test_builder_commits_time_row_and_sidecar_without_private_archives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Core sidecar-update coverage for CI: a valid monitor time_below_mtp row
    # is committed AND its MTP context reaches the sidecar, using only fixture
    # sources. Both the committed dataset and the sidecar are redirected to
    # tmp_path so the real committed files are untouched.
    from stale_blocks_analysis.config import ERROR_BLOCKS_MTP_CONTEXT_CSV

    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_fixture_sidecar_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _easy_header()
    export = _time_below_mtp_export(block_hash, header_hex)
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))

    committed_copy = tmp_path / "error_blocks.csv"
    committed_copy.write_bytes(_FIXTURE_SEED.read_bytes())
    sidecar_copy = tmp_path / "mtp_context.csv"
    sidecar_copy.write_bytes(ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes())
    monkeypatch.setattr(module, "ERROR_BLOCKS_CSV", committed_copy)
    monkeypatch.setattr(module, "ERROR_BLOCKS_MTP_CONTEXT_CSV", sidecar_copy)

    rc = module.main([*_fixture_source_args(), "--monitor-export", str(export_path)])

    assert rc == 0
    with committed_copy.open(newline="") as f:
        rows = list(csv.DictReader(f))
    merged = [r for r in rows if r["height"] == str(_FAKE_EPOCH_HEIGHT)]
    assert len(merged) == 1
    assert merged[0]["hash"] == block_hash
    with sidecar_copy.open(newline="") as f:
        sidecar = {
            (r["height"], r["hash"]): r["parent_median_time_past"]
            for r in csv.DictReader(f)
        }
    assert sidecar[(str(_FAKE_EPOCH_HEIGHT), block_hash)] == "1700000000"


def test_builder_atomic_replace_without_private_archives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Core atomic-replace coverage for CI: if the MTP sidecar update fails,
    # the staged dataset temp file must NOT be committed (the dataset stays
    # byte-identical), using only fixture sources. Both committed targets are
    # redirected to tmp_path.
    from stale_blocks_analysis.config import ERROR_BLOCKS_MTP_CONTEXT_CSV

    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_fixture_atomic_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _easy_header()
    export = _time_below_mtp_export(block_hash, header_hex)
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))

    committed_copy = tmp_path / "error_blocks.csv"
    committed_copy.write_bytes(_FIXTURE_SEED.read_bytes())
    sidecar_copy = tmp_path / "mtp_context.csv"
    sidecar_copy.write_bytes(ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes())
    monkeypatch.setattr(module, "ERROR_BLOCKS_CSV", committed_copy)
    monkeypatch.setattr(module, "ERROR_BLOCKS_MTP_CONTEXT_CSV", sidecar_copy)

    def _failing_update_mtp_context(*args: object, **kwargs: object) -> None:
        raise OSError("simulated sidecar write failure")

    monkeypatch.setattr(module, "update_mtp_context", _failing_update_mtp_context)

    with pytest.raises(OSError, match="simulated sidecar write failure"):
        module.main([*_fixture_source_args(), "--monitor-export", str(export_path)])
    # The staged dataset temp file was not committed: byte-identical.
    assert committed_copy.read_bytes() == _FIXTURE_SEED.read_bytes()
    assert sidecar_copy.read_bytes() == ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes()


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_reproduces_committed_dataset(tmp_path: Path) -> None:
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_under_test",
    )
    out = tmp_path / "error_blocks.csv"
    rc = module.main(["--output", str(out)])
    assert rc == 0
    assert _normalized_bytes(out) == _normalized_bytes(ERROR_BLOCKS_CSV)


def _self_consistent_header() -> tuple[str, str]:
    """Return (header_hex, display_hash) with sha256d(header)[::-1] == hash."""
    header = (
        (4).to_bytes(4, "little")
        + b"\x11" * 32  # prev hash
        + b"\x22" * 32  # merkle root
        + (1_700_000_000).to_bytes(4, "little")  # time
        + bytes.fromhex("17021369")  # bits
        + (42).to_bytes(4, "little")  # nonce
    )
    assert len(header) == 80
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return header.hex(), digest[::-1].hex()


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_merges_monitor_export(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_monitor_merge_under_test",
    )
    header_hex, block_hash = _self_consistent_header()
    export = {
        "height": 999999,
        "hash": block_hash,
        "btc_prev_hash": "11" * 32,
        "btc_header_hex": header_hex,
        "expected_nbits": "17021369",
        "coinbase_height": 999999,
        "coinbase_scriptsig_hex": "03" + (999999).to_bytes(3, "little").hex() + "00",
        "source_chains": "namecoin",
        "source_child_observations": "namecoin:1",
        "rejection_reason": "bip65_block_version_below_4",
        "first_observed_child_time": 1700000100,
        "provenance": "monitor-live-capture:namecoin:1",
        # No parent_median_time_past: the sidecar is not touched and the
        # builder warns (the validator would catch a missing entry later).
    }
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))
    out = tmp_path / "error_blocks.csv"

    rc = module.main(["--monitor-export", str(export_path), "--output", str(out)])

    assert rc == 0
    assert "no parent_median_time_past" in capsys.readouterr().err
    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))
    merged = [r for r in rows if r["height"] == "999999"]
    assert len(merged) == 1
    row = merged[0]
    assert row["hash"] == block_hash
    assert row["rejection_reason"] == "bip65_block_version_below_4"
    assert row["rules_violated"] == "bip65_block_version_below_4"
    assert row["provenance"] == "monitor-live-capture:namecoin:1"
    # The merged output is the committed 33 rows plus the new one, still
    # sorted by (height, hash).
    assert len(rows) == 34
    keys = [(int(r["height"]), r["hash"]) for r in rows]
    assert keys == sorted(keys)


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_scratch_output_does_not_touch_committed_mtp_sidecar(
    tmp_path: Path,
) -> None:
    # A --monitor-export run writing to a scratch --output must NOT rewrite the
    # committed mtp_context.csv sidecar (isolated regeneration).
    from stale_blocks_analysis.config import ERROR_BLOCKS_MTP_CONTEXT_CSV

    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_sidecar_isolation_under_test",
    )
    header_hex, block_hash = _self_consistent_header()
    export = {
        "height": 999999,
        "hash": block_hash,
        "btc_prev_hash": "11" * 32,
        "btc_header_hex": header_hex,
        "expected_nbits": "17021369",
        "coinbase_height": 999999,
        "coinbase_scriptsig_hex": "03" + (999999).to_bytes(3, "little").hex() + "00",
        "source_chains": "namecoin",
        "source_child_observations": "namecoin:1",
        "rejection_reason": "time_below_mtp",
        "first_observed_child_time": 1700000100,
        "parent_median_time_past": 1699999999,
        "provenance": "monitor-live-capture:namecoin:1",
    }
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))
    out = tmp_path / "scratch_error_blocks.csv"

    before = ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes()
    rc = module.main(["--monitor-export", str(export_path), "--output", str(out)])
    after = ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes()

    assert rc == 0
    assert out.exists()
    # The committed sidecar is untouched because --output was a scratch path.
    assert before == after


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
@pytest.mark.parametrize(
    "payload",
    [
        # Non-list JSON.
        {"height": 999999},
        # A list containing a non-dict item.
        ["not-a-row"],
        # A dict missing a required field (hash).
        [
            {
                "height": 999999,
                "btc_prev_hash": "11" * 32,
                "btc_header_hex": "00" * 80,
                "expected_nbits": "17021369",
                "coinbase_height": 999999,
                "coinbase_scriptsig_hex": "00",
                "source_chains": "emercoin",
                "source_child_observations": "emercoin:1",
                "rejection_reason": "nbits_retarget_not_applied",
                "first_observed_child_time": 1700000100,
                "provenance": "sweep-rejected-rows:emercoin:emercoin_stale_blocks.csv",
            }
        ],
    ],
    ids=["non-list-json", "non-dict-item", "missing-required-field"],
)
def test_builder_rejects_malformed_extra_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], payload: object
) -> None:
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_extra_rows_negative_under_test",
    )
    extra_path = tmp_path / "extra_rows.json"
    extra_path.write_text(json.dumps(payload))
    out = tmp_path / "error_blocks.csv"

    rc = module.main(["--extra-rows", str(extra_path), "--output", str(out)])

    assert rc == 1
    assert "invalid extra rows" in capsys.readouterr().err
    assert not out.exists()


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_fails_closed_on_self_contained_row_that_does_not_rederive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A self-contained monitor row whose claimed rule does NOT re-derive from
    # its own bytes: the header is self-consistent (hash check passes) but
    # the claimed rejection_reason is false. Writing the committed dataset
    # must fail closed (non-zero, no write).
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_fail_closed_under_test",
    )
    header_hex, block_hash = _self_consistent_header()
    export = {
        "height": 999999,
        "hash": block_hash,
        "btc_prev_hash": "11" * 32,
        "btc_header_hex": header_hex,
        "expected_nbits": "17021369",
        "coinbase_height": 999999,
        "coinbase_scriptsig_hex": "03" + (999999).to_bytes(3, "little").hex() + "00",
        "source_chains": "namecoin",
        "source_child_observations": "namecoin:1",
        # False claim: the header is version 4, so bip65_block_version_below_4
        # does not re-derive from the bytes.
        "rejection_reason": "bip65_block_version_below_4",
        "first_observed_child_time": 1700000100,
        "provenance": "monitor-live-capture:namecoin:1",
    }
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))

    committed_before = ERROR_BLOCKS_CSV.read_bytes()
    rc = module.main(["--monitor-export", str(export_path)])
    committed_after = ERROR_BLOCKS_CSV.read_bytes()

    assert rc == 1
    err = capsys.readouterr().err
    assert "self-contained row failed validation" in err
    assert "999999" in err
    # Fail closed: the committed dataset was not overwritten.
    assert committed_before == committed_after


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_rejects_extra_row_with_unrecognized_provenance_at_ingest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Regression: an --extra-rows row whose provenance does NOT start with one
    # of SELF_CONTAINED_PROVENANCE_PREFIXES must fail closed AT INGEST, before
    # any committed write. The transient _self_contained ingest tag is not a
    # dataset column, so a plain rebuild recognizes a committed self-contained
    # row only by its provenance prefix: committing an unrecognized-provenance
    # row would leave the next ordinary rebuild unable to place it (its height
    # is not in the verified source map), making the committed dataset
    # non-reproducible. Use a Group A row's real bytes so the row would
    # otherwise be committable; only the provenance prefix is unrecognized.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_unrecognized_provenance_ingest_under_test",
    )
    with ERROR_BLOCKS_CSV.open(newline="") as f:
        seed_row = next(r for r in csv.DictReader(f) if r["height"] == "225013")
    extra_row = {
        key: seed_row[key]
        for key in (
            "height",
            "hash",
            "btc_prev_hash",
            "btc_header_hex",
            "expected_nbits",
            "coinbase_height",
            "coinbase_scriptsig_hex",
            "source_chains",
            "source_child_observations",
            "rejection_reason",
            "first_observed_child_time",
        )
    }
    # An unrecognized provenance: not one of the self-contained prefixes.
    extra_row["provenance"] = "ad-hoc-import:operator-csv"
    extra_path = tmp_path / "extra_rows.json"
    extra_path.write_text(json.dumps([extra_row]))

    committed_before = ERROR_BLOCKS_CSV.read_bytes()
    rc = module.main(["--extra-rows", str(extra_path)])
    committed_after = ERROR_BLOCKS_CSV.read_bytes()

    assert rc == 1
    err = capsys.readouterr().err
    assert "invalid extra rows" in err
    assert "unrecognized self-contained provenance" in err
    assert "ad-hoc-import:operator-csv" in err
    # Fail closed at ingest: the committed dataset was not overwritten.
    assert committed_before == committed_after


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_ingests_and_rebuilds_extra_row_with_recognized_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A recognized-prefix (sweep-version-bip:) --extra-rows row ingests and
    # then survives a PLAIN rebuild (no --extra-rows): the rebuild recognizes
    # the committed row's provenance prefix and passes it through, producing
    # byte-identical output. This is the ingest/rebuild consistency the
    # unrecognized-prefix gate guarantees. The committed files are
    # snapshot-restored around the committed-path writes.
    from stale_blocks_analysis.config import ERROR_BLOCKS_MTP_CONTEXT_CSV

    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_recognized_provenance_ingest_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _easy_header()
    extra_row = _time_below_mtp_export(block_hash, header_hex)
    extra_row["provenance"] = "sweep-version-bip:namecoin:namecoin_stale_blocks.csv"
    extra_path = tmp_path / "extra_rows.json"
    extra_path.write_text(json.dumps([extra_row]))

    dataset_before = ERROR_BLOCKS_CSV.read_bytes()
    sidecar_before = ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes()
    try:
        # Ingest the extra row (writes the committed dataset)...
        rc = module.main(["--extra-rows", str(extra_path)])
        assert rc == 0
        with ERROR_BLOCKS_CSV.open(newline="") as f:
            rows = list(csv.DictReader(f))
        merged = [r for r in rows if r["height"] == str(_FAKE_EPOCH_HEIGHT)]
        assert len(merged) == 1
        assert (
            merged[0]["provenance"]
            == "sweep-version-bip:namecoin:namecoin_stale_blocks.csv"
        )
        ingested = ERROR_BLOCKS_CSV.read_bytes()
        # ...then a PLAIN rebuild (no --extra-rows) keeps the row:
        # byte-identical output.
        rc = module.main([])
        assert rc == 0
        assert ERROR_BLOCKS_CSV.read_bytes() == ingested
    finally:
        ERROR_BLOCKS_CSV.write_bytes(dataset_before)
        ERROR_BLOCKS_MTP_CONTEXT_CSV.write_bytes(sidecar_before)


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
@pytest.mark.parametrize(
    "output_dir",
    [
        # The committed dataset directory itself...
        ERROR_BLOCKS_CSV.parent,
        # ...and a subdirectory of it.
        ERROR_BLOCKS_CSV.parent / "nested",
    ],
    ids=["dataset-dir", "dataset-dir-nested"],
)
def test_builder_refuses_partial_output_dir_in_committed_dataset_dir(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], output_dir: Path
) -> None:
    # A partial build's --output-dir must be a genuinely disposable location:
    # --allow-partial --output-dir data/error-blocks --output mtp_context.csv
    # would otherwise overwrite the committed MTP sidecar with an error-block
    # CSV. Refused (exit 2, no write) even with --output naming the sidecar.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_partial_output_dir_under_test",
    )
    rc = module.main(
        [
            "--allow-partial",
            "--output-dir",
            str(output_dir),
            "--output",
            "mtp_context.csv",
        ]
    )
    assert rc == 2
    assert "disposable" in capsys.readouterr().err
    assert not (output_dir / "nested" / "mtp_context.csv").exists()


def test_builder_refuses_nonpartial_output_to_committed_sidecar(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: a non-partial scratch --output that resolves to a committed
    # artifact under data/error-blocks/ other than the dataset itself (e.g.
    # --output data/error-blocks/mtp_context.csv) must be refused, not written
    # — otherwise the committed MTP sidecar is overwritten with an error-block
    # CSV. The committed dataset path and sidecar are redirected to tmp_path so
    # the real committed files are untouched.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_nonpartial_sidecar_output_under_test",
    )
    committed_dir = tmp_path / "error-blocks"
    committed_dir.mkdir()
    committed_copy = committed_dir / "error_blocks.csv"
    committed_copy.write_bytes(_FIXTURE_SEED.read_bytes())
    sidecar_copy = committed_dir / "mtp_context.csv"
    sidecar_copy.write_text("height,parent_median_time_past\n")
    monkeypatch.setattr(module, "ERROR_BLOCKS_CSV", committed_copy)

    rc = module.main([*_fixture_source_args(), "--output", str(sidecar_copy)])

    assert rc == 2
    assert "committed artifact" in capsys.readouterr().err
    # Refused before writing: the sidecar is byte-identical.
    assert sidecar_copy.read_text() == "height,parent_median_time_past\n"


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_scratch_output_skips_self_contained_validation(
    tmp_path: Path,
) -> None:
    # Diagnostic mode: a scratch --output (not the committed path) skips the
    # self-contained re-derivation, so a row with a false claim still writes.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_scratch_skips_validation_under_test",
    )
    header_hex, block_hash = _self_consistent_header()
    export = {
        "height": 999999,
        "hash": block_hash,
        "btc_prev_hash": "11" * 32,
        "btc_header_hex": header_hex,
        "expected_nbits": "17021369",
        "coinbase_height": 999999,
        "coinbase_scriptsig_hex": "03" + (999999).to_bytes(3, "little").hex() + "00",
        "source_chains": "namecoin",
        "source_child_observations": "namecoin:1",
        "rejection_reason": "bip65_block_version_below_4",
        "first_observed_child_time": 1700000100,
        "provenance": "monitor-live-capture:namecoin:1",
    }
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))
    out = tmp_path / "error_blocks.csv"

    rc = module.main(["--monitor-export", str(export_path), "--output", str(out)])

    assert rc == 0
    assert out.exists()


def test_error_block_is_a_documented_classification() -> None:
    text = (REPO / "docs" / "data-reference.md").read_text()
    assert "`error_block`" in text
    assert "consensus-invalid" in text


# A bits value whose target is so large any header hash passes (exp 0x21),
# registered in a fake epoch-table entry so the validator's canonical-target
# and epoch-table checks accept the synthetic header without grinding real
# proof of work.
_EASY_BITS = "2100ffff"
_FAKE_EPOCH_START = 961632  # first epoch start beyond the committed table
_FAKE_EPOCH_HEIGHT = _FAKE_EPOCH_START + 5


def _easy_header() -> tuple[str, str]:
    """Return (header_hex, display_hash) at the trivially-met _EASY_BITS target."""
    header = (
        (4).to_bytes(4, "little")
        + b"\x11" * 32  # prev hash
        + b"\x22" * 32  # merkle root
        + (1_700_000_000).to_bytes(4, "little")  # time
        + bytes.fromhex(_EASY_BITS)[::-1]  # nBits is little-endian in the header
        + (42).to_bytes(4, "little")  # nonce
    )
    assert len(header) == 80
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return header.hex(), digest[::-1].hex()


def _time_below_mtp_export(block_hash: str, header_hex: str) -> dict[str, object]:
    return {
        "height": _FAKE_EPOCH_HEIGHT,
        "hash": block_hash,
        "btc_prev_hash": "11" * 32,
        "btc_header_hex": header_hex,
        "expected_nbits": _EASY_BITS,
        "coinbase_height": _FAKE_EPOCH_HEIGHT,
        "coinbase_scriptsig_hex": "03"
        + (_FAKE_EPOCH_HEIGHT).to_bytes(3, "little").hex()
        + "00",
        "source_chains": "namecoin",
        "source_child_observations": "namecoin:1",
        # The header nTime (1700000000) is NOT greater than the parent MTP
        # (1700000000): time_below_mtp re-derives from the bytes.
        "rejection_reason": "time_below_mtp",
        "first_observed_child_time": 1700000100,
        "parent_median_time_past": 1700000000,
        "provenance": "monitor-live-capture:namecoin:1",
    }


def _patch_nbits_table_with_fake_epoch(
    module: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Extend the real epoch table with one trivially-easy fake epoch.

    The committed self-contained rows (717696, 946213) keep their real epoch
    entries; the synthetic test row's expected_nbits matches the fake entry.
    """
    import validate_error_blocks

    real_table = validate_error_blocks._load_nbits_by_epoch()
    monkeypatch.setattr(
        validate_error_blocks,
        "_load_nbits_by_epoch",
        lambda: {**real_table, _FAKE_EPOCH_START: int(_EASY_BITS, 16)},
    )


def _multi_rule_header() -> tuple[str, str]:
    """Return (header_hex, display_hash) for a BIP66-era version-2 header.

    The header is version 2 at a [BIP66, BIP65) height, so BOTH
    bip66_block_version_below_3 and (with an over-100-byte scriptSig)
    coinbase_scriptsig_length_above_100 re-derive from the bytes. The bits
    are the trivially-met _EASY_BITS so the synthetic header passes PoW
    against the fake epoch-table entry.
    """
    header = (
        (2).to_bytes(4, "little", signed=True)
        + b"\x11" * 32  # prev hash
        + b"\x22" * 32  # merkle root
        + (1_700_000_000).to_bytes(4, "little")  # time
        + bytes.fromhex(_EASY_BITS)[::-1]  # nBits is little-endian in the header
        + (42).to_bytes(4, "little")  # nonce
    )
    assert len(header) == 80
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return header.hex(), digest[::-1].hex()


# A BIP66-era height ([BIP66_HEIGHT, BIP65_HEIGHT)) inside the fake epoch, so
# the version-2 header violates the version-3 minimum and the fake epoch-table
# entry covers the expected_nbits check.
_MULTI_RULE_HEIGHT = max(BIP66_HEIGHT, _FAKE_EPOCH_START) + 1
# A 101-byte scriptSig: over the 100-byte consensus limit, so
# coinbase_scriptsig_length_above_100 re-derives.
_OVERLONG_SCRIPTSIG = (
    "03" + _MULTI_RULE_HEIGHT.to_bytes(3, "little").hex()
) + "00" * 97


def _multi_rule_export(block_hash: str, header_hex: str) -> dict[str, object]:
    return {
        "height": _MULTI_RULE_HEIGHT,
        "hash": block_hash,
        "btc_prev_hash": "11" * 32,
        "btc_header_hex": header_hex,
        "expected_nbits": _EASY_BITS,
        "coinbase_height": _MULTI_RULE_HEIGHT,
        "coinbase_scriptsig_hex": _OVERLONG_SCRIPTSIG,
        "source_chains": "namecoin",
        "source_child_observations": "namecoin:1",
        # Primary (first) rule; the full set is carried in rules_violated.
        "rejection_reason": "bip66_block_version_below_3",
        "rules_violated": (
            "bip66_block_version_below_3|coinbase_scriptsig_length_above_100"
        ),
        "first_observed_child_time": 1700000100,
        "provenance": "monitor-live-capture:namecoin:1",
    }


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_preserves_multi_rule_rules_violated_for_self_contained_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A self-contained row carrying a multi-rule rules_violated where BOTH
    # rules re-derive from the bytes: the full pipe-joined set is preserved in
    # the output (rejection_reason stays the primary/first rule), and the
    # committed-dataset write validates every rule in the set.
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_multi_rule_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _multi_rule_header()
    export = _multi_rule_export(block_hash, header_hex)
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))
    out = tmp_path / "error_blocks.csv"

    rc = module.main(["--monitor-export", str(export_path), "--output", str(out)])

    assert rc == 0
    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))
    merged = [r for r in rows if r["height"] == str(_MULTI_RULE_HEIGHT)]
    assert len(merged) == 1
    row = merged[0]
    assert row["rejection_reason"] == "bip66_block_version_below_3"
    assert (
        row["rules_violated"]
        == "bip66_block_version_below_3|coinbase_scriptsig_length_above_100"
    )


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_fails_closed_when_a_secondary_rule_does_not_rederive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A self-contained row whose rules_violated carries a SECONDARY rule that
    # does NOT re-derive from the bytes (a 2-byte scriptSig is within the
    # 2..100 consensus range, so coinbase_scriptsig_length_above_100 is false):
    # the committed-dataset write must fail closed (non-zero, no write).
    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_multi_rule_fail_closed_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _multi_rule_header()
    export = _multi_rule_export(block_hash, header_hex)
    # A 2-byte scriptSig: within range, so the length-above-100 claim is false.
    export["coinbase_scriptsig_hex"] = "0100"
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))

    committed_before = ERROR_BLOCKS_CSV.read_bytes()
    rc = module.main(["--monitor-export", str(export_path)])
    committed_after = ERROR_BLOCKS_CSV.read_bytes()

    assert rc == 1
    err = capsys.readouterr().err
    assert "self-contained row failed validation" in err
    assert "coinbase_scriptsig_length_above_100 did not re-derive" in err
    assert committed_before == committed_after


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_commits_new_time_below_mtp_row_with_mtp_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: a NEW monitor time_below_mtp row carries its MTP context in
    # the export, but update_mtp_context() only adds it to the committed
    # sidecar AFTER validation. Validation must run against an in-memory merge
    # of the committed sidecar plus the new row's context, or a new
    # time_below_mtp row can never be committed. The committed files are
    # snapshot-restored around the committed-path write.
    from stale_blocks_analysis.config import ERROR_BLOCKS_MTP_CONTEXT_CSV

    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_new_time_row_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _easy_header()
    export = _time_below_mtp_export(block_hash, header_hex)
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))

    dataset_before = ERROR_BLOCKS_CSV.read_bytes()
    sidecar_before = ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes()
    try:
        rc = module.main(["--monitor-export", str(export_path)])

        assert rc == 0
        with ERROR_BLOCKS_CSV.open(newline="") as f:
            rows = list(csv.DictReader(f))
        merged = [r for r in rows if r["height"] == str(_FAKE_EPOCH_HEIGHT)]
        assert len(merged) == 1
        assert merged[0]["hash"] == block_hash
        assert merged[0]["rules_violated"] == "time_below_mtp"
        assert len(rows) == 34
        with ERROR_BLOCKS_MTP_CONTEXT_CSV.open(newline="") as f:
            sidecar = {
                (r["height"], r["hash"]): r["parent_median_time_past"]
                for r in csv.DictReader(f)
            }
        assert sidecar[(str(_FAKE_EPOCH_HEIGHT), block_hash)] == "1700000000"
    finally:
        ERROR_BLOCKS_CSV.write_bytes(dataset_before)
        ERROR_BLOCKS_MTP_CONTEXT_CSV.write_bytes(sidecar_before)


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_fails_closed_on_time_below_mtp_row_without_mtp_context(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A time_below_mtp row whose export carries no parent_median_time_past has
    # no MTP context anywhere: the in-memory merge adds nothing, the committed
    # sidecar lacks the key, and the build fails closed (no write).
    from stale_blocks_analysis.config import ERROR_BLOCKS_MTP_CONTEXT_CSV

    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_time_row_no_mtp_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _easy_header()
    export = _time_below_mtp_export(block_hash, header_hex)
    del export["parent_median_time_past"]
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))

    dataset_before = ERROR_BLOCKS_CSV.read_bytes()
    sidecar_before = ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes()
    rc = module.main(["--monitor-export", str(export_path)])

    assert rc == 1
    err = capsys.readouterr().err
    assert "self-contained row failed validation" in err
    assert "no committed MTP context" in err
    assert ERROR_BLOCKS_CSV.read_bytes() == dataset_before
    assert ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes() == sidecar_before


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_commits_extra_rows_time_below_mtp_row_with_mtp_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: an --extra-rows time_below_mtp row carries its MTP context in
    # the payload, but update_mtp_context() was only called for the
    # --monitor-export path, so the extra-rows row's context never reached the
    # committed sidecar — the dataset CSV could be written while its new
    # time-rule row had no committed MTP context, and the committed-dataset
    # validator would then FAIL that row. The sidecar update must cover ANY
    # self-contained row (monitor OR extra-rows) carrying a
    # parent_median_time_past. The committed files are snapshot-restored
    # around the committed-path write.
    from stale_blocks_analysis.config import ERROR_BLOCKS_MTP_CONTEXT_CSV

    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_extra_rows_time_row_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _easy_header()
    extra_row = _time_below_mtp_export(block_hash, header_hex)
    # A sweep-found extra-row's provenance (still a self-contained row).
    extra_row["provenance"] = "sweep-rejected-rows:namecoin:namecoin_stale_blocks.csv"
    extra_path = tmp_path / "extra_rows.json"
    extra_path.write_text(json.dumps([extra_row]))

    dataset_before = ERROR_BLOCKS_CSV.read_bytes()
    sidecar_before = ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes()
    try:
        rc = module.main(["--extra-rows", str(extra_path)])

        assert rc == 0
        # The dataset row is written...
        with ERROR_BLOCKS_CSV.open(newline="") as f:
            rows = list(csv.DictReader(f))
        merged = [r for r in rows if r["height"] == str(_FAKE_EPOCH_HEIGHT)]
        assert len(merged) == 1
        assert merged[0]["hash"] == block_hash
        assert merged[0]["rules_violated"] == "time_below_mtp"
        assert len(rows) == 34
        # ...AND the sidecar entry is written for the extra-rows row.
        with ERROR_BLOCKS_MTP_CONTEXT_CSV.open(newline="") as f:
            sidecar = {
                (r["height"], r["hash"]): r["parent_median_time_past"]
                for r in csv.DictReader(f)
            }
        assert sidecar[(str(_FAKE_EPOCH_HEIGHT), block_hash)] == "1700000000"
        # The committed-dataset validator then passes on the resulting CSV.
        import validate_error_blocks

        assert validate_error_blocks.validate_dataset(ERROR_BLOCKS_CSV) == []
    finally:
        ERROR_BLOCKS_CSV.write_bytes(dataset_before)
        ERROR_BLOCKS_MTP_CONTEXT_CSV.write_bytes(sidecar_before)


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
@pytest.mark.parametrize(
    "provenance",
    [
        "sweep-version-bip:namecoin:namecoin_stale_blocks.csv",
        "sweep-time-rule:namecoin:namecoin_stale_blocks.csv",
    ],
    ids=["sweep-version-bip", "sweep-time-rule"],
)
def test_builder_extra_row_with_sweep_provenance_persists_across_plain_rebuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, provenance: str
) -> None:
    # Regression: a row added via --extra-rows with a sweep-version-bip: /
    # sweep-time-rule: provenance is a self-contained row, so it must persist
    # across a PLAIN rebuild (no --extra-rows): the rebuild recognizes the
    # committed row's provenance prefix and passes it through, producing
    # byte-identical output including the row. The committed files are
    # snapshot-restored around the committed-path writes.
    from stale_blocks_analysis.config import ERROR_BLOCKS_MTP_CONTEXT_CSV

    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_sweep_provenance_persistence_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _easy_header()
    extra_row = _time_below_mtp_export(block_hash, header_hex)
    extra_row["provenance"] = provenance
    extra_path = tmp_path / "extra_rows.json"
    extra_path.write_text(json.dumps([extra_row]))

    dataset_before = ERROR_BLOCKS_CSV.read_bytes()
    sidecar_before = ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes()
    try:
        # Ingest the extra row (writes the committed dataset)...
        rc = module.main(["--extra-rows", str(extra_path)])
        assert rc == 0
        with ERROR_BLOCKS_CSV.open(newline="") as f:
            rows = list(csv.DictReader(f))
        merged = [r for r in rows if r["height"] == str(_FAKE_EPOCH_HEIGHT)]
        assert len(merged) == 1
        assert merged[0]["provenance"] == provenance
        ingested = ERROR_BLOCKS_CSV.read_bytes()
        # ...then a PLAIN rebuild (no --extra-rows) must keep the row:
        # byte-identical output.
        rc = module.main([])
        assert rc == 0
        assert ERROR_BLOCKS_CSV.read_bytes() == ingested
    finally:
        ERROR_BLOCKS_CSV.write_bytes(dataset_before)
        ERROR_BLOCKS_MTP_CONTEXT_CSV.write_bytes(sidecar_before)


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_committed_write_is_atomic_when_mtp_sidecar_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: the committed-path write must stage the dataset AND the MTP
    # sidecar before replacing either committed file. If update_mtp_context
    # fails, the new time_below_mtp row must NOT be left in error_blocks.csv
    # without its required MTP context (the committed-dataset validator would
    # then fail that row). Simulate the sidecar update raising and assert the
    # committed dataset is still byte-identical to before.
    from stale_blocks_analysis.config import ERROR_BLOCKS_MTP_CONTEXT_CSV

    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_atomic_write_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _easy_header()
    export = _time_below_mtp_export(block_hash, header_hex)
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))

    def _failing_update_mtp_context(*args: object, **kwargs: object) -> None:
        raise OSError("simulated sidecar write failure")

    monkeypatch.setattr(module, "update_mtp_context", _failing_update_mtp_context)

    dataset_before = ERROR_BLOCKS_CSV.read_bytes()
    sidecar_before = ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes()
    try:
        with pytest.raises(OSError, match="simulated sidecar write failure"):
            module.main(["--monitor-export", str(export_path)])
        # The sidecar preparation failed, so the staged dataset temp file must
        # NOT have been committed: error_blocks.csv is byte-identical.
        assert ERROR_BLOCKS_CSV.read_bytes() == dataset_before
        assert ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes() == sidecar_before
    finally:
        ERROR_BLOCKS_CSV.write_bytes(dataset_before)
        ERROR_BLOCKS_MTP_CONTEXT_CSV.write_bytes(sidecar_before)
        # Clean up any staged temp files left behind by the simulated failure.
        for tmp in (
            ERROR_BLOCKS_CSV.with_name(ERROR_BLOCKS_CSV.name + ".tmp"),
            ERROR_BLOCKS_MTP_CONTEXT_CSV.with_name(
                ERROR_BLOCKS_MTP_CONTEXT_CSV.name + ".tmp"
            ),
        ):
            tmp.unlink(missing_ok=True)


@pytest.mark.skipif(
    not all(path.exists() for path in _BUILDER_PRIVATE_INPUTS),
    reason="private evidence archives required by the builder are not staged",
)
def test_builder_replaces_mtp_sidecar_before_dataset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: the committed-path write must os.replace the staged MTP
    # sidecar BEFORE the dataset. If the dataset were committed first and the
    # sidecar replace then failed (or the process stopped between the two),
    # error_blocks.csv would reference required MTP context that was never
    # committed, leaving the published gate invalid. Sidecar-first means a
    # failure leaves the sidecar possibly-ahead (an extra MTP entry for a
    # not-yet-committed row — harmless, since the sidecar is only read for
    # rows in the dataset) rather than the dataset referencing a missing
    # sidecar entry. Simulate the SECOND os.replace (the dataset one)
    # failing: the dataset must be unmodified while the sidecar may be
    # ahead. The committed files are snapshot-restored around the write.
    import os as _os

    from stale_blocks_analysis.config import ERROR_BLOCKS_MTP_CONTEXT_CSV

    module = _load_script(
        "scripts/prep/build_error_blocks.py",
        "build_error_blocks_sidecar_first_under_test",
    )
    _patch_nbits_table_with_fake_epoch(module, monkeypatch)
    header_hex, block_hash = _easy_header()
    export = _time_below_mtp_export(block_hash, header_hex)
    export_path = tmp_path / "monitor_export.json"
    export_path.write_text(json.dumps(export))

    replace_calls: list[Path] = []
    real_replace = _os.replace

    def _recording_replace(src: Path, dst: Path) -> None:
        replace_calls.append(Path(dst))
        if len(replace_calls) == 2:
            raise OSError("simulated dataset replace failure")
        real_replace(src, dst)

    monkeypatch.setattr(module.os, "replace", _recording_replace)

    dataset_before = ERROR_BLOCKS_CSV.read_bytes()
    sidecar_before = ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes()
    try:
        with pytest.raises(OSError, match="simulated dataset replace failure"):
            module.main(["--monitor-export", str(export_path)])
        # The sidecar was replaced FIRST (the failing replace was the second
        # call, the dataset)...
        assert replace_calls == [ERROR_BLOCKS_MTP_CONTEXT_CSV, ERROR_BLOCKS_CSV]
        # ...so the dataset is unmodified (still valid: it references no
        # missing sidecar entry)...
        assert ERROR_BLOCKS_CSV.read_bytes() == dataset_before
        # ...while the sidecar is ahead, carrying the not-yet-committed row's
        # MTP entry (harmless: it is only read for rows in the dataset).
        with ERROR_BLOCKS_MTP_CONTEXT_CSV.open(newline="") as f:
            sidecar = {
                (r["height"], r["hash"]): r["parent_median_time_past"]
                for r in csv.DictReader(f)
            }
        assert sidecar[(str(_FAKE_EPOCH_HEIGHT), block_hash)] == "1700000000"
    finally:
        ERROR_BLOCKS_CSV.write_bytes(dataset_before)
        ERROR_BLOCKS_MTP_CONTEXT_CSV.write_bytes(sidecar_before)
        # Clean up any staged temp files left behind by the simulated failure.
        for tmp in (
            ERROR_BLOCKS_CSV.with_name(ERROR_BLOCKS_CSV.name + ".tmp"),
            ERROR_BLOCKS_MTP_CONTEXT_CSV.with_name(
                ERROR_BLOCKS_MTP_CONTEXT_CSV.name + ".tmp"
            ),
        ):
            tmp.unlink(missing_ok=True)


# ── Migrated from tests/test_stale_exclusions.py ─────────────────────────────
# The stale-exclusions overlay is gone (replaced by this error-blocks dataset),
# so its pinning test file was deleted. The tests below are NOT overlay-owned:
# they are the child-header-hydration and stale-descendant-reconciliation
# coverage that main added to that file. They are preserved here because this
# module already hosts their sibling reconcile/monitor tests and helpers.


@pytest.mark.dataset
def test_published_monitor_exact_descendant_rows_preserve_child_identity() -> None:
    # The committed monitor snapshot predates the exact chain/height/hash join.
    # The full-inventory publication preflight enforces completeness when it is
    # rebuilt (including the height-mismatch regression in the CLI tests); this
    # fixture instead verifies the stable properties of snapshot rows whose
    # complete identity can be established from the committed data.
    expected = load_stale_descendant_observation_keys()
    represented: set[tuple[str, int, str]] = set()
    for path in sorted(
        (REPO / "results" / "monitor-evidence").glob("*_monitor_evidence.csv")
    ):
        with path.open(newline="") as handle:
            for row in csv.DictReader(handle):
                if row.get("relevance_reason") != "valid_stale_descendant":
                    continue
                height = row.get("btc_height", "")
                if not height:
                    # Legacy committed monitor exports predate the exact
                    # chain/height/hash join. A source row without its Bitcoin
                    # height cannot represent a sidecar observation; a fresh
                    # export now omits it rather than matching on hash alone.
                    continue
                observation_key = (
                    row["chain"],
                    int(height),
                    row["btc_header_hash"].lower(),
                )
                if observation_key in expected:
                    assert row["validation_status"] == "VALID_STALE_DESCENDANT", (
                        path,
                        observation_key,
                    )
                    assert len(row["child_block_hash"]) == 64, (path, observation_key)
                    assert row["child_block_time"].isdigit(), (path, observation_key)
                    represented.add(observation_key)

    assert represented


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
                expected = (
                    "VALID_STALE_DESCENDANT"
                    if row.get("relevance_reason") == "valid_stale_descendant"
                    else ""
                )
                assert row.get("validation_status") == expected, (path, row_number)
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
