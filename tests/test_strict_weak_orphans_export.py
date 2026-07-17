"""Unit tests for scripts/reports/build_strict_weak_orphans.py."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts" / "reports"))

from build_strict_weak_orphans import build_strict_weak_exports  # noqa: E402

FIELDS = [
    "chain",
    "artifact_scope",
    "child_height",
    "btc_height",
    "btc_header_hash",
    "classification",
    "validation_status",
    "btc_stale_relevance",
    "relevance_reason",
]


def _write_export(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_counts(path: Path, rows: list[dict[str, str]]) -> None:
    fields = ["chain", "artifact_scope"]
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _row(
    chain: str, classification: str, relevance: str, **extra: str
) -> dict[str, str]:
    row = {
        "chain": chain,
        "artifact_scope": "full_classifier_inventory",
        "child_height": "1",
        "btc_height": "250000",
        "btc_header_hash": "aa" * 32,
        "classification": classification,
        "validation_status": "",
        "btc_stale_relevance": relevance,
        "relevance_reason": "",
    }
    row.update(extra)
    return row


def test_per_chain_files_keep_only_unknown_rows(tmp_path: Path) -> None:
    me_dir = tmp_path / "monitor-evidence"
    me_dir.mkdir()
    _write_export(
        me_dir / "namecoin_monitor_evidence.csv",
        [
            _row("namecoin", "stale", "", relevance_reason="valid_direct_stale"),
            _row(
                "namecoin",
                "unknown",
                "strict_btc_orphan",
                btc_header_hash="bb" * 32,
                relevance_reason="strict_height_nbits_match",
            ),
            _row(
                "namecoin",
                "unknown",
                "weak_btc_orphan",
                btc_header_hash="cc" * 32,
                btc_height="300000",
                relevance_reason="timestamp_epoch_nbits_match",
            ),
        ],
    )
    _write_export(
        me_dir / "geistgeld_monitor_evidence.csv",
        [],
    )
    _write_export(
        me_dir / "vcash_monitor_evidence.csv",
        [
            _row(
                "vcash",
                "canonical",
                "",
                artifact_scope="partial_canonical_subset",
            )
        ],
    )
    _write_export(
        me_dir / "hathor_monitor_evidence.csv",
        [
            _row(
                "hathor",
                "stale",
                "",
                artifact_scope="stale_only_publication",
            )
        ],
    )
    _write_counts(
        me_dir / "monitor-evidence-counts.csv",
        [
            {"chain": "namecoin", "artifact_scope": "full_inventory"},
            {"chain": "hathor", "artifact_scope": "stale_only_publication"},
            {"chain": "geistgeld", "artifact_scope": "full_classifier_inventory"},
        ],
    )
    # The stale-descendants sidecar must be ignored, not given a file.
    _write_export(
        me_dir / "stale-descendants_monitor_evidence.csv",
        [
            _row(
                "stale-descendants",
                "stale_descendant",
                "",
                relevance_reason="valid_stale_descendant",
            )
        ],
    )
    output_dir = tmp_path / "out"

    counts = build_strict_weak_exports(me_dir, output_dir)

    with (output_dir / "namecoin_strict_weak_orphans.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert [row["btc_stale_relevance"] for row in rows] == [
        "strict_btc_orphan",
        "weak_btc_orphan",
    ]
    assert all(row["classification"] == "unknown" for row in rows)

    # Header-only file for a chain with no admitted rows.
    with (output_dir / "geistgeld_strict_weak_orphans.csv").open(newline="") as f:
        assert list(csv.DictReader(f)) == []
    assert not (output_dir / "stale-descendants_strict_weak_orphans.csv").exists()
    assert not (output_dir / "vcash_strict_weak_orphans.csv").exists()
    assert not (output_dir / "hathor_strict_weak_orphans.csv").exists()

    assert counts["namecoin"] == {
        "strict_btc_orphan": 1,
        "weak_btc_orphan": 1,
        "total": 2,
    }
    assert counts["geistgeld"]["total"] == 0

    with (output_dir / "strict-weak-orphans-counts.csv").open(newline="") as f:
        count_rows = {row["chain"]: row for row in csv.DictReader(f)}
    assert count_rows["namecoin"]["total"] == "2"
    assert count_rows["geistgeld"]["total"] == "0"
    assert "vcash" not in count_rows
    assert "hathor" not in count_rows


def test_unknown_row_without_verdict_fails_loudly(tmp_path: Path) -> None:
    me_dir = tmp_path / "monitor-evidence"
    me_dir.mkdir()
    _write_export(
        me_dir / "devcoin_monitor_evidence.csv",
        [_row("devcoin", "unknown", "")],
    )

    with pytest.raises(SystemExit, match="inconsistent"):
        build_strict_weak_exports(me_dir, tmp_path / "out")


def test_stale_only_export_is_omitted_without_counts_sidecar(tmp_path: Path) -> None:
    me_dir = tmp_path / "monitor-evidence"
    me_dir.mkdir()
    _write_export(
        me_dir / "hathor_monitor_evidence.csv",
        [
            _row(
                "hathor",
                "stale",
                "",
                artifact_scope="stale_only_publication",
            )
        ],
    )

    counts = build_strict_weak_exports(me_dir, tmp_path / "out")

    assert "hathor" not in counts
    assert not (tmp_path / "out" / "hathor_strict_weak_orphans.csv").exists()


def test_empty_export_without_counts_sidecar_fails_closed(tmp_path: Path) -> None:
    me_dir = tmp_path / "monitor-evidence"
    me_dir.mkdir()
    _write_export(me_dir / "hathor_monitor_evidence.csv", [])
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    stale_output = output_dir / "hathor_strict_weak_orphans.csv"
    _write_export(stale_output, [])

    with pytest.raises(SystemExit, match="empty export requires"):
        build_strict_weak_exports(me_dir, output_dir)

    assert not stale_output.exists()
