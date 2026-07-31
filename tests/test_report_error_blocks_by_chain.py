"""Offline unit tests for the per-chain error-block observation views.

The generator re-splits the consolidated dataset into one CSV per witnessing
chain. These tests run fully offline against a synthetic dataset and a
disposable output directory.
"""

from __future__ import annotations

import csv
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _load_report():
    spec = importlib.util.spec_from_file_location(
        "report_error_blocks_by_chain_under_test",
        REPO / "scripts" / "reports" / "report_error_blocks_by_chain.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


report = _load_report()

FIELDS = [
    "height",
    "hash",
    "source_chains",
    "source_child_observations",
]


def _dataset(path: Path, rows: list[dict[str, str]]) -> Path:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _row(height: str, block_hash: str, chains: str, observations: str):
    return {
        "height": height,
        "hash": block_hash,
        "source_chains": chains,
        "source_child_observations": observations,
    }


def test_stale_chain_csv_is_removed_when_chain_loses_last_observation(
    tmp_path: Path,
) -> None:
    dataset = tmp_path / "error_blocks.csv"
    out_dir = tmp_path / "by-chain"

    # First regeneration: two chains each witness a row.
    _dataset(
        dataset,
        [
            _row("100", "aa" * 32, "namecoin", "namecoin:50"),
            _row("101", "bb" * 32, "devcoin", "devcoin:60"),
        ],
    )
    counts = report.build_by_chain_views(dataset, out_dir)
    assert counts == {"namecoin": 1, "devcoin": 1}
    assert (out_dir / "namecoin_error_blocks.csv").exists()
    assert (out_dir / "devcoin_error_blocks.csv").exists()

    # Second regeneration: devcoin lost its only observation. Its old
    # generated CSV must not survive — the directory is a faithful re-split.
    _dataset(
        dataset,
        [_row("100", "aa" * 32, "namecoin", "namecoin:50")],
    )
    counts = report.build_by_chain_views(dataset, out_dir)
    assert counts == {"namecoin": 1}
    assert (out_dir / "namecoin_error_blocks.csv").exists()
    assert not (out_dir / "devcoin_error_blocks.csv").exists()
    # No staging temp dir is left behind.
    assert not any(
        p.name.startswith(f".{out_dir.name}.tmp-") for p in out_dir.parent.iterdir()
    )


def test_chain_observation_column_is_surfaced(tmp_path: Path) -> None:
    dataset = tmp_path / "error_blocks.csv"
    out_dir = tmp_path / "by-chain"
    _dataset(
        dataset,
        [
            _row(
                "100",
                "aa" * 32,
                "namecoin|devcoin",
                "namecoin:50|devcoin:60",
            )
        ],
    )
    counts = report.build_by_chain_views(dataset, out_dir)
    assert counts == {"namecoin": 1, "devcoin": 1}
    with (out_dir / "devcoin_error_blocks.csv").open(newline="") as f:
        row = next(csv.DictReader(f))
    assert row[report.CHAIN_OBSERVATION_FIELD] == "60"


def test_refuses_to_rmtree_directory_with_non_generated_content(
    tmp_path: Path,
) -> None:
    import pytest

    dataset = tmp_path / "error_blocks.csv"
    _dataset(dataset, [_row("100", "aa" * 32, "namecoin", "namecoin:50")])

    # An existing directory holding a non-generated file must NOT be deleted:
    # regeneration refuses and leaves the content untouched.
    out_dir = tmp_path / "by-chain"
    out_dir.mkdir()
    keep = out_dir / "keepme.txt"
    keep.write_text("precious")
    with pytest.raises(ValueError, match="refusing to replace"):
        report.build_by_chain_views(dataset, out_dir)
    assert keep.read_text() == "precious"

    # A directory holding only previously-generated view files IS replaced.
    out_dir2 = tmp_path / "views"
    out_dir2.mkdir()
    (out_dir2 / "stale_chain_error_blocks.csv").write_text("old")
    counts = report.build_by_chain_views(dataset, out_dir2)
    assert counts == {"namecoin": 1}
    assert (out_dir2 / "namecoin_error_blocks.csv").exists()
    assert not (out_dir2 / "stale_chain_error_blocks.csv").exists()


def test_refuses_to_rmtree_worktree_dot_output_dir(tmp_path: Path) -> None:
    import pytest

    dataset = tmp_path / "error_blocks.csv"
    _dataset(dataset, [_row("100", "aa" * 32, "namecoin", "namecoin:50")])

    # `--output-dir .` resolves to an existing directory that is not the
    # recognized generated-views dir and holds non-generated content (the
    # dataset file itself): regeneration must refuse, not delete.
    cwd = tmp_path
    with pytest.raises(ValueError, match="refusing to replace"):
        report.build_by_chain_views(dataset, cwd)
    assert dataset.exists()


def test_precreated_empty_output_dir_is_safe_to_replace(tmp_path: Path) -> None:
    import pytest

    dataset = tmp_path / "error_blocks.csv"
    _dataset(dataset, [_row("100", "aa" * 32, "namecoin", "namecoin:50")])

    # A pre-created but EMPTY output directory is a normal first-run state
    # with no content to protect: regeneration succeeds (not refused).
    out_dir = tmp_path / "by-chain"
    out_dir.mkdir()
    counts = report.build_by_chain_views(dataset, out_dir)
    assert counts == {"namecoin": 1}
    assert (out_dir / "namecoin_error_blocks.csv").exists()

    # A directory holding any non-generated content is still refused.
    keep = out_dir / "keepme.txt"
    keep.write_text("precious")
    with pytest.raises(ValueError, match="refusing to replace"):
        report.build_by_chain_views(dataset, out_dir)
    assert keep.read_text() == "precious"


def test_default_output_dir_is_guarded_too(tmp_path: Path, monkeypatch) -> None:
    import pytest

    # Regression: the generated-content guard applies to the DEFAULT output
    # dir, not just custom --output-dir values. A non-generated file placed
    # under the default by-chain dir must stop regeneration (previously the
    # default dir was treated as safe regardless of its contents and the
    # file was silently rmtree'd).
    dataset = tmp_path / "error_blocks.csv"
    _dataset(dataset, [_row("100", "aa" * 32, "namecoin", "namecoin:50")])
    default_dir = tmp_path / "results" / "analysis" / "error-blocks" / "by-chain"
    default_dir.mkdir(parents=True)
    monkeypatch.setattr(report, "DEFAULT_OUTPUT_DIR", default_dir)

    keep = default_dir / "keepme.txt"
    keep.write_text("precious")
    with pytest.raises(ValueError, match="refusing to replace"):
        report.main(["--dataset", str(dataset)])
    assert keep.read_text() == "precious"

    # The normal case — the default dir holds only previously-generated view
    # files — still regenerates.
    keep.unlink()
    (default_dir / "stale_chain_error_blocks.csv").write_text("old")
    rc = report.main(["--dataset", str(dataset)])
    assert rc == 0
    assert (default_dir / "namecoin_error_blocks.csv").exists()
    assert not (default_dir / "stale_chain_error_blocks.csv").exists()
