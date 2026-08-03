"""Publication-safety tests for unknown-stale ancestry reconciliation."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "analysis" / "reconcile_unknown_stale_ancestry.py"
BASELINE_HASH = "11" * 32


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "reconcile_unknown_stale_ancestry_guard_test", SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_baseline(
    path: Path,
    *,
    observed_chains: str = "namecoin",
    unknown_rows: int = 1,
    source_rows: str = "namecoin:data/namecoin_unknown_blocks.csv:2",
    validation_status: str = "VALID_STALE_DESCENDANT",
) -> str:
    content = (
        "classification,validation_status,btc_header_hash,observed_chains,"
        "unknown_rows,source_rows\n"
        f"stale_descendant,{validation_status},{BASELINE_HASH},{observed_chains},"
        f"{unknown_rows},{source_rows}\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return content


def _set_publication_paths(module, monkeypatch, tmp_path: Path) -> tuple[Path, Path]:
    promoted = tmp_path / "publication" / "stale_descendants.csv"
    results = tmp_path / "publication-results"
    monkeypatch.setattr(module, "PROMOTED_CSV", promoted)
    monkeypatch.setattr(module, "RESULTS_DIR", results)
    return promoted, results


def test_promoted_evidence_never_stitches_coinbase_observations() -> None:
    module = _load_module()
    common = {
        "chain": "namecoin",
        "source_path": "<archive>/namecoin.csv",
        "block_hash": BASELINE_HASH,
        "btc_height": "100",
        "child_height": "200",
        "header_hex": "",
    }
    observations = [
        module.UnknownObservation(
            **common,
            row_number=2,
            prev_hash="22" * 32,
            btc_time="1",
            bits="1d00ffff",
            scriptsig_hex="03aabb",
            outputs="",
        ),
        module.UnknownObservation(
            **common,
            row_number=3,
            prev_hash="33" * 32,
            btc_time="2",
            bits="1b0404cb",
            scriptsig_hex="",
            outputs="76a91400",
        ),
    ]

    selected = module.select_promoted_evidence(observations, "00" * 80)

    assert selected == (
        "00" * 80,
        "22" * 32,
        "1",
        "1d00ffff",
        "03aabb",
        "",
    )


def test_descendant_notes_preserve_valid_baseline_audit_evidence(
    tmp_path: Path,
) -> None:
    module = _load_module()
    baseline_path = tmp_path / "stale_descendants.csv"
    baseline_path.write_text(
        "classification,validation_status,btc_header_hash,observed_chains,"
        "unknown_rows,source_rows,notes\n"
        f"stale_descendant,VALID_STALE_DESCENDANT,{BASELINE_HASH},namecoin,1,"
        "namecoin:data/namecoin_unknown_blocks.csv:2,"
        "reclassified_from_direct_stale;branch_mtp=1;old_validation_failure\n"
    )
    baseline = module.load_publication_baseline(baseline_path)

    assert module.descendant_notes(BASELINE_HASH, [], baseline) == (
        "reclassified_from_direct_stale;branch_mtp=1"
    )
    assert module.descendant_notes(
        BASELINE_HASH, ["pow_target_mismatch"], baseline
    ) == ("pow_target_mismatch")


def test_publication_mode_rejects_missing_baseline_chain_inventories_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_module()
    promoted, results = _set_publication_paths(module, monkeypatch, tmp_path)
    baseline = _write_baseline(promoted)
    data_dir = tmp_path / "empty-data"
    data_dir.mkdir()

    with pytest.raises(SystemExit, match="2"):
        module.main(
            [
                "--data-dir",
                str(data_dir),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--epoch-reference-dir",
                str(tmp_path / "epochs"),
            ]
        )

    assert "missing full/unknown inventories" in capsys.readouterr().err
    assert promoted.read_text() == baseline
    assert not results.exists()


def test_publication_mode_rejects_computed_descendant_regression_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_module()
    promoted, results = _set_publication_paths(module, monkeypatch, tmp_path)
    baseline = _write_baseline(promoted)
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "namecoin_unknown_blocks.csv").write_text(
        "btc_header_hash,btc_prev_hash,classification\n"
    )

    with pytest.raises(SystemExit, match="2"):
        module.main(
            [
                "--data-dir",
                str(data_dir),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--epoch-reference-dir",
                str(tmp_path / "epochs"),
            ]
        )

    assert "missing 1 committed descendant hashes" in capsys.readouterr().err
    assert promoted.read_text() == baseline
    assert not results.exists()


def test_publication_mode_rejects_overlapping_hash_with_reduced_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_module()
    promoted, results = _set_publication_paths(module, monkeypatch, tmp_path)
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    alpha_inventory = data_dir / "alpha_unknown_blocks.csv"
    beta_inventory = data_dir / "beta_unknown_blocks.csv"
    alpha_inventory.write_text("btc_header_hash,btc_prev_hash,classification\n")
    beta_inventory.write_text(
        "btc_header_hash,btc_prev_hash,classification\n"
        f"{BASELINE_HASH},{'22' * 32},unknown\n"
    )
    validated_dir = data_dir / "validated-stales"
    validated_dir.mkdir()
    (validated_dir / "gamma_validated_stales.csv").write_text(
        "btc_height,btc_header_hash,btc_prev_hash,classification,validation_status\n"
        f"100,{'22' * 32},{'11' * 32},stale,VALID\n"
    )
    baseline = _write_baseline(
        promoted,
        observed_chains="alpha|beta",
        unknown_rows=2,
        source_rows=(f"alpha:{alpha_inventory}:2|beta:{beta_inventory}:2"),
        validation_status="REJECTED_missing_header_hex|pow_target_mismatch",
    )

    with pytest.raises(SystemExit, match="2"):
        module.main(
            [
                "--data-dir",
                str(data_dir),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--epoch-reference-dir",
                str(tmp_path / "epochs"),
            ]
        )

    error = capsys.readouterr().err
    assert "lost observed chains" in error
    assert "missing alpha" in error
    assert "lost unknown-row observations" in error
    assert "requires at least 2" in error
    assert "per-chain source-observation counts were lost" in error
    assert "missing 'alpha' x1" in error
    assert promoted.read_text() == baseline
    assert not results.exists()


def test_publication_source_row_guard_preserves_same_chain_observation_counts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_module()
    baseline_path = tmp_path / "stale_descendants.csv"
    source_token = "namecoin:data/namecoin_unknown_blocks.csv:2"
    _write_baseline(
        baseline_path,
        unknown_rows=2,
        source_rows=f"{source_token}|{source_token}",
        validation_status="REJECTED_missing_header_hex",
    )
    baseline = module.load_publication_baseline(baseline_path)
    parser = module.build_parser()

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_rows(
            [
                {
                    "btc_header_hash": BASELINE_HASH,
                    "validation_status": "REJECTED_missing_header_hex",
                    "observed_chains": "namecoin",
                    "unknown_rows": 2,
                    "source_rows": source_token,
                }
            ],
            baseline,
            parser,
        )

    error = capsys.readouterr().err
    assert "per-chain source-observation counts were lost" in error
    assert "missing 'namecoin' x1" in error


def test_publication_source_row_guard_allows_path_and_row_renumbering(
    tmp_path: Path,
) -> None:
    module = _load_module()
    baseline_path = tmp_path / "stale_descendants.csv"
    _write_baseline(
        baseline_path,
        unknown_rows=2,
        source_rows=(
            "namecoin:historical-direct-stale-publication:656478|"
            "namecoin:data/namecoin_stale_blocks.csv:273300"
        ),
        validation_status="REJECTED_missing_header_hex",
    )
    baseline = module.load_publication_baseline(baseline_path)

    module.validate_publication_rows(
        [
            {
                "btc_header_hash": BASELINE_HASH,
                "validation_status": "REJECTED_missing_header_hex",
                "observed_chains": "namecoin",
                "unknown_rows": 2,
                "source_rows": (
                    "namecoin:data/relocated_namecoin_stale_blocks.csv:17|"
                    "namecoin:data/relocated_namecoin_stale_blocks.csv:23"
                ),
            }
        ],
        baseline,
        module.build_parser(),
    )


@pytest.mark.parametrize(
    ("observed_chains", "source_rows", "message"),
    [
        ("namecoin", ":data/namecoin_stale_blocks.csv:2", "empty chain prefix"),
        (
            "namecoin",
            "ixcoin:data/ixcoin_stale_blocks.csv:2",
            "not present in observed_chains",
        ),
    ],
)
def test_publication_baseline_rejects_invalid_source_chain_prefixes(
    tmp_path: Path,
    observed_chains: str,
    source_rows: str,
    message: str,
) -> None:
    module = _load_module()
    baseline_path = tmp_path / "stale_descendants.csv"
    _write_baseline(
        baseline_path,
        observed_chains=observed_chains,
        source_rows=source_rows,
    )

    with pytest.raises(ValueError, match=message):
        module.load_publication_baseline(baseline_path)


def test_allow_partial_refuses_publication_output_defaults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_module()
    promoted, results = _set_publication_paths(module, monkeypatch, tmp_path)

    with pytest.raises(SystemExit, match="2"):
        module.main(["--allow-partial", "--data-dir", str(tmp_path / "data")])

    error = capsys.readouterr().err
    assert "--results-dir" in error
    assert "--promoted-csv" in error
    assert not promoted.exists()
    assert not results.exists()


def test_allow_partial_writes_only_to_explicit_disposable_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    results = tmp_path / "scratch-results"
    promoted = tmp_path / "scratch" / "stale_descendants.csv"

    module.main(
        [
            "--allow-partial",
            "--data-dir",
            str(data_dir),
            "--results-dir",
            str(results),
            "--promoted-csv",
            str(promoted),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--epoch-reference-dir",
            str(tmp_path / "epochs"),
        ]
    )

    captured = capsys.readouterr()
    assert "do not replace publication artifacts" in captured.err
    assert promoted.is_file()
    assert promoted.read_text().count("\n") == 1
    assert (results / module.OUTPUT_SUMMARY).is_file()
