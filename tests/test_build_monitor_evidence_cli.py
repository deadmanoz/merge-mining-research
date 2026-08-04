"""Publication-safety tests for the monitor-evidence command."""

from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "reports" / "build_monitor_evidence.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("build_monitor_evidence", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_baseline(
    baseline_dir: Path,
    *,
    chain: str,
    source_kind: str,
    canonical: int = 0,
    stale: int = 0,
    stale_descendant: int = 0,
    strict: int = 0,
    weak: int = 0,
    source_rows: int = 0,
    canonical_hashes: tuple[str, ...] | None = None,
) -> None:
    """Write the minimal committed-baseline shape needed by preflight tests."""
    baseline_dir.mkdir(parents=True)
    (baseline_dir / "monitor-evidence-counts.csv").write_text(
        "chain,source_kind,canonical,stale,stale_descendant,strict_btc_orphan,"
        "weak_btc_orphan,monitor_rows,source_rows\n"
        f"{chain},{source_kind},{canonical},{stale},{stale_descendant},{strict},"
        f"{weak},{canonical + stale + stale_descendant + strict + weak},"
        f"{source_rows}\n"
    )
    (baseline_dir / "monitor-evidence-manifest.json").write_text(
        f'{{"strict_weak_verdicts_loaded": {strict + weak}}}\n'
    )
    if canonical_hashes is None:
        canonical_hashes = tuple(f"{index:064x}" for index in range(1, canonical + 1))
    assert len(canonical_hashes) == canonical
    artifact = baseline_dir / f"{chain}_monitor_evidence.csv"
    artifact.write_text(
        "chain,btc_header_hash,classification,btc_stale_relevance\n"
        + "".join(
            f"{chain},{block_hash},canonical,\n" for block_hash in canonical_hashes
        )
    )


def _preflight_args(module, tmp_path: Path, *, data_dir: Path, archive_dir: Path):
    inventory = tmp_path / "relevance.csv"
    inventory.write_text("btc_header_hash,btc_stale_relevance,relevance_reason\n")
    parser = module.build_parser()
    args = parser.parse_args(
        [
            "--data-dir",
            str(data_dir),
            "--output-dir",
            str(tmp_path / "output"),
            "--chain-archive-dir",
            str(archive_dir),
            "--relevance-inventory",
            str(inventory),
        ]
    )
    return parser, args


def test_publication_build_refuses_missing_private_inputs_before_writing(
    tmp_path: Path,
) -> None:
    module = _load_module()
    output_dir = tmp_path / "monitor"

    with pytest.raises(SystemExit, match="2"):
        module.main(
            [
                "--data-dir",
                str(tmp_path / "data"),
                "--output-dir",
                str(output_dir),
                "--relevance-inventory",
                str(tmp_path / "missing.csv"),
            ]
        )

    assert not output_dir.exists()


def test_allow_partial_is_an_explicit_diagnostic_escape_hatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    output_dir = tmp_path / "monitor"
    output_dir.mkdir()
    unrelated = output_dir / "operator-notes.txt"
    unrelated.write_bytes(b"preserve me\n")

    module.main(
        [
            "--data-dir",
            str(tmp_path / "data"),
            "--output-dir",
            str(output_dir),
            "--relevance-inventory",
            str(tmp_path / "missing.csv"),
            "--allow-partial",
            "--skip-canonical",
        ]
    )

    assert (output_dir / "monitor-evidence-counts.csv").is_file()
    assert (output_dir / "monitor-evidence-manifest.json").is_file()
    manifest = json.loads((output_dir / "monitor-evidence-manifest.json").read_text())
    assert manifest["output_dir"] == "<external>/monitor"
    assert unrelated.read_bytes() == b"preserve me\n"
    assert list(tmp_path.glob(".monitor.monitor-build-*")) == []
    assert "do not replace committed publication artifacts" in capsys.readouterr().err


def test_allow_partial_refuses_committed_output_directory() -> None:
    module = _load_module()

    with pytest.raises(SystemExit, match="2"):
        module.main(["--allow-partial"])


def test_late_vcash_validation_failure_preserves_existing_publication_set(
    tmp_path: Path,
) -> None:
    module = _load_module()
    output_dir = tmp_path / "monitor"
    output_dir.mkdir()
    existing = {
        "namecoin_monitor_evidence.csv": b"existing artifact\n",
        "monitor-evidence-counts.csv": b"existing counts\n",
        "monitor-evidence-manifest.json": b"existing manifest\n",
        "operator-notes.txt": b"unrelated file\n",
    }
    for name, content in existing.items():
        (output_dir / name).write_bytes(content)

    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text(
        "btc_height,btc_header_hash,classification,validation_status\n"
        f"1,{'11' * 32},stale,VALID\n"
    )

    vcash_source = data_dir / "vcash_canonical_blocks.csv"
    with vcash_source.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "child_height",
                "child_block_hash",
                "child_header_hex",
                "child_block_time",
                "child_nbits",
                "btc_header_hash",
                "classification",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "child_height": "1",
                "child_block_hash": "11" * 32,
                "child_header_hex": "00" * 80,
                "child_block_time": "0",
                "child_nbits": "00000000",
                "btc_header_hash": "22" * 32,
                "classification": "canonical",
            }
        )

    with pytest.raises(ValueError, match="does not match child_block_hash"):
        module.main(
            [
                "--allow-partial",
                "--data-dir",
                str(data_dir),
                "--output-dir",
                str(output_dir),
                "--relevance-inventory",
                str(tmp_path / "missing.csv"),
            ]
        )

    assert {path.name for path in output_dir.iterdir()} == set(existing)
    for name, content in existing.items():
        assert (output_dir / name).read_bytes() == content
    assert list(tmp_path.glob(".monitor.monitor-build-*")) == []


@pytest.mark.dataset
def test_publication_build_rejects_merely_discoverable_partial_archive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    archive_dir = tmp_path / "archive"
    source = (
        archive_dir / "chains" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    source.parent.mkdir(parents=True)
    source.write_text("btc_header_hash,classification\n")
    inventory = tmp_path / "relevance.csv"
    inventory.write_text(
        "btc_header_hash,btc_stale_relevance,relevance_reason\n"
        + "".join(
            f"{index:064x},strict_btc_orphan,strict_height_nbits_match\n"
            for index in range(1, 22)
        )
    )
    parser = module.build_parser()
    args = parser.parse_args(
        [
            "--data-dir",
            str(data_dir),
            "--chain-archive-dir",
            str(archive_dir),
            "--relevance-inventory",
            str(inventory),
        ]
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser)

    error = capsys.readouterr().err
    assert "lacks its private full inventory" in error
    assert "vcash canonical source is missing" in error


def test_vcash_baseline_accepts_standard_canonical_source(tmp_path: Path) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    archive_dir = tmp_path / "archive"
    canonical = (
        archive_dir / "chains" / "vcash" / "classified" / "vcash_canonical_blocks.csv"
    )
    canonical.parent.mkdir(parents=True)
    canonical.write_text("classification\ncanonical\ncanonical\n")
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="vcash",
        source_kind="wayback_canonical_hydration",
        canonical=2,
        source_rows=2,
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)


def test_canonical_baseline_requires_canonical_classified_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "sixeleven_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\n")
    archive_dir = tmp_path / "archive"
    canonical = (
        archive_dir
        / "chains"
        / "sixeleven"
        / "classified"
        / "sixeleven_canonical_blocks.csv"
    )
    canonical.parent.mkdir(parents=True)
    canonical.write_text("classification\nunknown\nnear\n")
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="sixeleven",
        source_kind="canonical_blocks",
        canonical=2,
        source_rows=2,
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)

    assert "canonical-classified evidence is below" in capsys.readouterr().err


def test_canonical_baseline_accepts_canonical_rows_in_full_inventory(
    tmp_path: Path,
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "sixeleven_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\n")
    archive_dir = tmp_path / "archive"
    inventory = (
        archive_dir
        / "chains"
        / "sixeleven"
        / "classified"
        / "sixeleven_stale_blocks.csv"
    )
    inventory.parent.mkdir(parents=True)
    inventory.write_text("classification\ncanonical\ncanonical\nunknown\n")
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="sixeleven",
        source_kind="canonical_blocks",
        canonical=2,
        source_rows=2,
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)


def test_full_inventory_coverage_applies_validated_stale_replacement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\nstale,VALID\n")
    archive_dir = tmp_path / "archive"
    inventory = (
        archive_dir / "chains" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    inventory.parent.mkdir(parents=True)
    inventory.write_text("classification\nunknown\nstale\nstale\n")
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        stale=1,
        source_rows=3,
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)

    error = capsys.readouterr().err
    assert "private inventory is below the publication baseline (2 < 3)" in error


def test_full_inventory_coverage_counts_split_canonical_companion(
    tmp_path: Path,
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\nstale,VALID\n")
    archive_dir = tmp_path / "archive"
    classified_dir = archive_dir / "chains" / "namecoin" / "classified"
    classified_dir.mkdir(parents=True)
    (classified_dir / "namecoin_stale_blocks.csv").write_text(
        "classification\nstale\nstale\n"
    )
    (classified_dir / "namecoin_unknown_blocks.csv").write_text(
        "classification\nunknown\n"
    )
    (classified_dir / "namecoin_canonical_blocks.csv").write_text(
        "classification\ncanonical\ncanonical\n"
    )
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        canonical=2,
        stale=1,
        source_rows=4,
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)


def test_full_inventory_coverage_unions_disjoint_canonical_companion(
    tmp_path: Path,
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\n")
    archive_dir = tmp_path / "archive"
    classified_dir = archive_dir / "chains" / "namecoin" / "classified"
    classified_dir.mkdir(parents=True)
    (classified_dir / "namecoin_stale_blocks.csv").write_text(
        f"classification,btc_header_hash\ncanonical,{'11' * 32}\nunknown,{'44' * 32}\n"
    )
    (classified_dir / "namecoin_canonical_blocks.csv").write_text(
        "classification,btc_header_hash\n"
        f"canonical,{'22' * 32}\n"
        f"canonical,{'33' * 32}\n"
    )
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        canonical=3,
        source_rows=4,
        canonical_hashes=("11" * 32, "22" * 32, "33" * 32),
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)


def test_full_inventory_cannot_hide_canonical_loss_with_more_unknown_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\n")
    archive_dir = tmp_path / "archive"
    classified_dir = archive_dir / "chains" / "namecoin" / "classified"
    classified_dir.mkdir(parents=True)
    (classified_dir / "namecoin_stale_blocks.csv").write_text(
        "classification\nunknown\nunknown\nunknown\n"
    )
    (classified_dir / "namecoin_canonical_blocks.csv").write_text(
        "classification\ncanonical\n"
    )
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        canonical=2,
        source_rows=3,
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)

    assert (
        "accepted canonical/stale/descendant evidence is below"
        in capsys.readouterr().err
    )


def test_full_inventory_cannot_replace_baseline_canonical_identity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    retained_hash = "11" * 32
    missing_hash = "22" * 32
    unrelated_stale_hash = "33" * 32
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text(
        "btc_header_hash,classification,validation_status\n"
        f"{unrelated_stale_hash},stale,VALID\n"
    )
    (data_dir / "stale_descendants.csv").write_text(
        "classification,validation_status,btc_header_hash,source_rows\n"
    )
    archive_dir = tmp_path / "archive"
    inventory = (
        archive_dir / "chains" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    inventory.parent.mkdir(parents=True)
    inventory.write_text(
        "btc_header_hash,classification\n"
        f"{retained_hash},canonical\n"
        f"{unrelated_stale_hash},stale\n"
    )
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        canonical=2,
        source_rows=2,
    )
    (baseline_dir / "namecoin_monitor_evidence.csv").write_text(
        "chain,btc_header_hash,classification,btc_stale_relevance\n"
        f"namecoin,{retained_hash},canonical,\n"
        f"namecoin,{missing_hash},canonical,\n"
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)

    error = capsys.readouterr().err
    assert "missing 1 baseline canonical header identities" in error
    assert missing_hash in error


def test_full_inventory_allows_canonical_reclassification_to_valid_stale(
    tmp_path: Path,
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text(
        "btc_height,btc_header_hash,classification,validation_status\n"
        f"2,{'22' * 32},stale,VALID\n"
    )
    (data_dir / "stale_descendants.csv").write_text(
        "classification,validation_status,btc_header_hash,source_rows\n"
    )
    (data_dir / "stale_block_exclusions.csv").write_text(
        "height,hash,exclusion_scope\n"
    )
    archive_dir = tmp_path / "archive"
    inventory = (
        archive_dir / "chains" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    inventory.parent.mkdir(parents=True)
    inventory.write_text(
        "btc_height,btc_header_hash,classification,validation_status\n"
        f"1,{'11' * 32},canonical,\n"
        f"2,{'22' * 32},stale,VALID\n"
    )
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        canonical=2,
        source_rows=2,
    )
    (baseline_dir / "namecoin_monitor_evidence.csv").write_text(
        "chain,btc_header_hash,classification,btc_stale_relevance\n"
        f"namecoin,{'11' * 32},canonical,\n"
        f"namecoin,{'22' * 32},canonical,\n"
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)


def test_full_inventory_allows_corrected_stale_as_valid_descendant(
    tmp_path: Path,
) -> None:
    # A baseline-canonical header corrected into a stale descendant is admitted
    # in its final category. Post error-blocks, the correction is expressed by
    # reclassifying the source row to stale_descendant (the former
    # direct_stale_only exclusion scope is abolished; the gate no longer
    # distinguishes scopes), not by an exclusion-overlay carve-out.
    module = _load_module()
    descendant_hash = "22" * 32
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\n")
    (data_dir / "stale_descendants.csv").write_text(
        "classification,validation_status,btc_header_hash,source_rows\n"
        f"stale_descendant,VALID_STALE_DESCENDANT,{descendant_hash},namecoin:2\n"
    )
    archive_dir = tmp_path / "archive"
    inventory = (
        archive_dir / "chains" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    inventory.parent.mkdir(parents=True)
    inventory.write_text(
        "btc_height,btc_header_hash,classification,validation_status\n"
        f"1,{'11' * 32},canonical,\n"
        f"2,{descendant_hash},stale_descendant,VALID_STALE_DESCENDANT\n"
    )
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        canonical=2,
        source_rows=2,
    )
    (baseline_dir / "namecoin_monitor_evidence.csv").write_text(
        "chain,btc_header_hash,classification,btc_stale_relevance\n"
        f"namecoin,{'11' * 32},canonical,\n"
        f"namecoin,{descendant_hash},canonical,\n"
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)


def test_full_inventory_rejects_stale_descendant_that_is_an_error_block(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The consensus-invalid gate is preserved for the direct-stale path: a
    # stale source row whose exact key the error-blocks dataset records as an
    # error block is NOT admitted as a stale descendant, even when the sidecar
    # names the observation. The preflight therefore reports the descendant
    # coverage shortfall.
    module = _load_module()
    descendant_hash = "22" * 32
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\n")
    (data_dir / "stale_descendants.csv").write_text(
        "classification,validation_status,btc_header_hash,source_rows\n"
        f"stale_descendant,VALID_STALE_DESCENDANT,{descendant_hash},namecoin:2\n"
    )
    error_blocks = data_dir / "error-blocks" / "error_blocks.csv"
    error_blocks.parent.mkdir(parents=True)
    error_blocks.write_text(
        "height,hash,classification\n"
        f"2,{descendant_hash},error_block\n"
    )
    archive_dir = tmp_path / "archive"
    inventory = (
        archive_dir / "chains" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    inventory.parent.mkdir(parents=True)
    inventory.write_text(
        "btc_height,btc_header_hash,classification,validation_status\n"
        f"1,{'11' * 32},canonical,\n"
        f"2,{descendant_hash},stale,VALID\n"
    )
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        canonical=2,
        source_rows=2,
    )
    (baseline_dir / "namecoin_monitor_evidence.csv").write_text(
        "chain,btc_header_hash,classification,btc_stale_relevance\n"
        f"namecoin,{'11' * 32},canonical,\n"
        f"namecoin,{descendant_hash},canonical,\n"
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)

    assert (
        "accepted canonical/stale/descendant evidence is below"
        in capsys.readouterr().err
    )


def test_full_inventory_does_not_double_count_transitional_stale_descendant(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    retained_hash = "11" * 32
    descendant_hash = "22" * 32
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text(
        "btc_height,btc_header_hash,classification,validation_status\n"
        f"2,{descendant_hash},stale,VALID\n"
    )
    (data_dir / "stale_descendants.csv").write_text(
        "classification,validation_status,btc_header_hash,source_rows\n"
        f"stale_descendant,VALID_STALE_DESCENDANT,{descendant_hash},namecoin:2\n"
    )
    (data_dir / "stale_block_exclusions.csv").write_text(
        f"height,hash,exclusion_scope\n2,{descendant_hash},direct_stale_only\n"
    )
    archive_dir = tmp_path / "archive"
    inventory = (
        archive_dir / "chains" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    inventory.parent.mkdir(parents=True)
    inventory.write_text(
        "btc_height,btc_header_hash,classification,validation_status\n"
        f"1,{retained_hash},canonical,\n"
        f"2,{descendant_hash},stale,VALID\n"
    )
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        canonical=2,
        stale=1,
        source_rows=2,
        canonical_hashes=(retained_hash, descendant_hash),
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)

    assert (
        "accepted canonical/stale/descendant evidence is below"
        in capsys.readouterr().err
    )


def test_full_inventory_cannot_use_unrepresented_descendant_to_hide_loss(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\n")
    (data_dir / "stale_descendants.csv").write_text(
        "classification,validation_status,btc_header_hash,source_rows\n"
        f"stale_descendant,VALID_STALE_DESCENDANT,{'33' * 32},namecoin:99\n"
    )
    (data_dir / "stale_block_exclusions.csv").write_text(
        "height,hash,exclusion_scope\n"
    )
    archive_dir = tmp_path / "archive"
    inventory = (
        archive_dir / "chains" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    inventory.parent.mkdir(parents=True)
    inventory.write_text(
        "btc_height,btc_header_hash,classification,validation_status\n"
        f"1,{'11' * 32},canonical,\n"
        f"2,{'22' * 32},unknown,\n"
    )
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        canonical=2,
        source_rows=2,
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)

    assert (
        "accepted canonical/stale/descendant evidence is below"
        in capsys.readouterr().err
    )


def test_full_inventory_must_retain_per_chain_baseline_relevance_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    required_hash = "11" * 32
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\n")
    archive_dir = tmp_path / "archive"
    inventory = (
        archive_dir / "chains" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    inventory.parent.mkdir(parents=True)
    inventory.write_text(
        f"btc_header_hash,classification\n{'22' * 32},unknown\n{'33' * 32},unknown\n"
    )
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        strict=1,
        source_rows=2,
    )
    (baseline_dir / "namecoin_monitor_evidence.csv").write_text(
        "chain,btc_header_hash,btc_stale_relevance\n"
        f"namecoin,{required_hash},strict_btc_orphan\n"
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )
    args.relevance_inventory.write_text(
        "btc_header_hash,btc_stale_relevance,relevance_reason\n"
        f"{required_hash},strict_btc_orphan,strict_height_nbits_match\n"
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)

    assert "missing 1 baseline strict/weak source rows" in capsys.readouterr().err


def test_malformed_numeric_publication_baseline_is_a_parser_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        source_rows=0,
    )
    counts = baseline_dir / "monitor-evidence-counts.csv"
    counts.write_text(counts.read_text().replace(",0\n", ",not-a-number\n"))
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)

    assert "invalid numeric source_rows" in capsys.readouterr().err


def test_publication_baseline_requires_each_monitor_artifact(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="namecoin",
        source_kind="full_inventory",
        canonical=1,
        source_rows=1,
    )
    (baseline_dir / "namecoin_monitor_evidence.csv").unlink()
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)

    assert "namecoin monitor-evidence artifact is missing" in capsys.readouterr().err


@pytest.mark.dataset
def test_repo_data_monitor_provenance_paths_exist() -> None:
    """Committed repo-data provenance must resolve after source-layout changes."""
    monitor_dir = REPO / "results" / "monitor-evidence"
    missing: list[tuple[str, int, str]] = []
    for path in sorted(monitor_dir.glob("*_monitor_evidence.csv")):
        with path.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), start=2):
                if row.get("provenance") != "repo-data":
                    continue
                source_path = row.get("source_path", "")
                if not source_path or not (REPO / source_path).is_file():
                    missing.append((path.name, row_number, source_path))

    assert missing == []
