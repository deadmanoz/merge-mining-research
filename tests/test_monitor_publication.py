"""Publication-writing contract tests for monitor evidence.

These tests cover the final, all-artifact publication path.  Descendant
evidence is authenticated by the committed parent verdict and its separate
child-observation ledger, and every artifact is written as one snapshot.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

import stale_blocks_analysis.monitor_publication as monitor_publication
from stale_blocks_analysis.full_evidence import parse_header_fields
from stale_blocks_analysis.error_observations import ERROR_OBSERVATION_FIELDS
from stale_blocks_analysis.monitor_exports import (
    MONITOR_COUNT_FIELDS,
    MONITOR_EVIDENCE_FIELDS,
)

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "reports" / "build_monitor_evidence.py"
TEST_PARENT_HASH = "0000000000000a0101e3939b59d526806e0545ee95e7b947b8233ed42bb1b5e7"
TEST_PARENT_HEADER = (
    "01000000b7206e118a8f33910ac281a57f7d0deb234be7cfe9f0f648a80d000000000000"
    "4ef56ab98f9aabaa381960242e408d1bdd75cc6aee049ded0f3e81b02122a7d8215cd44e9a"
    "110e1ac8cae712"
)
SECOND_PARENT_HEADER = (
    "00601d3455bb9fbd966b3ea2dc42d0c22722e4c0c1729fad172101000000000000000000"
    "55087fab0c8f3f89f8bcfd4df26c504d81b0a88e04907161838c0c53001af09135edbd"
    "64943805175e955e06"
)


def _load_cli_module():
    spec = importlib.util.spec_from_file_location("build_monitor_evidence", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(module, argv: list[str]) -> dict[str, object]:
    """Exercise the sole full-publication path exposed by the CLI."""
    parser = _load_cli_module().build_parser()
    args = parser.parse_args(argv)
    module.validate_publication_inputs(args, parser)
    return module.build_transactionally(args)


def _write_ordinary_artifact(path: Path, *, stale_rows: int = 1) -> None:
    parent_fields = parse_header_fields(TEST_PARENT_HEADER)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MONITOR_EVIDENCE_FIELDS)
        writer.writeheader()
        for index in range(stale_rows):
            row = {field: "" for field in MONITOR_EVIDENCE_FIELDS}
            row.update(
                {
                    "chain": "namecoin",
                    "source_kind": "full_inventory",
                    "source_path": "archive/namecoin_stale_blocks.csv",
                    "source_row_number": str(index + 2),
                    "artifact_scope": "full_classifier_inventory",
                    "provenance": "archive",
                    "child_height": str(index + 1),
                    "child_block_hash": f"{index + 1:064x}",
                    "child_block_time": str(index + 1),
                    "btc_height": "1",
                    "btc_header_hash": TEST_PARENT_HASH,
                    "btc_header_hex": TEST_PARENT_HEADER,
                    "btc_prev_hash": parent_fields["prev_hash"],
                    "btc_time": parent_fields["time"],
                    "btc_bits": parent_fields["bits"],
                    "btc_nonce": parent_fields["nonce"],
                    "classification": "stale",
                    "validation_status": "VALID",
                    "expected_nbits": parent_fields["bits"],
                    "relevance_reason": "valid_direct_stale",
                }
            )
            writer.writerow(row)


def _rewrite_first_row(path: Path, **changes: str) -> None:
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or ())
        rows = list(reader)
    assert fields and rows
    rows[0].update(changes)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _rewrite_rows(path: Path, rows: list[dict[str, str]]) -> None:
    """Replace data rows while preserving the artifact's exact schema."""
    with path.open(newline="") as handle:
        fields = list(csv.DictReader(handle).fieldnames or ())
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def _write_unknown_source(path: Path, hashes: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["classification", "btc_header_hash"],
        )
        writer.writeheader()
        for block_hash in hashes:
            writer.writerow(
                {"classification": "unknown", "btc_header_hash": block_hash}
            )


def _stage_trusted_root_inputs(
    data_dir: Path,
    parents: list[dict[str, str]],
) -> None:
    roots = sorted(
        {(parent["root_stale_height"], parent["root_stale_hash"]) for parent in parents}
    )
    validated = data_dir / "validated-stales" / "roots_validated_stales.csv"
    validated.parent.mkdir(parents=True, exist_ok=True)
    validated.write_text(
        "btc_height,btc_header_hash,classification,validation_status\n"
    )
    upstream = data_dir / "stale-blocks" / "stale-blocks.csv"
    upstream.parent.mkdir(parents=True, exist_ok=True)
    upstream.write_text(
        "height,hash\n"
        + "".join(f"{height},{block_hash}\n" for height, block_hash in roots)
    )
    errors = data_dir / "error-blocks" / "error_blocks.csv"
    errors.parent.mkdir(parents=True, exist_ok=True)
    errors.write_text(f"height,hash,classification\n0,{'00' * 32},error_block\n")


def _write_relevance_identities(
    path: Path,
    source_path: Path,
    identities: list[tuple[int, str]],
    *,
    chain: str = "namecoin",
) -> None:
    fields = [
        "chain",
        "source_path",
        "source_row_number",
        "source_classification",
        "btc_header_hash",
        "btc_stale_relevance",
        "relevance_reason",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for source_row, block_hash in identities:
            writer.writerow(
                {
                    "chain": chain,
                    "source_path": source_path,
                    "source_row_number": source_row,
                    "source_classification": "unknown",
                    "btc_header_hash": block_hash,
                    "btc_stale_relevance": "pending",
                    "relevance_reason": "mainchain_status_not_checked",
                }
            )


def _full_inventory_source(
    path: Path, *, chain: str = "namecoin"
) -> monitor_publication.EvidenceSource:
    return monitor_publication.EvidenceSource(
        chain=chain,
        display_name=chain.title(),
        path=path,
        source_kind="full_inventory",
        artifact_scope="full_classifier_inventory",
        provenance="archive",
    )


def _set_category(path: Path, category: str) -> None:
    cells = {
        "classification": category,
        "validation_status": "VALID" if category == "stale" else "",
        "btc_stale_relevance": "",
        "relevance_reason": "",
    }
    if category in {"strict_btc_orphan", "weak_btc_orphan"}:
        cells.update(
            {
                "classification": "unknown",
                "validation_status": "",
                "btc_stale_relevance": category,
                "relevance_reason": (
                    "strict_height_nbits_match"
                    if category == "strict_btc_orphan"
                    else "timestamp_epoch_nbits_match"
                ),
            }
        )
    elif category == "stale_descendant":
        cells.update(
            {
                "validation_status": "VALID_STALE_DESCENDANT",
                "relevance_reason": "valid_stale_descendant",
            }
        )
    _rewrite_first_row(path, **cells)


def _validate_semantic_floor(committed_dir: Path, staged_dir: Path) -> None:
    committed = monitor_publication._load_published_observation_groups(committed_dir)
    monitor_publication._validate_published_observation_floor(
        staged_dir,
        committed=committed,
    )


def _write_error_artifact(
    path: Path,
    source: dict[str, str],
    *,
    chain: str = "devcoin",
) -> None:
    row = {field: source.get(field, "") for field in ERROR_OBSERVATION_FIELDS}
    row.update(
        {
            "chain": chain,
            "classification": "error_block",
            "validation_status": "VALID_ERROR_BLOCK",
            "rejection_reason": "bip34_coinbase_height_mismatch",
            "btc_stale_relevance": "",
            "relevance_reason": "",
        }
    )
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ERROR_OBSERVATION_FIELDS)
        writer.writeheader()
        writer.writerow(row)


def _copy_descendant_contract(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    """Copy one committed parent and all of its canonical witness rows."""
    parents_path = REPO / "data" / "stale_descendants.csv"
    observations_path = REPO / "data" / "stale_descendant_observations.csv"
    with parents_path.open(newline="") as handle:
        parent_reader = csv.DictReader(handle)
        parent_fields = list(parent_reader.fieldnames or ())
        parents_by_identity = {
            (row["btc_height"], row["btc_header_hash"]): row for row in parent_reader
        }
    with observations_path.open(newline="") as handle:
        observation_reader = csv.DictReader(handle)
        observation_fields = list(observation_reader.fieldnames or ())
        observations_by_identity: dict[tuple[str, str], list[dict[str, str]]] = {}
        for row in observation_reader:
            observations_by_identity.setdefault(
                (row["btc_height"], row["btc_header_hash"]), []
            ).append(row)

    identity, observations = next(
        (identity, rows)
        for identity, rows in observations_by_identity.items()
        if identity in parents_by_identity
        and any(row["chain"] == "namecoin" for row in rows)
    )
    parent = parents_by_identity[identity]
    observation = next(row for row in observations if row["chain"] == "namecoin")
    parsed_parent = parse_header_fields(parent["btc_header_hex"])
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    parents_copy = data_dir / "stale_descendants.csv"
    with parents_copy.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=parent_fields)
        writer.writeheader()
        writer.writerow(parent)
    observations_copy = data_dir / "stale_descendant_observations.csv"
    with observations_copy.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=observation_fields)
        writer.writeheader()
        for row in observations:
            copied_observation = dict(row)
            copied_observation["parent_row_number"] = "2"
            writer.writerow(copied_observation)
    _stage_trusted_root_inputs(data_dir, [parent])

    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    row = {field: "" for field in MONITOR_EVIDENCE_FIELDS}
    row.update(
        {
            "chain": "namecoin",
            "source_kind": observation["source_kind"],
            "source_path": observation["source_path"],
            "source_row_number": observation["source_row_number"],
            "artifact_scope": "accepted_stale_descendant_observation",
            "provenance": observation["provenance"],
            "child_height": observation["child_height"],
            "child_block_hash": observation["child_block_hash"],
            "child_header_hex": observation["child_header_hex"],
            "child_block_time": observation["child_block_time"],
            "child_nbits": observation["child_nbits"],
            "btc_height": parent["btc_height"],
            "btc_header_hash": parent["btc_header_hash"],
            "btc_prev_hash": parsed_parent["prev_hash"],
            "btc_time": parsed_parent["time"],
            "btc_bits": parsed_parent["bits"],
            "btc_nonce": parsed_parent["nonce"],
            "btc_header_hex": parent["btc_header_hex"],
            "coinbase_scriptsig_hex": parent.get("coinbase_scriptsig_hex", ""),
            "coinbase_outputs": parent.get("coinbase_outputs", ""),
            "classification": "stale_descendant",
            "validation_status": "VALID_STALE_DESCENDANT",
            "expected_nbits": parent["expected_nbits"],
            "relevance_reason": "valid_stale_descendant",
        }
    )
    with artifact.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=MONITOR_EVIDENCE_FIELDS)
        writer.writeheader()
        writer.writerow(row)
    return data_dir, parents_copy, artifact, "namecoin"


def test_publication_build_refuses_missing_private_inputs_before_writing(
    tmp_path: Path,
) -> None:
    module = _load_cli_module()
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
    module = _load_cli_module()
    output_dir = tmp_path / "monitor"
    output_dir.mkdir()
    unrelated = output_dir / "operator-notes.txt"
    unrelated.write_text("preserve me\n")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    shutil.copyfile(
        REPO / "data" / "stale_descendants.csv", data_dir / "stale_descendants.csv"
    )
    shutil.copyfile(
        REPO / "data" / "stale_descendant_observations.csv",
        data_dir / "stale_descendant_observations.csv",
    )
    with (data_dir / "stale_descendants.csv").open(newline="") as handle:
        _stage_trusted_root_inputs(data_dir, list(csv.DictReader(handle)))

    module.main(
        [
            "--data-dir",
            str(data_dir),
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
    assert unrelated.read_text() == "preserve me\n"
    assert list(tmp_path.glob(".monitor.monitor-build-*")) == []
    assert "do not replace committed publication artifacts" in capsys.readouterr().err


def test_allow_partial_refuses_committed_output_directory() -> None:
    module = _load_cli_module()

    with pytest.raises(SystemExit, match="2"):
        module.main(["--allow-partial"])


def test_monitor_artifact_rejects_missing_parent_hash(tmp_path: Path) -> None:
    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(artifact)
    _rewrite_first_row(artifact, btc_header_hash="")

    with pytest.raises(ValueError, match="exact lowercase Bitcoin parent hash"):
        monitor_publication._load_monitor_artifact_counts(artifact, "namecoin")


def test_monitor_artifact_rejects_mismatched_parent_header(tmp_path: Path) -> None:
    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(artifact)
    _rewrite_first_row(artifact, btc_header_hex="00" * 80)

    with pytest.raises(ValueError, match="serialized Bitcoin parent header"):
        monitor_publication._load_monitor_artifact_counts(artifact, "namecoin")


def test_monitor_artifact_rejects_invalid_stale_relevance(tmp_path: Path) -> None:
    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(artifact)
    _rewrite_first_row(artifact, relevance_reason="strict_height_nbits_match")

    with pytest.raises(ValueError, match="stale row has invalid relevance"):
        monitor_publication._load_monitor_artifact_counts(artifact, "namecoin")


def test_no_coinbase_strict_height_must_match_typed_relevance_verdict(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(artifact)
    _rewrite_first_row(
        artifact,
        classification="unknown",
        validation_status="",
        expected_nbits="",
        coinbase_scriptsig_hex="",
        btc_height="300000",
        btc_stale_relevance="strict_btc_orphan",
        relevance_reason="strict_height_nbits_match",
    )
    verdicts = {
        TEST_PARENT_HASH: monitor_publication.MonitorVerdict(
            "strict_btc_orphan",
            "strict_height_nbits_match",
            btc_height=300001,
            strict_height_source="coinbase_bip34_height",
        )
    }

    with pytest.raises(
        ValueError,
        match="Bitcoin height disagrees with its authenticated relevance verdict",
    ):
        monitor_publication._load_monitor_artifact_counts(
            artifact,
            "namecoin",
            orphan_verdicts=verdicts,
        )


def test_monitor_artifact_rejects_duplicate_stale_identity(tmp_path: Path) -> None:
    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(artifact, stale_rows=2)

    with pytest.raises(ValueError, match="duplicate stale identity"):
        monitor_publication._load_monitor_artifact_counts(artifact, "namecoin")


def test_monitor_artifact_rejects_one_child_event_in_two_categories(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(artifact)
    rows = _read_rows(artifact)
    canonical = {
        **rows[0],
        "classification": "canonical",
        "validation_status": "",
        "expected_nbits": "",
        "relevance_reason": "",
    }
    _rewrite_rows(artifact, [rows[0], canonical])

    with pytest.raises(ValueError, match="appears in both stale and canonical"):
        monitor_publication._load_monitor_artifact_counts(artifact, "namecoin")


def test_monitor_artifact_rejects_repeated_authenticated_child_event(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(artifact)
    rows = _read_rows(artifact)
    _rewrite_rows(artifact, [rows[0], rows[0]])

    with pytest.raises(ValueError, match="repeats the stale category"):
        monitor_publication._load_monitor_artifact_counts(artifact, "namecoin")


def test_monitor_artifact_child_event_identity_does_not_depend_on_parent(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(artifact)
    rows = _read_rows(artifact)
    second = dict(rows[0])
    second_header_hex = SECOND_PARENT_HEADER
    second_parent = monitor_publication.hash_from_header_bytes(
        bytes.fromhex(second_header_hex)
    )[::-1].hex()
    second_parent_fields = parse_header_fields(second_header_hex)
    second.update(
        {
            "btc_header_hash": second_parent,
            "btc_header_hex": second_header_hex,
            "btc_prev_hash": second_parent_fields["prev_hash"],
            "btc_time": second_parent_fields["time"],
            "btc_bits": second_parent_fields["bits"],
            "btc_nonce": second_parent_fields["nonce"],
        }
    )
    _rewrite_rows(artifact, [rows[0], second])

    with pytest.raises(ValueError, match="repeats the stale category"):
        monitor_publication._load_monitor_artifact_counts(artifact, "namecoin")


def test_monitor_artifact_rejects_padded_child_field(tmp_path: Path) -> None:
    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(artifact)
    _rewrite_first_row(artifact, child_block_time=" 1")

    with pytest.raises(ValueError, match="exact unpadded encodings"):
        monitor_publication._load_monitor_artifact_counts(artifact, "namecoin")


@pytest.mark.parametrize(
    "status",
    ("VALID_ERROR_BLOCK", "VALIDATION_FAILED", "VALID_BOGUS", "VALID invented"),
)
def test_monitor_artifact_rejects_unrecognized_status_on_stale_row(
    tmp_path: Path, status: str
) -> None:
    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(artifact)
    _rewrite_first_row(artifact, validation_status=status)

    with pytest.raises(ValueError, match="invalid ordinary status"):
        monitor_publication._load_monitor_artifact_counts(artifact, "namecoin")


def test_descendant_witness_requires_canonical_parent_and_ledger(
    tmp_path: Path,
) -> None:
    data_dir, _parents, artifact, chain = _copy_descendant_contract(tmp_path)

    counts = monitor_publication._load_monitor_artifact_counts(
        artifact, chain, data_dir=data_dir
    )

    assert counts["stale_descendant"] == 1


def test_descendant_witness_rejects_ledger_identity_mismatch(tmp_path: Path) -> None:
    data_dir, _parents, artifact, chain = _copy_descendant_contract(tmp_path)
    _rewrite_first_row(artifact, child_block_hash="00" * 32)

    with pytest.raises(ValueError, match="canonical observation ledger"):
        monitor_publication._load_monitor_artifact_counts(
            artifact, chain, data_dir=data_dir
        )


def test_descendant_witness_rejects_missing_parent_verdict(tmp_path: Path) -> None:
    data_dir, parents, artifact, chain = _copy_descendant_contract(tmp_path)
    with parents.open(newline="") as handle:
        fields = list(csv.DictReader(handle).fieldnames or ())
    with parents.open("w", newline="") as handle:
        csv.DictWriter(handle, fieldnames=fields).writeheader()

    with pytest.raises(ValueError, match="parent-verdict interface is empty"):
        monitor_publication._load_monitor_artifact_counts(
            artifact, chain, data_dir=data_dir
        )


def test_publication_preflight_allows_coherent_descendant_module_growth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Strict loader success, not a frozen row count, is the reusable gate."""
    data_dir = tmp_path / "data"
    archive_dir = tmp_path / "archive"
    data_dir.mkdir()
    archive_dir.mkdir()
    relevance = tmp_path / "relevance.csv"
    relevance.write_text(
        "chain,source_path,source_row_number,source_classification,"
        "btc_header_hash,btc_stale_relevance,relevance_reason\n"
    )
    parser = _load_cli_module().build_parser()
    args = parser.parse_args(
        [
            "--data-dir",
            str(data_dir),
            "--output-dir",
            str(tmp_path / "output"),
            "--chain-archive-dir",
            str(archive_dir),
            "--relevance-inventory",
            str(relevance),
        ]
    )
    monkeypatch.setattr(
        monitor_publication,
        "_load_publication_baseline",
        lambda _path: {},
    )
    monkeypatch.setattr(
        monitor_publication, "discover_evidence_sources", lambda *_args: {}
    )
    monkeypatch.setattr(
        monitor_publication, "discover_canonical_sources", lambda *_args: {}
    )
    monkeypatch.setattr(
        monitor_publication, "discover_unknown_sources", lambda *_args: {}
    )
    monkeypatch.setattr(
        monitor_publication,
        "load_stale_descendant_parents",
        lambda *_args, **_kwargs: {index: object() for index in range(22)},
    )
    monkeypatch.setattr(
        monitor_publication,
        "load_stale_descendant_observations",
        lambda *_args, **_kwargs: tuple(range(32)),
    )
    monkeypatch.setattr(
        monitor_publication,
        "build_error_observation_rows",
        lambda **_kwargs: ([], {}),
    )
    monkeypatch.setattr(
        monitor_publication,
        "validate_error_module",
        lambda **_kwargs: ([], {}),
    )

    monitor_publication.validate_publication_inputs(
        args,
        parser,
        baseline_dir=tmp_path / "baseline",
    )


def test_unknown_inventory_assessment_accepts_exact_selected_multiset(
    tmp_path: Path,
) -> None:
    source_path = (
        tmp_path / "archive" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    hashes = [f"{value:064x}" for value in (1, 2)]
    _write_unknown_source(source_path, hashes)
    relevance = tmp_path / "relevance.csv"
    _write_relevance_identities(
        relevance,
        source_path,
        [(2, hashes[0]), (3, hashes[1])],
    )

    monitor_publication._validate_unknown_inventory_assessment(
        {"namecoin": _full_inventory_source(source_path)},
        {},
        relevance,
    )


@pytest.mark.parametrize(
    "assessed",
    [
        [(2, f"{1:064x}")],
        [(2, f"{1:064x}"), (3, f"{2:064x}"), (4, f"{3:064x}")],
        [(2, f"{1:064x}"), (3, f"{3:064x}")],
    ],
    ids=["missing", "extra", "same-count-substitution"],
)
def test_unknown_inventory_assessment_rejects_identity_drift(
    tmp_path: Path,
    assessed: list[tuple[int, str]],
) -> None:
    source_path = (
        tmp_path / "archive" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    hashes = [f"{value:064x}" for value in (1, 2)]
    _write_unknown_source(source_path, hashes)
    relevance = tmp_path / "relevance.csv"
    _write_relevance_identities(relevance, source_path, assessed)

    with pytest.raises(ValueError, match="unknown identities do not match"):
        monitor_publication._validate_unknown_inventory_assessment(
            {"namecoin": _full_inventory_source(source_path)},
            {},
            relevance,
        )


def test_unknown_inventory_assessment_skips_catalogued_error_hash_by_hash(
    tmp_path: Path,
) -> None:
    source_path = (
        tmp_path / "archive" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    error_hash, kept_hash = (f"{value:064x}" for value in (1, 2))
    _write_unknown_source(source_path, [error_hash, kept_hash])
    relevance = tmp_path / "relevance.csv"
    _write_relevance_identities(relevance, source_path, [(3, kept_hash)])

    monitor_publication._validate_unknown_inventory_assessment(
        {"namecoin": _full_inventory_source(source_path)},
        {},
        relevance,
        excluded_hashes={error_hash},
    )


def test_unknown_inventory_assessment_has_no_legacy_schema_fallback(
    tmp_path: Path,
) -> None:
    relevance = tmp_path / "relevance.csv"
    relevance.write_text("btc_header_hash,btc_stale_relevance\n")

    with pytest.raises(ValueError, match="lacks exact source-identity fields"):
        monitor_publication._assessed_unknown_identity_digests(relevance)


@pytest.mark.parametrize("block_hash", ["AB" * 32, "not-a-hash"])
def test_selected_unknown_source_rejects_noncanonical_parent_hash(
    tmp_path: Path,
    block_hash: str,
) -> None:
    source_path = (
        tmp_path / "archive" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    _write_unknown_source(source_path, [block_hash])

    with pytest.raises(ValueError, match="malformed or non-lowercase"):
        monitor_publication._selected_unknown_identity_digests(
            {"namecoin": _full_inventory_source(source_path)},
            {},
        )


@pytest.mark.parametrize("block_hash", ["AB" * 32, "not-a-hash"])
def test_assessed_unknown_inventory_rejects_noncanonical_parent_hash(
    tmp_path: Path,
    block_hash: str,
) -> None:
    source_path = (
        tmp_path / "archive" / "namecoin" / "classified" / "namecoin_stale_blocks.csv"
    )
    relevance = tmp_path / "relevance.csv"
    _write_relevance_identities(relevance, source_path, [(2, block_hash)])

    with pytest.raises(ValueError, match="malformed or non-lowercase"):
        monitor_publication._assessed_unknown_identity_digests(relevance)


def test_publication_preflight_reports_invalid_relevance_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_dir = tmp_path / "data"
    archive_dir = tmp_path / "archive"
    data_dir.mkdir()
    archive_dir.mkdir()
    relevance = tmp_path / "relevance.csv"
    relevance.write_text("btc_header_hash,btc_stale_relevance\n")
    parser = _load_cli_module().build_parser()
    args = parser.parse_args(
        [
            "--data-dir",
            str(data_dir),
            "--output-dir",
            str(tmp_path / "output"),
            "--chain-archive-dir",
            str(archive_dir),
            "--relevance-inventory",
            str(relevance),
        ]
    )
    monkeypatch.setattr(
        monitor_publication,
        "_load_publication_baseline",
        lambda _path: {},
    )
    monkeypatch.setattr(
        monitor_publication,
        "load_orphan_relevance_verdicts",
        lambda _path: (_ for _ in ()).throw(ValueError("invalid strict verdict")),
    )
    monkeypatch.setattr(
        monitor_publication, "discover_evidence_sources", lambda *_args: {}
    )
    monkeypatch.setattr(
        monitor_publication, "discover_canonical_sources", lambda *_args: {}
    )
    monkeypatch.setattr(
        monitor_publication, "discover_unknown_sources", lambda *_args: {}
    )
    monkeypatch.setattr(
        monitor_publication,
        "load_stale_descendant_parents",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        monitor_publication,
        "load_stale_descendant_observations",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(
        monitor_publication,
        "build_error_observation_rows",
        lambda **_kwargs: ([], {}),
    )
    monkeypatch.setattr(
        monitor_publication,
        "validate_error_module",
        lambda **_kwargs: ([], {}),
    )

    with pytest.raises(SystemExit, match="2"):
        monitor_publication.validate_publication_inputs(
            args,
            parser,
            baseline_dir=tmp_path / "baseline",
        )

    assert "invalid strict verdict" in capsys.readouterr().err


def test_publication_preflight_stops_on_consensus_invalid_error_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_dir = tmp_path / "data"
    archive_dir = tmp_path / "archive"
    data_dir.mkdir()
    archive_dir.mkdir()
    relevance = tmp_path / "relevance.csv"
    relevance.write_text(
        "chain,source_path,source_row_number,source_classification,"
        "btc_header_hash,btc_stale_relevance,relevance_reason\n"
    )
    parser = _load_cli_module().build_parser()
    args = parser.parse_args(
        [
            "--data-dir",
            str(data_dir),
            "--output-dir",
            str(tmp_path / "output"),
            "--chain-archive-dir",
            str(archive_dir),
            "--relevance-inventory",
            str(relevance),
        ]
    )
    monkeypatch.setattr(
        monitor_publication,
        "_load_publication_baseline",
        lambda _path: {},
    )
    monkeypatch.setattr(
        monitor_publication, "discover_evidence_sources", lambda *_args: {}
    )
    monkeypatch.setattr(
        monitor_publication, "discover_canonical_sources", lambda *_args: {}
    )
    monkeypatch.setattr(
        monitor_publication, "discover_unknown_sources", lambda *_args: {}
    )
    monkeypatch.setattr(
        monitor_publication,
        "load_stale_descendant_parents",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        monitor_publication,
        "load_stale_descendant_observations",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(
        monitor_publication,
        "validate_error_module",
        lambda **_kwargs: (_ for _ in ()).throw(
            ValueError("error block consensus claim does not re-derive")
        ),
    )
    monkeypatch.setattr(
        monitor_publication,
        "build_error_observation_rows",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("export must not run after consensus validation fails")
        ),
    )

    with pytest.raises(SystemExit, match="2"):
        monitor_publication.validate_publication_inputs(
            args,
            parser,
            baseline_dir=tmp_path / "baseline",
        )

    assert "consensus claim does not re-derive" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("committed_category", "staged_category"),
    [
        ("canonical", "canonical"),
        ("canonical", "stale"),
        ("canonical", "stale_descendant"),
        ("weak_btc_orphan", "weak_btc_orphan"),
        ("weak_btc_orphan", "strict_btc_orphan"),
        ("weak_btc_orphan", "stale"),
        ("weak_btc_orphan", "stale_descendant"),
        ("strict_btc_orphan", "strict_btc_orphan"),
        ("strict_btc_orphan", "stale"),
        ("strict_btc_orphan", "stale_descendant"),
        ("stale", "stale"),
        ("stale", "stale_descendant"),
        ("stale_descendant", "stale_descendant"),
    ],
)
def test_semantic_floor_allows_monotone_category_transitions(
    tmp_path: Path,
    committed_category: str,
    staged_category: str,
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / "devcoin_monitor_evidence.csv"
    staged = staged_dir / "devcoin_monitor_evidence.csv"
    _write_ordinary_artifact(committed)
    shutil.copy2(committed, staged)
    _set_category(committed, committed_category)
    _set_category(staged, staged_category)

    _validate_semantic_floor(committed_dir, staged_dir)


@pytest.mark.parametrize(
    ("committed_category", "staged_category"),
    [
        ("canonical", "strict_btc_orphan"),
        ("strict_btc_orphan", "weak_btc_orphan"),
        ("stale", "canonical"),
        ("stale_descendant", "stale"),
    ],
)
def test_semantic_floor_rejects_category_downgrades(
    tmp_path: Path,
    committed_category: str,
    staged_category: str,
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / "devcoin_monitor_evidence.csv"
    staged = staged_dir / "devcoin_monitor_evidence.csv"
    _write_ordinary_artifact(committed)
    shutil.copy2(committed, staged)
    _set_category(committed, committed_category)
    _set_category(staged, staged_category)

    with pytest.raises(ValueError, match="degrades published observation"):
        _validate_semantic_floor(committed_dir, staged_dir)


def test_semantic_floor_allows_enrichment_and_row_reordering(tmp_path: Path) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / "devcoin_monitor_evidence.csv"
    staged = staged_dir / "devcoin_monitor_evidence.csv"
    _write_ordinary_artifact(committed, stale_rows=2)
    committed_rows = _read_rows(committed)
    committed_rows[0].update(
        {
            "child_height": "",
            "child_block_hash": "",
            "child_block_time": "",
            "btc_header_hex": "",
            "coinbase_scriptsig_hex": "",
        }
    )
    _rewrite_rows(committed, committed_rows)
    shutil.copy2(committed, staged)
    staged_rows = list(reversed(_read_rows(committed)))
    staged_rows[1].update(
        {
            "child_height": "1",
            "child_block_hash": "1".zfill(64),
            "child_block_time": "1",
            "btc_header_hex": TEST_PARENT_HEADER,
            "coinbase_scriptsig_hex": "01",
        }
    )
    _rewrite_rows(staged, staged_rows)

    _validate_semantic_floor(committed_dir, staged_dir)


def test_semantic_floor_uses_injective_matching_for_same_parent_rows(
    tmp_path: Path,
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / "devcoin_monitor_evidence.csv"
    staged = staged_dir / "devcoin_monitor_evidence.csv"
    _write_ordinary_artifact(committed, stale_rows=2)
    committed_rows = _read_rows(committed)
    committed_rows[0]["child_block_hash"] = ""
    _rewrite_rows(committed, committed_rows)
    _write_ordinary_artifact(staged, stale_rows=2)

    _validate_semantic_floor(committed_dir, staged_dir)


def test_semantic_floor_bundles_duplicate_claims_for_one_authenticated_event(
    tmp_path: Path,
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / "devcoin_monitor_evidence.csv"
    staged = staged_dir / "devcoin_monitor_evidence.csv"
    _write_ordinary_artifact(committed)
    stale = _read_rows(committed)[0]
    canonical = {
        **stale,
        "classification": "canonical",
        "validation_status": "",
        "expected_nbits": "",
        "relevance_reason": "",
    }
    _rewrite_rows(committed, [stale, canonical])
    shutil.copy2(committed, staged)
    _rewrite_rows(staged, [stale])

    _validate_semantic_floor(committed_dir, staged_dir)


def test_semantic_floor_preserves_every_claim_in_an_event_bundle(
    tmp_path: Path,
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / "devcoin_monitor_evidence.csv"
    staged = staged_dir / "devcoin_monitor_evidence.csv"
    _write_ordinary_artifact(committed)
    stale = _read_rows(committed)[0]
    canonical = {
        **stale,
        "classification": "canonical",
        "validation_status": "",
        "expected_nbits": "",
        "relevance_reason": "",
        "coinbase_scriptsig_hex": "01",
    }
    _rewrite_rows(committed, [stale, canonical])
    shutil.copy2(committed, staged)
    _rewrite_rows(staged, [stale])

    with pytest.raises(ValueError, match="coinbase_scriptsig_hex"):
        _validate_semantic_floor(committed_dir, staged_dir)


def test_semantic_floor_rejects_duplicate_event_category_downgrade(
    tmp_path: Path,
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / "devcoin_monitor_evidence.csv"
    staged = staged_dir / "devcoin_monitor_evidence.csv"
    _write_ordinary_artifact(committed)
    stale = _read_rows(committed)[0]
    canonical = {
        **stale,
        "classification": "canonical",
        "validation_status": "",
        "expected_nbits": "",
        "relevance_reason": "",
    }
    _rewrite_rows(committed, [stale, canonical])
    shutil.copy2(committed, staged)
    _rewrite_rows(staged, [canonical])

    with pytest.raises(ValueError, match="category stale->canonical"):
        _validate_semantic_floor(committed_dir, staged_dir)


def test_semantic_floor_does_not_bundle_rows_without_authenticated_child_hash(
    tmp_path: Path,
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / "devcoin_monitor_evidence.csv"
    staged = staged_dir / "devcoin_monitor_evidence.csv"
    _write_ordinary_artifact(committed, stale_rows=2)
    committed_rows = _read_rows(committed)
    for row in committed_rows:
        row["child_block_hash"] = ""
    _rewrite_rows(committed, committed_rows)
    shutil.copy2(committed, staged)
    _rewrite_rows(staged, [committed_rows[0]])

    with pytest.raises(ValueError, match="multiplicity 2->1"):
        _validate_semantic_floor(committed_dir, staged_dir)


def test_semantic_floor_rejects_multiplicity_loss(tmp_path: Path) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    _write_ordinary_artifact(
        committed_dir / "devcoin_monitor_evidence.csv", stale_rows=2
    )
    _write_ordinary_artifact(staged_dir / "devcoin_monitor_evidence.csv")

    with pytest.raises(ValueError, match="multiplicity 2->1"):
        _validate_semantic_floor(committed_dir, staged_dir)


@pytest.mark.parametrize(
    "substitution",
    [
        {"btc_header_hash": "bb" * 32},
        {"btc_header_hex": ""},
        {"btc_prev_hash": "cc" * 32},
        {"child_block_hash": "cc" * 32},
        {"child_block_time": "2"},
        {"coinbase_scriptsig_hex": "aa"},
    ],
)
def test_semantic_floor_rejects_equal_count_evidence_substitution(
    tmp_path: Path,
    substitution: dict[str, str],
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / "devcoin_monitor_evidence.csv"
    staged = staged_dir / "devcoin_monitor_evidence.csv"
    _write_ordinary_artifact(committed)
    shutil.copy2(committed, staged)
    _rewrite_first_row(committed, coinbase_scriptsig_hex="01")
    staged_changes = {"coinbase_scriptsig_hex": "01", **substitution}
    _rewrite_first_row(staged, **staged_changes)

    with pytest.raises(ValueError, match="degrades published observation"):
        _validate_semantic_floor(committed_dir, staged_dir)


@pytest.mark.parametrize("chain", ("coiledcoin", "i0coin", "namecoin"))
def test_semantic_floor_allows_only_declared_scan_height_replacement(
    tmp_path: Path,
    chain: str,
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / f"{chain}_monitor_evidence.csv"
    staged = staged_dir / f"{chain}_monitor_evidence.csv"
    _write_ordinary_artifact(committed)
    shutil.copy2(committed, staged)
    _rewrite_first_row(staged, child_height="999")

    _validate_semantic_floor(committed_dir, staged_dir)

    _rewrite_first_row(committed, source_kind="validated_stales")
    with pytest.raises(ValueError, match="child_height"):
        _validate_semantic_floor(committed_dir, staged_dir)


def test_semantic_floor_allows_authenticated_error_promotion(tmp_path: Path) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / "devcoin_monitor_evidence.csv"
    _write_ordinary_artifact(committed)
    committed_row = _read_rows(committed)[0]
    _write_error_artifact(
        staged_dir / "error-block-observations_monitor_evidence.csv",
        committed_row,
    )

    _validate_semantic_floor(committed_dir, staged_dir)


def test_semantic_floor_rejects_error_witness_or_reason_substitution(
    tmp_path: Path,
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    source = tmp_path / "source.csv"
    _write_ordinary_artifact(source)
    source_row = _read_rows(source)[0]
    committed = committed_dir / "error-block-observations_monitor_evidence.csv"
    staged = staged_dir / "error-block-observations_monitor_evidence.csv"
    _write_error_artifact(committed, source_row)
    _write_error_artifact(staged, source_row)
    _rewrite_first_row(staged, child_block_hash="cc" * 32)

    with pytest.raises(ValueError, match="degrades published observation"):
        _validate_semantic_floor(committed_dir, staged_dir)

    _write_error_artifact(staged, source_row)
    _rewrite_first_row(staged, rejection_reason="time_below_mtp")
    with pytest.raises(ValueError, match="rejection_reason"):
        _validate_semantic_floor(committed_dir, staged_dir)


def test_semantic_floor_rejects_staged_error_parent_in_ordinary_artifact(
    tmp_path: Path,
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    committed = committed_dir / "devcoin_monitor_evidence.csv"
    staged = staged_dir / "devcoin_monitor_evidence.csv"
    _write_ordinary_artifact(committed)
    shutil.copy2(committed, staged)
    _write_error_artifact(
        staged_dir / "error-block-observations_monitor_evidence.csv",
        _read_rows(staged)[0],
    )

    with pytest.raises(ValueError, match="remain in ordinary"):
        _validate_semantic_floor(committed_dir, staged_dir)


def test_semantic_loader_rejects_error_parent_in_ordinary_baseline(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    ordinary = baseline / "devcoin_monitor_evidence.csv"
    error = baseline / "error-block-observations_monitor_evidence.csv"
    _write_ordinary_artifact(ordinary)
    source = _read_rows(ordinary)[0]
    _write_error_artifact(error, source)

    with pytest.raises(ValueError, match="remain in ordinary"):
        monitor_publication._load_published_observation_groups(baseline)


def test_semantic_loader_ignores_unknown_descendant_side_annotation(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(artifact)
    _rewrite_first_row(
        artifact,
        classification="unknown",
        validation_status="VALID_STALE_DESCENDANT",
        relevance_reason="valid_stale_descendant",
    )

    assert monitor_publication._load_published_observation_groups(tmp_path) == {}


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("canonical", "stale"),
        ("stale", "stale_descendant"),
        ("canonical", "strict_btc_orphan"),
        ("weak_btc_orphan", "strict_btc_orphan"),
    ],
)
def test_snapshot_rejects_two_final_categories_for_one_parent(
    tmp_path: Path,
    first: str,
    second: str,
) -> None:
    first_artifact = tmp_path / "devcoin_monitor_evidence.csv"
    second_artifact = tmp_path / "namecoin_monitor_evidence.csv"
    _write_ordinary_artifact(first_artifact)
    _write_ordinary_artifact(second_artifact)
    _set_category(first_artifact, first)
    _set_category(second_artifact, second)

    with pytest.raises(ValueError, match="appears in both"):
        monitor_publication._validate_parent_category_exclusivity(tmp_path)


def test_semantic_floor_bounds_production_loading_to_one_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    committed_dir = tmp_path / "committed"
    staged_dir = tmp_path / "staged"
    committed_dir.mkdir()
    staged_dir.mkdir()
    for chain in ("devcoin", "namecoin"):
        committed = committed_dir / f"{chain}_monitor_evidence.csv"
        staged = staged_dir / f"{chain}_monitor_evidence.csv"
        _write_ordinary_artifact(committed)
        shutil.copy2(committed, staged)

    loaded_slices: list[frozenset[str] | None] = []
    original_loader = monitor_publication._load_published_observation_groups

    def recording_loader(*args, **kwargs):
        loaded_slices.append(kwargs.get("ordinary_chains"))
        return original_loader(*args, **kwargs)

    monkeypatch.setattr(monitor_publication, "MONITOR_OUTPUT_DIR", committed_dir)
    monkeypatch.setattr(
        monitor_publication,
        "_load_published_observation_groups",
        recording_loader,
    )

    monitor_publication._validate_published_observation_floor(staged_dir)

    assert loaded_slices
    assert all(
        selection is not None and len(selection) == 1 for selection in loaded_slices
    )


def _publication_count_rows(
    logical_root: str,
    *,
    ordinary_source_rows: int = 1,
    error_rows: int = 0,
) -> list[dict[str, object]]:
    ordinary: dict[str, object] = {
        "chain": "namecoin",
        "source_kind": "full_inventory",
        "artifact_scope": "full_classifier_inventory",
        "artifact_path": f"{logical_root}/namecoin_monitor_evidence.csv",
        "source_path": "<chain-archive>/namecoin/classified/namecoin_stale_blocks.csv",
        "canonical": 0,
        "stale": 1,
        "stale_descendant": 0,
        "strict_btc_orphan": 0,
        "weak_btc_orphan": 0,
        "error_block": 0,
        "monitor_rows": 1,
        "source_rows": ordinary_source_rows,
        "canonical_evidence_status": "no_canonical_rows_in_discovered_artifact",
        "notes": "",
    }
    errors: dict[str, object] = {
        "chain": monitor_publication.ERROR_OBSERVATION_ARTIFACT,
        "source_kind": "error_block_catalogue",
        "artifact_scope": "error-block-observations",
        "artifact_path": (
            f"{logical_root}/"
            f"{monitor_publication.ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv"
        ),
        "source_path": "data/error-blocks/error_block_observations.csv",
        "canonical": 0,
        "stale": 0,
        "stale_descendant": 0,
        "strict_btc_orphan": 0,
        "weak_btc_orphan": 0,
        "error_block": error_rows,
        "monitor_rows": error_rows,
        "source_rows": error_rows,
        "canonical_evidence_status": "not_applicable",
        "notes": f"parents={error_rows}",
    }
    return [ordinary, errors]


def _write_count_rows(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MONITOR_COUNT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _write_error_rows(path: Path, chains: list[str]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ERROR_OBSERVATION_FIELDS)
        writer.writeheader()
        for chain in chains:
            row = {field: "" for field in ERROR_OBSERVATION_FIELDS}
            row["chain"] = chain
            writer.writerow(row)


def _write_staged_publication(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    logical_root = "results/monitor-evidence"
    _write_ordinary_artifact(directory / "namecoin_monitor_evidence.csv")
    error_artifact = (
        directory
        / f"{monitor_publication.ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv"
    )
    _write_error_rows(error_artifact, [])
    rows = _publication_count_rows(logical_root)
    _write_count_rows(directory / monitor_publication.PUBLICATION_COUNTS.name, rows)
    manifest_rows = []
    for row in rows:
        rendered = dict(row)
        for field in monitor_publication._MANIFEST_COUNT_FIELDS:
            rendered[field] = int(rendered[field])
        manifest_rows.append(rendered)
    artifacts = {str(row["chain"]): str(row["artifact_path"]) for row in rows}
    manifest = {
        "output_dir": logical_root,
        "counts_csv": f"{logical_root}/{monitor_publication.PUBLICATION_COUNTS.name}",
        "manifest_json": (
            f"{logical_root}/{monitor_publication.PUBLICATION_MANIFEST.name}"
        ),
        "validation_contracts": monitor_publication.MONITOR_VALIDATION_CONTRACTS,
        "artifacts": artifacts,
        "relevance_inventory": monitor_publication.REPORTED_RELEVANCE_INVENTORY,
        "strict_weak_verdicts_loaded": 0,
        "counts": manifest_rows,
    }
    (directory / monitor_publication.PUBLICATION_MANIFEST.name).write_text(
        json.dumps(manifest) + "\n"
    )
    relevance = directory.parent / "relevance.csv"
    relevance.write_text(
        "chain,source_path,source_row_number,source_classification,"
        "btc_header_hash,btc_stale_relevance,relevance_reason\n"
    )
    return relevance


def _read_manifest(directory: Path) -> dict[str, object]:
    return json.loads(
        (directory / monitor_publication.PUBLICATION_MANIFEST.name).read_text()
    )


def _write_manifest(directory: Path, manifest: dict[str, object]) -> None:
    (directory / monitor_publication.PUBLICATION_MANIFEST.name).write_text(
        json.dumps(manifest) + "\n"
    )


def test_staged_publication_requires_counts_and_manifest(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="lacks counts or manifest"):
        monitor_publication._validate_staged_publication(
            tmp_path, data_dir=REPO / "data"
        )


def test_staged_publication_accepts_exact_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staged"
    relevance = _write_staged_publication(staging)
    monkeypatch.setattr(monitor_publication, "MONITOR_OUTPUT_DIR", staging)

    monitor_publication._validate_staged_publication(
        staging,
        data_dir=REPO / "data",
        relevance_inventory=relevance,
    )


@pytest.mark.parametrize("field", MONITOR_COUNT_FIELDS)
def test_staged_publication_rejects_manifest_count_field_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    staging = tmp_path / "staged"
    relevance = _write_staged_publication(staging)
    manifest = _read_manifest(staging)
    manifest_row = manifest["counts"][0]
    assert isinstance(manifest_row, dict)
    if field in monitor_publication._MANIFEST_COUNT_FIELDS:
        manifest_row[field] = int(manifest_row[field]) + 1
    else:
        manifest_row[field] = str(manifest_row[field]) + "-drift"
    _write_manifest(staging, manifest)
    monkeypatch.setattr(monitor_publication, "MONITOR_OUTPUT_DIR", staging)

    with pytest.raises(ValueError, match="counts|exactly match"):
        monitor_publication._validate_staged_publication(
            staging,
            data_dir=REPO / "data",
            relevance_inventory=relevance,
        )


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("strict_weak_verdicts_loaded", 1, "verdict cardinality"),
        ("validation_contracts", {}, "validation contracts"),
        ("relevance_inventory", "stale.csv", "relevance inventory metadata"),
    ],
)
def test_staged_publication_rejects_top_level_manifest_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: object,
    message: str,
) -> None:
    staging = tmp_path / "staged"
    relevance = _write_staged_publication(staging)
    manifest = _read_manifest(staging)
    manifest[field] = replacement
    _write_manifest(staging, manifest)
    monkeypatch.setattr(monitor_publication, "MONITOR_OUTPUT_DIR", staging)

    with pytest.raises(ValueError, match=message):
        monitor_publication._validate_staged_publication(
            staging,
            data_dir=REPO / "data",
            relevance_inventory=relevance,
        )


def test_staged_publication_rejects_duplicate_manifest_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staged"
    relevance = _write_staged_publication(staging)
    manifest = _read_manifest(staging)
    manifest["counts"].append(dict(manifest["counts"][0]))
    _write_manifest(staging, manifest)
    monkeypatch.setattr(monitor_publication, "MONITOR_OUTPUT_DIR", staging)

    with pytest.raises(ValueError, match="duplicate|extra|reordered"):
        monitor_publication._validate_staged_publication(
            staging,
            data_dir=REPO / "data",
            relevance_inventory=relevance,
        )


def test_staged_publication_rejects_extra_artifact_metadata_and_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staged"
    relevance = _write_staged_publication(staging)
    manifest = _read_manifest(staging)
    manifest["artifacts"]["extra"] = "results/monitor-evidence/extra.csv"
    _write_manifest(staging, manifest)
    (staging / "extra_monitor_evidence.csv").write_text("chain\nextra\n")
    monkeypatch.setattr(monitor_publication, "MONITOR_OUTPUT_DIR", staging)

    with pytest.raises(ValueError, match="artifact map|extra"):
        monitor_publication._validate_staged_publication(
            staging,
            data_dir=REPO / "data",
            relevance_inventory=relevance,
        )


@pytest.mark.parametrize(
    ("chain_index", "field", "message"),
    [
        (0, "error_block", "ordinary artifact declares error blocks"),
        (1, "stale", "error aggregate has nonzero stale"),
    ],
)
def test_staged_publication_rejects_cross_interface_count_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    chain_index: int,
    field: str,
    message: str,
) -> None:
    staging = tmp_path / "staged"
    relevance = _write_staged_publication(staging)
    counts_path = staging / monitor_publication.PUBLICATION_COUNTS.name
    count_rows = _read_rows(counts_path)
    count_rows[chain_index][field] = "1"
    _write_count_rows(counts_path, count_rows)
    manifest = _read_manifest(staging)
    manifest["counts"][chain_index][field] = 1
    _write_manifest(staging, manifest)
    monkeypatch.setattr(monitor_publication, "MONITOR_OUTPUT_DIR", staging)

    with pytest.raises(ValueError, match=message):
        monitor_publication._validate_staged_publication(
            staging,
            data_dir=REPO / "data",
            relevance_inventory=relevance,
        )


def _write_coverage_snapshot(
    directory: Path,
    *,
    ordinary_source_rows: int,
    error_chains: list[str],
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    rows = _publication_count_rows(
        "results/monitor-evidence",
        ordinary_source_rows=ordinary_source_rows,
        error_rows=len(error_chains),
    )
    _write_count_rows(directory / monitor_publication.PUBLICATION_COUNTS.name, rows)
    _write_error_rows(
        directory
        / f"{monitor_publication.ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv",
        error_chains,
    )


def test_logical_source_coverage_floor_rejects_per_chain_loss(tmp_path: Path) -> None:
    committed = tmp_path / "committed"
    staged = tmp_path / "staged"
    _write_coverage_snapshot(
        committed,
        ordinary_source_rows=2,
        error_chains=[],
    )
    _write_coverage_snapshot(
        staged,
        ordinary_source_rows=1,
        error_chains=[],
    )

    with pytest.raises(ValueError, match="namecoin 1<2"):
        monitor_publication._validate_logical_source_coverage_floor(
            staged,
            committed,
        )


def test_logical_source_coverage_floor_allows_ordinary_to_error_shift(
    tmp_path: Path,
) -> None:
    committed = tmp_path / "committed"
    staged = tmp_path / "staged"
    _write_coverage_snapshot(
        committed,
        ordinary_source_rows=2,
        error_chains=[],
    )
    _write_coverage_snapshot(
        staged,
        ordinary_source_rows=1,
        error_chains=["namecoin"],
    )

    monitor_publication._validate_logical_source_coverage_floor(staged, committed)


def _write_publish_fixture(directory: Path, marker: str) -> None:
    """Write the minimal generated set used by publication transaction tests."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "namecoin_monitor_evidence.csv").write_text(
        f"chain,marker\nnamecoin,{marker}\n"
    )
    (directory / "monitor-evidence-counts.csv").write_text(
        f"chain,marker\nnamecoin,{marker}\n"
    )
    (directory / "monitor-evidence-manifest.json").write_text(
        json.dumps({"marker": marker}) + "\n"
    )


def test_publish_staged_artifacts_restores_every_file_after_install_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction_dir = tmp_path / ".monitor.monitor-build-test"
    staging_dir = transaction_dir / "staged"
    output_dir = tmp_path / "monitor"
    _write_publish_fixture(staging_dir, "new")
    _write_publish_fixture(output_dir, "old")
    original_replace = monitor_publication.os.replace
    failed = False

    def fail_one_install(source: Path, destination: Path) -> None:
        nonlocal failed
        source = Path(source)
        destination = Path(destination)
        if (
            not failed
            and source.parent == staging_dir
            and source.name == "monitor-evidence-counts.csv"
            and destination.parent == output_dir
        ):
            failed = True
            raise OSError("injected install failure")
        original_replace(source, destination)

    monkeypatch.setattr(monitor_publication.os, "replace", fail_one_install)

    with pytest.raises(OSError, match="injected install failure"):
        monitor_publication._publish_staged_artifacts(staging_dir, output_dir)

    assert failed
    assert "old" in (output_dir / "namecoin_monitor_evidence.csv").read_text()
    assert "old" in (output_dir / "monitor-evidence-counts.csv").read_text()
    assert "old" in (output_dir / "monitor-evidence-manifest.json").read_text()
    assert "new" in (staging_dir / "namecoin_monitor_evidence.csv").read_text()
    assert "new" in (staging_dir / "monitor-evidence-counts.csv").read_text()
    assert "new" in (staging_dir / "monitor-evidence-manifest.json").read_text()
    assert not any((transaction_dir / "previous").iterdir())


def test_transaction_preserves_recovery_files_when_rollback_is_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "monitor"
    _write_publish_fixture(output_dir, "old")

    def build_fixture(**kwargs: object) -> dict[str, object]:
        _write_publish_fixture(Path(kwargs["output_dir"]), "new")
        return {"status": "built"}

    monkeypatch.setattr(
        monitor_publication,
        "build_monitor_evidence_exports",
        build_fixture,
    )
    original_replace = monitor_publication.os.replace
    install_failed = False
    restore_attempts: list[str] = []

    def fail_install_and_one_restore(source: Path, destination: Path) -> None:
        nonlocal install_failed
        source = Path(source)
        destination = Path(destination)
        if source.parent.name == "previous" and destination.parent == output_dir:
            restore_attempts.append(source.name)
            if source.name == "namecoin_monitor_evidence.csv":
                raise OSError("injected rollback failure")
        if (
            not install_failed
            and source.parent.name == "staged"
            and source.name == "monitor-evidence-counts.csv"
            and destination.parent == output_dir
        ):
            install_failed = True
            raise OSError("injected install failure")
        original_replace(source, destination)

    monkeypatch.setattr(
        monitor_publication.os,
        "replace",
        fail_install_and_one_restore,
    )
    parser = _load_cli_module().build_parser()
    args = parser.parse_args(
        [
            "--allow-partial",
            "--skip-canonical",
            "--output-dir",
            str(output_dir),
            "--data-dir",
            str(tmp_path / "data"),
        ]
    )

    with pytest.raises(
        monitor_publication._PublicationRollbackError,
        match="rollback was incomplete",
    ) as caught:
        monitor_publication.build_transactionally(args)

    recovery_path = caught.value.recovery_path
    assert install_failed
    assert set(restore_attempts) == {
        "namecoin_monitor_evidence.csv",
        "monitor-evidence-counts.csv",
        "monitor-evidence-manifest.json",
    }
    assert recovery_path.is_dir()
    assert str(recovery_path) in str(caught.value)
    assert (recovery_path / "previous" / "namecoin_monitor_evidence.csv").is_file()
    assert (recovery_path / "staged" / "namecoin_monitor_evidence.csv").is_file()
    assert "old" in (output_dir / "monitor-evidence-counts.csv").read_text()
    assert "old" in (output_dir / "monitor-evidence-manifest.json").read_text()


def test_weak_orphan_rejects_timestamp_beyond_epoch_reference_horizon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        monitor_publication,
        "_load_btc_epoch_headers",
        lambda _data_dir: ((100, 0, 1), (200, 2016, 2)),
    )

    assert not monitor_publication._weak_orphan_nbits_match(tmp_path, 201, 2)


def test_publication_runner_dispatches_only_the_full_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = _load_cli_module().build_parser()
    args = parser.parse_args(
        [
            "--allow-partial",
            "--skip-canonical",
            "--output-dir",
            str(tmp_path / "output"),
            "--data-dir",
            str(tmp_path / "data"),
        ]
    )
    monkeypatch.setattr(
        monitor_publication, "validate_publication_inputs", lambda *_: None
    )
    monkeypatch.setattr(
        monitor_publication,
        "build_transactionally",
        lambda received: {"received": received},
    )

    # _run owns no special mode: it validates then invokes only the full writer.
    module = monitor_publication
    assert _run(
        module,
        [
            "--allow-partial",
            "--skip-canonical",
            "--output-dir",
            str(tmp_path / "output"),
            "--data-dir",
            str(tmp_path / "data"),
        ],
    ) == {"received": args}
