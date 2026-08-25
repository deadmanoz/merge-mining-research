"""Publication-safety tests for the monitor-evidence command."""

from __future__ import annotations

import csv
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from stale_blocks_analysis.full_evidence import MONITOR_EVIDENCE_FIELDS

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "reports" / "build_monitor_evidence.py"
TEST_PARENT_HASH = "0000000000000a0101e3939b59d526806e0545ee95e7b947b8233ed42bb1b5e7"
TEST_PARENT_HEADER = (
    "01000000b7206e118a8f33910ac281a57f7d0deb234be7cfe9f0f648a80d000000000000"
    "4ef56ab98f9aabaa381960242e408d1bdd75cc6aee049ded0f3e81b02122a7d8215cd44e9a"
    "110e1ac8cae712"
)


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
    error_block: int = 0,
    source_rows: int = 0,
    canonical_hashes: tuple[str, ...] | None = None,
) -> None:
    """Write the minimal committed-baseline shape needed by preflight tests."""
    baseline_dir.mkdir(parents=True)
    (baseline_dir / "monitor-evidence-counts.csv").write_text(
        "chain,source_kind,canonical,stale,stale_descendant,strict_btc_orphan,"
        "weak_btc_orphan,error_block,monitor_rows,source_rows\n"
        f"{chain},{source_kind},{canonical},{stale},{stale_descendant},{strict},"
        f"{weak},{error_block},{canonical + stale + stale_descendant + strict + weak},"
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


def _write_add_only_baseline(output_dir: Path, *, stale: int) -> Path:
    output_dir.mkdir()
    normal_artifact = output_dir / "namecoin_monitor_evidence.csv"
    with normal_artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MONITOR_EVIDENCE_FIELDS)
        writer.writeheader()
        for _index in range(stale):
            row = {field: "" for field in MONITOR_EVIDENCE_FIELDS}
            row.update(
                {
                    "chain": "namecoin",
                    "source_kind": "full_inventory",
                    "artifact_scope": "full_classifier_inventory",
                    "btc_height": "1",
                    "btc_header_hash": TEST_PARENT_HASH,
                    "btc_header_hex": TEST_PARENT_HEADER,
                    "expected_nbits": "1a0e119a",
                    "child_height": "1",
                    "child_block_hash": "11" * 32,
                    "child_block_time": "1",
                    "classification": "stale",
                    "validation_status": "VALID",
                    "relevance_reason": "valid_direct_stale",
                }
            )
            writer.writerow(row)
    count = {
        "chain": "namecoin",
        "source_kind": "full_inventory",
        "artifact_scope": "full_classifier_inventory",
        "artifact_path": "results/monitor-evidence/namecoin_monitor_evidence.csv",
        "source_path": "<chain-archive>/namecoin/classified/namecoin_stale_blocks.csv",
        "canonical": 0,
        "stale": stale,
        "stale_descendant": 0,
        "strict_btc_orphan": 0,
        "weak_btc_orphan": 0,
        "error_block": 0,
        "monitor_rows": stale,
        "source_rows": stale,
        "canonical_evidence_status": "not_applicable",
        "notes": "",
    }
    with (output_dir / "monitor-evidence-counts.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(count))
        writer.writeheader()
        writer.writerow(count)
    (output_dir / "monitor-evidence-manifest.json").write_text(
        json.dumps(
            {
                "artifacts": {"namecoin": count["artifact_path"]},
                "counts": [count],
                "strict_weak_verdicts_loaded": 0,
                "validation_contract": {"profile": "legacy"},
            }
        )
    )
    return normal_artifact


def _append_error_observation_baseline(
    output_dir: Path, *, child_hash: str, parent_hash: str
) -> None:
    counts_path = output_dir / "monitor-evidence-counts.csv"
    with counts_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        counts = list(reader)
    assert fieldnames is not None
    aggregate = {field: "0" for field in fieldnames}
    aggregate.update(
        {
            "chain": "error-block-observations",
            "source_kind": "error_block_catalogue",
            "artifact_scope": "error-block-observations",
            "artifact_path": (
                "results/monitor-evidence/error-block-observations_monitor_evidence.csv"
            ),
            "error_block": "1",
            "monitor_rows": "1",
            "source_rows": "1",
        }
    )
    counts.append(aggregate)
    with counts_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(counts)
    manifest_path = output_dir / "monitor-evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"]["error-block-observations"] = aggregate["artifact_path"]
    manifest["counts"] = counts
    manifest_path.write_text(json.dumps(manifest))
    (output_dir / "error-block-observations_monitor_evidence.csv").write_text(
        "chain,child_height,child_block_hash,btc_height,btc_header_hash\n"
        f"namecoin,1,{child_hash},100,{parent_hash}\n"
    )


def test_error_aggregate_updates_only_its_metadata_and_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    output_dir = tmp_path / "monitor"
    normal_artifact = _write_add_only_baseline(output_dir, stale=1)
    original_normal_artifact = normal_artifact.read_bytes()
    committed_dir = tmp_path / "committed"
    shutil.copytree(output_dir, committed_dir)
    monkeypatch.setattr(module, "MONITOR_OUTPUT_DIR", committed_dir)

    def write_aggregate(staging_dir: Path, **_kwargs: object) -> dict[str, object]:
        (staging_dir / "error-block-observations_monitor_evidence.csv").write_text(
            "chain,child_height,child_block_hash,btc_height,btc_header_hash\n"
            f"namecoin,1,{'01' * 32},100,{'02' * 32}\n"
            f"namecoin,2,{'03' * 32},100,{'02' * 32}\n"
        )
        return {
            "rows": 2,
            "parents": 1,
            "source_chain_counts": {"namecoin": 2},
            "child_field_availability": {"child_height": 2},
            "rsk_complete_sidecars": 0,
        }

    monkeypatch.setattr(module, "write_error_observation_artifact", write_aggregate)

    module.main(
        [
            "--add-error-observations",
            "--output-dir",
            str(output_dir),
            "--chain-archive-dir",
            str(tmp_path / "archive"),
        ]
    )

    assert normal_artifact.read_bytes() == original_normal_artifact
    assert (
        output_dir / "error-block-observations_monitor_evidence.csv"
    ).read_text().count("\n") == 3
    with (output_dir / "monitor-evidence-counts.csv").open(newline="") as handle:
        counts = list(csv.DictReader(handle))
    assert [row["chain"] for row in counts] == [
        "namecoin",
        "error-block-observations",
    ]
    assert [row["error_block"] for row in counts] == ["0", "2"]
    manifest = json.loads((output_dir / "monitor-evidence-manifest.json").read_text())
    assert "validation_contract" not in manifest
    assert manifest["validation_contracts"]["error-block-observations"]["profile"] == (
        "error_observation_consensus_invalid_v1"
    )
    assert manifest["artifacts"]["error-block-observations"].endswith(
        "error-block-observations_monitor_evidence.csv"
    )
    assert manifest["counts"][-1]["error_block"] == 2


def test_error_aggregate_rejects_partial_publication_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    committed_dir = tmp_path / "committed"
    _write_add_only_baseline(committed_dir, stale=1)
    partial_dir = tmp_path / "partial"
    _write_add_only_baseline(partial_dir, stale=0)
    monkeypatch.setattr(module, "MONITOR_OUTPUT_DIR", committed_dir)

    with pytest.raises(ValueError, match="namecoin stale is below floor"):
        module.main(["--add-error-observations", "--output-dir", str(partial_dir)])


def test_error_aggregate_rejects_missing_ordinary_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    committed_dir = tmp_path / "committed"
    _write_add_only_baseline(committed_dir, stale=1)
    partial_dir = tmp_path / "partial"
    _write_add_only_baseline(partial_dir, stale=1)
    (partial_dir / "namecoin_monitor_evidence.csv").unlink()
    monkeypatch.setattr(module, "MONITOR_OUTPUT_DIR", committed_dir)

    with pytest.raises(
        ValueError, match="namecoin monitor-evidence artifact is missing"
    ):
        module.main(["--add-error-observations", "--output-dir", str(partial_dir)])


def test_error_aggregate_rejects_truncated_ordinary_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    committed_dir = tmp_path / "committed"
    _write_add_only_baseline(committed_dir, stale=1)
    partial_dir = tmp_path / "partial"
    _write_add_only_baseline(partial_dir, stale=1)
    (partial_dir / "namecoin_monitor_evidence.csv").write_text(
        "chain,classification,validation_status,btc_stale_relevance,relevance_reason\n"
    )
    monkeypatch.setattr(module, "MONITOR_OUTPUT_DIR", committed_dir)

    with pytest.raises(ValueError, match="missing monitor-evidence fields"):
        module.main(["--add-error-observations", "--output-dir", str(partial_dir)])


def test_error_aggregate_rejects_invalid_relevance_on_confirmed_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    committed_dir = tmp_path / "committed"
    _write_add_only_baseline(committed_dir, stale=1)
    partial_dir = tmp_path / "partial"
    _write_add_only_baseline(partial_dir, stale=1)
    artifact_path = partial_dir / "namecoin_monitor_evidence.csv"
    with artifact_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rows[0]["relevance_reason"] = "strict_height_nbits_match"
    with artifact_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    monkeypatch.setattr(module, "MONITOR_OUTPUT_DIR", committed_dir)

    with pytest.raises(ValueError, match="stale row has invalid relevance"):
        module.main(["--add-error-observations", "--output-dir", str(partial_dir)])


def test_monitor_artifact_rejects_missing_parent_hash(tmp_path: Path) -> None:
    module = _load_module()
    artifact = _write_add_only_baseline(tmp_path / "monitor", stale=1)
    with artifact.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rows[0]["btc_header_hash"] = ""
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="valid Bitcoin parent hash"):
        module._load_monitor_artifact_counts(artifact, "namecoin")


def test_monitor_artifact_rejects_mismatched_parent_header(tmp_path: Path) -> None:
    module = _load_module()
    artifact = _write_add_only_baseline(tmp_path / "monitor", stale=1)
    with artifact.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rows[0]["btc_header_hex"] = "00" * 80
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="serialized Bitcoin parent header"):
        module._load_monitor_artifact_counts(artifact, "namecoin")


def test_monitor_artifact_rejects_mismatched_parent_field(tmp_path: Path) -> None:
    module = _load_module()
    artifact = _write_add_only_baseline(tmp_path / "monitor", stale=1)
    with artifact.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rows[0]["btc_nonce"] = "1"
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="btc_nonce disagrees"):
        module._load_monitor_artifact_counts(artifact, "namecoin")


def test_monitor_artifact_rejects_mismatched_live_child_header(
    tmp_path: Path,
) -> None:
    module = _load_module()
    artifact = _write_add_only_baseline(tmp_path / "monitor", stale=1)
    with artifact.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rows[0]["child_header_hex"] = "00" * 80
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="child fields disagree"):
        module._load_monitor_artifact_counts(artifact, "namecoin")


def test_monitor_artifact_rejects_incomplete_historical_child_bundle(
    tmp_path: Path,
) -> None:
    module = _load_module()
    artifact = _write_add_only_baseline(tmp_path / "monitor", stale=1)
    with artifact.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rows[0]["chain"] = "devcoin"
    rows[0]["child_header_hex"] = ""
    rows[0]["child_nbits"] = ""
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="historical child fields"):
        module._load_monitor_artifact_counts(artifact, "devcoin")


@pytest.mark.parametrize(
    ("classification", "validation_status", "artifact_scope", "reason"),
    [
        ("stale", "VALID", "full_classifier_inventory", "valid_direct_stale"),
        (
            "stale_descendant",
            "VALID_STALE_DESCENDANT",
            "stale_descendant_sidecar",
            "valid_stale_descendant",
        ),
    ],
)
def test_monitor_artifact_rejects_confirmed_row_without_btc_height(
    tmp_path: Path,
    classification: str,
    validation_status: str,
    artifact_scope: str,
    reason: str,
) -> None:
    module = _load_module()
    artifact = _write_add_only_baseline(tmp_path / "monitor", stale=1)
    with artifact.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rows[0].update(
        {
            "btc_height": "",
            "classification": classification,
            "validation_status": validation_status,
            "artifact_scope": artifact_scope,
            "relevance_reason": reason,
        }
    )
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="nonnegative Bitcoin height"):
        module._load_monitor_artifact_counts(artifact, "namecoin")


def test_monitor_artifact_rejects_crossed_orphan_relevance_tuple(
    tmp_path: Path,
) -> None:
    module = _load_module()
    artifact = _write_add_only_baseline(tmp_path / "monitor", stale=1)
    with artifact.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rows[0].update(
        {
            "classification": "unknown",
            "validation_status": "",
            "btc_stale_relevance": "strict_btc_orphan",
            "relevance_reason": "timestamp_epoch_nbits_match",
        }
    )
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="unsupported monitor classification"):
        module._load_monitor_artifact_counts(artifact, "namecoin")


def test_error_aggregate_rejects_manifest_count_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    committed_dir = tmp_path / "committed"
    _write_add_only_baseline(committed_dir, stale=1)
    partial_dir = tmp_path / "partial"
    _write_add_only_baseline(partial_dir, stale=1)
    manifest_path = partial_dir / "monitor-evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["counts"][0]["stale"] = 0
    manifest_path.write_text(json.dumps(manifest))
    monkeypatch.setattr(module, "MONITOR_OUTPUT_DIR", committed_dir)

    with pytest.raises(ValueError, match="manifest.*stale does not match counts"):
        module.main(["--add-error-observations", "--output-dir", str(partial_dir)])


def test_monitor_artifact_rejects_error_block_status_on_stale_row(
    tmp_path: Path,
) -> None:
    module = _load_module()
    artifact = _write_add_only_baseline(tmp_path / "monitor", stale=1)
    with artifact.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rows[0]["validation_status"] = "VALID_ERROR_BLOCK"
    with artifact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="invalid ordinary status"):
        module._load_monitor_artifact_counts(artifact, "namecoin")


def test_error_aggregate_rejects_orphan_bucket_on_non_unknown_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    committed_dir = tmp_path / "committed"
    _write_add_only_baseline(committed_dir, stale=0)
    partial_dir = tmp_path / "partial"
    _write_add_only_baseline(partial_dir, stale=0)
    counts_path = partial_dir / "monitor-evidence-counts.csv"
    with counts_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        counts = list(reader)
    assert fieldnames is not None
    counts[0]["strict_btc_orphan"] = "1"
    counts[0]["monitor_rows"] = "1"
    with counts_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(counts)
    manifest_path = partial_dir / "monitor-evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["counts"][0]["strict_btc_orphan"] = 1
    manifest["counts"][0]["monitor_rows"] = 1
    manifest_path.write_text(json.dumps(manifest))
    with (partial_dir / "namecoin_monitor_evidence.csv").open(
        "w", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=MONITOR_EVIDENCE_FIELDS)
        writer.writeheader()
        row = {field: "" for field in MONITOR_EVIDENCE_FIELDS}
        row.update(
            {
                "chain": "namecoin",
                "source_kind": "full_inventory",
                "artifact_scope": "full_classifier_inventory",
                "btc_header_hash": TEST_PARENT_HASH,
                "btc_header_hex": TEST_PARENT_HEADER,
                "child_height": "1",
                "child_block_hash": "11" * 32,
                "child_block_time": "1",
                "classification": "near",
                "btc_stale_relevance": "strict_btc_orphan",
                "relevance_reason": "strict_height_nbits_match",
            }
        )
        writer.writerow(row)
    monkeypatch.setattr(module, "MONITOR_OUTPUT_DIR", committed_dir)

    with pytest.raises(ValueError, match="unsupported monitor classification"):
        module.main(["--add-error-observations", "--output-dir", str(partial_dir)])


def test_error_aggregate_rejects_truncated_aggregate_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    output_dir = tmp_path / "monitor"
    _write_add_only_baseline(output_dir, stale=1)
    counts_path = output_dir / "monitor-evidence-counts.csv"
    with counts_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        counts = list(reader)
    assert fieldnames is not None
    aggregate = {field: "0" for field in fieldnames}
    aggregate.update(
        {
            "chain": "error-block-observations",
            "source_kind": "error_block_catalogue",
            "artifact_scope": "error-block-observations",
            "artifact_path": (
                "results/monitor-evidence/error-block-observations_monitor_evidence.csv"
            ),
            "error_block": "2",
            "monitor_rows": "2",
            "source_rows": "2",
        }
    )
    counts.append(aggregate)
    with counts_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(counts)
    manifest_path = output_dir / "monitor-evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"]["error-block-observations"] = aggregate["artifact_path"]
    manifest["counts"] = counts
    manifest_path.write_text(json.dumps(manifest))
    (output_dir / "error-block-observations_monitor_evidence.csv").write_text(
        "chain,child_height,child_block_hash,btc_height,btc_header_hash\n"
        f"namecoin,1,{'01' * 32},100,{'02' * 32}\n"
    )
    monkeypatch.setattr(module, "MONITOR_OUTPUT_DIR", output_dir)

    def write_truncated_aggregate(
        staging_dir: Path, **_kwargs: object
    ) -> dict[str, object]:
        (staging_dir / "error-block-observations_monitor_evidence.csv").write_text(
            "chain,child_height,child_block_hash,btc_height,btc_header_hash\n"
            f"namecoin,1,{'01' * 32},100,{'02' * 32}\n"
        )
        return {"rows": 1}

    monkeypatch.setattr(
        module, "write_error_observation_artifact", write_truncated_aggregate
    )

    with pytest.raises(
        ValueError, match="error-block-observations monitor_rows is below floor"
    ):
        module.main(["--add-error-observations", "--output-dir", str(output_dir)])


def test_error_aggregate_rejects_replaced_published_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    output_dir = tmp_path / "monitor"
    _write_add_only_baseline(output_dir, stale=1)
    _append_error_observation_baseline(
        output_dir, child_hash="01" * 32, parent_hash="02" * 32
    )
    monkeypatch.setattr(module, "MONITOR_OUTPUT_DIR", output_dir)

    def write_replacement(staging_dir: Path, **_kwargs: object) -> dict[str, object]:
        (staging_dir / "error-block-observations_monitor_evidence.csv").write_text(
            "chain,child_height,child_block_hash,btc_height,btc_header_hash\n"
            f"namecoin,1,{'03' * 32},101,{'04' * 32}\n"
        )
        return {"rows": 1}

    monkeypatch.setattr(module, "write_error_observation_artifact", write_replacement)

    with pytest.raises(ValueError, match="drops missing 1 published parent identities"):
        module.main(["--add-error-observations", "--output-dir", str(output_dir)])


def test_error_aggregate_rejects_ordinary_overlap_with_error_block_catalogue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    output_dir = tmp_path / "monitor"
    _write_add_only_baseline(output_dir, stale=1)
    committed_dir = tmp_path / "committed"
    shutil.copytree(output_dir, committed_dir)
    monkeypatch.setattr(module, "MONITOR_OUTPUT_DIR", committed_dir)
    data_dir = tmp_path / "data"
    error_blocks = data_dir / "error-blocks" / "error_blocks.csv"
    error_blocks.parent.mkdir(parents=True)
    error_blocks.write_text(
        f"height,hash,classification\n1,{TEST_PARENT_HASH},error_block\n"
    )

    with pytest.raises(ValueError, match="ordinary monitor artifacts overlap"):
        module.main(
            [
                "--add-error-observations",
                "--output-dir",
                str(output_dir),
                "--data-dir",
                str(data_dir),
            ]
        )


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


def test_error_observation_baseline_does_not_require_canonical_source(
    tmp_path: Path,
) -> None:
    module = _load_module()
    data_dir = module.DATA_DIR
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="error-block-observations",
        source_kind="error_block_catalogue",
        source_rows=73,
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=data_dir, archive_dir=archive_dir
    )

    module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)


def test_error_observation_baseline_refuses_regression(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    baseline_dir = tmp_path / "baseline"
    _write_baseline(
        baseline_dir,
        chain="error-block-observations",
        source_kind="error_block_catalogue",
        error_block=74,
        source_rows=74,
    )
    parser, args = _preflight_args(
        module, tmp_path, data_dir=module.DATA_DIR, archive_dir=archive_dir
    )

    with pytest.raises(SystemExit, match="2"):
        module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)

    error = capsys.readouterr().err
    assert "error-block-observations source_rows is below" in error
    assert "error-block-observations error_block is below" in error


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
        "classification,validation_status,btc_height,btc_header_hash,source_rows\n"
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
        "classification,validation_status,btc_height,btc_header_hash,source_rows\n"
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
    # in its final category only when the sidecar and exact-key correction
    # overlay agree.
    module = _load_module()
    descendant_hash = "22" * 32
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\n")
    (data_dir / "stale_descendants.csv").write_text(
        "classification,validation_status,btc_height,btc_header_hash,source_rows\n"
        f"stale_descendant,VALID_STALE_DESCENDANT,2,{descendant_hash},namecoin:2\n"
    )
    (data_dir / "stale_descendant_corrections.csv").write_text(
        "btc_height,btc_header_hash,correction_reason\n"
        f"2,{descendant_hash},reclassified_from_direct_stale\n"
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

    module.validate_publication_inputs(args, parser, baseline_dir=baseline_dir)


def test_full_inventory_rejects_descendant_sidecar_height_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A sidecar observation with the right chain/hash but a different Bitcoin
    # height must not reclassify or count the archive stale. Otherwise a bad
    # archive height could enter the monitor payload and make preflight coverage
    # appear complete.
    module = _load_module()
    descendant_hash = "22" * 32
    data_dir = tmp_path / "data"
    validated = data_dir / "validated-stales" / "namecoin_validated_stales.csv"
    validated.parent.mkdir(parents=True)
    validated.write_text("classification,validation_status\n")
    (data_dir / "stale_descendants.csv").write_text(
        "classification,validation_status,btc_height,btc_header_hash,source_rows\n"
        f"stale_descendant,VALID_STALE_DESCENDANT,1,{descendant_hash},namecoin:2\n"
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
        "classification,validation_status,btc_height,btc_header_hash,source_rows\n"
        f"stale_descendant,VALID_STALE_DESCENDANT,2,{descendant_hash},namecoin:2\n"
    )
    error_blocks = data_dir / "error-blocks" / "error_blocks.csv"
    error_blocks.parent.mkdir(parents=True)
    error_blocks.write_text(
        f"height,hash,classification\n2,{descendant_hash},error_block\n"
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
        "classification,validation_status,btc_height,btc_header_hash,source_rows\n"
        f"stale_descendant,VALID_STALE_DESCENDANT,2,{descendant_hash},namecoin:2\n"
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
        "classification,validation_status,btc_height,btc_header_hash,source_rows\n"
        f"stale_descendant,VALID_STALE_DESCENDANT,99,{'33' * 32},namecoin:99\n"
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
