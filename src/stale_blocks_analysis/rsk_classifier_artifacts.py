"""Staged, content-bound artifact family for the private RSK classifier."""

from __future__ import annotations

import csv
import json
import os
import tempfile
from pathlib import Path

from .config import PROJECT_ROOT
from .rsk_extraction import (
    checkpoint_artifact_path,
    fsync_directory_best_effort,
    is_lower_hex,
    sha256_file,
)

MANIFEST_VERSION = 3
DEFAULT_MANIFEST_NAME = "rsk_classification_manifest.json"
OUTPUT_LABELS = frozenset(
    {"canonical", "stale_unknown", "error_blocks", "validated_stales", "summary"}
)
DEPENDENCY_LABELS = frozenset({"classifier_script", "error_blocks", "pool_registry"})
FRESH_RSK_ARTIFACT_FIELDS = frozenset(
    {"rsk_block_hash", "child_block_time", "rsk_merkle_proof", "rsk_coinbase_tail"}
)


def default_manifest_path(stales_out: str | Path) -> Path:
    """Derive the classifier-family manifest beside the full inventory."""
    path = Path(stales_out)
    stem = path.name.removesuffix(".csv")
    if stem.endswith("_stale_blocks"):
        stem = stem.removesuffix("_stale_blocks")
    return path.with_name(f"{stem}_classification_manifest.json")


def validate_manifest_output_path(
    stales_out: str | Path, manifest_path: str | Path
) -> None:
    """Require a manifest path that Monitor publication can discover."""
    stales_path = Path(stales_out).resolve()
    resolved_manifest = Path(manifest_path).resolve()
    if resolved_manifest.parent != stales_path.parent or not resolved_manifest.match(
        "*classification_manifest*.json"
    ):
        raise ValueError(
            "RSK classification manifest must be colocated with --stales-out "
            "and match *classification_manifest*.json"
        )


def _portable_path(path: Path, manifest_path: Path) -> str:
    """Record a relative path without embedding an absolute host location."""
    return os.path.relpath(path.resolve(), manifest_path.parent.resolve())


def _dependency_location(path: Path, manifest_path: Path) -> dict[str, str]:
    """Keep repository inputs independent of the archive's host layout."""
    try:
        relative = path.resolve().relative_to(PROJECT_ROOT.resolve())
    except ValueError:
        return {"path_base": "manifest", "path": _portable_path(path, manifest_path)}
    return {"path_base": "repository", "path": relative.as_posix()}


def _resolve_dependency(record: dict, manifest_path: Path) -> Path:
    if record.get("path_base") == "manifest":
        return _resolve_recorded_path(record.get("path"), manifest_path)
    if record.get("path_base") == "repository":
        value = record.get("path")
        if not isinstance(value, str) or not value:
            raise ValueError(f"{manifest_path}: invalid repository dependency path")
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"{manifest_path}: invalid repository dependency path")
        return PROJECT_ROOT / path
    raise ValueError(f"{manifest_path}: invalid dependency path base")


def _resolve_recorded_path(value: object, manifest_path: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{manifest_path}: manifest contains an invalid path")
    path = Path(value)
    return path if path.is_absolute() else manifest_path.parent / path


def _stage_csv(
    final_path: Path,
    columns: list[str],
    rows: list[dict[str, object]],
) -> dict[str, object]:
    final_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{final_path.name}.", suffix=".tmp", dir=final_path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return {
        "temporary_path": temporary_path,
        "final_path": final_path,
        "sha256": sha256_file(temporary_path),
        "bytes": temporary_path.stat().st_size,
        "rows": len(rows),
        "columns": columns,
    }


def _stage_text(final_path: Path, text: str) -> dict[str, object]:
    final_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{final_path.name}.", suffix=".tmp", dir=final_path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return {
        "temporary_path": temporary_path,
        "final_path": final_path,
        "sha256": sha256_file(temporary_path),
        "bytes": temporary_path.stat().st_size,
        "rows": None,
        "columns": None,
    }


def _file_fingerprint(path: Path) -> tuple[int, str]:
    if not path.is_file():
        raise ValueError(f"RSK classifier dependency is missing: {path}")
    return path.stat().st_size, sha256_file(path)


def _validate_dependency_fingerprints(
    dependency_paths: dict[str, Path],
    expected: dict[str, tuple[int, str]],
) -> None:
    if set(dependency_paths) != DEPENDENCY_LABELS or set(expected) != DEPENDENCY_LABELS:
        raise ValueError("RSK classifier dependency set is incomplete")
    for label, path in dependency_paths.items():
        fingerprint = expected[label]
        if (
            not isinstance(fingerprint, tuple)
            or len(fingerprint) != 2
            or type(fingerprint[0]) is not int
            or fingerprint[0] < 0
            or not is_lower_hex(fingerprint[1])
        ):
            raise ValueError(
                f"RSK classifier dependency fingerprint is malformed: {label}"
            )
        if _file_fingerprint(path) != fingerprint:
            raise ValueError(
                f"RSK classifier dependency changed during the run: {label}"
            )


def _validate_checkpoint_state(checkpoint_path: Path, checkpoint_state: dict) -> None:
    try:
        persisted = json.loads(checkpoint_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"cannot read RSK classifier checkpoint {checkpoint_path}"
        ) from exc
    if persisted != checkpoint_state:
        raise ValueError("RSK extraction checkpoint changed during classification")


def _validate_bound_extraction(checkpoint_path: Path, checkpoint_state: dict) -> None:
    bindings = (
        (
            "raw extraction",
            checkpoint_state.get("output_path"),
            checkpoint_state.get("committed_bytes"),
            checkpoint_state.get("content_sha256"),
        ),
        (
            "skip ledger",
            checkpoint_state.get("skip_ledger_path"),
            checkpoint_state.get("skip_committed_bytes"),
            checkpoint_state.get("skip_ledger_sha256"),
        ),
    )
    for label, path_value, expected_bytes, expected_digest in bindings:
        if not isinstance(path_value, str) or not path_value:
            raise ValueError(f"RSK checkpoint has malformed {label} path")
        path = checkpoint_artifact_path(checkpoint_path, path_value)
        if (
            type(expected_bytes) is not int
            or expected_bytes < 0
            or not is_lower_hex(expected_digest)
            or not path.is_file()
            or path.stat().st_size != expected_bytes
        ):
            raise ValueError(f"RSK {label} changed before classifier publication")
        if sha256_file(path) != expected_digest:
            raise ValueError(f"RSK {label} changed before classifier publication")


def _validate_publication_paths(
    *,
    csv_artifacts: list[tuple[str, Path, list[str], list[dict[str, object]]]],
    summary_path: Path,
    manifest_path: Path,
    checkpoint_path: Path,
    checkpoint_state: dict,
    dependency_paths: dict[str, Path],
) -> None:
    """Reject every output, dependency, and extraction-path alias."""
    labelled: list[tuple[str, Path]] = [
        *((f"output {label}", path) for label, path, _columns, _rows in csv_artifacts),
        ("output summary", summary_path),
        ("output manifest", manifest_path),
        ("input checkpoint", checkpoint_path),
        *((f"dependency {label}", path) for label, path in dependency_paths.items()),
    ]
    for label, field in (
        ("input raw extraction", "output_path"),
        ("input skip ledger", "skip_ledger_path"),
    ):
        value = checkpoint_state.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"RSK checkpoint has malformed {field}")
        labelled.append((label, checkpoint_artifact_path(checkpoint_path, value)))
    seen: dict[Path, str] = {}
    for label, path in labelled:
        resolved = path.resolve()
        previous = seen.get(resolved)
        if previous is not None:
            raise ValueError(f"{label} aliases {previous}: {resolved}")
        seen[resolved] = label


def publish_output_family(
    *,
    csv_artifacts: list[tuple[str, Path, list[str], list[dict[str, object]]]],
    summary_path: Path,
    summary_text: str,
    manifest_path: Path,
    checkpoint_path: Path,
    checkpoint_state: dict,
    dependency_paths: dict[str, Path],
    expected_dependency_fingerprints: dict[str, tuple[int, str]],
    classification_context: dict,
) -> dict:
    """Stage the classifier family and publish its integrity manifest last."""
    labels = [label for label, *_rest in csv_artifacts] + ["summary"]
    if len(labels) != len(set(labels)) or set(labels) != OUTPUT_LABELS:
        raise ValueError(
            "RSK classifier output family labels are incomplete or duplicated"
        )
    stale_unknown_path = next(
        path
        for label, path, _columns, _rows in csv_artifacts
        if label == "stale_unknown"
    )
    validate_manifest_output_path(stale_unknown_path, manifest_path)
    _validate_classification_context(classification_context, manifest_path)
    _validate_publication_paths(
        csv_artifacts=csv_artifacts,
        summary_path=summary_path,
        manifest_path=manifest_path,
        checkpoint_path=checkpoint_path,
        checkpoint_state=checkpoint_state,
        dependency_paths=dependency_paths,
    )
    _validate_dependency_fingerprints(
        dependency_paths, expected_dependency_fingerprints
    )
    _validate_checkpoint_state(checkpoint_path, checkpoint_state)
    checkpoint_fingerprint = _file_fingerprint(checkpoint_path)
    dependencies: dict[str, dict[str, object]] = {}
    for label, path in dependency_paths.items():
        expected_bytes, expected_digest = expected_dependency_fingerprints[label]
        dependencies[label] = {
            **_dependency_location(path, manifest_path),
            "sha256": expected_digest,
            "bytes": expected_bytes,
        }
    staged: list[tuple[str, dict[str, object]]] = []
    manifest_temporary: Path | None = None
    try:
        for label, path, columns, rows in csv_artifacts:
            staged.append((label, _stage_csv(path, columns, rows)))
        staged.append(("summary", _stage_text(summary_path, summary_text)))
        output_manifest = {
            label: {
                "path": _portable_path(artifact["final_path"], manifest_path),
                "sha256": artifact["sha256"],
                "bytes": artifact["bytes"],
                "rows": artifact["rows"],
                "columns": artifact["columns"],
            }
            for label, artifact in staged
        }
        manifest = {
            "version": MANIFEST_VERSION,
            "input": {
                "checkpoint_path": _portable_path(checkpoint_path, manifest_path),
                "checkpoint_sha256": checkpoint_fingerprint[1],
                "checkpoint_version": checkpoint_state["version"],
                "start_height": checkpoint_state["start_height"],
                "end_height": checkpoint_state["end_height"],
                "start_identity": checkpoint_state["start_identity"],
                "end_identity": checkpoint_state["end_identity"],
                "csv_columns": checkpoint_state["csv_columns"],
                "content_sha256": checkpoint_state["content_sha256"],
                "content_bytes": checkpoint_state["committed_bytes"],
                "content_rows": checkpoint_state["output_rows"],
                "skip_ledger_sha256": checkpoint_state["skip_ledger_sha256"],
                "skip_ledger_bytes": checkpoint_state["skip_committed_bytes"],
                "skip_rows": checkpoint_state["skip_rows"],
            },
            "classification": classification_context,
            "dependencies": dependencies,
            "outputs": output_manifest,
        }
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{manifest_path.name}.", suffix=".tmp", dir=manifest_path.parent
        )
        manifest_temporary = Path(temporary_name)
        with os.fdopen(fd, "w") as output:
            json.dump(manifest, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())

        # Recheck the original classifier inputs inside the publisher, after
        # staging and immediately before any existing family is replaced.
        # This leaves only the unavoidable rename-sized race window.
        _validate_bound_extraction(checkpoint_path, checkpoint_state)
        _validate_checkpoint_state(checkpoint_path, checkpoint_state)
        if _file_fingerprint(checkpoint_path) != checkpoint_fingerprint:
            raise ValueError("RSK extraction checkpoint changed during publication")
        _validate_dependency_fingerprints(
            dependency_paths, expected_dependency_fingerprints
        )

        if manifest_path.exists():
            manifest_path.unlink()
            fsync_directory_best_effort(manifest_path.parent)
        for _label, artifact in staged:
            os.replace(artifact["temporary_path"], artifact["final_path"])
            fsync_directory_best_effort(Path(artifact["final_path"]).parent)
        os.replace(manifest_temporary, manifest_path)
        manifest_temporary = None
        fsync_directory_best_effort(manifest_path.parent)
        return manifest
    finally:
        for _label, artifact in staged:
            Path(artifact["temporary_path"]).unlink(missing_ok=True)
        if manifest_temporary is not None:
            manifest_temporary.unlink(missing_ok=True)


def _manifest_candidates(artifact_path: Path) -> list[Path]:
    exact = artifact_path.parent / DEFAULT_MANIFEST_NAME
    candidates = [exact] if exact.is_file() else []
    candidates.extend(
        path
        for path in sorted(artifact_path.parent.glob("*classification_manifest*.json"))
        if path not in candidates
    )
    return candidates


def classifier_manifest_present(artifact_path: Path) -> bool:
    """Return whether the artifact directory declares any classifier family."""
    return bool(_manifest_candidates(artifact_path))


def _manifest_output_paths(manifest: dict, manifest_path: Path) -> set[Path]:
    outputs = manifest.get("outputs")
    if not isinstance(outputs, dict):
        return set()
    paths: set[Path] = set()
    for record in outputs.values():
        if not isinstance(record, dict):
            continue
        try:
            paths.add(
                _resolve_recorded_path(record.get("path"), manifest_path).resolve()
            )
        except ValueError:
            continue
    return paths


def _find_manifest(artifact_path: Path) -> Path:
    matches: list[Path] = []
    for candidate in _manifest_candidates(artifact_path):
        try:
            value = json.loads(candidate.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if artifact_path.resolve() in _manifest_output_paths(value, candidate):
            matches.append(candidate)
    if len(matches) != 1:
        raise ValueError(
            f"{artifact_path}: expected exactly one RSK classifier manifest, "
            f"found {len(matches)}"
        )
    return matches[0]


def _exact_csv_header(path: Path) -> list[str]:
    with path.open(newline="") as source:
        return list(csv.DictReader(source).fieldnames or ())


def _csv_metadata(path: Path) -> tuple[list[str], int]:
    with path.open(newline="") as source:
        reader = csv.DictReader(source)
        rows = sum(1 for _row in reader)
        return list(reader.fieldnames or ()), rows


def _validate_classification_context(value: object, manifest_path: Path) -> None:
    if not isinstance(value, dict) or set(value) != {"bitcoin_core", "code"}:
        raise ValueError(f"{manifest_path}: malformed classification context")
    core = value["bitcoin_core"]
    if not isinstance(core, dict) or set(core) != {"start", "end"}:
        raise ValueError(f"{manifest_path}: malformed Bitcoin Core context")
    for label in ("start", "end"):
        identity = core[label]
        if (
            not isinstance(identity, dict)
            or type(identity.get("height")) is not int
            or identity["height"] < 0
            or not is_lower_hex(identity.get("hash"))
            or identity.get("chain") != "main"
            or type(identity.get("headers")) is not int
            or identity["headers"] < identity["height"]
            or identity.get("initial_block_download") is not False
            or not isinstance(identity.get("version"), int)
        ):
            raise ValueError(f"{manifest_path}: malformed Bitcoin Core {label} context")
    if core["end"]["height"] < core["start"]["height"]:
        raise ValueError(f"{manifest_path}: Bitcoin Core height regressed")
    code = value["code"]
    if (
        not isinstance(code, dict)
        or not is_lower_hex(code.get("git_commit"), lengths=(40, 64))
        or code.get("dirty") is not False
    ):
        raise ValueError(f"{manifest_path}: malformed classifier code context")


def _validate_manifest(manifest_name: str) -> dict:
    manifest_path = Path(manifest_name)
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"cannot read RSK classifier manifest {manifest_path}: {exc}"
        ) from exc
    if not isinstance(manifest, dict) or manifest.get("version") != MANIFEST_VERSION:
        raise ValueError(f"{manifest_path}: unsupported classifier manifest")
    outputs = manifest.get("outputs")
    if not isinstance(outputs, dict) or set(outputs) != OUTPUT_LABELS:
        raise ValueError(f"{manifest_path}: missing classifier output family")
    resolved_output_paths: set[Path] = set()
    for label, record in outputs.items():
        if not isinstance(record, dict):
            raise ValueError(f"{manifest_path}: malformed output record {label}")
        path = _resolve_recorded_path(record.get("path"), manifest_path)
        resolved_path = path.resolve()
        if resolved_path in resolved_output_paths:
            raise ValueError(f"{manifest_path}: classifier outputs alias each other")
        resolved_output_paths.add(resolved_path)
        expected_bytes = record.get("bytes")
        expected_digest = record.get("sha256")
        if (
            type(expected_bytes) is not int
            or expected_bytes < 0
            or not path.is_file()
            or path.stat().st_size != expected_bytes
            or not is_lower_hex(expected_digest)
            or sha256_file(path) != expected_digest
        ):
            raise ValueError(
                f"{manifest_path}: output {label} failed content verification"
            )
        columns = record.get("columns")
        rows = record.get("rows")
        if columns is not None:
            actual_columns, actual_rows = _csv_metadata(path)
            if not isinstance(columns, list) or actual_columns != columns:
                raise ValueError(f"{manifest_path}: output {label} schema mismatch")
            if type(rows) is not int or rows < 0 or rows != actual_rows:
                raise ValueError(f"{manifest_path}: output {label} row count mismatch")

    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, dict) or set(dependencies) != DEPENDENCY_LABELS:
        raise ValueError(f"{manifest_path}: missing classification dependencies")
    resolved_dependencies: set[Path] = set()
    for label, record in dependencies.items():
        if not isinstance(record, dict):
            raise ValueError(f"{manifest_path}: malformed dependency {label}")
        path = _resolve_dependency(record, manifest_path)
        resolved_path = path.resolve()
        expected_bytes = record.get("bytes")
        expected_digest = record.get("sha256")
        if resolved_path in resolved_dependencies:
            raise ValueError(f"{manifest_path}: dependencies alias each other")
        resolved_dependencies.add(resolved_path)
        if (
            type(expected_bytes) is not int
            or expected_bytes < 0
            or not is_lower_hex(expected_digest)
            or not path.is_file()
            or path.stat().st_size != expected_bytes
            or sha256_file(path) != expected_digest
        ):
            raise ValueError(
                f"{manifest_path}: dependency {label} failed content verification"
            )

    if resolved_output_paths & resolved_dependencies:
        raise ValueError(f"{manifest_path}: outputs alias classification dependencies")
    if manifest_path.resolve() in resolved_output_paths | resolved_dependencies:
        raise ValueError(f"{manifest_path}: manifest aliases an artifact path")

    _validate_classification_context(manifest.get("classification"), manifest_path)

    input_record = manifest.get("input")
    if not isinstance(input_record, dict):
        raise ValueError(f"{manifest_path}: missing input checkpoint binding")
    checkpoint_path = _resolve_recorded_path(
        input_record.get("checkpoint_path"), manifest_path
    )
    checkpoint_digest = input_record.get("checkpoint_sha256")
    resolved_checkpoint_path = checkpoint_path.resolve()
    if resolved_checkpoint_path in resolved_output_paths | resolved_dependencies:
        raise ValueError(f"{manifest_path}: checkpoint aliases an artifact path")
    if resolved_checkpoint_path == manifest_path.resolve():
        raise ValueError(f"{manifest_path}: manifest aliases its checkpoint")
    if (
        not checkpoint_path.is_file()
        or not is_lower_hex(checkpoint_digest)
        or sha256_file(checkpoint_path) != checkpoint_digest
    ):
        raise ValueError(f"{manifest_path}: input checkpoint digest mismatch")
    try:
        checkpoint = json.loads(checkpoint_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{manifest_path}: cannot read bound checkpoint") from exc
    exact_bindings = {
        "checkpoint_version": checkpoint.get("version"),
        "start_height": checkpoint.get("start_height"),
        "end_height": checkpoint.get("end_height"),
        "start_identity": checkpoint.get("start_identity"),
        "end_identity": checkpoint.get("end_identity"),
        "csv_columns": checkpoint.get("csv_columns"),
        "content_sha256": checkpoint.get("content_sha256"),
        "content_bytes": checkpoint.get("committed_bytes"),
        "content_rows": checkpoint.get("output_rows"),
        "skip_ledger_sha256": checkpoint.get("skip_ledger_sha256"),
        "skip_ledger_bytes": checkpoint.get("skip_committed_bytes"),
        "skip_rows": checkpoint.get("skip_rows"),
    }
    if not checkpoint.get("complete") or any(
        input_record.get(field) != value for field, value in exact_bindings.items()
    ):
        raise ValueError(f"{manifest_path}: input checkpoint binding mismatch")
    extraction_paths: set[Path] = set()
    for field in ("output_path", "skip_ledger_path"):
        value = checkpoint.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{manifest_path}: checkpoint has malformed {field}")
        extraction_paths.add(checkpoint_artifact_path(resolved_checkpoint_path, value))
    if len(extraction_paths) != 2 or extraction_paths & (
        resolved_output_paths | resolved_dependencies | {resolved_checkpoint_path}
    ):
        raise ValueError(f"{manifest_path}: extraction inputs alias artifact paths")
    return manifest


def validate_classifier_manifest_for_artifact(artifact_path: Path) -> dict:
    """Verify the complete output family and checkpoint binding for one artifact."""
    manifest_path = _find_manifest(artifact_path)
    return _validate_manifest(str(manifest_path.resolve()))


def is_fresh_rsk_classifier_artifact(path: Path) -> bool:
    """Return whether a CSV declares the manifest-bound current RSK schema."""
    return FRESH_RSK_ARTIFACT_FIELDS.issubset(_exact_csv_header(path))
