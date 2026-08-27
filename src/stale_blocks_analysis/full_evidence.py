"""Full-evidence assembly and established shared import surface."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Iterable

from .config import CHAIN_SPECS, DATA_DIR, RESULTS_DIR
from .evidence_hydration import (
    CHILD_IDENTITY_HYDRATION_CHAINS,
    CHILD_IDENTITY_REQUIRED_CHAINS,
    RSK_SIDECAR_EXPORT_FIELDS,
    ChildIdentityStats,
    HydrationStats,
    hydrate_child_identity,
    hydrate_namecoin_headers,
    load_child_identity,
    load_namecoin_header_hexes,
    namecoin_header_candidate_paths,
    verified_header_hex,
)
from .evidence_normalization import (
    COUNT_FIELDS,
    EVIDENCE_FIELDS,
    MANIFEST_FIELDS,
    SourceStats,
    canonical_evidence_status,
    child_hash_for,
    child_height_for,
    collect_source_rows,
    count_row,
    dedupe_canonical_companion_rows,
    enforce_unknown_split_contract,
    first_present,
    get_value,
    int_or_none,
    is_hash,
    manifest_row,
    merge_stats,
    normalize_evidence_row,
    normalize_hash,
    note_child_height_availability,
    parse_header_fields,
    safe_path,
    write_csv,
)
from .evidence_sources import (
    EvidenceSource,
    archive_candidates,
    archive_full_inventory_candidates,
    discover_canonical_sources,
    discover_evidence_sources,
    discover_unknown_sources,
    normalize_chain_archive_dirs,
    stale_descendant_source,
)

DEFAULT_OUTPUT_DIR = RESULTS_DIR / "full-evidence"

__all__ = (
    "CHILD_IDENTITY_HYDRATION_CHAINS",
    "CHILD_IDENTITY_REQUIRED_CHAINS",
    "COUNT_FIELDS",
    "DATA_DIR",
    "DEFAULT_OUTPUT_DIR",
    "EVIDENCE_FIELDS",
    "EvidenceSource",
    "HydrationStats",
    "MANIFEST_FIELDS",
    "RSK_SIDECAR_EXPORT_FIELDS",
    "SourceStats",
    "ChildIdentityStats",
    "archive_candidates",
    "archive_full_inventory_candidates",
    "build_full_evidence_exports",
    "canonical_evidence_status",
    "child_hash_for",
    "child_height_for",
    "collect_source_rows",
    "count_row",
    "dedupe_canonical_companion_rows",
    "discover_canonical_sources",
    "discover_evidence_sources",
    "discover_unknown_sources",
    "enforce_unknown_split_contract",
    "first_present",
    "get_value",
    "hydrate_child_identity",
    "hydrate_namecoin_headers",
    "int_or_none",
    "is_hash",
    "load_child_identity",
    "load_namecoin_header_hexes",
    "manifest_row",
    "merge_stats",
    "namecoin_header_candidate_paths",
    "normalize_chain_archive_dirs",
    "normalize_evidence_row",
    "normalize_hash",
    "note_child_height_availability",
    "parse_header_fields",
    "safe_path",
    "stale_descendant_source",
    "verified_header_hex",
    "write_csv",
)


def build_full_evidence_exports(
    *,
    data_dir: Path = DATA_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    reported_output_dir: Path | None = None,
    chain_archive_dirs: Iterable[Path] = (),
) -> dict[str, object]:
    """Write normalized full-evidence artifacts and summary reports.

    ``reported_output_dir`` is the logical final location recorded in
    manifests when generation writes through a separate staging directory.
    """
    logical_output_dir = reported_output_dir or output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    sources = discover_evidence_sources(data_dir, chain_archive_dirs)
    canonical_sources = discover_canonical_sources(data_dir, chain_archive_dirs)
    unknown_sources = discover_unknown_sources(data_dir, chain_archive_dirs)
    namecoin_paths = namecoin_header_candidate_paths(data_dir, chain_archive_dirs)
    child_identity = load_child_identity(data_dir)
    error_blocks_path = data_dir / "error-blocks" / "error_blocks.csv"

    count_rows: list[dict[str, object]] = []
    manifest_rows: list[dict[str, object]] = []
    artifacts: dict[str, str] = {}

    for chain in CHAIN_SPECS:
        source = sources[chain]
        artifact_path: Path | None = None
        rows, stats = collect_source_rows(source, error_blocks_path=error_blocks_path)
        companion = canonical_sources.get(chain)
        if companion is not None:
            companion_rows, companion_stats = collect_source_rows(
                companion, error_blocks_path=error_blocks_path
            )
            companion_rows, skipped = dedupe_canonical_companion_rows(
                rows, companion_rows
            )
            if skipped:
                companion_stats.source_rows -= skipped
                companion_stats.classifications["canonical"] -= skipped
                stats.notes.add(f"skipped_duplicate_canonical_companion_rows={skipped}")
            rows.extend(companion_rows)
            stats = merge_stats(stats, companion_stats)
            stats.notes.add(
                "canonical_companion=" + safe_path(companion.path, chain=chain)
            )
        unknown_companion = unknown_sources.get(chain)
        if unknown_companion is not None:
            enforce_unknown_split_contract(source, stats, unknown_companion)
            unknown_rows, unknown_stats = collect_source_rows(
                unknown_companion, error_blocks_path=error_blocks_path
            )
            rows.extend(unknown_rows)
            stats = merge_stats(stats, unknown_stats)
            stats.notes.add(
                "unknown_companion=" + safe_path(unknown_companion.path, chain=chain)
            )
        hydration = hydrate_namecoin_headers(rows, namecoin_paths)
        if hydration.note():
            stats.notes.add(hydration.note())
            stats.missing_btc_header_hex = max(
                0, stats.missing_btc_header_hex - hydration.hydrated
            )
        identity_hydration = hydrate_child_identity(rows, child_identity)
        if identity_hydration.note():
            stats.notes.add(identity_hydration.note())
        note_child_height_availability(stats, rows)
        if (
            source.path is not None
            or companion is not None
            or unknown_companion is not None
        ):
            artifact_path = output_dir / f"{chain}_evidence.csv"
            write_csv(artifact_path, rows, EVIDENCE_FIELDS)
            reported_artifact_path = logical_output_dir / artifact_path.name
            artifacts[chain] = safe_path(reported_artifact_path, chain=chain)
        else:
            reported_artifact_path = None
        count_rows.append(count_row(source, stats, reported_artifact_path))
        manifest_rows.append(manifest_row(source, stats, reported_artifact_path))

    sidecar = stale_descendant_source(data_dir)
    if sidecar is not None:
        rows, stats = collect_source_rows(sidecar, error_blocks_path=error_blocks_path)
        artifact_path = output_dir / "stale-descendants_evidence.csv"
        write_csv(artifact_path, rows, EVIDENCE_FIELDS)
        reported_artifact_path = logical_output_dir / artifact_path.name
        artifacts[sidecar.chain] = safe_path(
            reported_artifact_path, chain=sidecar.chain
        )
        count_rows.append(count_row(sidecar, stats, reported_artifact_path))
        manifest_rows.append(manifest_row(sidecar, stats, reported_artifact_path))

    counts_path = output_dir / "auxpow-full-evidence-counts.csv"
    manifest_csv_path = output_dir / "auxpow-full-evidence-manifest.csv"
    manifest_json_path = output_dir / "auxpow-full-evidence-manifest.json"
    write_csv(counts_path, count_rows, COUNT_FIELDS)
    write_csv(manifest_csv_path, manifest_rows, MANIFEST_FIELDS)

    summary = {
        "output_dir": safe_path(logical_output_dir),
        "counts_csv": safe_path(logical_output_dir / counts_path.name),
        "manifest_csv": safe_path(logical_output_dir / manifest_csv_path.name),
        "manifest_json": safe_path(logical_output_dir / manifest_json_path.name),
        "artifacts": artifacts,
        "chain_archive_dirs": [
            "<chain-archive>/" + root.name
            for root in normalize_chain_archive_dirs(chain_archive_dirs)
        ],
        "status_counts": dict(
            Counter(str(row["canonical_evidence_status"]) for row in manifest_rows)
        ),
        "counts": manifest_rows,
    }
    manifest_json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary
