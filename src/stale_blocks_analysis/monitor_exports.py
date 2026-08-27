"""Monitor-facing evidence export helpers.

This module projects normalized AuxPoW evidence into the final-category
artifacts consumed by the merge-mining monitor.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from .config import (
    CHAIN_SPECS,
    MONITOR_VALIDATION_CONTRACTS,
    RELEVANCE_STRICT_BTC_ORPHAN,
    RELEVANCE_WEAK_BTC_ORPHAN,
    RESULTS_DIR,
)
from .config import DATA_DIR
from .evidence_hydration import (
    RSK_SIDECAR_EXPORT_FIELDS,
    ChildIdentityStats,
    hydrate_child_identity,
    hydrate_namecoin_headers,
    load_child_identity,
    namecoin_header_candidate_paths,
)
from .evidence_normalization import (
    EVIDENCE_FIELDS,
    SourceStats,
    canonical_evidence_status,
    collect_source_rows,
    dedupe_canonical_companion_rows,
    enforce_unknown_split_contract,
    int_or_none,
    is_hash,
    merge_stats,
    normalize_hash,
    note_child_height_availability,
    safe_path,
    write_csv,
)
from .evidence_sources import (
    EvidenceSource,
    discover_canonical_sources,
    discover_evidence_sources,
    discover_unknown_sources,
    stale_descendant_source,
)
from .stale_blocks import (
    load_stale_descendant_correction_keys,
    load_stale_descendant_observation_keys,
)

MONITOR_OUTPUT_DIR = RESULTS_DIR / "monitor-evidence"
DEFAULT_RELEVANCE_INVENTORY = (
    RESULTS_DIR
    / "analysis"
    / "btc-stale-relevance"
    / "btc-stale-relevance-inventory.csv"
)
# Publication manifests use a stable logical external name so temporary
# staging basenames do not make otherwise identical builds non-reproducible.
# Diagnostic library calls still report the sanitized path they actually read.
REPORTED_RELEVANCE_INVENTORY = "<external>/btc-stale-relevance-inventory.csv"

# The full-evidence exports in ``full_evidence.py`` carry every evidence state,
# which makes them large (unknown/near rows dominate). This module keeps only
# the categories the merge-mining-monitor ingests as final —
# canonical rows, VALID direct stales, valid stale descendants, and
# strict/weak BTC orphans. Strict/weak verdicts are joined from the relevance
# inventory (scripts/analysis/classify_btc_stale_relevance.py) by header hash;
# the `btc_stale_relevance` / `relevance_reason` columns use the exact strings
# the monitor's importer parses.

MONITOR_EVIDENCE_FIELDS = EVIDENCE_FIELDS + [
    "btc_stale_relevance",
    "relevance_reason",
]

MONITOR_COUNT_FIELDS = [
    "chain",
    "source_kind",
    "artifact_scope",
    "artifact_path",
    "source_path",
    "canonical",
    "stale",
    "stale_descendant",
    "strict_btc_orphan",
    "weak_btc_orphan",
    "error_block",
    "monitor_rows",
    "source_rows",
    "canonical_evidence_status",
    "notes",
]


def load_orphan_relevance_verdicts(path: Path | None) -> dict[str, tuple[str, str]]:
    """Map ``btc_header_hash`` -> (bucket, reason) for strict/weak orphans.

    Reads the relevance inventory produced by
    ``scripts/analysis/classify_btc_stale_relevance.py``. Only the
    strict/weak orphan buckets are retained: excluded rows are dropped by
    the monitor, and ``pending`` rows have no final verdict yet.

    The verdict is per header: the same header observed by several chains
    can carry different per-row verdicts (evidence quality differs by
    source), and the strongest wins — a strict verdict from any observing
    chain beats a weak one, and the first row of the winning bucket is
    kept so regeneration is deterministic.
    """
    if path is None or not path.exists():
        return {}
    verdicts: dict[str, tuple[str, str]] = {}
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            bucket = (row.get("btc_stale_relevance") or "").strip()
            if bucket not in (
                RELEVANCE_STRICT_BTC_ORPHAN,
                RELEVANCE_WEAK_BTC_ORPHAN,
            ):
                continue
            block_hash = normalize_hash(row.get("btc_header_hash"))
            if not is_hash(block_hash):
                continue
            existing = verdicts.get(block_hash)
            if existing is not None and (
                existing[0] == RELEVANCE_STRICT_BTC_ORPHAN or bucket == existing[0]
            ):
                continue
            verdicts[block_hash] = (
                bucket,
                (row.get("relevance_reason") or "").strip(),
            )
    return verdicts


def monitor_verdict(
    row: dict[str, str],
    orphan_verdicts: dict[str, tuple[str, str]],
    descendant_observations: frozenset[tuple[str, int, str]] = frozenset(),
) -> tuple[str, str] | None:
    """Final-category verdict for a normalized evidence row; None drops it.

    Canonical rows carry an empty relevance (the relevance layer refines
    stale candidacy, not canonical membership). Stales and descendants must
    pass their persisted validation gates, and carry an empty relevance too:
    a confirmed row already restates its VALID verdict on the primary
    `classification`/`validation_status` axes, so the derived axis is left
    empty and only the `relevance_reason` records the confirmation.
    Unknown-classified rows survive when the accepted stale-descendant sidecar
    identifies the same source-chain observation, or with a strict/weak verdict
    from the relevance inventory. The caller projects the accepted sidecar's
    ``VALID_STALE_DESCENDANT`` verdict onto the published source observation.
    Near, rejected, and everything else is dropped.
    """
    classification = str(row.get("classification", ""))
    status = str(row.get("validation_status", "")).strip()
    if classification == "canonical":
        return "", ""
    if classification == "stale":
        # A stale row without a persisted VALID verdict (empty status in a
        # pre-gate archive inventory, or any REJECTED/UNKNOWN form) is not
        # admissible monitor evidence — the committed validated files are
        # the arbiter of which stales carry a gate verdict.
        if not status.startswith("VALID"):
            return None
        return "", "valid_direct_stale"
    if classification == "stale_descendant":
        if status != "VALID_STALE_DESCENDANT":
            return None
        return "", "valid_stale_descendant"
    if classification == "unknown":
        height = int_or_none(row.get("btc_height"))
        observation_key = (
            str(row.get("chain", "")),
            height,
            normalize_hash(row.get("btc_header_hash")),
        )
        if observation_key in descendant_observations:
            return "", "valid_stale_descendant"
        return orphan_verdicts.get(normalize_hash(row.get("btc_header_hash")))
    return None


def _monitor_rows_and_counts(
    rows: list[dict[str, str]],
    orphan_verdicts: dict[str, tuple[str, str]],
    *,
    include_canonical: bool = True,
    descendant_observations: frozenset[tuple[str, int, str]] = frozenset(),
) -> tuple[list[dict[str, str]], Counter[str]]:
    """Filter normalized rows to the monitor-facing set and tally categories.

    Keeps canonical rows (unless ``include_canonical`` is False), VALID
    stales and descendants (with an empty derived relevance and a
    ``valid_direct_stale``/``valid_stale_descendant`` reason), and unknown
    rows represented by an accepted descendant or carrying a strict/weak
    verdict; everything else is dropped. Each kept row gains the
    ``btc_stale_relevance`` / ``relevance_reason`` columns the monitor parses.
    The counter uses ``stale_descendant`` for admitted source observations,
    primary classification for canonical/stale rows, and bucket for
    strict/weak rows.
    """
    kept: list[dict[str, str]] = []
    counts: Counter[str] = Counter()
    for row in rows:
        verdict = monitor_verdict(row, orphan_verdicts, descendant_observations)
        if verdict is None:
            continue
        classification = str(row.get("classification", ""))
        if not include_canonical and classification == "canonical":
            # Compact configuration: canonical rows (whether from companion
            # files or retained in-file) are sized and published separately.
            continue
        bucket, reason = verdict
        out = dict(row)
        if reason == "valid_stale_descendant" and classification == "unknown":
            # The source classification remains provenance, while the accepted
            # descendant sidecar supplies the publication validation verdict.
            out["validation_status"] = "VALID_STALE_DESCENDANT"
        out["btc_stale_relevance"] = bucket
        out["relevance_reason"] = reason
        kept.append(out)
        if reason == "valid_stale_descendant" and classification == "unknown":
            counts["stale_descendant"] += 1
        elif bucket in (RELEVANCE_STRICT_BTC_ORPHAN, RELEVANCE_WEAK_BTC_ORPHAN):
            counts[bucket] += 1
        else:
            counts[classification] += 1
    return kept, counts


def monitor_count_row(
    source: EvidenceSource,
    stats: SourceStats,
    counts: Counter[str],
    monitor_rows: int,
    artifact_path: Path | None,
    notes: str = "",
) -> dict[str, object]:
    """Render one per-chain row for the monitor-evidence counts CSV."""
    return {
        "chain": source.chain,
        "source_kind": source.source_kind,
        "artifact_scope": source.artifact_scope,
        "artifact_path": safe_path(artifact_path, chain=source.chain),
        "source_path": safe_path(source.path, chain=source.chain),
        "canonical": counts.get("canonical", 0),
        "stale": counts.get("stale", 0),
        "stale_descendant": counts.get("stale_descendant", 0),
        "strict_btc_orphan": counts.get(RELEVANCE_STRICT_BTC_ORPHAN, 0),
        "weak_btc_orphan": counts.get(RELEVANCE_WEAK_BTC_ORPHAN, 0),
        "error_block": 0,
        "monitor_rows": monitor_rows,
        "source_rows": stats.source_rows,
        "canonical_evidence_status": canonical_evidence_status(source, stats),
        "notes": notes,
    }


def build_monitor_evidence_exports(
    *,
    data_dir: Path = DATA_DIR,
    output_dir: Path = MONITOR_OUTPUT_DIR,
    reported_output_dir: Path | None = None,
    chain_archive_dirs: Iterable[Path] = (),
    relevance_inventory: Path | None = DEFAULT_RELEVANCE_INVENTORY,
    reported_relevance_inventory: str | None = None,
    include_canonical: bool = True,
    fail_on_missing_child_identity: bool = False,
    include_error_observations: bool = False,
) -> dict[str, object]:
    """Write per-chain monitor-facing evidence CSVs plus a counts manifest.

    ``include_canonical=False`` skips canonical rows for every chain in an
    explicitly diagnostic build. ``fail_on_missing_child_identity`` makes an
    unhydrated live-chain row fatal: the monitor importer deliberately skips
    rows without exact child identity, so a publication build must fail closed
    rather than silently publish rows the importer will drop.
    ``reported_output_dir`` is the logical final directory recorded in counts
    and manifests when a caller writes to a temporary staging directory first.
    ``reported_relevance_inventory`` can supply a stable logical publication
    name while diagnostic callers retain the sanitized path they actually read.
    ``include_error_observations`` is enabled only by a complete publication
    build because the recovered witness ledger must agree with the catalogue;
    diagnostic exports deliberately leave the aggregate absent.
    """
    logical_output_dir = reported_output_dir or output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    sources = discover_evidence_sources(data_dir, chain_archive_dirs)
    canonical_sources = (
        discover_canonical_sources(data_dir, chain_archive_dirs)
        if include_canonical
        else {}
    )
    # Unknown companions are always discovered independently of include_canonical:
    # after the split the stale inventory has no unknown rows, so the strict/weak
    # orphan join depends on merging this companion.
    unknown_sources = discover_unknown_sources(data_dir, chain_archive_dirs)
    namecoin_paths = namecoin_header_candidate_paths(data_dir, chain_archive_dirs)
    child_identity = load_child_identity(data_dir)
    error_blocks_path = data_dir / "error-blocks" / "error_blocks.csv"
    orphan_verdicts = load_orphan_relevance_verdicts(relevance_inventory)
    descendant_observations = load_stale_descendant_observation_keys(
        data_dir / "stale_descendants.csv"
    )
    descendant_correction_keys = load_stale_descendant_correction_keys(
        data_dir / "stale_descendant_corrections.csv"
    )
    represented_descendant_observations: set[tuple[str, int, str]] = set()
    inventory_available = bool(orphan_verdicts) or (
        relevance_inventory is not None and relevance_inventory.exists()
    )

    count_rows: list[dict[str, object]] = []
    artifacts: dict[str, str] = {}
    identity_shortfalls: dict[str, ChildIdentityStats] = {}

    def export(
        source: EvidenceSource,
        artifact_name: str,
        companion: EvidenceSource | None = None,
        validated: EvidenceSource | None = None,
        unknown_companion: EvidenceSource | None = None,
    ) -> None:
        """Write one chain's monitor-evidence CSV and record its counts.

        ``validated`` replaces the full inventory's stale rows with the
        committed validated file (the arbiter of gate verdicts); ``companion``
        merges a canonical-parent companion file, skipping any companion
        canonical row already carried by the primary inventory (a
        never-split chain's inventory and companion can overlap; see
        ``dedupe_canonical_companion_rows``); ``unknown_companion`` merges
        the split-out ``_unknown_blocks.csv`` and is applied UNCONDITIONALLY --
        after the split the stale inventory has no unknown rows, so a
        conditional merge would silently drop every unknown monitor row and
        empty the strict/weak orphan join.
        """
        if validated is not None:
            # The committed validated file is the arbiter of which stales
            # carry a gate verdict. The full inventory contributes its
            # non-stale rows, including unknowns for the strict/weak join and
            # any canonical rows retained in-file. Other classifications stay
            # in source accounting but are omitted from monitor output.
            rows, stats = collect_source_rows(
                source,
                exclude_classifications=frozenset({"stale"}),
                stale_descendant_observations=descendant_observations,
                stale_descendant_correction_keys=descendant_correction_keys,
                error_blocks_path=error_blocks_path,
            )
            validated_rows, validated_stats = collect_source_rows(
                validated, error_blocks_path=error_blocks_path
            )
            rows.extend(validated_rows)
            stats = merge_stats(stats, validated_stats)
        else:
            rows, stats = collect_source_rows(
                source,
                stale_descendant_observations=descendant_observations,
                stale_descendant_correction_keys=descendant_correction_keys,
                error_blocks_path=error_blocks_path,
            )
        if unknown_companion is not None:
            enforce_unknown_split_contract(source, stats, unknown_companion)
            unknown_rows, unknown_stats = collect_source_rows(
                unknown_companion, error_blocks_path=error_blocks_path
            )
            rows.extend(unknown_rows)
            stats = merge_stats(stats, unknown_stats)
        skipped_canonical = 0
        if companion is not None:
            companion_rows, companion_stats = collect_source_rows(
                companion, error_blocks_path=error_blocks_path
            )
            companion_rows, skipped_canonical = dedupe_canonical_companion_rows(
                rows, companion_rows
            )
            if skipped_canonical:
                companion_stats.source_rows -= skipped_canonical
                companion_stats.classifications["canonical"] -= skipped_canonical
            rows.extend(companion_rows)
            stats = merge_stats(stats, companion_stats)
        kept, counts = _monitor_rows_and_counts(
            rows,
            orphan_verdicts,
            include_canonical=include_canonical,
            descendant_observations=descendant_observations,
        )
        hydration = hydrate_namecoin_headers(kept, namecoin_paths)
        identity_hydration = hydrate_child_identity(kept, child_identity)
        note_child_height_availability(stats, kept)
        if identity_hydration.missing_identity or identity_hydration.height_mismatch:
            identity_shortfalls[source.chain] = identity_hydration
        if source.chain != "stale-descendants":
            for row in kept:
                if row.get("relevance_reason") != "valid_stale_descendant":
                    continue
                child_height = int_or_none(row.get("child_height"))
                if (
                    child_height is None
                    or child_height < 0
                    or not row.get("child_block_hash")
                    or not row.get("child_block_time")
                ):
                    continue
                height = int_or_none(row.get("btc_height"))
                observation_key = (
                    source.chain,
                    height,
                    normalize_hash(row.get("btc_header_hash")),
                )
                if observation_key in descendant_observations:
                    represented_descendant_observations.add(observation_key)
        artifact_fields = MONITOR_EVIDENCE_FIELDS
        if source.chain == "rsk":
            artifact_fields = MONITOR_EVIDENCE_FIELDS + RSK_SIDECAR_EXPORT_FIELDS
        artifact_path: Path | None = None
        if (
            source.path is not None
            or companion is not None
            or unknown_companion is not None
        ):
            artifact_path = output_dir / artifact_name
            write_csv(artifact_path, kept, artifact_fields)
            reported_artifact_path = logical_output_dir / artifact_name
            artifacts[source.chain] = safe_path(
                reported_artifact_path, chain=source.chain
            )
        notes_parts = sorted(stats.notes)
        if stats.classifications.get("unknown", 0) and not inventory_available:
            notes_parts.append("unknown_rows_present_no_relevance_inventory")
        if skipped_canonical:
            notes_parts.append(
                f"skipped_duplicate_canonical_companion_rows={skipped_canonical}"
            )
        if source.artifact_scope == "partial_canonical_subset":
            notes_parts.append("partial_canonical_subset_not_complete_coverage")
        if hydration.note():
            notes_parts.append(hydration.note())
        if identity_hydration.note():
            notes_parts.append(identity_hydration.note())
        if source.chain == "stale-descendants":
            # The descendants export aggregates observations from several
            # chains into chain-less rows and cannot carry one exact child
            # identity. Report representation only when every corresponding
            # source-chain observation was actually admitted above.
            missing_observations = (
                descendant_observations - represented_descendant_observations
            )
            if missing_observations:
                notes_parts.append("child_identity=deferred_per_observation_recovery")
                notes_parts.append(
                    "missing_usable_source_chain_observations="
                    f"{len(missing_observations)}"
                )
            else:
                notes_parts.append(
                    "child_identity=represented_by_source_chain_observations"
                )
                notes_parts.append(
                    "represented_source_chain_observations="
                    f"{len(represented_descendant_observations)}"
                )
        notes = "; ".join(notes_parts)
        reported_artifact_path = (
            logical_output_dir / artifact_name if artifact_path is not None else None
        )
        count_rows.append(
            monitor_count_row(
                source,
                stats,
                counts,
                len(kept),
                reported_artifact_path,
                notes,
            )
        )

    for chain, spec in CHAIN_SPECS.items():
        main = sources[chain]
        validated: EvidenceSource | None = None
        validated_path = data_dir / "validated-stales" / spec.validated_csv.name
        if validated_path.exists():
            repo_validated = EvidenceSource(
                chain=chain,
                display_name=spec.display_name,
                path=validated_path,
                source_kind="validated_stales",
                artifact_scope="stale_only_publication",
                provenance="repo-data",
            )
            if main.source_kind == "validated_stales":
                # The committed file is the verdict arbiter; it replaces any
                # discovered (possibly older, verdict-less) validated copy.
                main = repo_validated
            else:
                validated = repo_validated
        export(
            main,
            f"{chain}_monitor_evidence.csv",
            companion=canonical_sources.get(chain),
            validated=validated,
            unknown_companion=unknown_sources.get(chain),
        )

    for chain, canonical_source in canonical_sources.items():
        if chain in CHAIN_SPECS:
            continue
        export(canonical_source, f"{chain}_monitor_evidence.csv")

    sidecar = stale_descendant_source(data_dir)
    if sidecar is not None:
        export(sidecar, "stale-descendants_monitor_evidence.csv")

    if include_error_observations:
        # Imported lazily to keep the ordinary final-category projection free
        # of the error aggregate's archive-only reconstruction dependency.
        from .error_observations import (
            error_observation_count_row,
            write_error_observation_artifact,
        )

        error_artifact = write_error_observation_artifact(
            output_dir,
            data_dir=data_dir,
        )
        error_chain = str(error_artifact["artifact"])
        error_path = error_artifact["path"]
        assert isinstance(error_path, Path)
        reported_error_path = logical_output_dir / error_path.name
        artifacts[error_chain] = safe_path(reported_error_path)
        count_rows.append(
            error_observation_count_row(
                error_artifact,
                data_dir=data_dir,
                artifact_path=reported_error_path,
            )
        )

    missing_descendant_observations = (
        descendant_observations - represented_descendant_observations
    )

    if fail_on_missing_child_identity and identity_shortfalls:
        detail = "; ".join(
            f"{chain}: missing_identity={stats.missing_identity}, "
            f"height_mismatch={stats.height_mismatch}"
            for chain, stats in sorted(identity_shortfalls.items())
        )
        raise ValueError(
            "live-chain rows lack a verified child identity and the monitor "
            f"importer would silently drop them ({detail}); regenerate "
            "data/child-identity/ with scripts/extract/recover_child_identity.py "
            "or pass --allow-partial for a disposable diagnostic build"
        )
    if fail_on_missing_child_identity and missing_descendant_observations:
        preview = ", ".join(
            f"{chain}:{height}:{block_hash}"
            for chain, height, block_hash in sorted(missing_descendant_observations)[:5]
        )
        raise ValueError(
            "accepted stale-descendant source observations are absent from the "
            "per-chain monitor payloads: "
            f"{len(missing_descendant_observations)} source observations missing"
            + (f" (first: {preview})" if preview else "")
            + "; restore the complete classified source inventories or pass "
            "--allow-partial for a disposable diagnostic build"
        )
    counts_path = output_dir / "monitor-evidence-counts.csv"
    manifest_json_path = output_dir / "monitor-evidence-manifest.json"
    reported_counts_path = logical_output_dir / counts_path.name
    reported_manifest_path = logical_output_dir / manifest_json_path.name
    write_csv(counts_path, count_rows, MONITOR_COUNT_FIELDS)

    summary = {
        "output_dir": safe_path(logical_output_dir),
        "counts_csv": safe_path(reported_counts_path),
        "manifest_json": safe_path(reported_manifest_path),
        "validation_contracts": MONITOR_VALIDATION_CONTRACTS,
        "artifacts": artifacts,
        "relevance_inventory": (
            (
                reported_relevance_inventory
                or safe_path(relevance_inventory, chain="relevance")
            )
            if inventory_available
            else "missing"
        ),
        "strict_weak_verdicts_loaded": len(orphan_verdicts),
        "counts": count_rows,
    }
    manifest_json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary
