#!/usr/bin/env python3
"""Build final-category monitor-facing evidence exports.

Filters the normalized evidence to the categories the merge-mining-monitor
ingests as final — canonical rows, VALID direct stales, valid stale
descendants, and strict/weak BTC orphans — and writes per-chain CSVs plus a
counts manifest under results/monitor-evidence/. Strict/weak orphan verdicts
are joined by header hash from the relevance inventory produced by
scripts/analysis/classify_btc_stale_relevance.py.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stale_blocks_analysis.full_evidence import (  # noqa: E402
    DATA_DIR,
    DEFAULT_RELEVANCE_INVENTORY,
    MONITOR_COUNT_FIELDS,
    MONITOR_OUTPUT_DIR,
    REPORTED_RELEVANCE_INVENTORY,
    EvidenceSource,
    build_monitor_evidence_exports,
    discover_canonical_sources,
    discover_evidence_sources,
    discover_unknown_sources,
    load_orphan_relevance_verdicts,
    normalize_evidence_row,
    write_csv,
)
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402
from stale_blocks_analysis.stale_blocks import (  # noqa: E402
    load_stale_descendant_correction_keys,
    load_stale_descendant_observation_keys,
)
from stale_blocks_analysis.error_blocks import (  # noqa: E402
    load_consensus_invalid_stale_keys,
    load_stale_exclusion_keys,
)
from stale_blocks_analysis.error_observations import (  # noqa: E402
    ERROR_OBSERVATION_ARTIFACT,
    error_observation_count_row,
    write_error_observation_artifact,
)

PUBLICATION_COUNTS = MONITOR_OUTPUT_DIR / "monitor-evidence-counts.csv"
PUBLICATION_MANIFEST = MONITOR_OUTPUT_DIR / "monitor-evidence-manifest.json"
GENERATED_MONITOR_FILENAMES = frozenset(
    {PUBLICATION_COUNTS.name, PUBLICATION_MANIFEST.name}
)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--output-dir", type=Path, default=MONITOR_OUTPUT_DIR)
    parser.add_argument(
        "--relevance-inventory",
        type=Path,
        default=DEFAULT_RELEVANCE_INVENTORY,
        help=(
            "Relevance inventory CSV supplying strict/weak orphan verdicts. "
            "When absent, unknown-classified rows are omitted and flagged in the manifest."
        ),
    )
    parser.add_argument(
        "--chain-archive-dir",
        dest="chain_archive_dirs",
        action="append",
        type=Path,
        default=[],
        help=(
            "Private chain archive root to scan for "
            "*/classified/*_stale_blocks.csv and "
            "*/validated/*_validated_stales.csv. May be repeated."
        ),
    )
    parser.add_argument(
        "--skip-canonical",
        action="store_true",
        help=(
            "Exclude canonical-parent evidence from a diagnostic export. "
            "Publication builds reject this option; use it only with "
            "--allow-partial and a disposable output directory."
        ),
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help=(
            "Explicitly permit a diagnostic export without the private chain "
            "archive and/or relevance inventory. Partial output can omit "
            "canonical and strict/weak observations and must not replace the "
            "committed publication artifacts."
        ),
    )
    parser.add_argument(
        "--add-error-observations",
        action="store_true",
        help=(
            "Add only the error-block witness aggregate to an existing complete "
            "monitor publication. This does not rebuild ordinary chain artifacts."
        ),
    )
    return parser


def _csv_row_count(path: Path) -> int:
    """Count data rows in a CSV without assuming one physical line per row."""
    with path.open(newline="") as handle:
        return sum(1 for _row in csv.DictReader(handle))


def _classification_counts(path: Path) -> Counter[str]:
    """Count normalized primary classifications in a source CSV."""
    with path.open(newline="") as handle:
        return Counter(
            (row.get("classification") or "").strip().lower() or "unknown"
            for row in csv.DictReader(handle)
        )


def _classification_hashes(path: Path, classification: str) -> set[str] | None:
    """Return exact header identities, or None for a count-only fixture."""
    hashes: set[str] = set()
    with path.open(newline="") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), start=2):
            row_classification = (
                row.get("classification") or ""
            ).strip().lower() or "unknown"
            if row_classification != classification:
                continue
            block_hash = (
                (row.get("btc_header_hash") or row.get("btc_hash") or "")
                .strip()
                .lower()
            )
            if not block_hash:
                return None
            if len(block_hash) != 64:
                raise ValueError(
                    f"{path}:{row_number}: malformed {classification} header hash"
                )
            try:
                int(block_hash, 16)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{row_number}: malformed {classification} header hash"
                ) from exc
            hashes.add(block_hash)
    return hashes


def _load_publication_baseline(
    baseline_dir: Path,
) -> tuple[
    dict[str, dict[str, str]],
    int,
    dict[str, str],
    dict[str, Counter[str]],
    dict[str, set[str]],
]:
    """Load the committed category/count floor used by publication preflight."""
    counts_path = baseline_dir / PUBLICATION_COUNTS.name
    manifest_path = baseline_dir / PUBLICATION_MANIFEST.name
    if not counts_path.is_file() or not manifest_path.is_file():
        raise ValueError(f"publication baseline is incomplete under {baseline_dir}")
    numeric_fields = (
        "canonical",
        "stale",
        "stale_descendant",
        "strict_btc_orphan",
        "weak_btc_orphan",
        "monitor_rows",
        "source_rows",
    )
    with counts_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required_fields = {"chain", "source_kind", *numeric_fields}
        missing_fields = required_fields - set(reader.fieldnames or [])
        if missing_fields:
            raise ValueError(
                f"{counts_path}: missing baseline fields: "
                + ", ".join(sorted(missing_fields))
            )
        rows: dict[str, dict[str, str]] = {}
        for row_number, row in enumerate(reader, start=2):
            chain = (row.get("chain") or "").strip()
            if not chain:
                raise ValueError(f"{counts_path}:{row_number}: empty chain")
            if chain in rows:
                raise ValueError(f"{counts_path}:{row_number}: duplicate chain {chain}")
            rows[chain] = row
    if not rows:
        raise ValueError(f"{counts_path}: publication baseline is empty")
    for chain, row in rows.items():
        for field in numeric_fields:
            value = row.get(field)
            if value is None or not value.strip():
                raise ValueError(
                    f"{counts_path}: {chain} has invalid numeric {field}: {value!r}"
                )
            try:
                parsed = int(value)
            except ValueError as exc:
                raise ValueError(
                    f"{counts_path}: {chain} has invalid numeric {field}: {value!r}"
                ) from exc
            if parsed < 0:
                raise ValueError(
                    f"{counts_path}: {chain} has negative {field}: {parsed}"
                )
    manifest = json.loads(manifest_path.read_text())
    expected_verdicts = manifest.get("strict_weak_verdicts_loaded")
    if not isinstance(expected_verdicts, int) or expected_verdicts < 0:
        raise ValueError(f"{manifest_path}: invalid strict/weak verdict count")
    relevance_by_hash: dict[str, str] = {}
    relevance_rows_by_chain: dict[str, Counter[str]] = {}
    canonical_hashes_by_chain: dict[str, set[str]] = {}
    for artifact in sorted(baseline_dir.glob("*_monitor_evidence.csv")):
        artifact_chain = artifact.name.removesuffix("_monitor_evidence.csv")
        canonical_hashes_by_chain.setdefault(artifact_chain, set())
        with artifact.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), start=2):
                classification = (row.get("classification") or "").strip().lower()
                bucket = (row.get("btc_stale_relevance") or "").strip()
                if classification != "canonical" and bucket not in (
                    "strict_btc_orphan",
                    "weak_btc_orphan",
                ):
                    continue
                block_hash = (row.get("btc_header_hash") or "").strip().lower()
                chain = (row.get("chain") or "").strip()
                if len(block_hash) != 64 or chain != artifact_chain:
                    raise ValueError(
                        f"{artifact}:{row_number}: malformed baseline evidence row"
                    )
                try:
                    int(block_hash, 16)
                except ValueError as exc:
                    raise ValueError(
                        f"{artifact}:{row_number}: malformed baseline evidence hash"
                    ) from exc
                if classification == "canonical":
                    canonical_hashes_by_chain.setdefault(chain, set()).add(block_hash)
                if bucket not in ("strict_btc_orphan", "weak_btc_orphan"):
                    continue
                relevance_rows_by_chain.setdefault(chain, Counter())[block_hash] += 1
                existing = relevance_by_hash.get(block_hash)
                if existing != "strict_btc_orphan":
                    relevance_by_hash[block_hash] = bucket
    for chain, row in rows.items():
        canonical_hashes = canonical_hashes_by_chain.get(chain)
        if canonical_hashes is None:
            raise ValueError(
                f"{baseline_dir}: {chain} monitor-evidence artifact is missing"
            )
        if len(canonical_hashes) != int(row["canonical"]):
            raise ValueError(
                f"{baseline_dir}: {chain} canonical identities do not match counts "
                f"({len(canonical_hashes)} != {row['canonical']})"
            )
        expected_rows = int(row["strict_btc_orphan"]) + int(row["weak_btc_orphan"])
        actual_rows = sum(relevance_rows_by_chain.get(chain, Counter()).values())
        if actual_rows != expected_rows:
            raise ValueError(
                f"{baseline_dir}: {chain} relevance rows do not match counts "
                f"({actual_rows} != {expected_rows})"
            )
    return (
        rows,
        expected_verdicts,
        relevance_by_hash,
        relevance_rows_by_chain,
        canonical_hashes_by_chain,
    )


def _missing_unknown_observations(
    required: Counter[str], sources: list[EvidenceSource]
) -> Counter[str]:
    """Return baseline unknown-hash observations absent from source inventories."""
    remaining = required.copy()
    if not remaining:
        return remaining
    for source in sources:
        if source.path is None or not source.path.is_file():
            continue
        with source.path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            for row_number, row in enumerate(reader, start=2):
                normalized, _errors = normalize_evidence_row(
                    source, row, reader.fieldnames, row_number
                )
                if normalized["classification"] != "unknown":
                    continue
                block_hash = normalized["btc_header_hash"]
                if remaining[block_hash] > 0:
                    remaining[block_hash] -= 1
                    if remaining[block_hash] == 0:
                        del remaining[block_hash]
                    if not remaining:
                        return remaining
    return remaining


def _accepted_stale_count(path: Path) -> int:
    """Count publication-gate-accepted direct stale rows in a loader input."""
    with path.open(newline="") as handle:
        return sum(
            1
            for row in csv.DictReader(handle)
            if (row.get("classification") or "").strip() == "stale"
            and (row.get("validation_status") or "").strip().startswith("VALID")
        )


def _accepted_stale_hashes(path: Path) -> set[str] | None:
    """Return exact accepted stale identities, or None for a count-only fixture."""
    hashes: set[str] = set()
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        if "btc_header_hash" not in (reader.fieldnames or []):
            return None
        for row_number, row in enumerate(reader, start=2):
            if (row.get("classification") or "").strip() != "stale" or not (
                row.get("validation_status") or ""
            ).strip().startswith("VALID"):
                continue
            block_hash = (row.get("btc_header_hash") or "").strip().lower()
            if len(block_hash) != 64:
                raise ValueError(f"{path}:{row_number}: malformed stale header hash")
            try:
                int(block_hash, 16)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{row_number}: malformed stale header hash"
                ) from exc
            hashes.add(block_hash)
    return hashes


def _accepted_descendant_count(path: Path) -> int:
    """Count accepted stale-descendant rows in the committed sidecar."""
    with path.open(newline="") as handle:
        return sum(
            1
            for row in csv.DictReader(handle)
            if (row.get("classification") or "").strip() == "stale_descendant"
            and (row.get("validation_status") or "").strip() == "VALID_STALE_DESCENDANT"
        )


def _projected_stale_descendant_count(
    source: EvidenceSource,
    descendant_observations: frozenset[tuple[str, int, str]],
    descendant_correction_keys: frozenset[tuple[int, str]],
    excluded_keys: set[tuple[int, str]],
    consensus_invalid_keys: set[tuple[int, str]],
) -> int:
    """Count stale source rows retained through descendant reclassification."""
    if source.path is None:
        return 0
    count = 0
    with source.path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for row_number, row in enumerate(reader, start=2):
            normalized, _errors = normalize_evidence_row(
                source, row, reader.fieldnames, row_number
            )
            if normalized["classification"] != "stale":
                continue
            block_hash = normalized["btc_header_hash"]
            try:
                key = (int(normalized["btc_height"]), block_hash)
            except ValueError:
                continue
            # A direct-stale correction must match the sidecar's source
            # observation and the compact exact-key correction overlay.
            if (
                source.chain,
                key[0],
                block_hash,
            ) in descendant_observations and (
                key in descendant_correction_keys and key not in consensus_invalid_keys
            ):
                count += 1
    return count


def _accepted_descendant_observations(
    sources: list[EvidenceSource],
    descendant_observations: frozenset[tuple[str, int, str]],
    descendant_correction_keys: frozenset[tuple[int, str]],
    excluded_keys: set[tuple[int, str]],
    consensus_invalid_keys: set[tuple[int, str]],
) -> set[tuple[str, int, str]]:
    """Return distinct source identities admitted as stale descendants."""
    accepted: set[tuple[str, int, str]] = set()
    for source in sources:
        if source.path is None:
            continue
        with source.path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            for row_number, row in enumerate(reader, start=2):
                normalized, _errors = normalize_evidence_row(
                    source, row, reader.fieldnames, row_number
                )
                classification = normalized["classification"]
                block_hash = normalized["btc_header_hash"]
                try:
                    key = (int(normalized["btc_height"]), block_hash)
                except ValueError:
                    continue
                observation_key = (source.chain, key[0], block_hash)
                if observation_key not in descendant_observations:
                    continue
                if key in consensus_invalid_keys:
                    continue
                if classification == "unknown":
                    if key in excluded_keys:
                        continue
                    accepted.add(observation_key)
                    continue
                if classification == "stale_descendant":
                    if normalized["validation_status"] == "VALID_STALE_DESCENDANT":
                        accepted.add(observation_key)
                    continue
                if classification != "stale":
                    continue
                if key in descendant_correction_keys:
                    accepted.add(observation_key)
    return accepted


def validate_publication_inputs(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    baseline_dir: Path = MONITOR_OUTPUT_DIR,
) -> None:
    """Reject inputs that would silently produce a degraded publication export."""
    if args.allow_partial:
        if args.output_dir.resolve() == MONITOR_OUTPUT_DIR.resolve():
            parser.error(
                "--allow-partial requires an explicit disposable --output-dir; "
                "refusing to overwrite committed monitor evidence"
            )
        return

    problems: list[str] = []
    try:
        (
            baseline,
            expected_verdicts,
            expected_relevance,
            expected_relevance_rows,
            baseline_canonical_hashes,
        ) = _load_publication_baseline(baseline_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        baseline = {}
        expected_verdicts = 0
        expected_relevance = {}
        expected_relevance_rows = {}
        baseline_canonical_hashes = {}
        problems.append(str(exc))

    archive_dirs = [path.expanduser() for path in args.chain_archive_dirs]
    sources = {}
    canonical = {}
    unknown = {}
    if not archive_dirs:
        problems.append("at least one --chain-archive-dir is required")
    else:
        missing_dirs = [str(path) for path in archive_dirs if not path.is_dir()]
        if missing_dirs:
            problems.append(
                "chain archive directories do not exist: " + ", ".join(missing_dirs)
            )
        else:
            sources = discover_evidence_sources(args.data_dir, archive_dirs)
            canonical = discover_canonical_sources(args.data_dir, archive_dirs)
            unknown = discover_unknown_sources(args.data_dir, archive_dirs)

    if args.relevance_inventory is None or not args.relevance_inventory.is_file():
        problems.append("--relevance-inventory must name an existing CSV")
    else:
        actual_relevance = load_orphan_relevance_verdicts(args.relevance_inventory)
        if len(actual_relevance) < expected_verdicts:
            problems.append(
                "relevance inventory has fewer final verdicts than the publication "
                f"baseline ({len(actual_relevance)} < {expected_verdicts})"
            )
        for block_hash, expected_bucket in expected_relevance.items():
            actual = actual_relevance.get(block_hash)
            if actual is None or (
                expected_bucket == "strict_btc_orphan"
                and actual[0] != "strict_btc_orphan"
            ):
                problems.append(
                    f"relevance inventory is missing baseline verdict for {block_hash}"
                )
    if args.skip_canonical:
        problems.append("--skip-canonical is a partial-build option")

    if sources:
        descendants_path = args.data_dir / "stale_descendants.csv"
        descendant_observations = load_stale_descendant_observation_keys(
            descendants_path
        )
        descendant_correction_keys = load_stale_descendant_correction_keys(
            args.data_dir / "stale_descendant_corrections.csv"
        )
        descendant_counts = Counter(
            chain for chain, _height, _block_hash in descendant_observations
        )
        exclusions_path = args.data_dir / "error-blocks" / "error_blocks.csv"
        excluded_keys = (
            load_stale_exclusion_keys(exclusions_path)
            if exclusions_path.is_file()
            else set()
        )
        consensus_invalid_keys = (
            load_consensus_invalid_stale_keys(exclusions_path)
            if exclusions_path.is_file()
            else set()
        )
        for chain, baseline_row in baseline.items():
            # The full build regenerates this aggregate from its separately
            # validated catalogue and witness ledger after canonical preflight.
            if chain == ERROR_OBSERVATION_ARTIFACT:
                continue
            expected_source_rows = int(baseline_row.get("source_rows") or 0)
            expected_categories = {
                category: int(baseline_row.get(category) or 0)
                for category in (
                    "canonical",
                    "stale",
                    "stale_descendant",
                    "strict_btc_orphan",
                    "weak_btc_orphan",
                )
            }

            if chain not in CHAIN_SPECS:
                if chain == "stale-descendants":
                    sidecar = args.data_dir / "stale_descendants.csv"
                    if not sidecar.is_file():
                        problems.append("stale-descendant sidecar is missing")
                    elif _csv_row_count(sidecar) < expected_source_rows:
                        problems.append(
                            "stale-descendant sidecar is below the publication baseline"
                        )
                    elif (
                        _accepted_descendant_count(sidecar)
                        < expected_categories["stale_descendant"]
                    ):
                        problems.append(
                            "accepted stale-descendant coverage is below the "
                            "publication baseline"
                        )
                    continue
                canonical_source = canonical.get(chain)
                if canonical_source is None or canonical_source.path is None:
                    problems.append(f"{chain} canonical source is missing")
                    continue
                source_counts = _classification_counts(canonical_source.path)
                if source_counts["canonical"] < expected_categories["canonical"]:
                    problems.append(
                        f"{chain} canonical-classified evidence is below the "
                        "publication baseline"
                    )
                if _csv_row_count(canonical_source.path) < expected_source_rows:
                    problems.append(
                        f"{chain} canonical source is below the publication baseline"
                    )
                continue

            source = sources[chain]
            validated_path = (
                args.data_dir
                / "validated-stales"
                / CHAIN_SPECS[chain].validated_csv.name
            )
            if not validated_path.is_file():
                problems.append(f"{chain} committed validated input is missing")
                accepted_stale_count = 0
                accepted_stale_hashes: set[str] | None = set()
            else:
                accepted_stale_count = _accepted_stale_count(validated_path)
                try:
                    accepted_stale_hashes = _accepted_stale_hashes(validated_path)
                except ValueError as exc:
                    accepted_stale_hashes = set()
                    problems.append(str(exc))
                if accepted_stale_count < expected_categories["stale"]:
                    problems.append(
                        f"{chain} accepted direct-stale coverage is below the "
                        "publication baseline"
                    )
            baseline_source_kind = baseline_row.get("source_kind") or ""
            if baseline_source_kind == "full_inventory":
                if (
                    source.source_kind != "full_inventory"
                    or source.provenance != "archive"
                    or source.path is None
                ):
                    problems.append(f"{chain} lacks its private full inventory")
                    continue
                # The builder replaces every stale row in the private inventory
                # with the committed validated overlay. Count that projected
                # result, rather than adding the overlay to the unfiltered raw
                # inventory (which could let duplicate stales hide truncation).
                source_counts = _classification_counts(source.path)
                coverage = sum(source_counts.values()) - source_counts["stale"]
                canonical_source = canonical.get(chain)
                canonical_coverage = source_counts["canonical"]
                source_hashes = _classification_hashes(source.path, "canonical")
                if canonical_source is not None and canonical_source.path is not None:
                    companion_canonical = _classification_counts(canonical_source.path)[
                        "canonical"
                    ]
                    companion_hashes = _classification_hashes(
                        canonical_source.path, "canonical"
                    )
                    if source_hashes is not None and companion_hashes is not None:
                        canonical_coverage = len(source_hashes | companion_hashes)
                        coverage += len(companion_hashes - source_hashes)
                    elif source_counts["canonical"] == 0:
                        canonical_coverage = companion_canonical
                        coverage += companion_canonical
                    else:
                        canonical_coverage = max(
                            canonical_coverage, companion_canonical
                        )
                    if source_hashes is not None:
                        if companion_hashes is None:
                            source_hashes = None
                        else:
                            source_hashes |= companion_hashes
                unknown_source = unknown.get(chain)
                descendant_sources = [source]
                if unknown_source is not None:
                    descendant_sources.append(unknown_source)
                accepted_descendants = _accepted_descendant_observations(
                    descendant_sources,
                    descendant_observations,
                    descendant_correction_keys,
                    excluded_keys,
                    consensus_invalid_keys,
                )
                accepted_descendant_hashes = {
                    block_hash
                    for observation_chain, _height, block_hash in accepted_descendants
                    if observation_chain == chain
                }
                accepted_stale_coverage = accepted_stale_count
                if accepted_stale_hashes is not None:
                    accepted_stale_coverage = len(
                        accepted_stale_hashes - accepted_descendant_hashes
                    )
                accepted_final_coverage = (
                    canonical_coverage
                    + accepted_stale_coverage
                    + len(accepted_descendants)
                )
                expected_final_coverage = sum(
                    expected_categories[category]
                    for category in ("canonical", "stale", "stale_descendant")
                )
                if accepted_final_coverage < expected_final_coverage:
                    problems.append(
                        f"{chain} accepted canonical/stale/descendant evidence is "
                        "below the publication baseline"
                    )
                if source_hashes is not None and baseline_canonical_hashes.get(chain):
                    # Category corrections are intentional: a header published as
                    # canonical in the baseline may now be an accepted direct stale
                    # or stale descendant. Preserve its exact identity in any final
                    # category, while rejecting unrelated rows that merely replace
                    # the old count.
                    current_final_hashes = set(source_hashes)
                    if accepted_stale_hashes is not None:
                        current_final_hashes.update(accepted_stale_hashes)
                    current_final_hashes.update(accepted_descendant_hashes)
                    missing_canonical_hashes = (
                        baseline_canonical_hashes.get(chain, set())
                        - current_final_hashes
                    )
                    if missing_canonical_hashes:
                        first_missing = min(missing_canonical_hashes)
                        problems.append(
                            f"{chain} accepted evidence is missing "
                            f"{len(missing_canonical_hashes)} baseline canonical "
                            f"header identities (first: {first_missing})"
                        )
                if unknown_source is not None and unknown_source.path is not None:
                    coverage += _csv_row_count(unknown_source.path)
                if validated_path.is_file():
                    coverage += _csv_row_count(validated_path)
                if descendant_counts[chain]:
                    coverage += _projected_stale_descendant_count(
                        source,
                        descendant_observations,
                        descendant_correction_keys,
                        excluded_keys,
                        consensus_invalid_keys,
                    )
                if coverage < expected_source_rows:
                    problems.append(
                        f"{chain} private inventory is below the publication baseline "
                        f"({coverage} < {expected_source_rows})"
                    )
                relevance_sources = [source]
                if unknown_source is not None:
                    relevance_sources.append(unknown_source)
                missing_relevance = _missing_unknown_observations(
                    expected_relevance_rows.get(chain, Counter()), relevance_sources
                )
                if missing_relevance:
                    missing_count = sum(missing_relevance.values())
                    first_missing = min(missing_relevance)
                    problems.append(
                        f"{chain} private inventory is missing {missing_count} "
                        "baseline strict/weak source rows "
                        f"(first: {first_missing})"
                    )
            elif baseline_source_kind == "canonical_blocks":
                canonical_source = canonical.get(chain)
                # A full archival classifier inventory is authoritative for
                # its canonical rows even when no separate canonical companion
                # exists. Accept that strictly richer representation here.
                if (
                    canonical_source is None
                    and source.source_kind == "full_inventory"
                    and source.provenance == "archive"
                    and source.path is not None
                ):
                    canonical_source = source
                if (
                    canonical_source is None
                    or canonical_source.provenance != "archive"
                    or canonical_source.path is None
                ):
                    problems.append(
                        f"{chain} lacks required private canonical evidence"
                    )
                else:
                    canonical_counts = _classification_counts(canonical_source.path)
                    if canonical_counts["canonical"] < expected_categories["canonical"]:
                        problems.append(
                            f"{chain} canonical-classified evidence is below the "
                            "publication baseline"
                        )
                    if sum(canonical_counts.values()) < expected_source_rows:
                        problems.append(
                            f"{chain} canonical evidence is below the publication "
                            "baseline"
                        )
            elif baseline_source_kind == "validated_stales":
                if (
                    source.path is None
                    or _csv_row_count(source.path) < expected_source_rows
                ):
                    problems.append(
                        f"{chain} validated evidence is below the publication baseline"
                    )

    if problems:
        parser.error(
            "refusing a degraded monitor-evidence publication build: "
            + "; ".join(problems)
            + ". Pass --allow-partial only for disposable diagnostic output."
        )


def _is_generated_monitor_artifact(path: Path) -> bool:
    """Return whether ``path`` belongs to the generated monitor artifact set."""
    return path.name in GENERATED_MONITOR_FILENAMES or path.name.endswith(
        "_monitor_evidence.csv"
    )


def _generated_monitor_artifacts(directory: Path) -> list[Path]:
    """List generated monitor artifacts without touching unrelated entries."""
    if not directory.exists():
        return []
    artifacts: list[Path] = []
    for path in directory.iterdir():
        if not _is_generated_monitor_artifact(path):
            continue
        if path.is_dir() and not path.is_symlink():
            raise ValueError(f"generated monitor artifact path is a directory: {path}")
        artifacts.append(path)
    return sorted(artifacts, key=lambda path: path.name)


def _publish_order(path: Path) -> tuple[int, str]:
    """Publish evidence first, then counts, then the manifest."""
    if path.name == PUBLICATION_COUNTS.name:
        return (1, path.name)
    if path.name == PUBLICATION_MANIFEST.name:
        return (2, path.name)
    return (0, path.name)


def _publish_staged_artifacts(staging_dir: Path, output_dir: Path) -> None:
    """Replace only generated files, restoring the prior set on any failure."""
    staged = _generated_monitor_artifacts(staging_dir)
    staged_names = {path.name for path in staged}
    missing_metadata = GENERATED_MONITOR_FILENAMES - staged_names
    if missing_metadata:
        raise ValueError(
            "staged monitor build lacks required metadata: "
            + ", ".join(sorted(missing_metadata))
        )
    unexpected = [
        path
        for path in staging_dir.iterdir()
        if not _is_generated_monitor_artifact(path)
    ]
    if unexpected:
        raise ValueError(
            "staged monitor build produced unexpected entries: "
            + ", ".join(str(path) for path in sorted(unexpected))
        )

    output_preexisted = output_dir.exists()
    if output_preexisted and not output_dir.is_dir():
        raise NotADirectoryError(
            f"monitor output path is not a directory: {output_dir}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    backup_dir = staging_dir.parent / "previous"
    backup_dir.mkdir()

    previous = _generated_monitor_artifacts(output_dir)
    moved_previous: list[tuple[Path, Path]] = []
    installed: list[tuple[Path, Path]] = []
    try:
        for existing in previous:
            backup = backup_dir / existing.name
            os.replace(existing, backup)
            moved_previous.append((backup, existing))
        for staged_path in sorted(staged, key=_publish_order):
            destination = output_dir / staged_path.name
            os.replace(staged_path, destination)
            installed.append((destination, staged_path))
    except BaseException:
        for destination, staged_path in reversed(installed):
            if destination.exists() or destination.is_symlink():
                os.replace(destination, staged_path)
        for backup, destination in reversed(moved_previous):
            if backup.exists() or backup.is_symlink():
                os.replace(backup, destination)
        if (
            not output_preexisted
            and output_dir.exists()
            and not any(output_dir.iterdir())
        ):
            output_dir.rmdir()
        raise


def _load_error_update_baseline(
    output_dir: Path,
) -> tuple[list[dict[str, str]], dict[str, object]]:
    """Load a complete normal publication before adding its error aggregate."""
    counts_path = output_dir / PUBLICATION_COUNTS.name
    manifest_path = output_dir / PUBLICATION_MANIFEST.name
    if not counts_path.is_file() or not manifest_path.is_file():
        raise ValueError(f"publication baseline is incomplete under {output_dir}")
    with counts_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required = set(MONITOR_COUNT_FIELDS) - {"error_block"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"{counts_path}: missing columns: {', '.join(sorted(missing))}"
            )
        count_rows = list(reader)
    if not count_rows:
        raise ValueError(f"{counts_path}: publication baseline is empty")
    chains = [(row.get("chain") or "").strip() for row in count_rows]
    if not all(chains) or len(chains) != len(set(chains)):
        raise ValueError(f"{counts_path}: invalid or duplicate chain rows")
    for row in count_rows:
        row.setdefault("error_block", "0")

    manifest = json.loads(manifest_path.read_text())
    artifacts = manifest.get("artifacts")
    manifest_counts = manifest.get("counts")
    if not isinstance(artifacts, dict) or not isinstance(manifest_counts, list):
        raise ValueError(f"{manifest_path}: missing artifacts or counts")
    manifest_chains = [
        item.get("chain") for item in manifest_counts if isinstance(item, dict)
    ]
    if set(chains) != set(manifest_chains) or len(manifest_chains) != len(
        set(manifest_chains)
    ):
        raise ValueError(f"{manifest_path}: counts do not match the CSV baseline")
    for item in manifest_counts:
        assert isinstance(item, dict)
        item.setdefault("error_block", 0)
    return count_rows, manifest


def _replace_or_append_count(
    rows: list[dict[str, object]], count: dict[str, object]
) -> list[dict[str, object]]:
    """Replace this aggregate's existing row, keeping normal publication order."""
    chain = str(count["chain"])
    replaced = False
    updated: list[dict[str, object]] = []
    for row in rows:
        if str(row.get("chain") or "") != chain:
            updated.append(row)
            continue
        if replaced:
            raise ValueError(f"duplicate {chain} count rows")
        updated.append(count)
        replaced = True
    if not replaced:
        updated.append(count)
    return updated


def _publish_error_observation_update(staging_dir: Path, output_dir: Path) -> None:
    """Atomically replace the aggregate and its two publication metadata files."""
    names = (
        f"{ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv",
        PUBLICATION_COUNTS.name,
        PUBLICATION_MANIFEST.name,
    )
    staged = [staging_dir / name for name in names]
    missing = [str(path) for path in staged if not path.is_file()]
    if missing:
        raise ValueError("error-observation update lacks: " + ", ".join(missing))
    backup_dir = staging_dir.parent / "previous"
    backup_dir.mkdir()
    moved_previous: list[tuple[Path, Path]] = []
    installed: list[tuple[Path, Path]] = []
    try:
        for staged_path in staged:
            destination = output_dir / staged_path.name
            if destination.exists() or destination.is_symlink():
                backup = backup_dir / staged_path.name
                os.replace(destination, backup)
                moved_previous.append((backup, destination))
        for staged_path in sorted(staged, key=_publish_order):
            destination = output_dir / staged_path.name
            os.replace(staged_path, destination)
            installed.append((destination, staged_path))
    except BaseException:
        for destination, staged_path in reversed(installed):
            if destination.exists() or destination.is_symlink():
                os.replace(destination, staged_path)
        for backup, destination in reversed(moved_previous):
            if backup.exists() or backup.is_symlink():
                os.replace(backup, destination)
        raise


def build_error_observation_update(args: argparse.Namespace) -> dict[str, object]:
    """Publish the sparse error aggregate without rebuilding normal artifacts."""
    output_dir = args.output_dir.expanduser().resolve()
    if not output_dir.is_dir():
        raise ValueError(f"publication output directory is missing: {output_dir}")
    count_rows, manifest = _load_error_update_baseline(output_dir)
    transaction_dir = Path(
        tempfile.mkdtemp(
            prefix=f".{output_dir.name}.error-observations-", dir=output_dir.parent
        )
    )
    staging_dir = transaction_dir / "staged"
    staging_dir.mkdir()
    try:
        artifact = write_error_observation_artifact(
            staging_dir,
            data_dir=args.data_dir,
        )
        artifact_path = (
            output_dir / f"{ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv"
        )
        count = error_observation_count_row(
            artifact,
            data_dir=args.data_dir,
            artifact_path=artifact_path,
        )
        updated_csv_counts = _replace_or_append_count(count_rows, count)
        manifest_counts = manifest.get("counts")
        assert isinstance(manifest_counts, list)
        manifest["counts"] = _replace_or_append_count(manifest_counts, count)
        artifacts = manifest.get("artifacts")
        assert isinstance(artifacts, dict)
        artifacts[str(count["chain"])] = str(count["artifact_path"])
        write_csv(
            staging_dir / PUBLICATION_COUNTS.name,
            updated_csv_counts,
            MONITOR_COUNT_FIELDS,
        )
        (staging_dir / PUBLICATION_MANIFEST.name).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        _publish_error_observation_update(staging_dir, output_dir)
        return {
            "counts_csv": output_dir / PUBLICATION_COUNTS.name,
            "manifest_json": output_dir / PUBLICATION_MANIFEST.name,
            "error_observations": count["monitor_rows"],
        }
    finally:
        shutil.rmtree(transaction_dir, ignore_errors=True)


def build_transactionally(args: argparse.Namespace) -> dict[str, object]:
    """Build in a same-filesystem staging directory, then publish the full set."""
    output_dir = args.output_dir.expanduser().resolve()
    if output_dir == output_dir.parent:
        raise ValueError("refusing to use a filesystem root as monitor output")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    transaction_dir = Path(
        tempfile.mkdtemp(
            prefix=f".{output_dir.name}.monitor-build-", dir=output_dir.parent
        )
    )
    staging_dir = transaction_dir / "staged"
    staging_dir.mkdir()
    try:
        summary = build_monitor_evidence_exports(
            data_dir=args.data_dir,
            output_dir=staging_dir,
            reported_output_dir=output_dir,
            chain_archive_dirs=args.chain_archive_dirs,
            relevance_inventory=args.relevance_inventory,
            reported_relevance_inventory=(
                None if args.allow_partial else REPORTED_RELEVANCE_INVENTORY
            ),
            include_canonical=not args.skip_canonical,
            # A publication build fails closed on an unhydrated live-chain
            # row (the importer would silently drop it); a partial diagnostic
            # build reports the shortfall in the counts notes instead.
            fail_on_missing_child_identity=not args.allow_partial,
            include_error_observations=not args.allow_partial,
        )
        _publish_staged_artifacts(staging_dir, output_dir)
        return summary
    finally:
        shutil.rmtree(transaction_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> None:
    """Write the monitor-facing exports and print the manifest summary."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.add_error_observations:
        if args.allow_partial or args.skip_canonical:
            parser.error(
                "--add-error-observations cannot be combined with partial-build options"
            )
        summary = build_error_observation_update(args)
        print(f"wrote {summary['counts_csv']}")
        print(f"wrote {summary['manifest_json']}")
        print(f"error observations added: {summary['error_observations']}")
        return
    validate_publication_inputs(args, parser)
    if args.allow_partial:
        print(
            "WARNING: building partial monitor evidence; do not replace committed "
            "publication artifacts with this output",
            file=sys.stderr,
        )
    summary = build_transactionally(args)
    print(f"wrote {summary['counts_csv']}")
    print(f"wrote {summary['manifest_json']}")
    print(f"strict/weak verdicts joined: {summary['strict_weak_verdicts_loaded']}")
    if summary["relevance_inventory"] == "missing":
        print(
            "WARNING: relevance inventory missing; unknown-classified rows omitted "
            "(run scripts/analysis/classify_btc_stale_relevance.py first)"
        )


if __name__ == "__main__":
    main()
