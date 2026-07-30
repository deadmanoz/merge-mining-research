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
    MONITOR_OUTPUT_DIR,
    EvidenceSource,
    build_monitor_evidence_exports,
    discover_canonical_sources,
    discover_evidence_sources,
    discover_unknown_sources,
    load_orphan_relevance_verdicts,
    normalize_evidence_row,
)
from stale_blocks_analysis.config import CHAIN_SPECS  # noqa: E402

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
    for artifact in sorted(baseline_dir.glob("*_monitor_evidence.csv")):
        with artifact.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), start=2):
                bucket = (row.get("btc_stale_relevance") or "").strip()
                if bucket not in ("strict_btc_orphan", "weak_btc_orphan"):
                    continue
                block_hash = (row.get("btc_header_hash") or "").strip().lower()
                chain = (row.get("chain") or "").strip()
                if len(block_hash) != 64 or not chain:
                    raise ValueError(
                        f"{artifact}:{row_number}: malformed baseline relevance row"
                    )
                try:
                    int(block_hash, 16)
                except ValueError as exc:
                    raise ValueError(
                        f"{artifact}:{row_number}: malformed baseline relevance hash"
                    ) from exc
                relevance_rows_by_chain.setdefault(chain, Counter())[block_hash] += 1
                existing = relevance_by_hash.get(block_hash)
                if existing != "strict_btc_orphan":
                    relevance_by_hash[block_hash] = bucket
    for chain, row in rows.items():
        expected_rows = int(row["strict_btc_orphan"]) + int(row["weak_btc_orphan"])
        actual_rows = sum(relevance_rows_by_chain.get(chain, Counter()).values())
        if actual_rows != expected_rows:
            raise ValueError(
                f"{baseline_dir}: {chain} relevance rows do not match counts "
                f"({actual_rows} != {expected_rows})"
            )
    return rows, expected_verdicts, relevance_by_hash, relevance_rows_by_chain


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


def _accepted_descendant_count(path: Path) -> int:
    """Count accepted stale-descendant rows in the committed sidecar."""
    with path.open(newline="") as handle:
        return sum(
            1
            for row in csv.DictReader(handle)
            if (row.get("classification") or "").strip() == "stale_descendant"
            and (row.get("validation_status") or "").strip() == "VALID_STALE_DESCENDANT"
        )


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
        ) = _load_publication_baseline(baseline_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        baseline = {}
        expected_verdicts = 0
        expected_relevance = {}
        expected_relevance_rows = {}
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
        for chain, baseline_row in baseline.items():
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
            elif _accepted_stale_count(validated_path) < expected_categories["stale"]:
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
                if canonical_source is not None and canonical_source.path is not None:
                    companion_canonical = _classification_counts(canonical_source.path)[
                        "canonical"
                    ]
                    source_hashes = _classification_hashes(source.path, "canonical")
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
                if canonical_coverage < expected_categories["canonical"]:
                    problems.append(
                        f"{chain} canonical-classified evidence is below the "
                        "publication baseline"
                    )
                unknown_source = unknown.get(chain)
                if unknown_source is not None and unknown_source.path is not None:
                    coverage += _csv_row_count(unknown_source.path)
                if validated_path.is_file():
                    coverage += _csv_row_count(validated_path)
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
            include_canonical=not args.skip_canonical,
            # A publication build fails closed on an unhydrated live-chain
            # row (the importer would silently drop it); a partial diagnostic
            # build reports the shortfall in the counts notes instead.
            fail_on_missing_child_identity=not args.allow_partial,
        )
        _publish_staged_artifacts(staging_dir, output_dir)
        return summary
    finally:
        shutil.rmtree(transaction_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> None:
    """Write the monitor-facing exports and print the manifest summary."""
    parser = build_parser()
    args = parser.parse_args(argv)
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
