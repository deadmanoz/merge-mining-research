"""Full-evidence AuxPoW export helpers.

This module builds a monitor-facing evidence layer without changing the
stale-only loader inputs. It prefers full classifier inventories when they are
available, falls back to stale-only validated files with an explicit manifest
status, and writes normalized CSV rows plus count/manifest summaries.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .auxpow_chainid import hash_from_header_bytes
from .auxpow_parse import (
    CHILD_HEADER_FIELDS,
    ChildHeaderValidationError,
    validate_available_child_header_fields,
    validate_child_header_fields,
)
from .bitcoin_binary import format_outputs_addr, parse_coinbase_tx, sha256d
from .config import (
    CHAIN_SPECS,
    DATA_DIR,
    HISTORICAL_CHILD_HEADER_CHAINS,
    PROJECT_ROOT,
    RESULTS_DIR,
    RELEVANCE_STRICT_BTC_ORPHAN,
    RELEVANCE_WEAK_BTC_ORPHAN,
)
from .stale_exclusions import (
    load_consensus_invalid_stale_keys,
    load_stale_exclusion_keys,
)
from .stale_blocks import load_stale_descendant_observation_keys

DEFAULT_OUTPUT_DIR = RESULTS_DIR / "full-evidence"
MONITOR_OUTPUT_DIR = RESULTS_DIR / "monitor-evidence"
DEFAULT_RELEVANCE_INVENTORY = (
    RESULTS_DIR
    / "analysis"
    / "btc-stale-relevance"
    / "btc-stale-relevance-inventory.csv"
)

EVIDENCE_FIELDS = [
    "chain",
    "source_kind",
    "source_path",
    "source_row_number",
    "artifact_scope",
    "provenance",
    "child_height",
    "child_block_hash",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_nonce",
    "btc_header_hex",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "full_coinbase_hex",
    "classification",
    "validation_status",
    "expected_nbits",
    "rejection_reason",
]

COUNT_FIELDS = [
    "chain",
    "source_kind",
    "artifact_scope",
    "artifact_path",
    "source_path",
    "source_rows",
    "canonical",
    "stale",
    "unknown",
    "stale_descendant",
    "near",
    "rejected",
    "malformed",
    "other",
    "missing_btc_header_hex",
    "missing_coinbase_scriptsig_hex",
    "missing_coinbase_outputs",
    "canonical_evidence_status",
    "notes",
]

MANIFEST_FIELDS = [
    "chain",
    "display_name",
    "source_kind",
    "artifact_scope",
    "artifact_path",
    "source_path",
    "canonical_evidence_status",
    "canonical",
    "stale",
    "unknown",
    "stale_descendant",
    "near",
    "rejected",
    "malformed",
    "source_rows",
    "notes",
]

HASH_COLUMNS = ("btc_header_hash", "btc_hash", "hash")
PREV_COLUMNS = ("btc_prev_hash",)
HEADER_HEX_COLUMNS = ("btc_header_hex", "header")
BITS_COLUMNS = ("btc_bits", "btc_bits_hex")
BTC_HEIGHT_COLUMNS = (
    "btc_height",
    "btc_stale_height",
    "height",
    "btc_canonical_height",
)
NON_CHILD_HEIGHT_COLUMNS = {
    "btc_height",
    "btc_stale_height",
    "btc_parent_height",
    "btc_canonical_height",
    "btc_bip34_height",
    "height",
    "root_stale_height",
    "stale_fork_depth",
}


@dataclass(frozen=True, slots=True)
class EvidenceSource:
    chain: str
    display_name: str
    path: Path | None
    source_kind: str
    artifact_scope: str
    provenance: str


@dataclass(slots=True)
class SourceStats:
    source_rows: int = 0
    classifications: Counter[str] = field(default_factory=Counter)
    rejected: int = 0
    malformed: int = 0
    other: int = 0
    missing_btc_header_hex: int = 0
    missing_coinbase_scriptsig_hex: int = 0
    missing_coinbase_outputs: int = 0
    notes: set[str] = field(default_factory=set)


def normalize_chain_archive_dirs(chain_archive_dirs: Iterable[Path] = ()) -> list[Path]:
    """Normalize archive roots to their `chains/` directory when present."""
    roots: list[Path] = []
    for root in chain_archive_dirs:
        if not root:
            continue
        expanded = root.expanduser()
        chains_root = expanded / "chains"
        roots.append(chains_root if chains_root.is_dir() else expanded)
    return roots


def safe_path(path: Path | None, *, chain: str = "") -> str:
    """Render paths without leaking private archive roots."""
    if path is None:
        return ""
    expanded = path.expanduser()
    resolved = (
        expanded if expanded.is_absolute() else PROJECT_ROOT / expanded
    ).resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        pass
    else:
        parts = relative.parts
        if (
            chain
            and len(parts) >= 3
            and parts[:2] == ("staging", "chains")
            and parts[2] == chain
        ):
            return "<chain-archive>/" + "/".join(parts[2:])
        return str(relative)

    parts = resolved.parts
    if chain and chain in parts:
        idx = parts.index(chain)
        return "<chain-archive>/" + "/".join(parts[idx:])
    return "<external>/" + resolved.name


def first_present(fieldnames: Iterable[str] | None, candidates: Iterable[str]) -> str:
    """Return the first candidate column name present in ``fieldnames``, else ''."""
    names = set(fieldnames or [])
    for candidate in candidates:
        if candidate in names:
            return candidate
    return ""


def get_value(
    row: dict[str, str],
    fieldnames: Iterable[str] | None,
    candidates: Iterable[str],
) -> str:
    """Return the stripped value of the first candidate column present in the row."""
    field = first_present(fieldnames, candidates)
    return row.get(field, "").strip() if field else ""


def normalize_hash(value: str | None) -> str:
    """Lowercase and strip a hash string; None becomes ''."""
    return (value or "").strip().lower()


def is_hash(value: str) -> bool:
    """Return True for a 64-character hex string (a display-order block hash)."""
    if len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def parse_header_fields(header_hex: str) -> dict[str, str]:
    """Derive header fields from an 80-byte header hex string.

    Returns ``hash`` / ``prev_hash`` (display-order hex), ``time`` /
    ``nonce`` (decimal strings), and ``bits`` (big-endian hex), or {} when
    the hex is missing, malformed, or shorter than 80 bytes. Used to fill
    columns a source CSV omits.
    """
    header_hex = (header_hex or "").strip()
    if not header_hex:
        return {}
    try:
        raw = bytes.fromhex(header_hex)
    except ValueError:
        return {}
    if len(raw) < 80:
        return {}
    return {
        "hash": sha256d(raw[:80])[::-1].hex(),
        "prev_hash": raw[4:36][::-1].hex(),
        "time": str(int.from_bytes(raw[68:72], "little")),
        "bits": raw[72:76][::-1].hex(),
        "nonce": str(int.from_bytes(raw[76:80], "little")),
    }


def int_or_none(value: str) -> int | None:
    """Parse an int, returning None on empty or non-numeric input."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def btc_height(
    row: dict[str, str], fieldnames: Iterable[str] | None, classification: str
) -> str:
    """Resolve the BTC parent height for a row, as a string.

    Takes the first populated height column; for stale rows falls back to
    ``btc_parent_height + 1`` (the stale sits one above its canonical
    parent). Returns '' when nothing resolves.
    """
    height = get_value(row, fieldnames, BTC_HEIGHT_COLUMNS)
    if height:
        return height
    parent_height = int_or_none(row.get("btc_parent_height", "").strip())
    if classification == "stale" and parent_height is not None:
        return str(parent_height + 1)
    return ""


def child_height_for(
    chain: str,
    row: dict[str, str],
    fieldnames: Iterable[str] | None,
) -> str:
    """Resolve the child-chain height column for ``chain``.

    Prefers the chain's registered ``height_column`` from CHAIN_SPECS, then
    any populated ``*_height`` column that is not a BTC-side height, then a
    literal ``child_height`` column. Returns '' when absent.
    """
    spec = CHAIN_SPECS.get(chain)
    if spec and spec.height_column and spec.height_column in (fieldnames or []):
        value = row.get(spec.height_column, "").strip()
        if value:
            return value
    for field in fieldnames or []:
        if field.endswith("_height") and field not in NON_CHILD_HEIGHT_COLUMNS:
            value = row.get(field, "").strip()
            if value:
                return value
    return row.get("child_height", "").strip()


def child_hash_for(
    chain: str,
    row: dict[str, str],
    fieldnames: Iterable[str] | None,
) -> str:
    """Return the child block hash from the chain-specific or generic column."""
    underscored = chain.replace("-", "_")
    return get_value(
        row,
        fieldnames,
        (
            f"{chain}_block_hash",
            f"{underscored}_block_hash",
            "child_block_hash",
            "block_hash",
        ),
    )


def parse_coinbase_fields(row: dict[str, str]) -> tuple[str, str, str, bool]:
    """Extract coinbase evidence, decoding ``full_coinbase_hex`` when needed.

    Returns ``(scriptsig_hex, outputs, full_coinbase_hex, malformed)``.
    Hathor-style rows carry only the full coinbase transaction; when the
    scriptsig or outputs columns are empty, they are filled by parsing it.
    ``malformed`` flags a full coinbase that failed to parse.
    """
    scriptsig = row.get("coinbase_scriptsig_hex", "").strip()
    outputs = row.get("coinbase_outputs", "").strip()
    full_coinbase = row.get("full_coinbase_hex", "").strip()
    malformed = False
    if full_coinbase and (not scriptsig or not outputs):
        try:
            parsed = parse_coinbase_tx(bytes.fromhex(full_coinbase))
        except ValueError:
            parsed = None
        if parsed is None:
            malformed = True
        else:
            scriptsig = scriptsig or parsed["scriptsig"].hex()
            outputs = outputs or format_outputs_addr(parsed["outputs"])
    return scriptsig, outputs, full_coinbase, malformed


def normalize_classification(source: EvidenceSource, row: dict[str, str]) -> str:
    """Normalize a row's classification value.

    Validated-stales files may omit the column (every row is a stale);
    the legacy ``orphan`` spelling maps to ``unknown``; anything else
    passes through lowercased, defaulting to ``unknown`` when empty.
    """
    classification = row.get("classification", "").strip().lower()
    if not classification and source.source_kind == "validated_stales":
        return "stale"
    if classification == "orphan":  # legacy artifacts wrote "orphan"
        return "unknown"
    return classification or "unknown"


def rejection_reason(row: dict[str, str], validation_status: str) -> str:
    """Return the row's rejection reason.

    Prefers an explicit ``rejection_reason`` column; otherwise a
    REJECTED-prefixed ``validation_status`` doubles as the reason. '' for
    rows that were not rejected.
    """
    direct = row.get("rejection_reason", "").strip()
    if direct:
        return direct
    if validation_status.upper().startswith("REJECTED"):
        return validation_status
    return ""


def normalize_evidence_row(
    source: EvidenceSource,
    row: dict[str, str],
    fieldnames: Iterable[str] | None,
    row_number: int,
) -> tuple[dict[str, str], set[str]]:
    """Normalize one source CSV row into the EVIDENCE_FIELDS shape.

    Fills header fields from ``btc_header_hex`` where the source omits
    columns, normalizes the classification (legacy ``orphan`` becomes
    ``unknown``), and resolves coinbase evidence. Returns the normalized
    row plus a set of error labels (missing/malformed header hash, header
    hex, or full coinbase) that feed the per-source stats.
    """
    classification = normalize_classification(source, row)
    header_hex = get_value(row, fieldnames, HEADER_HEX_COLUMNS)
    parsed = parse_header_fields(header_hex)
    header_hash = normalize_hash(get_value(row, fieldnames, HASH_COLUMNS))
    if not is_hash(header_hash):
        header_hash = parsed.get("hash", "")
    prev_hash = normalize_hash(get_value(row, fieldnames, PREV_COLUMNS))
    if not is_hash(prev_hash):
        prev_hash = parsed.get("prev_hash", "")
    btc_time = get_value(row, fieldnames, ("btc_time",)) or parsed.get("time", "")
    btc_bits = get_value(row, fieldnames, BITS_COLUMNS).lower() or parsed.get(
        "bits", ""
    )
    btc_nonce = row.get("btc_nonce", "").strip() or parsed.get("nonce", "")
    validation_status = row.get("validation_status", "").strip()
    scriptsig, outputs, full_coinbase, malformed_coinbase = parse_coinbase_fields(row)
    child_hash = child_hash_for(source.chain, row, fieldnames).lower()
    child_header_hex = get_value(row, fieldnames, ("child_header_hex",)).lower()
    child_time = get_value(row, fieldnames, ("child_block_time",))
    child_nbits = get_value(row, fieldnames, ("child_nbits",)).lower()

    errors: set[str] = set()
    if not is_hash(header_hash):
        errors.add("missing_or_malformed_btc_header_hash")
    if header_hex and not parsed:
        errors.add("malformed_btc_header_hex")
    if malformed_coinbase:
        errors.add("malformed_full_coinbase_hex")
    child_bundle = {
        "child_block_hash": child_hash,
        "child_header_hex": child_header_hex,
        "child_block_time": child_time,
        "child_nbits": child_nbits,
    }
    populated_child_fields = [
        field for field in CHILD_HEADER_FIELDS if child_bundle[field]
    ]
    source_spec = CHAIN_SPECS.get(source.chain)
    # Every target historical row enters the complete-bundle validator,
    # including an all-empty row. Non-target sources retain whatever child
    # evidence their native format exposes, with all available fields checked.
    try:
        if source.chain in HISTORICAL_CHILD_HEADER_CHAINS or len(
            populated_child_fields
        ) == len(CHILD_HEADER_FIELDS):
            validate_child_header_fields(
                child_bundle,
                nbits_from_header=(
                    source_spec.child_nbits_from_header if source_spec else True
                ),
            )
        elif populated_child_fields:
            validate_available_child_header_fields(child_bundle)
    except ChildHeaderValidationError as exc:
        detail = str(exc)
        if source.chain in HISTORICAL_CHILD_HEADER_CHAINS and len(
            populated_child_fields
        ) != len(CHILD_HEADER_FIELDS):
            detail = (
                "historical source requires regeneration with a complete "
                f"child header bundle; {detail}"
            )
        raise ChildHeaderValidationError(
            f"{source.chain} evidence row {row_number}: {detail}"
        ) from exc

    normalized = {
        "chain": source.chain,
        "source_kind": source.source_kind,
        "source_path": safe_path(source.path, chain=source.chain),
        "source_row_number": str(row_number),
        "artifact_scope": source.artifact_scope,
        "provenance": source.provenance,
        "child_height": child_height_for(source.chain, row, fieldnames),
        "child_block_hash": child_hash,
        "child_header_hex": child_header_hex,
        "child_block_time": child_time,
        "child_nbits": child_nbits,
        "btc_height": btc_height(row, fieldnames, classification),
        "btc_header_hash": header_hash,
        "btc_prev_hash": prev_hash,
        "btc_time": btc_time,
        "btc_bits": btc_bits,
        "btc_nonce": btc_nonce,
        "btc_header_hex": header_hex,
        "coinbase_scriptsig_hex": scriptsig,
        "coinbase_outputs": outputs,
        "full_coinbase_hex": full_coinbase,
        "classification": classification,
        "validation_status": validation_status,
        "expected_nbits": row.get("expected_nbits", "").strip(),
        "rejection_reason": rejection_reason(row, validation_status),
    }
    return normalized, errors


def archive_candidates(root: Path, chain: str, suffix: str, family: str) -> list[Path]:
    """Candidate paths for ``<chain>_<suffix>.csv`` under an archive root.

    Checks the per-chain ``family`` subdirectory (``classified/`` or
    ``validated/``), the chain directory itself, then the root.
    """
    return [
        root / chain / family / f"{chain}_{suffix}.csv",
        root / chain / f"{chain}_{suffix}.csv",
        root / f"{chain}_{suffix}.csv",
    ]


_ARCHIVE_FULL_INVENTORY_OVERRIDES: dict[str, tuple[Path, ...]] = {
    # Doichain's authoritative full inventory has a nonstandard archive
    # location. The file in ``classified/`` is the intentionally header-only
    # publication output, while this dated artifact contains all 50,621 rows.
    "doichain": (Path("2026-06-24-redo/doichain_stale_blocks.csv"),),
}


def archive_full_inventory_candidates(root: Path, chain: str) -> list[Path]:
    """Return full-inventory candidates, honoring explicit archive layouts."""
    overrides = [
        root / chain / relative
        for relative in _ARCHIVE_FULL_INVENTORY_OVERRIDES.get(chain, ())
    ]
    return overrides + archive_candidates(root, chain, "stale_blocks", "classified")


def first_existing(paths: Iterable[Path]) -> Path | None:
    """Return the first path that exists, else None."""
    for path in paths:
        if path.exists():
            return path
    return None


def discover_evidence_sources(
    data_dir: Path = DATA_DIR,
    chain_archive_dirs: Iterable[Path] = (),
) -> dict[str, EvidenceSource]:
    """Discover the best available evidence source for every integrated chain."""
    archive_dirs = normalize_chain_archive_dirs(chain_archive_dirs)
    sources: dict[str, EvidenceSource] = {}
    for chain, spec in CHAIN_SPECS.items():
        archive_full: list[Path] = []
        archive_validated: list[Path] = []
        for root in archive_dirs:
            archive_full.extend(archive_full_inventory_candidates(root, chain))
            archive_validated.extend(
                archive_candidates(root, chain, "validated_stales", "validated")
            )

        full_path = first_existing(archive_full)
        if full_path is None:
            full_path = data_dir / f"{chain}_stale_blocks.csv"
            if not full_path.exists():
                full_path = None
        if full_path is not None:
            sources[chain] = EvidenceSource(
                chain=chain,
                display_name=spec.display_name,
                path=full_path,
                source_kind="full_inventory",
                artifact_scope="full_classifier_inventory",
                provenance="archive" if full_path in archive_full else "repo-data",
            )
            continue

        validated_path = first_existing(archive_validated)
        if validated_path is None:
            validated_path = (
                data_dir / "validated-stales" / f"{chain}_validated_stales.csv"
            )
            if not validated_path.exists():
                validated_path = None
        if validated_path is not None:
            sources[chain] = EvidenceSource(
                chain=chain,
                display_name=spec.display_name,
                path=validated_path,
                source_kind="validated_stales",
                artifact_scope="stale_only_publication",
                provenance="archive"
                if validated_path in archive_validated
                else "repo-data",
            )
        else:
            sources[chain] = EvidenceSource(
                chain=chain,
                display_name=spec.display_name,
                path=None,
                source_kind="missing",
                artifact_scope="missing",
                provenance="",
            )
    return sources


def discover_canonical_sources(
    data_dir: Path = DATA_DIR,
    chain_archive_dirs: Iterable[Path] = (),
) -> dict[str, EvidenceSource]:
    """Discover per-chain canonical-parent companions where they exist.

    Canonical parents are kept in a separate
    ``<chain>_canonical_blocks.csv`` artifact (written by ``run_classifier``;
    the same convention the private archive uses), so they are discovered
    independently of the stale/unknown inventory and merged into the exports.
    Only chains with an existing companion appear in the result. A
    never-split chain's inventory can already carry the same canonical rows
    as its companion (see i0coin), so callers merging this companion dedupe
    with ``dedupe_canonical_companion_rows``.
    """
    archive_dirs = normalize_chain_archive_dirs(chain_archive_dirs)
    sources: dict[str, EvidenceSource] = {}
    source_profiles = [
        (
            chain,
            spec.display_name,
            "canonical_blocks",
            "canonical_blocks",
            "",
        )
        for chain, spec in CHAIN_SPECS.items()
    ]
    source_profiles.append(
        (
            "vcash",
            "VCash",
            "wayback_canonical_hydration",
            "partial_canonical_subset",
            "wayback:vcash.tech/block + bitcoin-core:canonical",
        )
    )
    for chain, display_name, source_kind, artifact_scope, provenance in source_profiles:
        candidates: list[Path] = []
        for root in archive_dirs:
            candidates.extend(
                archive_candidates(root, chain, "canonical_blocks", "classified")
            )
        candidates.append(data_dir / f"{chain}_canonical_blocks.csv")
        path = first_existing(candidates)
        if path is None:
            continue
        sources[chain] = EvidenceSource(
            chain=chain,
            display_name=display_name,
            path=path,
            source_kind=source_kind,
            artifact_scope=artifact_scope,
            provenance=(
                provenance or ("repo-data" if path.parent == data_dir else "archive")
            ),
        )
    return sources


def discover_unknown_sources(
    data_dir: Path = DATA_DIR,
    chain_archive_dirs: Iterable[Path] = (),
) -> dict[str, EvidenceSource]:
    """Discover per-chain unknown companions where they exist.

    Unknown rows are split into a separate ``<chain>_unknown_blocks.csv``
    artifact (the classifier's shared writer), so they are discovered
    independently of the stale-only inventory and merged into the exports. A
    never-split chain has no unknown companion -- its unknowns stay in the
    commingled ``<chain>_stale_blocks.csv`` -- so only chains with an existing
    companion appear here. Rows carry ``source_kind="full_inventory"`` so
    ``collect_source_rows`` processes them exactly like the inventory's unknowns.
    """
    archive_dirs = normalize_chain_archive_dirs(chain_archive_dirs)
    sources: dict[str, EvidenceSource] = {}
    for chain, spec in CHAIN_SPECS.items():
        candidates: list[Path] = []
        for root in archive_dirs:
            candidates.extend(
                archive_candidates(root, chain, "unknown_blocks", "classified")
            )
        candidates.append(data_dir / f"{chain}_unknown_blocks.csv")
        path = first_existing(candidates)
        if path is None:
            continue
        sources[chain] = EvidenceSource(
            chain=chain,
            display_name=spec.display_name,
            path=path,
            source_kind="full_inventory",
            artifact_scope="full_classifier_inventory",
            provenance="repo-data" if path.parent == data_dir else "archive",
        )
    return sources


def merge_stats(a: SourceStats, b: SourceStats) -> SourceStats:
    """Combine two SourceStats field-wise (counts summed, notes unioned)."""
    merged = SourceStats(
        source_rows=a.source_rows + b.source_rows,
        classifications=a.classifications + b.classifications,
        rejected=a.rejected + b.rejected,
        malformed=a.malformed + b.malformed,
        other=a.other + b.other,
        missing_btc_header_hex=a.missing_btc_header_hex + b.missing_btc_header_hex,
        missing_coinbase_scriptsig_hex=(
            a.missing_coinbase_scriptsig_hex + b.missing_coinbase_scriptsig_hex
        ),
        missing_coinbase_outputs=(
            a.missing_coinbase_outputs + b.missing_coinbase_outputs
        ),
    )
    merged.notes = a.notes | b.notes
    return merged


def enforce_unknown_split_contract(
    source: EvidenceSource,
    stats: SourceStats,
    unknown_companion: EvidenceSource | None,
) -> None:
    """Reject inventories that mix in-file and split unknown storage."""
    if unknown_companion is not None and stats.classifications["unknown"]:
        raise ValueError(
            f"{source.path}: contains unknown rows while "
            f"{unknown_companion.path} also exists; regenerate the classifier "
            "inventory into uniform split outputs"
        )


def dedupe_canonical_companion_rows(
    primary_rows: list[dict[str, str]],
    companion_rows: list[dict[str, str]],
) -> tuple[list[dict[str, str]], int]:
    """Drop companion canonical rows already present among ``primary_rows``.

    A never-split chain's full inventory can already carry the same
    canonical rows a separate ``<chain>_canonical_blocks.csv`` companion also
    carries (see i0coin), which would otherwise double the canonical
    evidence in canonical-bearing exports. Split chains have no such
    overlap, so this is a no-op there. Rows are matched on
    ``(btc_height, btc_header_hash)`` with the hash lowercased. Returns
    ``(deduped_companion_rows, skipped_count)``.
    """
    seen = {
        (row["btc_height"], row["btc_header_hash"].strip().lower())
        for row in primary_rows
        if row.get("classification") == "canonical"
    }
    kept: list[dict[str, str]] = []
    skipped = 0
    for row in companion_rows:
        if row.get("classification") == "canonical":
            key = (row["btc_height"], row["btc_header_hash"].strip().lower())
            if key in seen:
                skipped += 1
                continue
        kept.append(row)
    return kept, skipped


def write_csv(
    path: Path, rows: Iterable[dict[str, object]], fieldnames: list[str]
) -> int:
    """Write rows to ``path`` restricted to ``fieldnames``; return the row count.

    Missing keys are written as empty strings, so every output artifact has
    a uniform column set regardless of source variation.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})
            count += 1
    return count


def iter_source_rows(
    source: EvidenceSource,
) -> Iterable[tuple[dict[str, str], set[str]]]:
    """Yield ``(normalized_row, errors)`` for every row of a source CSV.

    Row numbers start at 2 to match spreadsheet line numbering (line 1 is
    the header). Yields nothing when the source has no path.
    """
    if source.path is None:
        return
    with source.path.open(newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        for row_number, row in enumerate(reader, start=2):
            yield normalize_evidence_row(source, row, fieldnames, row_number)


def collect_source_rows(
    source: EvidenceSource,
    *,
    exclude_classifications: frozenset[str] = frozenset(),
    stale_descendant_observations: frozenset[tuple[str, str]] = frozenset(),
) -> tuple[list[dict[str, str]], SourceStats]:
    """Read and normalize an entire source CSV, accumulating SourceStats.

    Every normalized row is kept except requested source classifications and
    exact identities in the public consensus-invalid overlay. The stats record
    error labels rather than dropping malformed rows; classification tallies,
    rejection counts, and missing-evidence counts feed the counts/manifest
    artifacts. A source row formerly published as a direct stale is projected
    into its accepted ``stale_descendant`` state only when both its exact
    chain/hash observation appears in the descendant sidecar and its exact
    height/hash appears in the correction overlay.
    """
    stats = SourceStats()
    rows: list[dict[str, str]] = []
    if source.path is None:
        stats.notes.add("no evidence source discovered")
        return rows, stats
    excluded = load_stale_exclusion_keys()
    consensus_invalid = load_consensus_invalid_stale_keys()
    excluded_count = 0
    reclassified_descendant_count = 0
    for normalized, errors in iter_source_rows(source):
        classification = normalized["classification"]
        try:
            key = (
                int(normalized["btc_height"]),
                normalized["btc_header_hash"].lower(),
            )
        except (TypeError, ValueError):
            key = None
        observation_key = (
            source.chain,
            normalize_hash(normalized.get("btc_header_hash")),
        )
        if (
            classification == "stale"
            and observation_key in stale_descendant_observations
            and key in excluded
            and key not in consensus_invalid
        ):
            normalized = {
                **normalized,
                "classification": "stale_descendant",
                "validation_status": "VALID_STALE_DESCENDANT",
            }
            classification = "stale_descendant"
            reclassified_descendant_count += 1
        if classification in exclude_classifications:
            continue
        if key in consensus_invalid or (
            key in excluded and normalized["classification"] != "stale_descendant"
        ):
            excluded_count += 1
            continue
        rows.append(normalized)
        stats.source_rows += 1
        stats.classifications[classification] += 1
        if classification not in {
            "canonical",
            "stale",
            "unknown",
            "stale_descendant",
            "near",
        }:
            stats.other += 1
        if normalized["validation_status"].upper().startswith("REJECTED"):
            stats.rejected += 1
        if errors or classification == "malformed":
            stats.malformed += 1
        if not normalized["btc_header_hex"]:
            stats.missing_btc_header_hex += 1
        if not normalized["coinbase_scriptsig_hex"]:
            stats.missing_coinbase_scriptsig_hex += 1
        if not normalized["coinbase_outputs"]:
            stats.missing_coinbase_outputs += 1
    if excluded_count:
        stats.notes.add(f"publication_exclusions={excluded_count}")
    if reclassified_descendant_count:
        stats.notes.add(
            "reclassified_stale_descendant_observations="
            f"{reclassified_descendant_count}"
        )
    return rows, stats


def canonical_evidence_status(source: EvidenceSource, stats: SourceStats) -> str:
    """Classify how well the discovered source represents canonical parents.

    ``canonical_retained`` means canonical rows made it into the stats
    (in-file or via a companion); a validated-stales source that cannot
    carry them reports the stale-only-publication status instead.
    """
    if source.source_kind == "missing":
        return "not_checked_missing_source"
    if source.source_kind == "stale_descendant_sidecar":
        return "not_applicable"
    # A canonical companion merged into stats retains canonical evidence even
    # when the primary source is a stale-only publication.
    if stats.classifications["canonical"] > 0:
        return "canonical_retained"
    if source.source_kind == "validated_stales":
        return "canonical_rows_not_represented_stale_only_publication_path"
    return "no_canonical_rows_in_discovered_artifact"


def count_row(
    source: EvidenceSource,
    stats: SourceStats,
    artifact_path: Path | None,
) -> dict[str, object]:
    """Render one COUNT_FIELDS row for the counts CSV from a source's stats."""
    return {
        "chain": source.chain,
        "source_kind": source.source_kind,
        "artifact_scope": source.artifact_scope,
        "artifact_path": safe_path(artifact_path, chain=source.chain),
        "source_path": safe_path(source.path, chain=source.chain),
        "source_rows": stats.source_rows,
        "canonical": stats.classifications["canonical"],
        "stale": stats.classifications["stale"],
        "unknown": stats.classifications["unknown"],
        "stale_descendant": stats.classifications["stale_descendant"],
        "near": stats.classifications["near"],
        "rejected": stats.rejected,
        "malformed": stats.malformed,
        "other": stats.other,
        "missing_btc_header_hex": stats.missing_btc_header_hex,
        "missing_coinbase_scriptsig_hex": stats.missing_coinbase_scriptsig_hex,
        "missing_coinbase_outputs": stats.missing_coinbase_outputs,
        "canonical_evidence_status": canonical_evidence_status(source, stats),
        "notes": "; ".join(sorted(stats.notes)),
    }


def manifest_row(
    source: EvidenceSource,
    stats: SourceStats,
    artifact_path: Path | None,
) -> dict[str, object]:
    """Render one MANIFEST_FIELDS row (count_row plus the display name)."""
    row = count_row(source, stats, artifact_path)
    return {
        "chain": source.chain,
        "display_name": source.display_name,
        "source_kind": row["source_kind"],
        "artifact_scope": row["artifact_scope"],
        "artifact_path": row["artifact_path"],
        "source_path": row["source_path"],
        "canonical_evidence_status": row["canonical_evidence_status"],
        "canonical": row["canonical"],
        "stale": row["stale"],
        "unknown": row["unknown"],
        "stale_descendant": row["stale_descendant"],
        "near": row["near"],
        "rejected": row["rejected"],
        "malformed": row["malformed"],
        "source_rows": row["source_rows"],
        "notes": row["notes"],
    }


def stale_descendant_source(data_dir: Path) -> EvidenceSource | None:
    """Build the pseudo-chain source for ``data/stale_descendants.csv``.

    Returns None when the sidecar is absent. The descendants export uses
    the reserved chain key ``stale-descendants``.
    """
    path = data_dir / "stale_descendants.csv"
    if not path.exists():
        return None
    return EvidenceSource(
        chain="stale-descendants",
        display_name="Stale descendants",
        path=path,
        source_kind="stale_descendant_sidecar",
        artifact_scope="stale_descendant_sidecar",
        provenance="repo-data",
    )


# ── Namecoin header-hex hydration ───────────────────────────────────────
#
# Namecoin's committed validated input carries most, but not all, of the
# recovered 80-byte parent headers. Its strict/weak-orphan archive rows may
# also be headerless. The merge-mining-monitor refuses headerless rows at
# import because it PoW-validates every header, so hydrate only the missing
# `btc_header_hex` values from the Namecoin block.dat prototype extracts or
# private archive sources. A recovered header is written only when it verifies
# against the row's own `btc_header_hash`.

NAMECOIN_CHAIN = "namecoin"


def load_namecoin_header_hexes(
    targets: set[str],
    candidate_paths: Iterable[Path],
) -> dict[str, str]:
    """Map ``btc_hash`` -> ``btc_header_hex`` for ``targets`` from prototype extracts.

    Reads the ``candidate_paths`` CSVs in order (by convention the namecoin
    ``*_blkdat_classified.csv`` then ``*_blkdat_candidates.csv`` extracts,
    which carry full 80-byte headers), recording each row's header hex keyed
    by its own ``btc_hash`` column and restricted to ``targets``. Missing
    files are skipped, and scanning stops early once every target hash is
    resolved, so an earlier path in the list wins when it covers the targets.
    Returns ``{block_hash: header_hex}`` for the resolved subset of ``targets``.

    This is a pure loader keyed by the source CSV's own ``btc_hash`` column;
    it does NOT check that a header hex actually hashes to that hash (the
    reconcile loader this was lifted from did not either). Callers that need a
    verified header must check it -- ``hydrate_namecoin_headers`` does.
    """
    if not targets:
        return {}
    out: dict[str, str] = {}
    for path in candidate_paths:
        if not path.exists():
            continue
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                h = normalize_hash(row.get("btc_hash", ""))
                header_hex = row.get("btc_header_hex", "").strip()
                if h in targets and header_hex:
                    out[h] = header_hex
        if len(out) == len(targets):
            break
    return out


def namecoin_header_candidate_paths(
    data_dir: Path,
    chain_archive_dirs: Iterable[Path] = (),
) -> list[Path]:
    """Ordered ``btc_header_hex`` recovery sources for namecoin, repo-local first.

    The repo-local ``data/prototype/`` pair takes precedence, then each
    normalized chain-archive root's ``namecoin/classified`` +
    ``namecoin/raw-extraction`` extract pair. ``load_namecoin_header_hexes``
    reads these in order and stops once every target is resolved, so the
    repo-local extracts win when they cover the targets.
    """
    paths = [
        data_dir / "prototype" / "namecoin_blkdat_classified.csv",
        data_dir / "prototype" / "namecoin_blkdat_candidates.csv",
    ]
    for root in normalize_chain_archive_dirs(chain_archive_dirs):
        paths.append(
            root / NAMECOIN_CHAIN / "classified" / "namecoin_blkdat_classified.csv"
        )
        paths.append(
            root / NAMECOIN_CHAIN / "raw-extraction" / "namecoin_blkdat_candidates.csv"
        )
    return paths


def verified_header_hex(header_hex: str, expected_display_hash: str) -> bool:
    """True if ``header_hex``'s 80-byte double-SHA256, reversed, is ``expected_display_hash``.

    ``expected_display_hash`` is a display-order (RPC-order) lowercase hex
    hash. A malformed hex string, a header shorter than 80 bytes, or any hash
    disagreement returns False, so a bad candidate header is never written.
    """
    try:
        raw = bytes.fromhex(header_hex)
    except ValueError:
        return False
    if len(raw) < 80:
        return False
    return hash_from_header_bytes(raw[:80])[::-1].hex() == expected_display_hash


@dataclass(slots=True)
class HydrationStats:
    """Per-run namecoin ``btc_header_hex`` hydration coverage.

    ``targets`` is the number of headerless namecoin rows considered;
    ``hydrated`` gained a verified header; ``hash_mismatch_rejected`` is the
    subset of ``still_missing`` whose candidate header was present but failed
    verification. ``sources_available`` records whether any candidate extract
    file existed at all, so a zero-source run is never silent.
    """

    targets: int = 0
    hydrated: int = 0
    still_missing: int = 0
    hash_mismatch_rejected: int = 0
    sources_available: bool = False

    def note(self) -> str:
        """One coverage line for a manifest/counts notes field; '' when no targets."""
        if not self.targets:
            return ""
        line = (
            "namecoin_header_hydration="
            f"hydrated:{self.hydrated}"
            f"/still_missing:{self.still_missing}"
            f"/hash_mismatch_rejected:{self.hash_mismatch_rejected}"
        )
        if not self.sources_available:
            line += "; no_namecoin_header_hydration_sources_found"
        return line


def hydrate_namecoin_headers(
    rows: list[dict[str, str]],
    candidate_paths: list[Path],
) -> HydrationStats:
    """Fill empty ``btc_header_hex`` on namecoin rows from recovered extracts, in place.

    Targets the namecoin rows whose ``btc_header_hex`` is empty but whose
    ``btc_header_hash`` is a well-formed hash, loads their headers via
    ``load_namecoin_header_hexes`` (lazily -- no files are read when there are
    no targets), and writes a header ONLY when it verifies against the row's
    hash (``verified_header_hex``). A candidate that is missing, malformed, or
    hashes to the wrong value is never written and is counted. The ``rows``
    list is mutated in place; returns the coverage stats.
    """
    stats = HydrationStats()
    target_rows = [
        row
        for row in rows
        if row.get("chain") == NAMECOIN_CHAIN
        and not row.get("btc_header_hex")
        and is_hash(normalize_hash(row.get("btc_header_hash", "")))
    ]
    if not target_rows:
        return stats
    stats.targets = len(target_rows)
    stats.sources_available = any(path.exists() for path in candidate_paths)
    target_hashes = {
        normalize_hash(row.get("btc_header_hash", "")) for row in target_rows
    }
    header_map = load_namecoin_header_hexes(target_hashes, candidate_paths)
    for row in target_rows:
        display_hash = normalize_hash(row.get("btc_header_hash", ""))
        candidate = header_map.get(display_hash)
        if candidate and verified_header_hex(candidate, display_hash):
            row["btc_header_hex"] = candidate
            stats.hydrated += 1
        else:
            if candidate:
                stats.hash_mismatch_rejected += 1
            stats.still_missing += 1
    return stats


# ── Live-chain child identity hydration ─────────────────────────────────
#
# The six live-lifecycle chains (namecoin, rsk, syscoin, hathor, elastos,
# fractal) were recovered without child block identity: their artifacts carry
# the child HEIGHT but no child block hash or timestamp. merge-mining-monitor
# keys live-captured events by (source, child_height, child_block_hash), so
# imported rows need the exact identity to deduplicate against live capture.
# scripts/extract/recover_child_identity.py recovers and node-verifies the
# identity per parent header from the still-reachable child nodes; the
# committed per-chain CSVs under data/child-identity/ are joined here by
# (chain, btc_header_hash). RSK rows additionally carry the fields the
# monitor's rsk_merge_mining_evidence sidecar requires; they are attached to
# the row and published only in the RSK export's extra columns.

CHILD_IDENTITY_DIR_NAME = "child-identity"

# The six live-lifecycle chains whose evidence rows REQUIRE a recovered child
# identity: merge-mining-monitor keys their live-captured events by
# (source, child_height, child_block_hash), and its importer skips rows
# without exact identity. Hydration targets these chains unconditionally --
# a missing or empty identity file must surface as missing_identity, never
# silently narrow the target set.
LIVE_CHILD_IDENTITY_CHAINS = frozenset(
    {"namecoin", "rsk", "syscoin", "hathor", "elastos", "fractal"}
)

RSK_SIDECAR_EXPORT_FIELDS = [
    "rsk_miner",
    "merge_mining_hash",
    "is_uncle",
    "uncle_index",
    "uncle_parent_height",
    "rsk_merkle_proof",
    "rsk_coinbase_tail",
]


def load_child_identity(data_dir: Path) -> dict[tuple[str, str], dict[str, str]]:
    """Map ``(chain, btc_header_hash)`` -> verified child-identity row.

    Reads every ``data/child-identity/*_child_identity.csv``; a row is usable
    only when its ``verification`` is non-empty (node-verified) AND its
    ``child_block_hash`` is a well-formed 32-byte hex value AND its
    ``child_block_time`` is a positive integer. A verified-but-incomplete row
    (malformed or manually truncated sidecar) is dropped here, so the
    affected evidence rows surface as ``missing_identity`` downstream
    instead of hydrating blanks that defeat the publication gate.
    """
    identity_dir = data_dir / CHILD_IDENTITY_DIR_NAME
    if not identity_dir.is_dir():
        return {}
    identity: dict[tuple[str, str], dict[str, str]] = {}
    for path in sorted(identity_dir.glob("*_child_identity.csv")):
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                if not (row.get("verification") or "").strip():
                    continue
                child_hash = (row.get("child_block_hash") or "").strip().lower()
                child_time = (row.get("child_block_time") or "").strip()
                if not is_hash(child_hash) or not child_time.isdigit():
                    continue
                chain = (row.get("chain") or "").strip()
                block_hash = normalize_hash(row.get("btc_header_hash"))
                if chain and is_hash(block_hash):
                    identity[(chain, block_hash)] = row
    return identity


@dataclass(slots=True)
class ChildIdentityStats:
    """Per-chain child-identity hydration coverage.

    ``targets`` is the number of rows considered (child hash empty, header
    hash well-formed); ``hydrated`` gained a verified identity;
    ``missing_identity`` / ``height_mismatch`` count NON-canonical rows left
    empty (fatal to a publication build: the monitor importer consumes these
    categories and skips rows without exact identity).
    ``canonical_unhydrated`` counts canonical rows left empty. These rows are
    still emitted because canonical evidence is part of the publication set;
    the count records the source's child-identity limit without treating an
    absent optional identity join as contradictory evidence.
    """

    targets: int = 0
    hydrated: int = 0
    missing_identity: int = 0
    height_mismatch: int = 0
    canonical_unhydrated: int = 0

    def note(self) -> str:
        """One coverage line for a counts notes field; '' when no targets."""
        if not self.targets:
            return ""
        line = f"child_identity_hydration=hydrated:{self.hydrated}"
        if self.missing_identity:
            line += f"/missing_identity:{self.missing_identity}"
        if self.height_mismatch:
            line += f"/height_mismatch:{self.height_mismatch}"
        if self.canonical_unhydrated:
            line += f"/canonical_unhydrated:{self.canonical_unhydrated}"
        return line


def hydrate_child_identity(
    rows: list[dict[str, str]],
    identity: dict[tuple[str, str], dict[str, str]],
) -> ChildIdentityStats:
    """Fill empty child identity fields from verified recovery rows, in place.

    Targets every live-chain row (``LIVE_CHILD_IDENTITY_CHAINS``) regardless
    of whether the source prepopulated ``child_block_hash`` -- the
    node-verified sidecar is authoritative there, so a raw inventory's
    display-order hash is replaced and a missing identity still counts as a
    shortfall -- plus any other chain's empty-hash rows when identity data
    was loaded for it. The live set is targeted unconditionally so a
    missing, empty, or verification-less identity file surfaces as
    ``missing_identity`` instead of silently narrowing the target set. The
    identity row must agree on ``child_height``; a disagreement leaves the
    row untouched and is counted, so a stale identity file can never
    mislabel evidence. RSK sidecar fields ride along on the row dict and
    only reach output when the caller includes them in the export's field
    list.
    """
    stats = ChildIdentityStats()
    chains_with_identity = {chain for chain, _ in identity}
    for row in rows:
        chain = row.get("chain", "")
        if row.get("child_block_hash") and chain not in LIVE_CHILD_IDENTITY_CHAINS:
            # Non-live chains keep their source-supplied identity untouched
            # (the explicit-recovery artifacts are authoritative for it).
            continue
        if (
            chain not in LIVE_CHILD_IDENTITY_CHAINS
            and chain not in chains_with_identity
        ):
            continue
        block_hash = normalize_hash(row.get("btc_header_hash", ""))
        if not is_hash(block_hash):
            continue
        stats.targets += 1
        is_canonical_row = (row.get("classification") or "") == "canonical"
        candidate = identity.get((chain, block_hash))
        if candidate is None:
            if is_canonical_row:
                stats.canonical_unhydrated += 1
            else:
                stats.missing_identity += 1
            continue
        candidate_height = (candidate.get("child_height") or "").strip()
        row_height = (row.get("child_height") or "").strip()
        try:
            heights_agree = int(candidate_height) == int(row_height)
        except ValueError:
            # Non-numeric heights fall back to exact-string agreement; a
            # malformed identity height can then never hydrate a row.
            heights_agree = candidate_height == row_height
        if not heights_agree:
            if is_canonical_row:
                stats.canonical_unhydrated += 1
            else:
                stats.height_mismatch += 1
            continue
        # The node-verified identity is authoritative for live chains: a
        # source-prepopulated hash (e.g. a raw Hathor inventory's
        # display-order tx_id) is replaced with the verified internal-order
        # value rather than trusted as-is.
        row["child_block_hash"] = (candidate.get("child_block_hash") or "").strip()
        if not row.get("child_block_time"):
            row["child_block_time"] = (candidate.get("child_block_time") or "").strip()
        if chain == "rsk":
            # Sidecar fields are an RSK-only extension; the explicit gate keeps
            # a stray sidecar-named column in another chain's identity file
            # from ever leaking into a non-RSK row.
            for field in RSK_SIDECAR_EXPORT_FIELDS:
                value = (candidate.get(field) or "").strip()
                if value:
                    row[field] = value
        stats.hydrated += 1
    return stats


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

    count_rows: list[dict[str, object]] = []
    manifest_rows: list[dict[str, object]] = []
    artifacts: dict[str, str] = {}

    for chain in CHAIN_SPECS:
        source = sources[chain]
        artifact_path: Path | None = None
        rows, stats = collect_source_rows(source)
        companion = canonical_sources.get(chain)
        if companion is not None:
            companion_rows, companion_stats = collect_source_rows(companion)
            companion_rows, skipped = dedupe_canonical_companion_rows(
                rows, companion_rows
            )
            if skipped:
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
            unknown_rows, unknown_stats = collect_source_rows(unknown_companion)
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
        rows, stats = collect_source_rows(sidecar)
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


# ── Monitor-facing exports ──────────────────────────────────────────────
#
# The full-evidence exports above carry every evidence state, which makes
# them large (unknown/near rows dominate). The monitor-facing exports below
# keep only the categories the merge-mining-monitor ingests as final —
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
    descendant_observations: frozenset[tuple[str, str]] = frozenset(),
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
    from the relevance inventory. Near, rejected, and everything else is
    dropped.
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
    if classification in ("orphan", "unknown"):
        observation_key = (
            str(row.get("chain", "")),
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
    descendant_observations: frozenset[tuple[str, str]] = frozenset(),
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
        out["btc_stale_relevance"] = bucket
        out["relevance_reason"] = reason
        kept.append(out)
        if reason == "valid_stale_descendant" and classification in (
            "orphan",
            "unknown",
        ):
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
    include_canonical: bool = True,
    fail_on_missing_child_identity: bool = False,
) -> dict[str, object]:
    """Write per-chain monitor-facing evidence CSVs plus a counts manifest.

    ``include_canonical=False`` skips canonical rows for every chain in an
    explicitly diagnostic build. ``fail_on_missing_child_identity`` makes an
    unhydrated live-chain row fatal: the monitor importer deliberately skips
    rows without exact child identity, so a publication build must fail closed
    rather than silently publish rows the importer will drop.
    ``reported_output_dir`` is the logical final directory recorded in counts
    and manifests when a caller writes to a temporary staging directory first.
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
    orphan_verdicts = load_orphan_relevance_verdicts(relevance_inventory)
    descendant_observations = load_stale_descendant_observation_keys(
        data_dir / "stale_descendants.csv"
    )
    represented_descendant_observations: set[tuple[str, str]] = set()
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
            )
            validated_rows, validated_stats = collect_source_rows(validated)
            rows.extend(validated_rows)
            stats = merge_stats(stats, validated_stats)
        else:
            rows, stats = collect_source_rows(
                source,
                stale_descendant_observations=descendant_observations,
            )
        if unknown_companion is not None:
            enforce_unknown_split_contract(source, stats, unknown_companion)
            unknown_rows, unknown_stats = collect_source_rows(unknown_companion)
            rows.extend(unknown_rows)
            stats = merge_stats(stats, unknown_stats)
        skipped_canonical = 0
        if companion is not None:
            companion_rows, companion_stats = collect_source_rows(companion)
            companion_rows, skipped_canonical = dedupe_canonical_companion_rows(
                rows, companion_rows
            )
            if skipped_canonical:
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
                observation_key = (
                    source.chain,
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
            f"{chain}:{block_hash}"
            for chain, block_hash in sorted(missing_descendant_observations)[:5]
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
        "validation_contract": {
            "profile": "direct_stale_header_context_v1",
            "valid_token_scope": "publication_gate_accepted_not_full_block_validity",
            "full_block_consensus_validity_asserted": False,
            "required_checks": [
                "candidate_header_hash_and_self_pow",
                "active_chain_parent_and_expected_height",
                "expected_nbits",
                "median_time_past",
                "historical_minimum_block_version",
                "coinbase_scriptsig_length_when_available",
                "bip34_coinbase_height_when_available",
            ],
            "known_exception": {
                "rsk": "coinbase-dependent checks unavailable from compressed proof"
            },
            "documentation": "docs/data-validity.md",
        },
        "artifacts": artifacts,
        "relevance_inventory": (
            safe_path(relevance_inventory) if inventory_available else "missing"
        ),
        "strict_weak_verdicts_loaded": len(orphan_verdicts),
        "counts": count_rows,
    }
    manifest_json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary
