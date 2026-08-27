"""Full-evidence AuxPoW export helpers.

This module builds the complete normalized evidence layer without changing the
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
)
from .error_blocks import (
    load_consensus_invalid_stale_keys,
    load_stale_exclusion_keys,
)

DEFAULT_OUTPUT_DIR = RESULTS_DIR / "full-evidence"

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
    resolved_root = PROJECT_ROOT.resolve()
    resolved = (
        expanded if expanded.is_absolute() else resolved_root / expanded
    ).resolve()
    try:
        relative = resolved.relative_to(resolved_root)
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
    parent), then to the validated BIP34 coinbase height used by legacy
    Namecoin inventories. Returns '' when nothing resolves.
    """
    height = get_value(row, fieldnames, BTC_HEIGHT_COLUMNS)
    if height:
        return height
    parent_height = int_or_none(row.get("btc_parent_height", "").strip())
    if classification == "stale" and parent_height is not None:
        return str(parent_height + 1)
    if classification == "stale":
        return row.get("btc_bip34_height", "").strip()
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


def note_child_height_availability(
    stats: SourceStats, rows: list[dict[str, str]]
) -> None:
    """Disclose when any normalized evidence row lacks an exact child height."""
    if rows and any(not (row.get("child_height") or "").strip() for row in rows):
        stats.notes.add("child_height=unavailable")


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
    normalized_input = set(EVIDENCE_FIELDS).issubset(fieldnames or ())

    def source_metadata(field: str, fallback: str) -> str:
        """Preserve provenance when a normalized export is read again."""
        if normalized_input:
            value = row.get(field, "").strip()
            if value:
                if field == "source_path":
                    return safe_path(Path(value), chain=source.chain)
                return value
        return fallback

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
            validate_available_child_header_fields(
                child_bundle,
                nbits_from_header=(
                    source_spec.child_nbits_from_header if source_spec else True
                ),
            )
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

    expected_nbits = row.get("expected_nbits", "").strip()
    normalized_rejection_reason = rejection_reason(row, validation_status)
    if classification in ("canonical", "unknown"):
        # Canonical and unresolved-unknown state is already represented on the
        # primary axis. Source-specific annotations do not belong on the
        # stale-validation axis; accepted descendants receive their verdict
        # later from the exact-key sidecar.
        validation_status = ""
        expected_nbits = ""
        normalized_rejection_reason = ""

    normalized = {
        "chain": source.chain,
        "source_kind": source_metadata("source_kind", source.source_kind),
        "source_path": source_metadata(
            "source_path", safe_path(source.path, chain=source.chain)
        ),
        "source_row_number": source_metadata("source_row_number", str(row_number)),
        "artifact_scope": source_metadata("artifact_scope", source.artifact_scope),
        "provenance": source_metadata("provenance", source.provenance),
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
        "expected_nbits": expected_nbits,
        "rejection_reason": normalized_rejection_reason,
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
    stale_descendant_observations: frozenset[tuple[str, int, str]] = frozenset(),
    stale_descendant_correction_keys: frozenset[tuple[int, str]] = frozenset(),
    error_blocks_path: Path | None = None,
) -> tuple[list[dict[str, str]], SourceStats]:
    """Read and normalize an entire source CSV, accumulating SourceStats.

    Every normalized row is kept except requested source classifications and
    exact identities in the committed error-blocks dataset. The stats record
    error labels rather than dropping malformed rows; classification tallies,
    rejection counts, and missing-evidence counts feed the counts/manifest
    artifacts. A source row formerly published as a direct stale is projected
    into its accepted ``stale_descendant`` state only when the descendant
    sidecar supplies both its exact chain/height/hash observation and the
    compact exact-key correction overlay. A stale descendant is never an error
    block, but the consensus-invalid gate below still filters any exact key the
    dataset records as an error block.
    """
    stats = SourceStats()
    rows: list[dict[str, str]] = []
    if source.path is None:
        stats.notes.add("no evidence source discovered")
        return rows, stats
    if error_blocks_path is None:
        excluded = load_stale_exclusion_keys()
        consensus_invalid = load_consensus_invalid_stale_keys()
    elif error_blocks_path.is_file():
        excluded = load_stale_exclusion_keys(error_blocks_path)
        consensus_invalid = load_consensus_invalid_stale_keys(error_blocks_path)
    else:
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
        observation_key = None
        if key is not None:
            observation_key = (source.chain, key[0], key[1])
        if (
            classification == "stale"
            and observation_key in stale_descendant_observations
            and key in stale_descendant_correction_keys
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
    only when its ``verification`` is non-empty (node-verified), its
    ``child_height`` is a nonnegative integer, its ``child_block_hash`` is a
    well-formed 32-byte hex value, and its ``child_block_time`` is a positive
    integer. A verified-but-incomplete row (malformed or manually truncated
    sidecar) is dropped here, so the affected evidence rows surface as
    ``missing_identity`` downstream instead of hydrating blanks that defeat
    the publication gate.
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
                child_height = int_or_none(row.get("child_height"))
                child_time = (row.get("child_block_time") or "").strip()
                if (
                    child_height is None
                    or child_height < 0
                    or not is_hash(child_hash)
                    or not child_time.isdigit()
                ):
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
        candidate_height = int_or_none(candidate.get("child_height"))
        row_height = int_or_none(row.get("child_height"))
        heights_agree = (
            candidate_height is not None
            and candidate_height >= 0
            and row_height is not None
            and row_height >= 0
            and candidate_height == row_height
        )
        if not heights_agree:
            if is_canonical_row:
                stats.canonical_unhydrated += 1
            else:
                stats.height_mismatch += 1
            continue
        row_child_header = (row.get("child_header_hex") or "").strip()
        if row_child_header:
            row_child_hash = normalize_hash(row.get("child_block_hash"))
            candidate_hash = normalize_hash(candidate.get("child_block_hash"))
            row_child_time = (row.get("child_block_time") or "").strip()
            candidate_time = (candidate.get("child_block_time") or "").strip()
            if row_child_hash != candidate_hash or (
                row_child_time and row_child_time != candidate_time
            ):
                raise ChildHeaderValidationError(
                    f"{chain} child identity disagrees with the "
                    f"source-authenticated bundle for BTC header {block_hash}"
                )
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
