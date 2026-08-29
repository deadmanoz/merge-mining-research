"""Shared normalized AuxPoW evidence-row contracts."""

from __future__ import annotations

import csv
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .auxpow_chainid import hash_from_header_bytes
from .auxpow_parse import (
    CHILD_HEADER_FIELDS,
    ChildHeaderValidationError,
    validate_available_child_header_fields,
    validate_child_header_fields,
)
from .bitcoin_binary import format_outputs_addr, parse_coinbase_tx, sha256d
from .config import CHAIN_SPECS, HISTORICAL_CHILD_HEADER_CHAINS, PROJECT_ROOT
from .error_blocks import load_consensus_invalid_stale_keys, load_stale_exclusion_keys
from .evidence_sources import EvidenceSource

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

STALE_DESCENDANT_CORRECTION_REASON_BY_SOURCE_CLASSIFICATION = {
    "stale": "reclassified_from_direct_stale",
    "canonical": "reclassified_from_canonical",
}


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
    if source.chain == "hathor" and child_hash:
        try:
            child_hash_matches_header = (
                len(bytes.fromhex(header_hex)) == 80
                and hash_from_header_bytes(bytes.fromhex(header_hex)).hex()
                == child_hash
            )
        except ValueError:
            child_hash_matches_header = False
        if not child_hash_matches_header:
            raise ChildHeaderValidationError(
                f"hathor evidence row {row_number}: child_block_hash does not "
                "match btc_header_hex"
            )

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


def require_matching_stale_descendant_correction(
    corrections: Mapping[tuple[int, str], str],
    key: tuple[int, str],
    source_classification: str,
    *,
    label: str,
) -> bool:
    """Return whether ``key`` has the correction required by its source bucket.

    A missing correction leaves the source row in its original classification.
    A present correction with the wrong type is contradictory publication input
    and therefore fails closed instead of being treated as an absent overlay.
    """
    actual_reason = corrections.get(key)
    if actual_reason is None:
        return False
    expected_reason = STALE_DESCENDANT_CORRECTION_REASON_BY_SOURCE_CLASSIFICATION.get(
        source_classification
    )
    if expected_reason is None:
        raise ValueError(
            f"{label}: unsupported correction source classification "
            f"{source_classification!r}"
        )
    if actual_reason != expected_reason:
        raise ValueError(
            f"{label}: {source_classification} source requires correction_reason="
            f"{expected_reason}, got {actual_reason!r}"
        )
    return True


def collect_source_rows(
    source: EvidenceSource,
    *,
    exclude_classifications: frozenset[str] = frozenset(),
    exclude_canonical_identities: frozenset[tuple[int, str]] = frozenset(),
    stale_descendant_observations: frozenset[tuple[str, int, str]] = frozenset(),
    stale_descendant_corrections: Mapping[tuple[int, str], str] | None = None,
    error_blocks_path: Path | None = None,
) -> tuple[list[dict[str, str]], SourceStats]:
    """Read and normalize an entire source CSV, accumulating SourceStats.

    Every normalized row is kept except requested source classifications,
    canonical identities already represented by a primary inventory, and exact
    identities in the committed error-blocks dataset. Applying canonical
    duplicate exclusions here keeps them out of both projection and source
    statistics before any correction changes their final classification. The
    stats record error labels rather than dropping malformed rows;
    classification tallies, rejection counts, and missing-evidence counts feed
    the counts/manifest artifacts. A source row formerly published as a direct stale is projected
    into its accepted ``stale_descendant`` state only when the descendant
    sidecar supplies both its exact chain/height/hash observation and the
    compact exact-key correction overlay. This also applies to a canonical
    archive row corrected after independent Bitcoin Core ancestry checks. A
    stale descendant is never an error
    block, but the consensus-invalid gate below still filters any exact key the
    dataset records as an error block.
    """
    stats = SourceStats()
    rows: list[dict[str, str]] = []
    if source.path is None:
        stats.notes.add("no evidence source discovered")
        return rows, stats
    corrections = stale_descendant_corrections or {}
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
    skipped_duplicate_canonical_count = 0
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
        if classification == "canonical" and key in exclude_canonical_identities:
            skipped_duplicate_canonical_count += 1
            continue
        if (
            classification
            in STALE_DESCENDANT_CORRECTION_REASON_BY_SOURCE_CLASSIFICATION
            and observation_key in stale_descendant_observations
            and key is not None
            and require_matching_stale_descendant_correction(
                corrections,
                key,
                classification,
                label=(f"{source.path}:{normalized.get('source_row_number', '?')}"),
            )
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
    if skipped_duplicate_canonical_count:
        stats.notes.add(
            "skipped_duplicate_canonical_companion_rows="
            f"{skipped_duplicate_canonical_count}"
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
