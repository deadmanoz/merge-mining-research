"""Shared normalized AuxPoW evidence-row contracts."""

from __future__ import annotations

import csv
import hashlib
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .auxpow_chainid import hash_from_header_bytes
from .auxpow_parse import (
    CHILD_HEADER_FIELDS,
    ChildHeaderValidationError,
    validate_available_child_header_fields,
    validate_child_header_fields,
)
from .bitcoin_binary import format_outputs_canonical, parse_coinbase_tx, sha256d
from .coinbase_output_claims import (
    CHILD_DECODED_ACQUISITION_CHAINS,
    FILTERED_ACQUISITION_CHAINS,
    parse_coinbase_output_claims,
    render_coinbase_outputs_column,
)
from .config import CHAIN_SPECS, DATA_DIR, HISTORICAL_CHILD_HEADER_CHAINS, PROJECT_ROOT
from .error_blocks import load_error_block_keys
from .evidence_sources import (
    CHILD_HEIGHT_AUTHENTICATED,
    CHILD_HEIGHT_NOT_APPLICABLE,
    CHILD_HEIGHT_UNAUTHENTICATED_SCAN_ORDER,
    EvidenceSource,
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
    "active_mainchain_hash_at_height",
    "btc_height",
    "btc_stale_height",
    "btc_parent_height",
    "btc_canonical_height",
    "btc_bip34_height",
    "height",
    "root_active_mainchain_hash_at_height",
    "root_stale_height",
    "stale_fork_depth",
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


def reconcile_parent_header_fields(
    row: dict[str, str],
    *,
    context: str,
    parsed: dict[str, str] | None = None,
) -> None:
    """Fill and authenticate normalized audit fields from a parent header.

    A parseable serialized Bitcoin parent header is the authoritative source
    for its hash, previous hash, time, bits, and nonce. Missing normalized
    fields are filled in place; every populated field must agree after the
    normal lowercase normalization for hashes and bits. Missing or malformed
    header hex remains the caller's separate coverage concern.
    """
    if parsed is None:
        parsed = parse_header_fields(row.get("btc_header_hex", ""))
    if not parsed:
        return
    for field, parsed_field in (
        ("btc_header_hash", "hash"),
        ("btc_prev_hash", "prev_hash"),
        ("btc_time", "time"),
        ("btc_bits", "bits"),
        ("btc_nonce", "nonce"),
    ):
        published = (row.get(field) or "").strip()
        if field in {"btc_header_hash", "btc_prev_hash", "btc_bits"}:
            published = published.lower()
        derived = parsed[parsed_field]
        if published and published != derived:
            raise ValueError(
                f"{context}: {field} disagrees with serialized Bitcoin parent header"
            )
        row[field] = published or derived


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
    source: EvidenceSource,
    row: dict[str, str],
    fieldnames: Iterable[str] | None,
) -> str:
    """Resolve the authenticated child-chain height for ``source``.

    Sources whose declared schema records scan order instead of consensus
    height return blank for later authenticated hydration. Parent-only sources
    declare child height not applicable and also return blank. Authenticated
    child sources prefer the chain's registered ``height_column`` from
    CHAIN_SPECS, then any populated ``*_height`` column that is not a BTC-side
    height, then a literal ``child_height`` column. Returns '' when absent.
    """
    if source.child_height_semantics in {
        CHILD_HEIGHT_UNAUTHENTICATED_SCAN_ORDER,
        CHILD_HEIGHT_NOT_APPLICABLE,
    }:
        return ""
    if source.child_height_semantics != CHILD_HEIGHT_AUTHENTICATED:
        raise ValueError(
            f"unsupported child-height semantics: {source.child_height_semantics}"
        )
    spec = CHAIN_SPECS.get(source.chain)
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


def _is_legacy_address_projection(outputs: str) -> bool:
    """True when a legacy cell holds only decoded addresses and no placeholder.

    An all-address vector identifies an address *decode*, but a decode is a
    projection only for an acquisition that dropped what it could not name,
    so the caller applies this test solely to ``FILTERED_ACQUISITION_CHAINS``
    rows. Terracoin/Bitcoin Vault read exact script bytes, and Syscoin's
    decode kept a placeholder for every unnameable output, so their
    address-only cells are complete vectors with exact positions. The test is
    on the source tokens rather than the parsed claims because a P2SH address
    parses to an exact script, which would hide an all-P2SH filtered row.

    Inferring this is sound at the legacy boundary precisely because it is not
    sound for canonical data: the contract renders address-bearing scripts as
    addresses, so only a decode yields an all-address vector. A retained
    ``OP_RETURN`` placeholder means nothing was dropped, so those stay exact.
    Once normalized the projection is stated with the marker instead.
    """
    tokens = [
        token.strip() for token in outputs.replace("|", ";").split(";") if token.strip()
    ]
    if not tokens:
        return False
    for token in tokens:
        payout = token.rpartition(":")[0] if ":" in token else token
        payout = payout.strip().lstrip("~")
        if not payout or payout.startswith("OP_RETURN") or payout.endswith("*"):
            return False  # a retained placeholder: nothing was dropped
        try:
            bytes.fromhex(payout)
        except ValueError:
            continue  # an address
        return False  # a raw script: the bytes are ours, not a decode
    return True


def normalize_outputs_cell(outputs: str, *, chain: str) -> str:
    """Render a populated, possibly legacy, cell through the claims layer.

    An archive row's cell can predate the rendering contract; publication and
    reconciliation must still emit the contract, so the cell is re-rendered
    from its parsed claims. ``chain`` carries the acquisition provenance,
    applied only to a cell the contract would rewrite -- one that already
    round-trips unchanged is canonical and states its own claims:

    - a ``CHILD_DECODED_ACQUISITION_CHAINS`` legacy cell holds the child
      node's decoded addresses, which collapse P2PK to the P2PKH form, so its
      address tokens establish only the recipient hash160 and render as
      ``pkh(...)`` even in Bitcoin's version-0 form;
    - a ``FILTERED_ACQUISITION_CHAINS`` all-address legacy cell kept only the
      outputs the decode could name, so it gains the ``~`` filtered marker.

    Raises ``ValueError`` when the cell does not parse.
    """
    rendered = render_coinbase_outputs_column(parse_coinbase_output_claims(outputs))
    if rendered == outputs:
        return rendered
    if chain in CHILD_DECODED_ACQUISITION_CHAINS:
        rendered = render_coinbase_outputs_column(
            parse_coinbase_output_claims(outputs, child_decoded_addresses=True)
        )
    if chain in FILTERED_ACQUISITION_CHAINS and _is_legacy_address_projection(outputs):
        rendered = ";".join(
            ("~" + token if token else token) for token in rendered.split(";")
        )
    return rendered


def parse_coinbase_fields(
    row: dict[str, str], *, chain: str
) -> tuple[str, str, str, bool]:
    """Extract coinbase evidence, decoding ``full_coinbase_hex`` when needed.

    Returns ``(scriptsig_hex, outputs, full_coinbase_hex, malformed)``.
    Hathor-style rows carry only the full coinbase transaction; when the
    scriptsig or outputs columns are empty, they are filled by parsing it.
    ``chain`` is the source chain, carried into the legacy-cell normalization
    so the filtered-projection inference applies only to acquisitions that
    actually filtered. ``malformed`` flags a cell that failed to parse.
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
            outputs = outputs or format_outputs_canonical(parsed["outputs"])
    if outputs:
        try:
            outputs = normalize_outputs_cell(outputs, chain=chain)
        except ValueError:
            malformed = True
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
    parent_header_fields = {
        "btc_header_hash": normalize_hash(get_value(row, fieldnames, HASH_COLUMNS)),
        "btc_prev_hash": normalize_hash(get_value(row, fieldnames, PREV_COLUMNS)),
        "btc_time": get_value(row, fieldnames, ("btc_time",)),
        "btc_bits": get_value(row, fieldnames, BITS_COLUMNS).lower(),
        "btc_nonce": row.get("btc_nonce", "").strip(),
        "btc_header_hex": header_hex,
    }
    reconcile_parent_header_fields(
        parent_header_fields,
        context=f"{source.chain} evidence row {row_number}",
        parsed=parsed,
    )
    header_hash = parent_header_fields["btc_header_hash"]
    prev_hash = parent_header_fields["btc_prev_hash"]
    btc_time = parent_header_fields["btc_time"]
    btc_bits = parent_header_fields["btc_bits"]
    btc_nonce = parent_header_fields["btc_nonce"]
    validation_status = row.get("validation_status", "").strip()
    scriptsig, outputs, full_coinbase, malformed_coinbase = parse_coinbase_fields(
        row, chain=source.chain
    )
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
        # later from the accepted parent-verdict module.
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
        "child_height": child_height_for(source, row, fieldnames),
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
    *,
    data_dir: Path = DATA_DIR,
) -> Iterable[tuple[dict[str, str], set[str]]]:
    """Yield ``(normalized_row, errors)`` for every row of a source CSV.

    Row numbers start at 2 to match spreadsheet line numbering (line 1 is
    the header). Yields nothing when the source has no path.
    """
    if source.path is None:
        return
    if source.source_kind == "stale_descendant_parent_verdicts":
        # Import lazily because the canonical parent loader authenticates
        # serialized fields with helpers from this module.
        from .stale_descendants import load_stale_descendant_parents

        for parent in load_stale_descendant_parents(
            source.path,
            data_dir=data_dir,
        ).values():
            yield normalize_evidence_row(
                source,
                parent.row,
                list(parent.row),
                parent.row_number,
            )
        return
    with source.path.open(newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        for row_number, row in enumerate(reader, start=2):
            yield normalize_evidence_row(source, row, fieldnames, row_number)


def collect_source_rows(
    source: EvidenceSource,
    *,
    data_dir: Path = DATA_DIR,
    exclude_classifications: frozenset[str] = frozenset(),
    error_blocks_path: Path | None = None,
    excluded_error_rows: list[dict[str, str]] | None = None,
) -> tuple[list[dict[str, str]], SourceStats]:
    """Read and normalize an entire source CSV, accumulating SourceStats.

    Every normalized row is kept except requested source classifications and
    exact identities in the committed error-blocks dataset. Applying
    exclusions here keeps them out of both projection and source statistics.
    Final-category conflicts are not repaired at this boundary: source
    classifiers must emit the current verdict, and the publication validator
    rejects any conflicting snapshot.
    """
    stats = SourceStats()
    rows: list[dict[str, str]] = []
    if source.path is None:
        stats.notes.add("no evidence source discovered")
        return rows, stats
    error_block_keys = (
        load_error_block_keys(error_blocks_path)
        if error_blocks_path is not None and error_blocks_path.is_file()
        else load_error_block_keys()
    )
    error_block_hashes = {block_hash for _height, block_hash in error_block_keys}
    source_sha256: str | None = None

    def authenticated_source_sha256() -> str:
        nonlocal source_sha256
        if source_sha256 is not None:
            return source_sha256
        digest = hashlib.sha256()
        assert source.path is not None
        with source.path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        source_sha256 = digest.hexdigest()
        return source_sha256

    excluded_count = 0
    for normalized, errors in iter_source_rows(source, data_dir=data_dir):
        classification = normalized["classification"]
        parent_hash = normalized["btc_header_hash"].lower()
        if parent_hash in error_block_hashes:
            if excluded_error_rows is not None:
                captured = dict(normalized)
                captured["source_sha256"] = authenticated_source_sha256()
                excluded_error_rows.append(captured)
            excluded_count += 1
            continue
        if classification in exclude_classifications:
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
    return rows, stats


def canonical_evidence_status(source: EvidenceSource, stats: SourceStats) -> str:
    """Classify how well the discovered source represents canonical parents.

    ``canonical_retained`` means canonical rows made it into the stats
    (in-file or via a companion); a validated-stales source that cannot
    carry them reports the stale-only-publication status instead.
    """
    if source.source_kind == "missing":
        return "not_checked_missing_source"
    if source.source_kind == "stale_descendant_parent_verdicts":
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
