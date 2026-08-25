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
from bisect import bisect_right
import csv
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stale_blocks_analysis.full_evidence import (  # noqa: E402
    DATA_DIR,
    DEFAULT_RELEVANCE_INVENTORY,
    HISTORICAL_CHILD_HEADER_CHAINS,
    LIVE_CHILD_IDENTITY_CHAINS,
    MONITOR_COUNT_FIELDS,
    MONITOR_EVIDENCE_FIELDS,
    MONITOR_OUTPUT_DIR,
    REPORTED_RELEVANCE_INVENTORY,
    RSK_SIDECAR_EXPORT_FIELDS,
    EvidenceSource,
    build_monitor_evidence_exports,
    discover_canonical_sources,
    discover_evidence_sources,
    discover_unknown_sources,
    int_or_none,
    is_hash,
    load_orphan_relevance_verdicts,
    normalize_evidence_row,
    parse_header_fields,
    safe_path,
    verified_header_hex,
    write_csv,
)
from stale_blocks_analysis.config import BIP34_HEIGHT, CHAIN_SPECS  # noqa: E402
from stale_blocks_analysis.config import MONITOR_VALIDATION_CONTRACTS  # noqa: E402
from stale_blocks_analysis.bitcoin_epoch_reference import (  # noqa: E402
    HEADERS_FILENAME,
    RETARGET_INTERVAL,
    load_nbits_by_epoch,
)
from stale_blocks_analysis.auxpow_parse import (  # noqa: E402
    ChildHeaderValidationError,
    hash_meets_btc_difficulty,
    validate_child_header_fields,
    validate_available_child_header_fields,
)
from stale_blocks_analysis.auxpow_chainid import hash_from_header_bytes  # noqa: E402
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
    build_error_observation_rows,
    error_observation_count_row,
    write_error_observation_artifact,
)

PUBLICATION_COUNTS = MONITOR_OUTPUT_DIR / "monitor-evidence-counts.csv"
PUBLICATION_MANIFEST = MONITOR_OUTPUT_DIR / "monitor-evidence-manifest.json"
GENERATED_MONITOR_FILENAMES = frozenset(
    {PUBLICATION_COUNTS.name, PUBLICATION_MANIFEST.name}
)
PUBLICATION_FLOOR_FIELDS = (
    "canonical",
    "stale",
    "stale_descendant",
    "strict_btc_orphan",
    "weak_btc_orphan",
    "monitor_rows",
    "source_rows",
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


_ORDINARY_MONITOR_CATEGORIES = (
    "canonical",
    "stale",
    "stale_descendant",
    "strict_btc_orphan",
    "weak_btc_orphan",
)
_ORPHAN_RELEVANCE_REASONS = {
    "strict_btc_orphan": "strict_height_nbits_match",
    "weak_btc_orphan": "timestamp_epoch_nbits_match",
}
_DESCENDANT_SIDECAR_CHAIN = "stale-descendants"
_MANIFEST_COUNT_FIELDS = (
    *_ORDINARY_MONITOR_CATEGORIES,
    "error_block",
    "monitor_rows",
    "source_rows",
)


@lru_cache(maxsize=8)
def _load_btc_nbits_by_epoch(data_dir: Path) -> dict[int, int]:
    """Load the committed Bitcoin epoch targets used by strict orphan rows."""
    try:
        return load_nbits_by_epoch(data_dir / "bitcoin-epoch-reference")
    except (OSError, ValueError) as exc:
        raise ValueError(
            f"{data_dir}: Bitcoin epoch nBits reference is unavailable"
        ) from exc


@lru_cache(maxsize=8)
def _load_btc_epoch_headers(data_dir: Path) -> tuple[tuple[int, int, int], ...]:
    """Load ``(time, height, nBits)`` rows for weak-orphan validation."""
    path = data_dir / "bitcoin-epoch-reference" / HEADERS_FILENAME
    try:
        raw_rows = json.loads(path.read_text())
        rows = tuple(
            sorted(
                (
                    int(row["time"]),
                    int(row["height"]),
                    int(str(row["bits"]), 16),
                )
                for row in raw_rows
                if isinstance(row, dict)
            )
        )
    except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"{data_dir}: Bitcoin epoch header reference is unavailable"
        ) from exc
    if not rows:
        raise ValueError(f"{path}: Bitcoin epoch header reference is empty")
    return rows


def _weak_orphan_nbits_match(data_dir: Path, timestamp: int, nbits: int) -> bool:
    """Check the classifier's timestamp and adjacent-epoch nBits predicate."""
    rows = _load_btc_epoch_headers(data_dir)
    times = [row[0] for row in rows]
    if timestamp < times[0] or timestamp > times[-1]:
        return False
    index = bisect_right(times, timestamp) - 1
    if index < 0 or index >= len(rows):
        return False
    epoch_height = rows[index][1]
    allowed = {
        row_bits
        for _time, row_height, row_bits in rows
        if row_height
        in {
            epoch_height - RETARGET_INTERVAL,
            epoch_height,
            epoch_height + RETARGET_INTERVAL,
        }
    }
    return nbits in allowed


def _btc_epoch_height_for_time(data_dir: Path, timestamp: int) -> int | None:
    """Return the retarget epoch selected by the timestamp evidence."""
    rows = _load_btc_epoch_headers(data_dir)
    times = [row[0] for row in rows]
    if timestamp < times[0] or timestamp > times[-1]:
        return None
    index = bisect_right(times, timestamp) - 1
    return rows[index][1]


def _is_ordinary_stale_status(status: str) -> bool:
    """Return whether a status belongs to the ordinary stale contract."""
    return status == "VALID" or status.startswith("VALID ")


def _load_monitor_artifact_counts(
    path: Path,
    chain: str,
    *,
    data_dir: Path = DATA_DIR,
    expected_artifact_scope: str = "",
) -> Counter[str]:
    """Count and validate the published categories in one ordinary artifact."""
    counts: Counter[str] = Counter()
    stale_identities: set[tuple[int, str]] = set()
    btc_nbits_by_epoch: dict[int, int] | None = None
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required = set(MONITOR_EVIDENCE_FIELDS)
        if chain == "rsk":
            required.update(RSK_SIDECAR_EXPORT_FIELDS)
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"{path}: missing monitor-evidence fields: "
                + ", ".join(sorted(missing))
            )
        for row_number, row in enumerate(reader, start=2):
            row_chain = (row.get("chain") or "").strip()
            if row_chain != chain:
                raise ValueError(
                    f"{path}:{row_number}: row chain {row_chain!r} does not match {chain!r}"
                )
            if (
                expected_artifact_scope
                and (row.get("artifact_scope") or "").strip() != expected_artifact_scope
            ):
                raise ValueError(
                    f"{path}:{row_number}: artifact scope disagrees with "
                    f"the publication contract ({expected_artifact_scope!r})"
                )
            raw_classification = row.get("classification") or ""
            classification = raw_classification.strip().lower()
            status = (row.get("validation_status") or "").strip()
            if raw_classification != classification:
                raise ValueError(
                    f"{path}:{row_number}: classification vocabulary is not exact"
                )
            raw_bucket = row.get("btc_stale_relevance") or ""
            raw_reason = row.get("relevance_reason") or ""
            bucket = raw_bucket.strip()
            reason = raw_reason.strip()
            if raw_bucket != bucket or raw_reason != reason:
                raise ValueError(
                    f"{path}:{row_number}: relevance vocabulary is not exact"
                )
            parent_hash = row.get("btc_header_hash") or ""
            if not is_hash(parent_hash) or parent_hash != parent_hash.lower():
                raise ValueError(
                    f"{path}:{row_number}: row lacks an exact lowercase Bitcoin "
                    "parent hash"
                )
            parent_header_hex = row.get("btc_header_hex") or ""
            if (
                len(parent_header_hex) != 160
                or parent_header_hex != parent_header_hex.lower()
                or any(char not in "0123456789abcdef" for char in parent_header_hex)
            ):
                raise ValueError(
                    f"{path}:{row_number}: serialized Bitcoin parent header must "
                    "be exactly 160 lowercase hexadecimal characters"
                )
            try:
                parent_header = bytes.fromhex(parent_header_hex)
            except ValueError:
                parent_header = b""
            if len(parent_header) != 80:
                raise ValueError(
                    f"{path}:{row_number}: serialized Bitcoin parent header must "
                    "be exactly 80 bytes"
                )
            if not verified_header_hex(parent_header_hex, parent_hash):
                raise ValueError(
                    f"{path}:{row_number}: serialized Bitcoin parent header is "
                    "missing or does not match its hash"
                )
            parsed_header = parse_header_fields(parent_header_hex)
            if not hash_meets_btc_difficulty(
                hash_from_header_bytes(parent_header),
                int(parsed_header["bits"], 16),
            ):
                raise ValueError(
                    f"{path}:{row_number}: Bitcoin parent header fails its "
                    "encoded proof-of-work target"
                )
            for field, parsed_field in (
                ("btc_prev_hash", "prev_hash"),
                ("btc_time", "time"),
                ("btc_bits", "bits"),
                ("btc_nonce", "nonce"),
            ):
                published = row.get(field) or ""
                if not published or published != parsed_header[parsed_field]:
                    raise ValueError(
                        f"{path}:{row_number}: {field} disagrees with "
                        "serialized Bitcoin parent header"
                    )
            raw_child_bundle = {
                field: row.get(field) or ""
                for field in (
                    "child_block_hash",
                    "child_header_hex",
                    "child_block_time",
                    "child_nbits",
                )
            }
            if any(value != value.strip() for value in raw_child_bundle.values()):
                raise ValueError(
                    f"{path}:{row_number}: child header fields must use exact "
                    "unpadded encodings"
                )
            child_header_hex = raw_child_bundle["child_header_hex"]
            child_bundle = {
                "child_block_hash": raw_child_bundle["child_block_hash"],
                "child_header_hex": child_header_hex,
                "child_block_time": raw_child_bundle["child_block_time"],
                "child_nbits": raw_child_bundle["child_nbits"],
            }
            spec = CHAIN_SPECS.get(chain)
            if chain in HISTORICAL_CHILD_HEADER_CHAINS:
                try:
                    validate_child_header_fields(
                        child_bundle,
                        nbits_from_header=(
                            spec.child_nbits_from_header if spec else True
                        ),
                    )
                except ChildHeaderValidationError as exc:
                    raise ValueError(
                        f"{path}:{row_number}: historical child fields are not "
                        f"a complete authenticated bundle ({exc})"
                    ) from exc
            elif any(child_bundle.values()):
                try:
                    validate_available_child_header_fields(
                        child_bundle,
                        nbits_from_header=(
                            spec.child_nbits_from_header if spec else True
                        ),
                    )
                except ChildHeaderValidationError as exc:
                    raise ValueError(
                        f"{path}:{row_number}: child fields disagree with "
                        f"serialized child header ({exc})"
                    ) from exc
            if chain in LIVE_CHILD_IDENTITY_CHAINS and classification != "canonical":
                child_height = int_or_none((row.get("child_height") or "").strip())
                child_hash = (row.get("child_block_hash") or "").strip().lower()
                child_time = (row.get("child_block_time") or "").strip()
                if (
                    child_height is None
                    or child_height < 0
                    or not is_hash(child_hash)
                    or not child_time.isdigit()
                    or int(child_time) <= 0
                ):
                    raise ValueError(
                        f"{path}:{row_number}: live-chain row lacks a verified "
                        "child identity"
                    )
            if classification in {"stale", "stale_descendant"}:
                btc_height = int_or_none((row.get("btc_height") or "").strip())
                if btc_height is None or btc_height < 0:
                    raise ValueError(
                        f"{path}:{row_number}: {classification} row lacks a "
                        "nonnegative Bitcoin height"
                    )
                stale_identity = (btc_height, parent_hash)
                if stale_identity in stale_identities:
                    raise ValueError(
                        f"{path}:{row_number}: duplicate {classification} identity "
                        f"{stale_identity!r}"
                    )
                stale_identities.add(stale_identity)
            requires_expected_nbits = classification == "stale" or (
                classification == "stale_descendant"
                and (
                    chain == _DESCENDANT_SIDECAR_CHAIN
                    or (row.get("artifact_scope") or "").strip()
                    == "stale_descendant_sidecar"
                )
            )
            if requires_expected_nbits:
                expected_nbits = row.get("expected_nbits") or ""
                if (
                    len(expected_nbits) != 8
                    or expected_nbits != expected_nbits.lower()
                    or any(char not in "0123456789abcdef" for char in expected_nbits)
                    or expected_nbits != parsed_header["bits"]
                ):
                    raise ValueError(
                        f"{path}:{row_number}: {classification} row has invalid "
                        "expected_nbits"
                    )
            if classification == "canonical":
                if status:
                    raise ValueError(
                        f"{path}:{row_number}: canonical row has invalid status"
                    )
                if bucket or reason:
                    raise ValueError(
                        f"{path}:{row_number}: canonical row has non-empty relevance"
                    )
                counts["canonical"] += 1
            elif classification == "stale":
                if not _is_ordinary_stale_status(status):
                    raise ValueError(
                        f"{path}:{row_number}: stale row has invalid ordinary status"
                    )
                if bucket or reason != "valid_direct_stale":
                    raise ValueError(
                        f"{path}:{row_number}: stale row has invalid relevance"
                    )
                counts["stale"] += 1
            elif classification == "stale_descendant":
                if status != "VALID_STALE_DESCENDANT":
                    raise ValueError(
                        f"{path}:{row_number}: stale descendant row has invalid status"
                    )
                if bucket or reason != "valid_stale_descendant":
                    raise ValueError(
                        f"{path}:{row_number}: stale descendant has invalid relevance"
                    )
                counts["stale_descendant"] += 1
            elif classification == "unknown" and reason == "valid_stale_descendant":
                if status != "VALID_STALE_DESCENDANT":
                    raise ValueError(
                        f"{path}:{row_number}: descendant observation has invalid status"
                    )
                if bucket:
                    raise ValueError(
                        f"{path}:{row_number}: descendant observation has invalid relevance"
                    )
                btc_height = int_or_none((row.get("btc_height") or "").strip())
                if btc_height is None or btc_height < 0:
                    raise ValueError(
                        f"{path}:{row_number}: descendant observation lacks a "
                        "nonnegative Bitcoin height"
                    )
                counts["stale_descendant"] += 1
            elif (
                classification == "unknown"
                and bucket in {"strict_btc_orphan", "weak_btc_orphan"}
                and reason == _ORPHAN_RELEVANCE_REASONS[bucket]
            ):
                if status:
                    raise ValueError(
                        f"{path}:{row_number}: orphan row has invalid status"
                    )
                if bucket == "strict_btc_orphan":
                    btc_height = int_or_none((row.get("btc_height") or "").strip())
                    if btc_height is None or btc_height < 0:
                        raise ValueError(
                            f"{path}:{row_number}: strict orphan row lacks a "
                            "nonnegative Bitcoin height"
                        )
                    if btc_height < BIP34_HEIGHT:
                        raise ValueError(
                            f"{path}:{row_number}: strict orphan row height is "
                            "below the BIP34 threshold"
                        )
                    epoch_height = _btc_epoch_height_for_time(
                        data_dir, int(parsed_header["time"])
                    )
                    if epoch_height is None or not (
                        epoch_height <= btc_height < epoch_height + RETARGET_INTERVAL
                    ):
                        raise ValueError(
                            f"{path}:{row_number}: strict orphan row height does "
                            "not match the Bitcoin header timestamp epoch"
                        )
                    if btc_nbits_by_epoch is None:
                        btc_nbits_by_epoch = _load_btc_nbits_by_epoch(data_dir)
                    expected_nbits = btc_nbits_by_epoch.get(
                        (btc_height // RETARGET_INTERVAL) * RETARGET_INTERVAL
                    )
                    if (
                        expected_nbits is None
                        or int(parsed_header["bits"], 16) != expected_nbits
                    ):
                        raise ValueError(
                            f"{path}:{row_number}: strict orphan row nBits does "
                            "not match the Bitcoin target at btc_height"
                        )
                else:
                    if not _weak_orphan_nbits_match(
                        data_dir,
                        int(parsed_header["time"]),
                        int(parsed_header["bits"], 16),
                    ):
                        raise ValueError(
                            f"{path}:{row_number}: weak orphan row time and nBits "
                            "do not match the Bitcoin epoch evidence"
                        )
                counts[bucket] += 1
            else:
                raise ValueError(
                    f"{path}:{row_number}: unsupported monitor classification"
                )
    counts["monitor_rows"] = sum(
        counts[category] for category in _ORDINARY_MONITOR_CATEGORIES
    )
    return counts


def _load_error_observation_identity_sets(
    path: Path,
) -> tuple[set[tuple[int, str]], set[tuple[str, int, str, int, str]]]:
    """Load exact parent and witness identities from an error aggregate."""
    parent_identities: set[tuple[int, str]] = set()
    witness_identities: set[tuple[str, int, str, int, str]] = set()
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "chain",
            "child_height",
            "child_block_hash",
            "btc_height",
            "btc_header_hash",
        }
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"{path}: missing error-observation identity fields: "
                + ", ".join(sorted(missing))
            )
        for row_number, row in enumerate(reader, start=2):
            chain = (row.get("chain") or "").strip()
            child_height = int_or_none((row.get("child_height") or "").strip())
            btc_height = int_or_none((row.get("btc_height") or "").strip())
            child_hash = (row.get("child_block_hash") or "").strip().lower()
            parent_hash = (row.get("btc_header_hash") or "").strip().lower()
            if (
                not chain
                or child_height is None
                or child_height < 0
                or btc_height is None
                or btc_height < 0
                or not is_hash(child_hash)
                or not is_hash(parent_hash)
            ):
                raise ValueError(
                    f"{path}:{row_number}: malformed error-observation identity"
                )
            parent_identities.add((btc_height, parent_hash))
            witness = (chain, child_height, child_hash, btc_height, parent_hash)
            if witness in witness_identities:
                raise ValueError(
                    f"{path}:{row_number}: duplicate error-observation witness"
                )
            witness_identities.add(witness)
    return parent_identities, witness_identities


def _load_ordinary_monitor_parent_identities(
    output_dir: Path, count_rows: list[dict[str, str]]
) -> set[tuple[int, str]]:
    """Return published ordinary parent identities with usable heights."""
    identities: set[tuple[int, str]] = set()
    for count_row in count_rows:
        chain = (count_row.get("chain") or "").strip()
        if not chain or chain == ERROR_OBSERVATION_ARTIFACT:
            continue
        artifact_path = output_dir / f"{chain}_monitor_evidence.csv"
        with artifact_path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                height = int_or_none((row.get("btc_height") or "").strip())
                parent_hash = (row.get("btc_header_hash") or "").strip().lower()
                if height is not None and height >= 0 and is_hash(parent_hash):
                    identities.add((height, parent_hash))
    return identities


def _coinbase_evidence_digest(row: dict[str, str], chain: str) -> str:
    """Digest preserved provenance and evidence fields in an ordinary row."""
    fields = [
        row.get("source_kind") or "",
        row.get("source_path") or "",
        row.get("source_row_number") or "",
        row.get("provenance") or "",
        row.get("coinbase_scriptsig_hex") or "",
        row.get("coinbase_outputs") or "",
        row.get("full_coinbase_hex") or "",
    ]
    if chain == "rsk":
        fields.extend(row.get(field) or "" for field in RSK_SIDECAR_EXPORT_FIELDS)
    if not any(fields):
        return ""
    return hashlib.sha256("\x00".join(fields).encode()).hexdigest()


def _load_monitor_final_identity_sets(
    output_dir: Path,
) -> dict[tuple[str, str], Counter[tuple[str, str, str, str, str]]]:
    """Load per-chain final-category identities from ordinary artifacts."""
    identities: dict[tuple[str, str], Counter[tuple[str, str, str, str, str]]] = {}
    for path in sorted(output_dir.glob("*_monitor_evidence.csv")):
        chain = path.name.removesuffix("_monitor_evidence.csv")
        if chain == ERROR_OBSERVATION_ARTIFACT:
            continue
        with path.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), start=2):
                classification = (row.get("classification") or "").strip().lower()
                bucket = (row.get("btc_stale_relevance") or "").strip()
                if classification == "canonical":
                    category = "canonical"
                elif classification == "stale":
                    category = "stale"
                elif classification == "stale_descendant":
                    category = "stale_descendant"
                elif classification == "unknown" and bucket in {
                    "strict_btc_orphan",
                    "weak_btc_orphan",
                }:
                    category = bucket
                elif (
                    classification == "unknown"
                    and (row.get("relevance_reason") or "").strip()
                    == "valid_stale_descendant"
                ):
                    category = "stale_descendant"
                else:
                    continue
                parent_hash = (row.get("btc_header_hash") or "").strip().lower()
                if not is_hash(parent_hash):
                    raise ValueError(
                        f"{path}:{row_number}: final row lacks a valid parent hash"
                    )
                raw_height = (row.get("btc_height") or "").strip()
                height = int_or_none(raw_height)
                if raw_height and (height is None or height < 0):
                    raise ValueError(
                        f"{path}:{row_number}: final row has an invalid Bitcoin height"
                    )
                child_height = int_or_none((row.get("child_height") or "").strip())
                child_hash = (row.get("child_block_hash") or "").strip().lower()
                key = (
                    str(height) if height is not None else "",
                    parent_hash,
                    str(child_height) if child_height is not None else "",
                    child_hash if is_hash(child_hash) else "",
                    _coinbase_evidence_digest(row, chain),
                )
                identities.setdefault((chain, category), Counter())[key] += 1
    return identities


def _validate_ordinary_monitor_identity_floor(
    output_dir: Path,
    *,
    committed: dict[tuple[str, str], Counter[tuple[str, str, str, str, str]]]
    | None = None,
) -> None:
    """Reject add-only updates that drop any committed final-category identity."""
    if committed is None:
        committed = _load_monitor_final_identity_sets(MONITOR_OUTPUT_DIR)
    current = _load_monitor_final_identity_sets(output_dir)
    missing: list[str] = []
    for key, expected in committed.items():
        dropped = expected - current.get(key, Counter())
        if dropped:
            chain, category = key
            missing.append(f"{chain} {category}: {sum(dropped.values())}")
    if missing:
        raise ValueError(
            "add-only update drops committed ordinary evidence identities: "
            + ", ".join(missing)
        )


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
            if chain == ERROR_OBSERVATION_ARTIFACT:
                try:
                    error_rows, _error_inventory = build_error_observation_rows(
                        data_dir=args.data_dir
                    )
                except (OSError, ValueError) as exc:
                    problems.append(str(exc))
                    continue
                for field in ("error_block", "monitor_rows", "source_rows"):
                    expected = int_or_none(baseline_row.get(field) or "0")
                    if expected is None or expected < 0:
                        problems.append(f"{chain} has invalid {field} baseline")
                    elif len(error_rows) < expected:
                        problems.append(
                            f"{chain} {field} is below the publication baseline "
                            f"({len(error_rows)} < {expected})"
                        )
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
    *,
    data_dir: Path = DATA_DIR,
) -> tuple[
    list[dict[str, str]],
    dict[str, object],
    tuple[set[tuple[int, str]], set[tuple[str, int, str, int, str]]],
]:
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
    manifest.pop("validation_contract", None)
    manifest["validation_contracts"] = MONITOR_VALIDATION_CONTRACTS
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
    count_rows_by_chain = {row["chain"]: row for row in count_rows}
    manifest_counts_by_chain = {
        str(item["chain"]): item
        for item in manifest_counts
        if isinstance(item, dict) and item.get("chain")
    }
    for chain, row in count_rows_by_chain.items():
        manifest_row = manifest_counts_by_chain.get(chain)
        if manifest_row is None:
            raise ValueError(f"{manifest_path}: {chain} has no manifest count row")
        csv_scope = (row.get("artifact_scope") or "").strip()
        manifest_scope = str(manifest_row.get("artifact_scope") or "").strip()
        if not csv_scope or csv_scope != manifest_scope:
            raise ValueError(
                f"{manifest_path}: {chain} artifact scope does not match counts "
                f"({manifest_scope!r} != {csv_scope!r})"
            )
        for field in _MANIFEST_COUNT_FIELDS:
            csv_raw = row.get(field)
            manifest_raw = manifest_row.get(field)
            csv_value = int_or_none(str(csv_raw) if csv_raw is not None else "")
            manifest_value = int_or_none(
                str(manifest_raw) if manifest_raw is not None else ""
            )
            if (
                csv_value is None
                or manifest_value is None
                or csv_value != manifest_value
            ):
                raise ValueError(
                    f"{manifest_path}: {chain} {field} does not match counts "
                    f"({manifest_value!r} != {csv_value!r})"
                )
    artifact_chains = (set(chains) | set(artifacts)) - {ERROR_OBSERVATION_ARTIFACT}
    for chain in artifact_chains:
        expected_name = f"{chain}_monitor_evidence.csv"
        permitted_paths = {
            f"results/monitor-evidence/{expected_name}",
            f"<external>/{expected_name}",
            safe_path(output_dir / expected_name, chain=chain),
        }
        manifest_declared = artifacts.get(chain)
        count_declared = count_rows_by_chain.get(chain, {}).get("artifact_path")
        if (
            manifest_declared != count_declared
            or manifest_declared not in permitted_paths
        ):
            raise ValueError(
                f"{output_dir}: {chain} manifest and count artifact paths must "
                "agree on a permitted logical publication path"
            )
        artifact_path = output_dir / expected_name
        if not artifact_path.is_file():
            raise ValueError(
                f"{output_dir}: {chain} monitor-evidence artifact is missing"
            )
        expected = count_rows_by_chain.get(chain)
        if expected is None:
            raise ValueError(f"{output_dir}: {chain} artifact has no count row")
        actual = _load_monitor_artifact_counts(
            artifact_path,
            chain,
            data_dir=data_dir,
            expected_artifact_scope=(expected.get("artifact_scope") or "").strip(),
        )
        for field in (*_ORDINARY_MONITOR_CATEGORIES, "monitor_rows"):
            observed = actual[field]
            minimum = int(expected.get(field) or "0")
            if observed != minimum:
                raise ValueError(
                    f"{output_dir}: {chain} {field} does not match artifact "
                    f"({observed} != {minimum})"
                )
        error_block_count = int(expected.get("error_block") or "0")
        if error_block_count != 0:
            raise ValueError(
                f"{output_dir}: {chain} ordinary artifact declares "
                f"nonzero error_block count ({error_block_count})"
            )
    aggregate_path = output_dir / f"{ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv"
    if aggregate_path.is_file():
        baseline_identities = _load_error_observation_identity_sets(aggregate_path)
    elif (
        aggregate := count_rows_by_chain.get(ERROR_OBSERVATION_ARTIFACT)
    ) is not None and any(
        int(aggregate.get(field) or "0") > 0
        for field in ("error_block", "monitor_rows", "source_rows")
    ):
        raise ValueError(f"{output_dir}: error-observation artifact is missing")
    else:
        baseline_identities = (set(), set())
    _validate_add_only_baseline_floors(count_rows, counts_path)
    _validate_ordinary_monitor_identity_floor(
        output_dir,
        committed=_load_monitor_final_identity_sets(MONITOR_OUTPUT_DIR),
    )
    return count_rows, manifest, baseline_identities


def _validate_add_only_baseline_floors(
    count_rows: list[dict[str, str]], counts_path: Path
) -> None:
    """Reject a partial diagnostic export before publishing an add-only aggregate."""
    committed, *_rest = _load_publication_baseline(MONITOR_OUTPUT_DIR)
    actual = {str(row["chain"]): row for row in count_rows}
    problems: list[str] = []
    for chain, expected in committed.items():
        if chain == ERROR_OBSERVATION_ARTIFACT:
            continue
        row = actual.get(chain)
        if row is None:
            problems.append(f"missing {chain}")
            continue
        for field in PUBLICATION_FLOOR_FIELDS:
            value = row.get(field)
            try:
                observed = int(value or "")
            except ValueError:
                problems.append(f"{chain} has invalid {field}: {value!r}")
                continue
            minimum = int(expected[field])
            if observed < minimum:
                problems.append(
                    f"{chain} {field} is below floor ({observed} < {minimum})"
                )
    if problems:
        raise ValueError(
            f"{counts_path}: baseline is below committed publication floors: "
            + "; ".join(problems)
        )


def _validate_error_observation_update_floor(
    count_rows: list[dict[str, str]], counts_path: Path, observed_rows: int
) -> None:
    """Reject an add-only aggregate that would reduce its existing floor."""
    baseline = next(
        (
            row
            for row in count_rows
            if (row.get("chain") or "").strip() == ERROR_OBSERVATION_ARTIFACT
        ),
        None,
    )
    if baseline is None:
        return
    problems: list[str] = []
    for field in ("error_block", "monitor_rows", "source_rows"):
        value = baseline.get(field)
        try:
            expected = int(value or "")
        except ValueError:
            problems.append(
                f"{ERROR_OBSERVATION_ARTIFACT} has invalid {field}: {value!r}"
            )
            continue
        if observed_rows < expected:
            problems.append(
                f"{ERROR_OBSERVATION_ARTIFACT} {field} is below floor "
                f"({observed_rows} < {expected})"
            )
    if problems:
        raise ValueError(
            f"{counts_path}: regenerated error-observation aggregate is below "
            "the publication floor: " + "; ".join(problems)
        )


def _validate_error_observation_update_identities(
    baseline: tuple[set[tuple[int, str]], set[tuple[str, int, str, int, str]]],
    regenerated: tuple[set[tuple[int, str]], set[tuple[str, int, str, int, str]]],
    counts_path: Path,
) -> None:
    """Reject an aggregate replacement that drops published exact identities."""
    missing_parents = baseline[0] - regenerated[0]
    missing_witnesses = baseline[1] - regenerated[1]
    if not missing_parents and not missing_witnesses:
        return
    details: list[str] = []
    if missing_parents:
        details.append(f"missing {len(missing_parents)} published parent identities")
    if missing_witnesses:
        details.append(f"missing {len(missing_witnesses)} published witness identities")
    raise ValueError(
        f"{counts_path}: regenerated error-observation aggregate drops "
        + "; ".join(details)
    )


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
    if output_dir == MONITOR_OUTPUT_DIR.expanduser().resolve():
        raise ValueError(
            "add-only error-observation updates require an explicit output "
            "directory with an immutable ordinary-publication baseline"
        )
    count_rows, manifest, baseline_identities = _load_error_update_baseline(
        output_dir, data_dir=args.data_dir
    )
    error_blocks_path = args.data_dir / "error-blocks" / "error_blocks.csv"
    if error_blocks_path.is_file():
        ordinary_identities = _load_ordinary_monitor_parent_identities(
            output_dir, count_rows
        )
        consensus_invalid_identities = load_consensus_invalid_stale_keys(
            error_blocks_path
        )
        overlap = ordinary_identities & consensus_invalid_identities
        if overlap:
            raise ValueError(
                "add-only error-observation update cannot proceed: ordinary "
                f"monitor artifacts overlap {len(overlap)} current error-block "
                "parent identities; run a full publication rebuild"
            )
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
        observed_rows = int_or_none(str(artifact.get("rows") or ""))
        if observed_rows is None or observed_rows < 0:
            raise ValueError("error-observation artifact has an invalid row count")
        regenerated_identities = _load_error_observation_identity_sets(
            staging_dir / f"{ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv"
        )
        _validate_error_observation_update_identities(
            baseline_identities,
            regenerated_identities,
            output_dir / PUBLICATION_COUNTS.name,
        )
        _validate_error_observation_update_floor(
            count_rows,
            output_dir / PUBLICATION_COUNTS.name,
            observed_rows,
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
