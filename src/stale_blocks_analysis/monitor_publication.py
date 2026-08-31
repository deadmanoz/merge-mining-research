"""Fail-closed monitor-evidence publication writing."""

from __future__ import annotations

import argparse
from bisect import bisect_right
import csv
import hashlib
import json
import os
import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .auxpow_chainid import hash_from_header_bytes
from .auxpow_parse import (
    ChildHeaderValidationError,
    hash_meets_btc_difficulty,
    validate_available_child_header_fields,
    validate_child_header_fields,
)
from .bitcoin_epoch_reference import (
    HEADERS_FILENAME,
    RETARGET_INTERVAL,
    load_nbits_by_epoch,
)
from .bitcoin_binary import parse_coinbase_tx
from .coinbase_markers import parse_bip34_height
from .coinbase_output_claims import (
    CoinbaseOutputClaim,
    coinbase_output_claims_refine,
    merge_coinbase_output_claim_sets,
    parse_coinbase_output_claims,
    render_coinbase_output_claims,
)
from .config import (
    ACCEPTED_STALE_VALIDATION_STATUSES,
    BIP34_HEIGHT,
    CHAIN_SPECS,
    DATA_DIR,
    HISTORICAL_CHILD_HEADER_CHAINS,
    MONITOR_VALIDATION_CONTRACTS,
)
from .error_blocks import load_error_block_keys
from .error_block_validation import validate_error_module
from .error_observations import (
    ERROR_OBSERVATION_ARTIFACT,
    ERROR_OBSERVATION_FIELDS,
    ERROR_OBSERVATION_LEDGER,
    ERROR_OBSERVATION_SCOPE,
    ERROR_OBSERVATION_STATUS,
    build_error_observation_rows,
    validate_rsk_sidecar_cells,
)
from .evidence_hydration import (
    CHILD_IDENTITY_REQUIRED_CHAINS,
    RSK_SIDECAR_EXPORT_FIELDS,
    verified_header_hex,
)
from .evidence_normalization import (
    int_or_none,
    is_hash,
    normalize_hash,
    parse_header_fields,
)
from .evidence_sources import (
    CHILD_HEIGHT_UNAUTHENTICATED_SCAN_ORDER,
    EvidenceSource,
    child_height_semantics_for_source,
    discover_canonical_sources,
    discover_evidence_sources,
    discover_unknown_sources,
)
from .monitor_exports import (
    MONITOR_COUNT_FIELDS,
    MONITOR_EVIDENCE_FIELDS,
    MONITOR_OUTPUT_DIR,
    MonitorVerdict,
    REPORTED_RELEVANCE_INVENTORY,
    STALE_DESCENDANT_OBSERVATION_ARTIFACT,
    build_monitor_evidence_exports,
    load_orphan_relevance_verdicts,
)
from .stale_descendants import (
    load_stale_descendant_observations,
    load_stale_descendant_parents,
)

PUBLICATION_COUNTS = MONITOR_OUTPUT_DIR / "monitor-evidence-counts.csv"
PUBLICATION_MANIFEST = MONITOR_OUTPUT_DIR / "monitor-evidence-manifest.json"
GENERATED_MONITOR_FILENAMES = frozenset(
    {PUBLICATION_COUNTS.name, PUBLICATION_MANIFEST.name}
)


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
_DESCENDANT_PARENT_VERDICTS_CHAIN = "stale-descendants"
_MANIFEST_COUNT_FIELDS = (
    *_ORDINARY_MONITOR_CATEGORIES,
    "error_block",
    "monitor_rows",
    "source_rows",
)
_MANIFEST_TOP_LEVEL_FIELDS = frozenset(
    {
        "output_dir",
        "counts_csv",
        "manifest_json",
        "validation_contracts",
        "artifacts",
        "relevance_inventory",
        "strict_weak_verdicts_loaded",
        "observation_chain_counts",
        "counts",
    }
)
_OBSERVATION_CHAIN_COUNT_ARTIFACTS = frozenset(
    {ERROR_OBSERVATION_ARTIFACT, STALE_DESCENDANT_OBSERVATION_ARTIFACT}
)
_UNKNOWN_IDENTITY_FIELDS = frozenset(
    {
        "chain",
        "source_path",
        "source_row_number",
        "source_classification",
        "btc_header_hash",
    }
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
    return status in ACCEPTED_STALE_VALIDATION_STATUSES


def _load_monitor_artifact_counts(
    path: Path,
    chain: str,
    *,
    data_dir: Path = DATA_DIR,
    expected_artifact_scope: str | frozenset[str] = "",
    orphan_verdicts: dict[str, MonitorVerdict] | None = None,
) -> Counter[str]:
    """Count and validate the published categories in one monitor artifact."""
    error_aggregate = chain == ERROR_OBSERVATION_ARTIFACT
    counts: Counter[str] = Counter()
    stale_identities: set[tuple[int, str]] = set()
    event_categories: dict[tuple[str, int, str], str] = {}
    btc_nbits_by_epoch: dict[int, int] | None = None
    descendant_observations: set[tuple[str, int, str, int, str]] | None = None
    descendant_parents: set[tuple[int, str]] | None = None
    descendant_error_blocks: set[tuple[int, str]] | None = None
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        if len(fieldnames) != len(set(fieldnames)):
            raise ValueError(f"{path}: monitor-evidence schema has duplicate columns")
        required = set(
            ERROR_OBSERVATION_FIELDS if error_aggregate else MONITOR_EVIDENCE_FIELDS
        )
        expected_fields = list(
            ERROR_OBSERVATION_FIELDS if error_aggregate else MONITOR_EVIDENCE_FIELDS
        )
        if not error_aggregate and chain == "rsk":
            required.update(RSK_SIDECAR_EXPORT_FIELDS)
            expected_fields.extend(RSK_SIDECAR_EXPORT_FIELDS)
        missing = required - set(fieldnames)
        if missing:
            raise ValueError(
                f"{path}: missing monitor-evidence fields: "
                + ", ".join(sorted(missing))
            )
        if fieldnames != expected_fields:
            raise ValueError(
                f"{path}: monitor-evidence header must exactly match the {chain} schema"
            )
        for row_number, row in enumerate(reader, start=2):
            if None in row or any(value is None for value in row.values()):
                raise ValueError(
                    f"{path}:{row_number}: monitor-evidence row does not match "
                    "the schema width"
                )
            row_chain = row.get("chain") or ""
            if error_aggregate:
                if row_chain not in CHAIN_SPECS:
                    raise ValueError(
                        f"{path}:{row_number}: error-observation row has "
                        f"unsupported chain {row_chain!r}"
                    )
                contract_chain = row_chain
            elif row_chain != chain:
                raise ValueError(
                    f"{path}:{row_number}: row chain {row_chain!r} does not match {chain!r}"
                )
            else:
                contract_chain = chain
            row_scope = (row.get("artifact_scope") or "").strip()
            if isinstance(expected_artifact_scope, str):
                allowed_scopes = (
                    {expected_artifact_scope} if expected_artifact_scope else set()
                )
            else:
                allowed_scopes = {scope for scope in expected_artifact_scope if scope}
            if allowed_scopes and row_scope not in allowed_scopes:
                raise ValueError(
                    f"{path}:{row_number}: artifact scope disagrees with "
                    f"the publication contract ({sorted(allowed_scopes)!r})"
                )
            raw_classification = row.get("classification") or ""
            classification = raw_classification.strip().lower()
            raw_status = row.get("validation_status") or ""
            status = raw_status.strip()
            if raw_classification != classification:
                raise ValueError(
                    f"{path}:{row_number}: classification vocabulary is not exact"
                )
            if raw_status != status:
                raise ValueError(
                    f"{path}:{row_number}: validation_status vocabulary is not exact"
                )
            raw_bucket = row.get("btc_stale_relevance") or ""
            raw_reason = row.get("relevance_reason") or ""
            bucket = raw_bucket.strip()
            reason = raw_reason.strip()
            if raw_bucket != bucket or raw_reason != reason:
                raise ValueError(
                    f"{path}:{row_number}: relevance vocabulary is not exact"
                )
            raw_btc_height = row.get("btc_height") or ""
            if raw_btc_height and (
                raw_btc_height != raw_btc_height.strip()
                or not raw_btc_height.isascii()
                or not raw_btc_height.isdigit()
                or str(int(raw_btc_height)) != raw_btc_height
            ):
                raise ValueError(
                    f"{path}:{row_number}: btc_height must be blank or an "
                    "exact unpadded non-negative decimal"
                )
            btc_height = int(raw_btc_height) if raw_btc_height else None
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
            raw_child_height = row.get("child_height") or ""
            if contract_chain == _DESCENDANT_PARENT_VERDICTS_CHAIN and (
                raw_child_height or any(child_bundle.values())
            ):
                raise ValueError(
                    f"{path}:{row_number}: stale-descendant parent verdict must "
                    "not carry child witness fields"
                )
            if raw_child_height and (
                raw_child_height != raw_child_height.strip()
                or not raw_child_height.isascii()
                or not raw_child_height.isdigit()
                or str(int(raw_child_height)) != raw_child_height
            ):
                raise ValueError(
                    f"{path}:{row_number}: child_height must be blank or an "
                    "exact non-negative integer"
                )
            child_height = int(raw_child_height) if raw_child_height else None
            spec = CHAIN_SPECS.get(contract_chain)
            if contract_chain in HISTORICAL_CHILD_HEADER_CHAINS:
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
            child_hash = child_bundle["child_block_hash"].lower()
            if child_height is not None and is_hash(child_hash):
                event_identity = (contract_chain, child_height, child_hash)
                event_category = _published_category(row) or classification
                previous_category = event_categories.get(event_identity)
                if previous_category is not None:
                    if previous_category == event_category:
                        detail = f"repeats the {event_category} category"
                    else:
                        detail = (
                            f"appears in both {previous_category} and {event_category}"
                        )
                    raise ValueError(
                        f"{path}:{row_number}: one authenticated child event {detail}"
                    )
                event_categories[event_identity] = event_category
            if (
                contract_chain in CHILD_IDENTITY_REQUIRED_CHAINS
                and classification != "canonical"
            ):
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
                if btc_height is None or btc_height < 0:
                    raise ValueError(
                        f"{path}:{row_number}: {classification} row lacks a "
                        "nonnegative Bitcoin height"
                    )
                # Ordinary descendant artifacts are one row per authenticated
                # child event; ``event_categories`` enforces that identity above.
                if (
                    classification == "stale"
                    or contract_chain == _DESCENDANT_PARENT_VERDICTS_CHAIN
                ):
                    stale_identity = (btc_height, parent_hash)
                    if stale_identity in stale_identities:
                        raise ValueError(
                            f"{path}:{row_number}: duplicate {classification} "
                            f"identity {stale_identity!r}"
                        )
                    stale_identities.add(stale_identity)
            requires_expected_nbits = classification == "stale" or (
                classification == "stale_descendant"
                and (
                    contract_chain == _DESCENDANT_PARENT_VERDICTS_CHAIN
                    or (row.get("artifact_scope") or "").strip()
                    == "stale_descendant_parent_verdicts"
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
                if (row.get("rejection_reason") or "").strip():
                    raise ValueError(
                        f"{path}:{row_number}: accepted {classification} row has a "
                        "rejection_reason"
                    )
            elif classification == "stale_descendant":
                expected_nbits = row.get("expected_nbits") or ""
                if expected_nbits and (
                    len(expected_nbits) != 8
                    or expected_nbits != expected_nbits.lower()
                    or any(char not in "0123456789abcdef" for char in expected_nbits)
                    or expected_nbits != parsed_header["bits"]
                ):
                    raise ValueError(
                        f"{path}:{row_number}: stale descendant row has invalid "
                        "retained expected_nbits"
                    )
                if (row.get("rejection_reason") or "").strip():
                    raise ValueError(
                        f"{path}:{row_number}: accepted stale descendant row has a "
                        "rejection_reason"
                    )
            elif classification == "error_block":
                expected_nbits = row.get("expected_nbits") or ""
                if (
                    len(expected_nbits) != 8
                    or expected_nbits != expected_nbits.lower()
                    or any(char not in "0123456789abcdef" for char in expected_nbits)
                ):
                    raise ValueError(
                        f"{path}:{row_number}: error block has invalid expected_nbits"
                    )
                if not (row.get("rejection_reason") or "").strip():
                    raise ValueError(
                        f"{path}:{row_number}: error block lacks a rejection_reason"
                    )
            elif any(
                (row.get(field) or "")
                for field in ("expected_nbits", "rejection_reason")
            ):
                raise ValueError(
                    f"{path}:{row_number}: non-stale row has stale-gate fields"
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
                if descendant_observations is None:
                    parents_path = data_dir / "stale_descendants.csv"
                    parent_rows = load_stale_descendant_parents(
                        parents_path,
                        data_dir=data_dir,
                    )
                    observation_rows = load_stale_descendant_observations(
                        data_dir / "stale_descendant_observations.csv",
                        parents_path=parents_path,
                        data_dir=data_dir,
                    )
                    descendant_parents = set(parent_rows)
                    descendant_observations = {
                        (
                            observation.chain,
                            observation.parent_height,
                            observation.parent_hash,
                            observation.child_height,
                            observation.child_hash,
                        )
                        for observation in observation_rows
                    }
                    exclusions_path = data_dir / "error-blocks" / "error_blocks.csv"
                    descendant_error_blocks = (
                        load_error_block_keys(exclusions_path)
                        if exclusions_path.is_file()
                        else set()
                    )
                parent_identity = (btc_height, parent_hash)
                if (
                    btc_height is None
                    or parent_identity not in (descendant_parents or set())
                    or parent_identity in (descendant_error_blocks or set())
                ):
                    raise ValueError(
                        f"{path}:{row_number}: stale descendant parent is not "
                        "authenticated by the accepted parent verdict"
                    )
                if contract_chain != _DESCENDANT_PARENT_VERDICTS_CHAIN and (
                    child_height is None
                    or (
                        contract_chain,
                        btc_height,
                        parent_hash,
                        child_height,
                        child_bundle["child_block_hash"],
                    )
                    not in descendant_observations
                ):
                    raise ValueError(
                        f"{path}:{row_number}: stale descendant witness is not "
                        "authenticated by the canonical observation ledger"
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
                if orphan_verdicts is not None:
                    expected_verdict = orphan_verdicts.get(parent_hash)
                    if (
                        expected_verdict is None
                        or expected_verdict.bucket != bucket
                        or expected_verdict.reason != reason
                    ):
                        raise ValueError(
                            f"{path}:{row_number}: orphan row disagrees with its "
                            "authenticated relevance verdict"
                        )
                    if (
                        bucket == "strict_btc_orphan"
                        and expected_verdict.btc_height != btc_height
                    ):
                        raise ValueError(
                            f"{path}:{row_number}: strict orphan Bitcoin height "
                            "disagrees with its authenticated relevance verdict"
                        )
                if bucket == "strict_btc_orphan":
                    if btc_height is None or btc_height < 0:
                        raise ValueError(
                            f"{path}:{row_number}: strict orphan row lacks a "
                            "nonnegative Bitcoin height"
                        )
                    assert btc_height is not None
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
                    scriptsig_hex = (row.get("coinbase_scriptsig_hex") or "").strip()
                    if scriptsig_hex:
                        try:
                            scriptsig = bytes.fromhex(scriptsig_hex)
                        except ValueError as exc:
                            raise ValueError(
                                f"{path}:{row_number}: strict orphan row has malformed "
                                "coinbase scriptSig evidence"
                            ) from exc
                        decoded_height = parse_bip34_height(scriptsig)
                    else:
                        source_row_number = int_or_none(
                            (row.get("source_row_number") or "").strip()
                        )
                        if (
                            not (row.get("source_kind") or "").strip()
                            or not (row.get("source_path") or "").strip()
                            or not (row.get("provenance") or "").strip()
                            or source_row_number is None
                            or source_row_number <= 0
                        ):
                            raise ValueError(
                                f"{path}:{row_number}: strict orphan row lacks "
                                "authenticated strict-height source evidence"
                            )
                        decoded_height = btc_height
                    if decoded_height != btc_height:
                        raise ValueError(
                            f"{path}:{row_number}: strict orphan row BIP34 height "
                            f"does not match btc_height ({decoded_height!r} != "
                            f"{btc_height})"
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
            elif classification == "error_block":
                if not error_aggregate:
                    raise ValueError(
                        f"{path}:{row_number}: ordinary artifact contains an error block"
                    )
                if btc_height is None or btc_height < 0:
                    raise ValueError(
                        f"{path}:{row_number}: error block lacks a nonnegative "
                        "Bitcoin height"
                    )
                if status != ERROR_OBSERVATION_STATUS:
                    raise ValueError(
                        f"{path}:{row_number}: error block has invalid status"
                    )
                if bucket or reason:
                    raise ValueError(
                        f"{path}:{row_number}: error block has non-empty relevance"
                    )
                counts["error_block"] += 1
            else:
                raise ValueError(
                    f"{path}:{row_number}: unsupported monitor classification"
                )
    counts["monitor_rows"] = (
        counts["error_block"]
        if error_aggregate
        else sum(counts[category] for category in _ORDINARY_MONITOR_CATEGORIES)
    )
    return counts


def validate_error_observation_publication(
    path: Path, *, data_dir: Path = DATA_DIR
) -> dict[str, int]:
    """Validate the canonical error ledger and return its source inventory."""
    _load_monitor_artifact_counts(
        path,
        ERROR_OBSERVATION_ARTIFACT,
        data_dir=data_dir,
        expected_artifact_scope=ERROR_OBSERVATION_SCOPE,
    )
    expected_rows, inventory = build_error_observation_rows(data_dir=data_dir)
    # Output claims may be enriched from the selected archive source rows.
    # Every field derived from the committed catalogue and witness ledger must
    # remain byte-for-byte canonical in the aggregate.
    canonical_fields = tuple(
        field
        for field in ERROR_OBSERVATION_FIELDS
        if field not in {"coinbase_outputs", "full_coinbase_hex"}
    )
    expected_by_identity = {
        (
            row["chain"],
            row["child_height"],
            row["child_block_hash"],
            row["btc_header_hash"],
        ): row
        for row in expected_rows
    }
    observed_identities: set[tuple[str, str, str, str]] = set()
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or ())
        if fieldnames != list(ERROR_OBSERVATION_FIELDS):
            raise ValueError(
                f"{path}: error-observation header must exactly match the "
                "34-column union schema"
            )
        for row_number, row in enumerate(reader, start=2):
            chain = row.get("chain") or ""
            outputs = row.get("coinbase_outputs") or ""
            full_coinbase_hex = row.get("full_coinbase_hex") or ""
            try:
                output_claims = parse_coinbase_output_claims(
                    outputs,
                    full_coinbase_hex,
                )
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{row_number}: malformed coinbase output evidence: {exc}"
                ) from exc
            if outputs != render_coinbase_output_claims(output_claims):
                raise ValueError(
                    f"{path}:{row_number}: coinbase output evidence is not canonical"
                )
            if full_coinbase_hex:
                if (
                    len(full_coinbase_hex) % 2
                    or full_coinbase_hex != full_coinbase_hex.lower()
                    or any(char not in "0123456789abcdef" for char in full_coinbase_hex)
                ):
                    raise ValueError(
                        f"{path}:{row_number}: full coinbase transaction must use "
                        "exact lowercase hex"
                    )
                try:
                    parsed_coinbase = parse_coinbase_tx(
                        bytes.fromhex(full_coinbase_hex)
                    )
                except ValueError as exc:
                    raise ValueError(
                        f"{path}:{row_number}: full coinbase transaction is not valid hex"
                    ) from exc
                if parsed_coinbase is None:
                    raise ValueError(
                        f"{path}:{row_number}: full coinbase transaction could not be parsed"
                    )
                scriptsig_hex = row.get("coinbase_scriptsig_hex") or ""
                if (
                    scriptsig_hex
                    and parsed_coinbase["scriptsig"].hex() != scriptsig_hex
                ):
                    raise ValueError(
                        f"{path}:{row_number}: full coinbase transaction disagrees "
                        "with coinbase_scriptsig_hex"
                    )
            identity = (
                chain,
                row.get("child_height") or "",
                row.get("child_block_hash") or "",
                row.get("btc_header_hash") or "",
            )
            if identity in observed_identities:
                raise ValueError(
                    f"{path}:{row_number}: duplicate canonical error-observation "
                    f"identity {identity!r}"
                )
            expected = expected_by_identity.get(identity)
            if expected is None:
                raise ValueError(
                    f"{path}:{row_number}: row is not an exact canonical "
                    f"error-observation identity {identity!r}"
                )
            observed_identities.add(identity)
            for field in canonical_fields:
                if (row.get(field) or "") != expected[field]:
                    raise ValueError(
                        f"{path}:{row_number}: {field} disagrees with the canonical "
                        "error-observation ledger"
                    )
            if chain == "rsk":
                validate_rsk_sidecar_cells(row, row_id=f"{path}:{row_number}")
                continue
            extra = [
                field
                for field in RSK_SIDECAR_EXPORT_FIELDS
                if (row.get(field) or "").strip()
            ]
            if extra:
                raise ValueError(
                    f"{path}:{row_number}: non-RSK error-observation row has "
                    f"sidecar values: {', '.join(extra)}"
                )
    missing = set(expected_by_identity) - observed_identities
    if missing:
        raise ValueError(
            f"{path}: error-observation aggregate is missing {len(missing)} "
            f"canonical ledger identities (first {min(missing)!r})"
        )
    source_chain_counts = inventory["source_chain_counts"]
    assert isinstance(source_chain_counts, dict)
    return source_chain_counts


_CATEGORY_SUCCESSORS = {
    "canonical": frozenset({"canonical", "stale", "stale_descendant"}),
    "weak_btc_orphan": frozenset(
        {"weak_btc_orphan", "strict_btc_orphan", "stale", "stale_descendant"}
    ),
    "strict_btc_orphan": frozenset({"strict_btc_orphan", "stale", "stale_descendant"}),
    "stale": frozenset({"stale", "stale_descendant"}),
    "stale_descendant": frozenset({"stale_descendant"}),
    "error_block": frozenset({"error_block"}),
}
_STICKY_OBSERVATION_FIELDS = (
    "btc_height",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_nonce",
    "btc_header_hex",
    "child_block_hash",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
    "coinbase_scriptsig_hex",
    "full_coinbase_hex",
    "expected_nbits",
    "rejection_reason",
    *RSK_SIDECAR_EXPORT_FIELDS,
)
_STICKY_OBSERVATION_FIELD_INDEX = {
    field: index for index, field in enumerate(_STICKY_OBSERVATION_FIELDS)
}


@dataclass(frozen=True, slots=True)
class PublishedObservation:
    """One final monitor observation independent of source location and row order."""

    chain: str
    parent_hash: str
    category: str
    source_kind: str
    source_path: str
    row_number: int
    fields: tuple[str, ...]
    child_height: str
    coinbase_outputs: str

    @property
    def anchor(self) -> tuple[str, str]:
        """Return the stable grouping key; multiplicity is preserved within it."""
        return self.chain, self.parent_hash

    @property
    def label(self) -> str:
        """Return a concise diagnostic identity for publication errors."""
        child = self.value("child_block_hash") or self.child_height
        suffix = f":{child}" if child else ""
        return f"{self.chain}:{self.parent_hash}:{self.category}{suffix}"

    def value(self, field: str) -> str:
        """Return one named sticky field without a per-row dictionary."""
        return self.fields[_STICKY_OBSERVATION_FIELD_INDEX[field]]

    def output_claims(self) -> tuple[CoinbaseOutputClaim, ...]:
        """Decode the canonical compact output representation on demand."""
        return _cached_output_claims(
            self.coinbase_outputs,
            self.value("full_coinbase_hex"),
        )


@lru_cache(maxsize=4096)
def _cached_output_claims(
    outputs: str,
    full_coinbase_hex: str,
) -> tuple[CoinbaseOutputClaim, ...]:
    """Bound repeated semantic parsing without retaining the whole corpus."""
    return parse_coinbase_output_claims(outputs, full_coinbase_hex)


def _published_category(row: dict[str, str]) -> str | None:
    """Return the explicit final-state category encoded by one monitor row."""
    classification = (row.get("classification") or "").strip().lower()
    bucket = (row.get("btc_stale_relevance") or "").strip()
    if classification == "error_block":
        return "error_block"
    if classification in {"canonical", "stale", "stale_descendant"}:
        return classification
    if classification == "unknown" and bucket in {
        "strict_btc_orphan",
        "weak_btc_orphan",
    }:
        return bucket
    return None


def _published_observation(
    row: dict[str, str],
    *,
    chain: str,
    path: Path,
    row_number: int,
) -> PublishedObservation | None:
    """Decode and validate the semantic identity/evidence cells of one row."""
    category = _published_category(row)
    if category is None:
        return None
    parent_hash = (row.get("btc_header_hash") or "").strip().lower()
    if not is_hash(parent_hash):
        raise ValueError(f"{path}:{row_number}: final row lacks a valid parent hash")
    raw_height = (row.get("btc_height") or "").strip()
    height = int_or_none(raw_height)
    if raw_height and (height is None or height < 0):
        raise ValueError(
            f"{path}:{row_number}: final row has an invalid Bitcoin height"
        )
    raw_child_height = (row.get("child_height") or "").strip()
    child_height = int_or_none(raw_child_height)
    if raw_child_height and (child_height is None or child_height < 0):
        raise ValueError(f"{path}:{row_number}: final row has an invalid child height")
    try:
        output_claims = parse_coinbase_output_claims(
            row.get("coinbase_outputs") or "",
            row.get("full_coinbase_hex") or "",
        )
    except ValueError as exc:
        raise ValueError(
            f"{path}:{row_number}: malformed coinbase output evidence: {exc}"
        ) from exc
    fields = tuple(
        (row.get(field) or "").strip() for field in _STICKY_OBSERVATION_FIELDS
    )
    return PublishedObservation(
        chain=chain,
        parent_hash=parent_hash,
        category=category,
        source_kind=(row.get("source_kind") or "").strip(),
        source_path=(row.get("source_path") or "").strip(),
        row_number=row_number,
        fields=fields,
        child_height=raw_child_height,
        coinbase_outputs=render_coinbase_output_claims(output_claims),
    )


def _load_published_observation_groups(
    output_dir: Path,
    *,
    ordinary_chains: frozenset[str] | None = None,
) -> dict[tuple[str, str], tuple[PublishedObservation, ...]]:
    """Load selected chains into one strict final observation model."""
    error_path = output_dir / f"{ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv"
    errors: list[PublishedObservation] = []
    error_hashes: set[str] = set()
    if error_path.is_file():
        with error_path.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), start=2):
                chain = (row.get("chain") or "").strip()
                observation = _published_observation(
                    row,
                    chain=chain,
                    path=error_path,
                    row_number=row_number,
                )
                if observation is None or observation.category != "error_block":
                    raise ValueError(
                        f"{error_path}:{row_number}: error aggregate row is not final"
                    )
                error_hashes.add(observation.parent_hash)
                if ordinary_chains is None or chain in ordinary_chains:
                    errors.append(observation)

    ordinary: list[PublishedObservation] = []
    error_overlaps: list[str] = []
    for path in sorted(output_dir.glob("*_monitor_evidence.csv")):
        chain = path.name.removesuffix("_monitor_evidence.csv")
        if chain == ERROR_OBSERVATION_ARTIFACT:
            continue
        if ordinary_chains is not None and chain not in ordinary_chains:
            continue
        with path.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), start=2):
                observation = _published_observation(
                    row,
                    chain=chain,
                    path=path,
                    row_number=row_number,
                )
                if observation is None:
                    continue
                if observation.parent_hash in error_hashes:
                    error_overlaps.append(observation.label)
                    continue
                ordinary.append(observation)
    if error_overlaps:
        raise ValueError(
            "error parents remain in ordinary evidence artifacts "
            f"({len(error_overlaps)}; first {error_overlaps[0]})"
        )

    # Error parents have two interfaces: one row per authenticated child
    # witness, and one catalogue-level parent verdict. The synthetic reserved
    # chain keeps the parent claim comparable if a stale-descendant parent is
    # later proven consensus-invalid and leaves the parent-verdict artifact.
    synthetic_errors: list[PublishedObservation] = []
    by_error_parent: dict[str, list[PublishedObservation]] = {}
    for observation in errors:
        siblings = by_error_parent.setdefault(observation.parent_hash, [])
        previous = siblings[0] if siblings else None
        siblings.append(observation)
        if previous is None:
            continue
        for field in (
            "btc_height",
            "btc_prev_hash",
            "btc_time",
            "btc_bits",
            "btc_nonce",
            "btc_header_hex",
            "coinbase_scriptsig_hex",
            "expected_nbits",
            "rejection_reason",
        ):
            if previous.value(field) != observation.value(field):
                raise ValueError(
                    "error observations disagree on parent evidence for "
                    f"{observation.parent_hash}: {field}"
                )
    include_synthetic_errors = (
        ordinary_chains is None or _DESCENDANT_PARENT_VERDICTS_CHAIN in ordinary_chains
    )
    for parent_hash, observations in by_error_parent.items():
        if not include_synthetic_errors:
            continue
        observation = observations[0]
        parent_fields = list(observation.fields)
        for field in (
            "child_block_hash",
            "child_header_hex",
            "child_block_time",
            "child_nbits",
            *RSK_SIDECAR_EXPORT_FIELDS,
        ):
            parent_fields[_STICKY_OBSERVATION_FIELD_INDEX[field]] = ""
        merged_output_claims = merge_coinbase_output_claim_sets(
            *(item.output_claims() for item in observations)
        )
        synthetic_errors.append(
            PublishedObservation(
                chain=_DESCENDANT_PARENT_VERDICTS_CHAIN,
                parent_hash=parent_hash,
                category="error_block",
                source_kind="error_block_catalogue",
                source_path=observation.source_path,
                row_number=observation.row_number,
                fields=tuple(parent_fields),
                child_height="",
                coinbase_outputs=render_coinbase_output_claims(merged_output_claims),
            )
        )

    grouped: dict[tuple[str, str], list[PublishedObservation]] = {}
    for observation in (*ordinary, *errors, *synthetic_errors):
        grouped.setdefault(observation.anchor, []).append(observation)
    return {anchor: tuple(rows) for anchor, rows in grouped.items()}


def _expected_canonical_evidence_status(
    row: dict[str, str], canonical_count: int
) -> str:
    """Return the only canonical-coverage status valid for a count row."""
    source_kind = (row.get("source_kind") or "").strip()
    if source_kind == "missing":
        return "not_checked_missing_source"
    if source_kind in {
        "stale_descendant_parent_verdicts",
        "error_block_catalogue",
    }:
        return "not_applicable"
    if canonical_count > 0:
        return "canonical_retained"
    if source_kind == "validated_stales":
        return "canonical_rows_not_represented_stale_only_publication_path"
    return "no_canonical_rows_in_discovered_artifact"


def _child_height_is_sticky(observation: PublishedObservation) -> bool:
    """Return whether a published child-height cell is consensus-authenticated."""
    return (
        child_height_semantics_for_source(
            observation.chain,
            observation.source_kind,
        )
        != CHILD_HEIGHT_UNAUTHENTICATED_SCAN_ORDER
    )


def _observation_refinement(
    committed: PublishedObservation,
    staged: PublishedObservation,
) -> tuple[bool, str]:
    """Return whether `staged` monotonically refines one committed observation."""
    successors = _CATEGORY_SUCCESSORS[committed.category] | {"error_block"}
    if staged.category not in successors:
        return False, f"category {committed.category}->{staged.category}"
    for field in _STICKY_OBSERVATION_FIELDS:
        expected = committed.value(field)
        if expected and staged.value(field) != expected:
            return False, field
    committed_child_height = committed.child_height
    if (
        committed_child_height
        and _child_height_is_sticky(committed)
        and staged.child_height != committed_child_height
    ):
        return False, "child_height"
    if not coinbase_output_claims_refine(
        committed.output_claims(),
        staged.output_claims(),
    ):
        return False, "coinbase_outputs"
    return True, ""


def _authenticated_event_bundles(
    observations: tuple[PublishedObservation, ...],
) -> tuple[tuple[PublishedObservation, ...], ...]:
    """Bundle claims for one authenticated child event into one observation.

    Physical source rows are not publication multiplicity. Within one
    ``(chain, parent_hash)`` anchor, a valid child block hash identifies one
    logical event. Every claim for that event must refine into the same staged
    row. Rows without an authenticated child hash remain singleton claims.
    """
    by_child_hash: dict[str, list[PublishedObservation]] = {}
    bundles: list[tuple[PublishedObservation, ...]] = []
    for observation in observations:
        child_hash = observation.value("child_block_hash").lower()
        if not is_hash(child_hash):
            bundles.append((observation,))
            continue
        by_child_hash.setdefault(child_hash, []).append(observation)
    bundles.extend(tuple(rows) for rows in by_child_hash.values())
    return tuple(bundles)


def _maximum_refinement_matching(
    committed: tuple[PublishedObservation, ...],
    staged: tuple[PublishedObservation, ...],
) -> tuple[bool, str]:
    """Injectively match every committed logical event to one staged row."""
    committed_bundles = _authenticated_event_bundles(committed)
    edges: list[list[int]] = []
    reasons: list[list[str]] = []
    for expected_bundle in committed_bundles:
        compatible: list[int] = []
        rejected: list[str] = []
        for index, candidate in enumerate(staged):
            refinements = [
                _observation_refinement(expected, candidate)
                for expected in expected_bundle
            ]
            if all(accepted for accepted, _reason in refinements):
                compatible.append(index)
            else:
                rejected.append(
                    next(reason for accepted, reason in refinements if not accepted)
                )
        edges.append(compatible)
        reasons.append(rejected)
    # Sparse observations must claim candidates before broad observations.
    # The augmenting-path matcher then revisits earlier assignments, so a
    # greedy choice cannot consume the only candidate for a more specific row.
    order = sorted(range(len(committed_bundles)), key=lambda index: len(edges[index]))
    staged_to_committed: dict[int, int] = {}

    def assign(committed_index: int, seen: set[int]) -> bool:
        for staged_index in edges[committed_index]:
            if staged_index in seen:
                continue
            seen.add(staged_index)
            previous = staged_to_committed.get(staged_index)
            if previous is None or assign(previous, seen):
                staged_to_committed[staged_index] = committed_index
                return True
        return False

    for committed_index in order:
        if not assign(committed_index, set()):
            expected_bundle = committed_bundles[committed_index]
            expected = expected_bundle[0]
            if not staged:
                return False, f"missing {expected.label}"
            rejected = reasons[committed_index]
            detail = (
                Counter(rejected).most_common(1)[0][0] if rejected else "multiplicity"
            )
            return False, f"cannot refine {expected.label} ({detail})"
    return True, ""


def _validate_parent_category_exclusivity(output_dir: Path) -> None:
    """Require one explicit final category for each Bitcoin parent hash."""
    categories: dict[str, tuple[str, Path, int]] = {}
    for path in sorted(output_dir.glob("*_monitor_evidence.csv")):
        with path.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), start=2):
                category = _published_category(row)
                parent_hash = (row.get("btc_header_hash") or "").strip().lower()
                if category is None or not is_hash(parent_hash):
                    continue
                previous = categories.get(parent_hash)
                if previous is not None and previous[0] != category:
                    previous_category, previous_path, previous_row = previous
                    raise ValueError(
                        f"{path}:{row_number}: parent {parent_hash} appears in "
                        f"both {previous_category} ({previous_path}:{previous_row}) "
                        f"and {category}"
                    )
                categories[parent_hash] = (category, path, row_number)


def _validate_published_observation_floor(
    output_dir: Path,
    *,
    committed: dict[tuple[str, str], tuple[PublishedObservation, ...]] | None = None,
) -> None:
    """Reject any final observation deletion, substitution, or category downgrade."""
    if committed is None:
        chains = _published_observation_chains(MONITOR_OUTPUT_DIR) | (
            _published_observation_chains(output_dir)
        )
        problems: list[str] = []
        for chain in sorted(chains):
            selected = frozenset({chain})
            committed_chain = _load_published_observation_groups(
                MONITOR_OUTPUT_DIR,
                ordinary_chains=selected,
            )
            staged_chain = _load_published_observation_groups(
                output_dir,
                ordinary_chains=selected,
            )
            problems.extend(
                _published_observation_floor_problems(
                    committed_chain,
                    staged_chain,
                )
            )
            if len(problems) >= 10:
                break
    else:
        staged = _load_published_observation_groups(
            output_dir,
        )
        problems = _published_observation_floor_problems(committed, staged)
    if problems:
        raise ValueError(
            "full rebuild degrades published observation evidence: "
            + "; ".join(problems[:10])
        )


def _published_observation_chains(output_dir: Path) -> set[str]:
    """Return ordinary and error-witness chains without loading row evidence."""
    chains = {
        path.name.removesuffix("_monitor_evidence.csv")
        for path in output_dir.glob("*_monitor_evidence.csv")
        if path.name != f"{ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv"
    }
    error_path = output_dir / f"{ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv"
    if error_path.is_file():
        with error_path.open(newline="") as handle:
            for row in csv.DictReader(handle):
                chain = (row.get("chain") or "").strip()
                if chain:
                    chains.add(chain)
        chains.add(_DESCENDANT_PARENT_VERDICTS_CHAIN)
    return chains


def _published_observation_floor_problems(
    committed: dict[tuple[str, str], tuple[PublishedObservation, ...]],
    staged: dict[tuple[str, str], tuple[PublishedObservation, ...]],
) -> list[str]:
    """Return semantic non-degradation failures for one bounded chain slice."""
    problems: list[str] = []
    for anchor, expected in committed.items():
        candidates = staged.get(anchor, ())
        expected_bundles = _authenticated_event_bundles(expected)
        if len(candidates) < len(expected_bundles):
            problems.append(
                f"{anchor[0]}:{anchor[1]} multiplicity "
                f"{len(expected_bundles)}->{len(candidates)}"
            )
            continue
        matched, detail = _maximum_refinement_matching(expected, candidates)
        if not matched:
            problems.append(detail)
    return problems


def _canonical_source_path(value: str | Path, chain: str) -> str:
    """Normalize one source coordinate to the path below its chain directory."""
    path = Path(value)
    chain_indexes = [index for index, part in enumerate(path.parts) if part == chain]
    if chain_indexes:
        return Path(*path.parts[chain_indexes[-1] + 1 :]).as_posix()
    return path.name


class _UnknownIdentityDigest:
    """Order-independent streaming digest of an exact identity multiset."""

    __slots__ = ("count", "additive", "xor")

    def __init__(self) -> None:
        self.count = 0
        self.additive = 0
        self.xor = 0

    def add(self, identity: tuple[str, str, str, str]) -> None:
        token = hashlib.sha256("\x00".join(identity).encode()).digest()
        value = int.from_bytes(token, "big")
        self.count += 1
        self.additive = (self.additive + value) % (1 << 256)
        self.xor ^= value

    def update(self, other: _UnknownIdentityDigest) -> None:
        self.count += other.count
        self.additive = (self.additive + other.additive) % (1 << 256)
        self.xor ^= other.xor

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _UnknownIdentityDigest):
            return NotImplemented
        return (self.count, self.additive, self.xor) == (
            other.count,
            other.additive,
            other.xor,
        )


def _source_unknown_identity_digest(
    source: EvidenceSource,
    *,
    excluded_hashes: frozenset[str] | set[str] = frozenset(),
) -> _UnknownIdentityDigest:
    """Stream unknown/orphan identities from one selected classifier source."""
    digest = _UnknownIdentityDigest()
    if source.path is None:
        return digest
    with source.path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        for row_number, row in enumerate(reader, start=2):
            classification = (
                row.get("classification") or ""
            ).strip().lower() or "unknown"
            if classification not in {"unknown", "orphan"}:
                continue
            raw_block_hash = ""
            for column in ("btc_header_hash", "btc_hash", "hash"):
                if column in fieldnames:
                    raw_block_hash = row.get(column) or ""
                    break
            block_hash = raw_block_hash.strip()
            if block_hash:
                if (
                    raw_block_hash != block_hash
                    or block_hash != block_hash.lower()
                    or not is_hash(block_hash)
                ):
                    raise ValueError(
                        f"{source.path}:{row_number}: unknown source row has a "
                        "malformed or non-lowercase Bitcoin parent hash"
                    )
            else:
                for column in ("btc_header_hex", "header"):
                    if column in fieldnames:
                        block_hash = parse_header_fields(row.get(column) or "").get(
                            "hash", ""
                        )
                        break
                if not is_hash(block_hash):
                    raise ValueError(
                        f"{source.path}:{row_number}: unknown source row has a "
                        "malformed or missing Bitcoin parent hash"
                    )
            if block_hash in excluded_hashes:
                continue
            digest.add(
                (
                    source.chain,
                    _canonical_source_path(source.path, source.chain),
                    str(row_number),
                    block_hash,
                )
            )
    return digest


def _selected_unknown_identity_digests(
    sources: dict[str, EvidenceSource],
    unknown_sources: dict[str, EvidenceSource],
    *,
    excluded_hashes: frozenset[str] | set[str] = frozenset(),
) -> dict[str, _UnknownIdentityDigest]:
    """Digest every unknown observation selected for the current full build."""
    identities: dict[str, _UnknownIdentityDigest] = {}
    for chain in sorted(set(sources) | set(unknown_sources)):
        combined = _UnknownIdentityDigest()
        for source in (sources.get(chain), unknown_sources.get(chain)):
            if (
                source is None
                or source.path is None
                or source.source_kind != "full_inventory"
            ):
                continue
            combined.update(
                _source_unknown_identity_digest(
                    source,
                    excluded_hashes=excluded_hashes,
                )
            )
        if combined.count:
            identities[chain] = combined
    return identities


def _assessed_unknown_identity_digests(
    path: Path,
) -> dict[str, _UnknownIdentityDigest]:
    """Digest exact unknown/orphan source coordinates assessed by a classifier run."""
    identities: dict[str, _UnknownIdentityDigest] = {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        missing = _UNKNOWN_IDENTITY_FIELDS - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"{path}: relevance inventory lacks exact source-identity fields: "
                + ", ".join(sorted(missing))
            )
        for row_number, row in enumerate(reader, start=2):
            classification = (
                row.get("source_classification") or ""
            ).strip().lower() or "unknown"
            if classification not in {"unknown", "orphan"}:
                continue
            chain = (row.get("chain") or "").strip()
            source_path = (row.get("source_path") or "").strip()
            raw_source_row = (row.get("source_row_number") or "").strip()
            try:
                source_row = int(raw_source_row)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{row_number}: unknown assessment has an invalid "
                    "physical source row"
                ) from exc
            if (
                not chain
                or not source_path
                or source_row < 2
                or str(source_row) != raw_source_row
            ):
                raise ValueError(
                    f"{path}:{row_number}: unknown assessment lacks an exact "
                    "chain-relative physical source coordinate"
                )
            raw_block_hash = row.get("btc_header_hash") or ""
            block_hash = raw_block_hash.strip()
            if (
                raw_block_hash != block_hash
                or block_hash != block_hash.lower()
                or not is_hash(block_hash)
            ):
                raise ValueError(
                    f"{path}:{row_number}: unknown assessment has a malformed or "
                    "non-lowercase Bitcoin parent hash"
                )
            identities.setdefault(chain, _UnknownIdentityDigest()).add(
                (
                    chain,
                    _canonical_source_path(source_path, chain),
                    raw_source_row,
                    block_hash,
                )
            )
    return identities


def _validate_unknown_inventory_assessment(
    sources: dict[str, EvidenceSource],
    unknown_sources: dict[str, EvidenceSource],
    relevance_inventory: Path,
    *,
    excluded_hashes: frozenset[str] | set[str] = frozenset(),
) -> None:
    """Require the relevance inventory to assess the selected unknown multiset."""
    expected = _selected_unknown_identity_digests(
        sources,
        unknown_sources,
        excluded_hashes=excluded_hashes,
    )
    assessed = _assessed_unknown_identity_digests(relevance_inventory)
    empty = _UnknownIdentityDigest()
    mismatches: list[str] = []
    for chain in sorted(set(expected) | set(assessed)):
        source_digest = expected.get(chain, empty)
        assessed_digest = assessed.get(chain, empty)
        if source_digest != assessed_digest:
            mismatches.append(
                f"{chain} selected={source_digest.count} assessed={assessed_digest.count}"
            )
    if mismatches:
        raise ValueError(
            "relevance inventory unknown identities do not match the selected "
            "full/unknown sources (" + "; ".join(mismatches) + ")"
        )


def _load_publication_baseline(
    baseline_dir: Path,
) -> dict[str, dict[str, str]]:
    """Validate and load the committed publication metadata baseline."""
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
    return rows


def validate_publication_inputs(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    baseline_dir: Path = MONITOR_OUTPUT_DIR,
) -> None:
    """Reject incomplete inputs before starting the full publication build."""
    if args.allow_partial:
        if args.output_dir.resolve() == MONITOR_OUTPUT_DIR.resolve():
            parser.error(
                "--allow-partial requires an explicit disposable --output-dir; "
                "refusing to overwrite committed monitor evidence"
            )
        return

    problems: list[str] = []
    try:
        baseline = _load_publication_baseline(baseline_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        baseline = {}
        problems.append(str(exc))

    archive_dirs = [path.expanduser() for path in args.chain_archive_dirs]
    if not archive_dirs:
        problems.append("at least one --chain-archive-dir is required")
        sources: dict[str, EvidenceSource] = {}
        canonical: dict[str, EvidenceSource] = {}
        unknown: dict[str, EvidenceSource] = {}
    else:
        missing_dirs = [str(path) for path in archive_dirs if not path.is_dir()]
        if missing_dirs:
            problems.append(
                "chain archive directories do not exist: " + ", ".join(missing_dirs)
            )
            sources = {}
            canonical = {}
            unknown = {}
        else:
            sources = discover_evidence_sources(args.data_dir, archive_dirs)
            canonical = discover_canonical_sources(args.data_dir, archive_dirs)
            unknown = discover_unknown_sources(args.data_dir, archive_dirs)

    error_blocks_path = args.data_dir / "error-blocks" / "error_blocks.csv"
    invalid_hashes: set[str] = set()
    if error_blocks_path.is_file():
        try:
            invalid_hashes = {
                block_hash
                for _height, block_hash in load_error_block_keys(error_blocks_path)
            }
        except (OSError, ValueError) as exc:
            problems.append(str(exc))

    if args.relevance_inventory is None or not args.relevance_inventory.is_file():
        problems.append("--relevance-inventory must name an existing CSV")
    else:
        try:
            load_orphan_relevance_verdicts(args.relevance_inventory)
            _validate_unknown_inventory_assessment(
                sources,
                unknown,
                args.relevance_inventory,
                excluded_hashes=invalid_hashes,
            )
        except (OSError, ValueError) as exc:
            problems.append(str(exc))
    if args.skip_canonical:
        problems.append("--skip-canonical is a partial-build option")

    try:
        parents_path = args.data_dir / "stale_descendants.csv"
        parents = load_stale_descendant_parents(
            parents_path,
            data_dir=args.data_dir,
        )
        load_stale_descendant_observations(
            args.data_dir / "stale_descendant_observations.csv",
            parents_path=parents_path,
            data_dir=args.data_dir,
        )
    except (OSError, ValueError) as exc:
        parents = {}
        problems.append(str(exc))
    if error_blocks_path.is_file() and parents:
        overlap = invalid_hashes & {parent.block_hash for parent in parents.values()}
        if overlap:
            problems.append(
                "accepted stale descendants overlap the error catalogue "
                f"({len(overlap)}; first {min(overlap)})"
            )

    for chain, baseline_row in baseline.items():
        if chain in {
            ERROR_OBSERVATION_ARTIFACT,
            _DESCENDANT_PARENT_VERDICTS_CHAIN,
        }:
            continue
        expected_rows = int_or_none(baseline_row.get("source_rows") or "0") or 0
        discovered = [sources.get(chain), canonical.get(chain), unknown.get(chain)]
        if expected_rows and not any(
            source is not None and source.path is not None for source in discovered
        ):
            problems.append(f"{chain} lacks a complete publication evidence source")
    try:
        validate_error_module(
            catalogue_path=error_blocks_path,
            ledger_path=error_blocks_path.parent / ERROR_OBSERVATION_LEDGER,
            nbits_by_epoch_path=(
                args.data_dir / "bitcoin-epoch-reference" / "btc_nbits_by_epoch.json"
            ),
            mtp_context_path=error_blocks_path.parent / "mtp_context.csv",
        )
        build_error_observation_rows(data_dir=args.data_dir)
    except (OSError, ValueError) as exc:
        problems.append(str(exc))

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


class _PublicationRollbackError(RuntimeError):
    """A failed publication whose rollback needs operator recovery."""

    def __init__(
        self,
        recovery_path: Path,
        rollback_failures: list[str],
    ) -> None:
        self.recovery_path = recovery_path
        detail = "; ".join(rollback_failures)
        super().__init__(
            "monitor publication rollback was incomplete; recovery files "
            f"preserved at {recovery_path}: {detail}"
        )


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
    except BaseException as publication_error:
        rollback_failures: list[str] = []
        for destination, staged_path in reversed(installed):
            if destination.exists() or destination.is_symlink():
                try:
                    os.replace(destination, staged_path)
                except BaseException as exc:
                    rollback_failures.append(
                        f"could not return {destination} to {staged_path} "
                        f"({type(exc).__name__}: {exc})"
                    )
        for backup, destination in reversed(moved_previous):
            if backup.exists() or backup.is_symlink():
                try:
                    os.replace(backup, destination)
                except BaseException as exc:
                    rollback_failures.append(
                        f"could not restore {backup} to {destination} "
                        f"({type(exc).__name__}: {exc})"
                    )
        if (
            not output_preexisted
            and output_dir.exists()
            and not any(output_dir.iterdir())
        ):
            try:
                output_dir.rmdir()
            except BaseException as exc:
                rollback_failures.append(
                    f"could not remove empty output directory {output_dir} "
                    f"({type(exc).__name__}: {exc})"
                )
        if rollback_failures:
            raise _PublicationRollbackError(
                staging_dir.parent.resolve(), rollback_failures
            ) from publication_error
        raise


def _load_monitor_count_rows(path: Path) -> list[dict[str, str]]:
    """Load one canonical counts CSV with exact nonnegative integer cells."""
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        if list(reader.fieldnames or ()) != list(MONITOR_COUNT_FIELDS):
            raise ValueError(f"{path}: counts header is not canonical")
        rows: list[dict[str, str]] = []
        chains: set[str] = set()
        for row_number, row in enumerate(reader, start=2):
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"{path}:{row_number}: malformed count row")
            chain = row["chain"]
            if not chain or chain != chain.strip() or chain in chains:
                raise ValueError(
                    f"{path}:{row_number}: missing or duplicate chain metadata"
                )
            chains.add(chain)
            for field in _MANIFEST_COUNT_FIELDS:
                raw = row[field]
                try:
                    value = int(raw)
                except ValueError as exc:
                    raise ValueError(
                        f"{path}:{row_number}: {chain} {field} is not a "
                        "canonical nonnegative integer"
                    ) from exc
                if value < 0 or str(value) != raw:
                    raise ValueError(
                        f"{path}:{row_number}: {chain} {field} is not a "
                        "canonical nonnegative integer"
                    )
            rows.append(row)
    if not rows:
        raise ValueError(f"{path}: publication counts are empty")
    return rows


def _logical_source_coverage(
    output_dir: Path,
    *,
    count_rows: list[dict[str, str]] | None = None,
) -> Counter[str]:
    """Count per-child source coverage across ordinary and error interfaces."""
    if count_rows is None:
        count_rows = _load_monitor_count_rows(output_dir / PUBLICATION_COUNTS.name)
    coverage: Counter[str] = Counter()
    for row in count_rows:
        chain = row["chain"]
        if chain in {
            ERROR_OBSERVATION_ARTIFACT,
            _DESCENDANT_PARENT_VERDICTS_CHAIN,
        }:
            continue
        coverage[chain] += int(row["source_rows"])

    error_path = output_dir / f"{ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv"
    if not error_path.is_file():
        return coverage
    with error_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        if "chain" not in (reader.fieldnames or ()):
            raise ValueError(f"{error_path}: error aggregate lacks a chain column")
        for row_number, row in enumerate(reader, start=2):
            chain = (row.get("chain") or "").strip()
            if not chain:
                raise ValueError(f"{error_path}:{row_number}: error row lacks a chain")
            if chain == _DESCENDANT_PARENT_VERDICTS_CHAIN:
                continue
            coverage[chain] += 1
    return coverage


def _validate_logical_source_coverage_floor(
    staging_dir: Path,
    committed_dir: Path,
    *,
    staged_count_rows: list[dict[str, str]] | None = None,
) -> None:
    """Reject source loss while permitting an ordinary-to-error category move."""
    committed = _logical_source_coverage(committed_dir)
    staged = _logical_source_coverage(
        staging_dir,
        count_rows=staged_count_rows,
    )
    losses = [
        f"{chain} {staged[chain]}<{minimum}"
        for chain, minimum in sorted(committed.items())
        if staged[chain] < minimum
    ]
    if losses:
        raise ValueError(
            "full rebuild loses logical per-chain source coverage: " + "; ".join(losses)
        )


def _validate_global_child_event_uniqueness(staging_dir: Path) -> None:
    """Assign each authenticated child event to one staged artifact location."""
    events: dict[tuple[str, int, str], tuple[str, str]] = {}
    for artifact in sorted(staging_dir.glob("*_monitor_evidence.csv")):
        with artifact.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), start=2):
                child_height = int_or_none((row.get("child_height") or "").strip())
                child_hash = normalize_hash(row.get("child_block_hash"))
                if child_height is None or child_height < 0 or not is_hash(child_hash):
                    continue
                chain = (row.get("chain") or "").strip()
                parent_hash = normalize_hash(row.get("btc_header_hash"))
                identity = (chain, child_height, child_hash)
                location = f"{artifact.name}:{row_number}"
                previous = events.get(identity)
                if previous is None:
                    events[identity] = (parent_hash, location)
                    continue
                previous_parent, previous_location = previous
                if previous_parent == parent_hash:
                    detail = f"repeats in {previous_location} and {location}"
                else:
                    detail = (
                        "maps to different Bitcoin parents "
                        f"{previous_parent} and {parent_hash} in "
                        f"{previous_location} and {location}"
                    )
                raise ValueError(f"authenticated child event {identity!r} {detail}")


def _validate_staged_publication(
    staging_dir: Path,
    *,
    data_dir: Path,
    relevance_inventory: Path | None = None,
) -> None:
    """Validate one coherent full snapshot before any destination is replaced."""
    orphan_verdicts = (
        load_orphan_relevance_verdicts(relevance_inventory)
        if relevance_inventory is not None
        else {}
    )
    counts_path = staging_dir / PUBLICATION_COUNTS.name
    manifest_path = staging_dir / PUBLICATION_MANIFEST.name
    if not counts_path.is_file() or not manifest_path.is_file():
        raise ValueError("staged publication lacks counts or manifest")
    count_rows = _load_monitor_count_rows(counts_path)
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict):
        raise ValueError(f"{manifest_path}: manifest must be a JSON object")
    if set(manifest) != _MANIFEST_TOP_LEVEL_FIELDS:
        missing = sorted(_MANIFEST_TOP_LEVEL_FIELDS - set(manifest))
        extra = sorted(set(manifest) - _MANIFEST_TOP_LEVEL_FIELDS)
        raise ValueError(
            f"{manifest_path}: manifest top-level metadata is not exact "
            f"(missing={missing}, extra={extra})"
        )
    logical_root = manifest.get("output_dir")
    if (
        not isinstance(logical_root, str)
        or not logical_root
        or logical_root.endswith("/")
    ):
        raise ValueError(f"{manifest_path}: output_dir is not a canonical logical path")
    expected_counts_path = f"{logical_root}/{PUBLICATION_COUNTS.name}"
    expected_manifest_path = f"{logical_root}/{PUBLICATION_MANIFEST.name}"
    if (
        manifest.get("counts_csv") != expected_counts_path
        or manifest.get("manifest_json") != expected_manifest_path
    ):
        raise ValueError(f"{manifest_path}: top-level logical paths are inconsistent")
    if manifest.get("validation_contracts") != MONITOR_VALIDATION_CONTRACTS:
        raise ValueError(f"{manifest_path}: validation contracts are not canonical")
    expected_relevance = (
        REPORTED_RELEVANCE_INVENTORY if relevance_inventory is not None else "missing"
    )
    if manifest.get("relevance_inventory") != expected_relevance:
        raise ValueError(
            f"{manifest_path}: relevance inventory metadata is not canonical"
        )
    if type(manifest.get("strict_weak_verdicts_loaded")) is not int or manifest[
        "strict_weak_verdicts_loaded"
    ] != len(orphan_verdicts):
        raise ValueError(
            f"{manifest_path}: strict/weak verdict cardinality does not match "
            "the relevance inventory"
        )
    manifest_observation_chain_counts = manifest.get("observation_chain_counts")
    if (
        not isinstance(manifest_observation_chain_counts, dict)
        or set(manifest_observation_chain_counts) != _OBSERVATION_CHAIN_COUNT_ARTIFACTS
        or any(
            not isinstance(chain_counts, dict)
            or any(
                not isinstance(chain, str) or type(count) is not int or count < 0
                for chain, count in chain_counts.items()
            )
            for chain_counts in manifest_observation_chain_counts.values()
        )
    ):
        raise ValueError(f"{manifest_path}: observation chain inventory is invalid")
    descendant_observations = load_stale_descendant_observations(
        data_dir / "stale_descendant_observations.csv",
        parents_path=data_dir / "stale_descendants.csv",
        data_dir=data_dir,
    )
    observed_observation_chain_counts: dict[str, dict[str, int]] = {
        STALE_DESCENDANT_OBSERVATION_ARTIFACT: dict(
            sorted(Counter(row.chain for row in descendant_observations).items())
        )
    }

    manifest_counts = manifest.get("counts")
    if not isinstance(manifest_counts, list):
        raise ValueError(f"{manifest_path}: counts do not match the CSV")
    manifest_chains: list[str] = []
    for index, manifest_row in enumerate(manifest_counts, start=1):
        if not isinstance(manifest_row, dict) or set(manifest_row) != set(
            MONITOR_COUNT_FIELDS
        ):
            raise ValueError(
                f"{manifest_path}: count metadata row {index} is not exact"
            )
        chain = manifest_row.get("chain")
        if not isinstance(chain, str) or not chain:
            raise ValueError(
                f"{manifest_path}: count metadata row {index} lacks a chain"
            )
        manifest_chains.append(chain)
    count_chains = [row["chain"] for row in count_rows]
    if manifest_chains != count_chains or len(manifest_chains) != len(
        set(manifest_chains)
    ):
        raise ValueError(
            f"{manifest_path}: counts have missing, duplicate, extra, or reordered chains"
        )
    manifest_by_chain = {
        row["chain"]: row for row in manifest_counts if isinstance(row, dict)
    }
    for row in count_rows:
        chain = row["chain"]
        manifest_row = manifest_by_chain[chain]
        for field in MONITOR_COUNT_FIELDS:
            if field in _MANIFEST_COUNT_FIELDS:
                manifest_value = manifest_row[field]
                if type(manifest_value) is not int or manifest_value != int(row[field]):
                    raise ValueError(
                        f"{manifest_path}: {chain} {field} does not exactly match "
                        "the counts CSV"
                    )
            elif (
                type(manifest_row[field]) is not str
                or manifest_row[field] != row[field]
            ):
                raise ValueError(
                    f"{manifest_path}: {chain} {field} does not exactly match "
                    "the counts CSV"
                )

    expected_artifacts: dict[str, str] = {}
    for row in count_rows:
        chain = row["chain"]
        expected_path = f"{logical_root}/{chain}_monitor_evidence.csv"
        if row["artifact_path"] != expected_path:
            raise ValueError(
                f"{counts_path}: {chain} artifact path is not the canonical "
                "logical publication path"
            )
        expected_artifacts[chain] = expected_path
    artifacts = manifest.get("artifacts")
    if artifacts != expected_artifacts:
        raise ValueError(
            f"{manifest_path}: artifact map has missing, extra, or mismatched entries"
        )
    expected_artifact_names = {
        f"{chain}_monitor_evidence.csv" for chain in count_chains
    }
    actual_artifact_names = {
        path.name for path in staging_dir.glob("*_monitor_evidence.csv")
    }
    if actual_artifact_names != expected_artifact_names:
        raise ValueError(
            f"{staging_dir}: staged artifacts have missing or extra entries"
        )

    for row in count_rows:
        chain = row["chain"]
        artifact = staging_dir / f"{chain}_monitor_evidence.csv"
        if not artifact.is_file():
            raise ValueError(f"{staging_dir}: missing staged artifact for {chain}")
        if chain == ERROR_OBSERVATION_ARTIFACT:
            observed_source_counts = validate_error_observation_publication(
                artifact, data_dir=data_dir
            )
            observed_observation_chain_counts[chain] = observed_source_counts
            observed_rows = _csv_row_count(artifact)
            for field in _ORDINARY_MONITOR_CATEGORIES:
                if int(row[field]) != 0:
                    raise ValueError(
                        f"{counts_path}: error aggregate has nonzero {field}"
                    )
            for field in ("error_block", "monitor_rows", "source_rows"):
                if int(row[field]) != observed_rows:
                    raise ValueError(
                        f"{counts_path}: {chain} {field} does not match artifact"
                    )
            expected_status = _expected_canonical_evidence_status(row, 0)
            if row["canonical_evidence_status"] != expected_status:
                raise ValueError(
                    f"{counts_path}: {chain} canonical evidence status is invalid"
                )
            continue
        if int(row["error_block"]) != 0:
            raise ValueError(f"{counts_path}: ordinary artifact declares error blocks")
        actual = _load_monitor_artifact_counts(
            artifact,
            chain,
            data_dir=data_dir,
            expected_artifact_scope=frozenset(
                {
                    (row.get("artifact_scope") or "").strip(),
                    "accepted_stale_descendant_observation",
                    "canonical_blocks",
                    "full_classifier_inventory",
                    "partial_canonical_subset",
                    "stale_descendant_parent_verdicts",
                    "stale_only_publication",
                }
            ),
            orphan_verdicts=orphan_verdicts,
        )
        for field in (*_ORDINARY_MONITOR_CATEGORIES, "monitor_rows"):
            if actual[field] != int(row[field]):
                raise ValueError(
                    f"{counts_path}: {chain} {field} does not match artifact "
                    f"({actual[field]} != {row[field]})"
                )
        expected_status = _expected_canonical_evidence_status(row, actual["canonical"])
        if row["canonical_evidence_status"] != expected_status:
            raise ValueError(
                f"{counts_path}: {chain} canonical evidence status is invalid "
                f"({row['canonical_evidence_status']!r} != {expected_status!r})"
            )
    if manifest_observation_chain_counts != observed_observation_chain_counts:
        for artifact_name in sorted(_OBSERVATION_CHAIN_COUNT_ARTIFACTS):
            if artifact_name not in observed_observation_chain_counts:
                raise ValueError(
                    f"{manifest_path}: staged publication lacks the canonical "
                    f"{artifact_name} artifact"
                )
            published = manifest_observation_chain_counts[artifact_name]
            observed = observed_observation_chain_counts[artifact_name]
            for chain in sorted(set(published) | set(observed)):
                if published.get(chain) != observed.get(chain):
                    raise ValueError(
                        f"{manifest_path}: {artifact_name} observation chain inventory "
                        f"does not match the canonical ledgers for {chain!r} "
                        f"({published.get(chain)!r} != {observed.get(chain)!r})"
                    )
        raise AssertionError("unequal observation chain inventories lack a delta")
    _validate_global_child_event_uniqueness(staging_dir)
    _validate_parent_category_exclusivity(staging_dir)
    if (
        MONITOR_OUTPUT_DIR.is_dir()
        and MONITOR_OUTPUT_DIR.resolve() != staging_dir.resolve()
    ):
        _validate_logical_source_coverage_floor(
            staging_dir,
            MONITOR_OUTPUT_DIR,
            staged_count_rows=count_rows,
        )
        _validate_published_observation_floor(staging_dir)


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
    preserve_transaction = False
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
        if not args.allow_partial:
            _validate_staged_publication(
                staging_dir,
                data_dir=args.data_dir,
                relevance_inventory=args.relevance_inventory,
            )
        _publish_staged_artifacts(staging_dir, output_dir)
        return summary
    except _PublicationRollbackError:
        preserve_transaction = True
        raise
    finally:
        if not preserve_transaction:
            shutil.rmtree(transaction_dir, ignore_errors=True)
