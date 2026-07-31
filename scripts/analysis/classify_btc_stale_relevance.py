#!/usr/bin/env python3
"""Classify derived BTC stale relevance across AuxPoW recovery inputs.

This is a proving-ground layer for review before any monitor-side change. It
does not replace source classifications: ``stale``, ``unknown`` (legacy
``orphan``),
``near``, and ``canonical`` remain evidence states. The derived bucket is:

1. An EMPTY ``btc_stale_relevance`` with ``relevance_reason``
   ``valid_direct_stale`` or ``valid_stale_descendant`` for structurally
   valid committed/available direct stales and validated stale descendants.
   These rows are already confirmed on the primary ``classification`` plus
   ``validation_status`` axes, so the derived axis carries nothing extra.
2. ``strict_btc_orphan`` for unknown-classified rows with valid self-PoW, no known
   stale/mainchain membership, strict BTC height evidence, and matching BTC
   nBits at that height.
3. ``weak_btc_orphan`` for unknown-classified rows with valid self-PoW, no strict
   height evidence, no known stale/mainchain membership, and timestamp-selected
   BTC nBits consistency within plus/minus one retarget epoch.
4. ``excluded`` for source canonical/near rows, malformed rows, nBits/PoW
   failures, known rejected descendants, known stale/mainchain rows, and
   rows whose evidence is insufficient under the available caches.
5. ``pending`` for unknown-classified rows whose strict height or timestamp lies
   beyond the nBits table's coverage horizon: no final verdict is possible
   yet, and the row is re-classifiable once the table is extended. This
   mirrors the merge-mining-monitor's ``pending`` horizon semantics (its
   BTC-orphan classifier is a port of this script); rows below the table's
   floor remain ``excluded`` as before.

The bucket strings are shared constants in ``stale_blocks_analysis.config``;
the monitor's importer reads them verbatim from the inventory CSV.

RSK deliberately has no strict path because its public inventory has no BTC
coinbase/BIP34 evidence. Hathor is treated as a special full-inventory schema:
current canonical rows are excluded and stale rows are confirmed, but
``full_coinbase_hex`` is not decoded as a strict orphan signal in this first
implementation.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import reconcile_unknown_stale_ancestry as rec
from stale_blocks_analysis.auxpow_parse import parse_coinbase_height
from stale_blocks_analysis.btc_rpc import BtcRpc, get_btc_auth
from stale_blocks_analysis.config import (
    BIP34_HEIGHT,
    BITCOIN_EPOCH_REFERENCE_DIR,
    RELEVANCE_EXCLUDED as EXCLUDED,
    RELEVANCE_PENDING as PENDING,
    RELEVANCE_STRICT_BTC_ORPHAN as STRICT_ORPHAN,
    RELEVANCE_WEAK_BTC_ORPHAN as WEAK_ORPHAN,
)
from stale_blocks_analysis.error_blocks import load_stale_exclusion_keys

# Reasons stamped on confirmed direct-stale / stale-descendant rows. These
# rows write an EMPTY `btc_stale_relevance` (the primary `classification`
# plus a VALID `validation_status` already say "confirmed"; the derived axis
# holds only the unknown-row refinement values), so the reason string is
# what identifies them for the summary counters below.
CONFIRMED_REASONS = ("valid_direct_stale", "valid_stale_descendant")


DATA_DIR = PROJECT_ROOT / "data"
RESULTS_DIR = PROJECT_ROOT / "results" / "analysis" / "btc-stale-relevance"
CACHE_DIR = PROJECT_ROOT / "cache"
PROMOTED_CSV = DATA_DIR / "stale_descendants.csv"
OUTPUT_INVENTORY = "btc-stale-relevance-inventory.csv"
OUTPUT_SUMMARY = "btc-stale-relevance-summary.json"
NON_CHAIN_DOC_STEMS = {"surveyed-infra"}
# "orphan" is the legacy spelling of "unknown" in archive artifacts.
UNKNOWN_SOURCE_CLASSIFICATIONS = {"unknown", "orphan"}
EXCLUDED_SOURCE_CLASSIFICATIONS = {"canonical", "near"}
STRICT_HEIGHT_COLUMNS = ("btc_bip34_height",)
BTC_COINBASE_SCRIPTSIG_CHAINS = {
    "argentum",
    "bitcoin-vault",
    "bitmark",
    "coiledcoin",
    "crown",
    "devcoin",
    "doichain",
    "elastos",
    "emercoin",
    "fractal",
    "geistgeld",
    "groupcoin",
    "huntercoin",
    "i0coin",
    "ixcoin",
    "myriadcoin",
    "namecoin",
    "syscoin",
    "terracoin",
    "unobtanium",
}
MAINCHAIN_CACHE_FILES = (
    "shadow-resolver-mainchain-cache.json",
    "unknown_origin_btc_headers_by_hash.json",
    "unknown-stale-reconciliation-mainchain-cache.json",
)
EPOCH_BITS_CACHE = "btc_nbits_by_epoch.json"
EPOCH_HEADERS_CACHE = "btc_epoch_headers.json"

OUTPUT_FIELDS = [
    "chain",
    "source_path",
    "source_row_number",
    "source_classification",
    "btc_stale_relevance",
    "relevance_reason",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_height",
    "strict_height_source",
    "btc_time",
    "btc_bits",
    "expected_nbits_by_height",
    "expected_nbits_by_time",
    "allowed_nbits_by_time_pm1_epoch",
    "self_pow_valid",
    "known_stale_hash",
    "known_mainchain",
    "mainchain_verification_status",
    "validation_status",
    "source_schema",
    "notes",
    "rsk_height",
    "rsk_miner",
    "pool_label",
    "is_uncle",
    "uncle_index",
    "root_stale_hash",
    "root_stale_height",
    "stale_fork_depth",
    "promotion_subclass",
    "observed_chains",
]


@dataclass(slots=True)
class SourceRow:
    """One raw CSV row plus the column-detection context needed to read it.

    `source_kind` is `full_inventory`, `validated_stales`, or
    `stale_descendant`; `source_schema` (from `source_schema_for`) is
    `standard`, `rsk`, `hathor`, `xaya`, `validated_stales`, or
    `stale_descendant`. `hash_col`/`prev_col`/`bits_col`/`header_col` are the
    column names detected for this file (empty string if not present).
    """

    chain: str
    source_kind: str
    source_path: Path
    row_number: int
    row: dict[str, str]
    fieldnames: list[str]
    hash_col: str
    prev_col: str
    bits_col: str
    header_col: str
    source_schema: str


@dataclass(slots=True)
class StrictHeightEvidence:
    """Result of trying to derive a strict BIP34 height for an unknown row.

    `attempted` is True once a candidate height was found (even if it was
    ultimately rejected), so callers can distinguish "no BIP34 evidence" from
    "BIP34 evidence found but not usable". `note` carries the rejection
    reason (e.g. a `..._time_epoch_mismatch` or `..._out_of_epoch_cache_range`
    suffix) when `source`/`expected_bits` are left empty.
    """

    height: str
    source: str
    expected_bits: str
    attempted: bool = False
    note: str = ""


@dataclass(slots=True)
class EpochTimeLookup:
    """Timestamp-indexed view of the epoch-headers cache for weak-orphan matching.

    `headers` is the sorted-by-time list loaded by `load_epoch_headers`;
    `times` is the parallel list of their `time` values for `bisect`; and
    `bits_by_height` indexes the same headers by `height` for the +/-1-epoch
    neighbor lookup in `expected_for_time`.
    """

    headers: list[dict[str, Any]]
    times: list[int]
    bits_by_height: dict[int, str]

    @classmethod
    def from_headers(cls, headers: list[dict[str, Any]]) -> "EpochTimeLookup":
        """Build an EpochTimeLookup from parsed epoch-header dicts.

        `headers` must already be sorted by ascending `time` (as
        `load_epoch_headers` returns them); this only derives the parallel
        `times` list and the height->bits index used by `expected_for_time`.
        """
        return cls(
            headers=headers,
            times=[int(row["time"]) for row in headers],
            bits_by_height={
                int(row["height"]): str(row["bits"]).lower() for row in headers
            },
        )

    def expected_for_time(self, ts: str) -> tuple[str, str, str]:
        """Look up expected nBits for a BTC timestamp using the epoch-time index.

        Returns `(expected_bits, allowed_bits_pm1_epoch, epoch_height)` where
        `expected_bits` is the bits of the retarget epoch whose start time is
        at or before `ts`, `allowed_bits_pm1_epoch` is a `|`-joined set of
        bits for that epoch plus its immediate neighbors, and `epoch_height`
        is the matched epoch's starting height. Returns `("", "", "")` when
        `ts` is empty/unparseable or falls outside the covered time range.
        """
        if not ts or not self.headers:
            return "", "", ""
        try:
            timestamp = int(ts)
        except ValueError:
            return "", "", ""
        if timestamp < self.times[0] or timestamp > self.times[-1]:
            return "", "", ""
        idx = bisect.bisect_right(self.times, timestamp) - 1
        epoch_height = int(self.headers[idx]["height"])
        allowed = [
            bits
            for height in (epoch_height - 2016, epoch_height, epoch_height + 2016)
            if (bits := self.bits_by_height.get(height))
        ]
        return (
            str(self.headers[idx]["bits"]).lower(),
            "|".join(allowed),
            str(epoch_height),
        )


def rel(path: Path) -> str:
    """Return `path` relative to the project root.

    Delegates to `reconcile_unknown_stale_ancestry.rel`.
    """
    return rec.rel(path)


def normalize_bool(value: object) -> str:
    """Render a Python truthy value as the CSV string `"true"` or `"false"`."""
    return "true" if bool(value) else "false"


def csv_status(value: object) -> str:
    """Alias for `normalize_bool`, used at call sites that represent a status flag."""
    return normalize_bool(value)


def source_classification(src: SourceRow) -> str:
    """Return the row's `classification`, lowercased and stripped.

    Validated-stales rows with no explicit `classification` column default to
    `"stale"`, since that file only ever carries stale rows.
    """
    classification = src.row.get("classification", "").strip().lower()
    if src.source_kind == "validated_stales" and not classification:
        return "stale"
    return classification


def validation_status(src: SourceRow) -> str:
    """Return the row's raw `validation_status` value, stripped."""
    return src.row.get("validation_status", "").strip()


def validation_allows_direct_stale(status: str) -> bool:
    """True when `status` is empty or starts with `VALID` (a confirmed direct stale)."""
    return not status or status.startswith("VALID")


def validation_rejects(status: str) -> bool:
    """True when a direct-stale status is non-empty and not `VALID`-prefixed."""
    return bool(status and not status.startswith("VALID"))


def get_header_hash(src: SourceRow) -> str:
    """Return the row's BTC header hash.

    Recovers it from `header_hex` via SHA256d when the hash column is empty.
    """
    block_hash = rec.get_hash(src.row, src.hash_col)
    if not block_hash and src.header_col:
        block_hash = rec.header_hash(src.row.get(src.header_col, ""))
    return block_hash


def get_prev_hash(src: SourceRow) -> str:
    """Return the row's BTC prev-hash.

    Recovers it from `header_hex` when the prev-hash column is empty.
    """
    prev_hash, _recovered = rec.get_prev(src.row, src.prev_col, src.header_col)
    return prev_hash


def get_bits(src: SourceRow) -> str:
    """Return the row's `btc_bits` as lowercase hex.

    Recovers it from `header_hex` when the bits column is empty.
    """
    bits = src.row.get(src.bits_col, "").strip().lower() if src.bits_col else ""
    if not bits and src.header_col:
        bits = rec.parse_header_fields(src.row.get(src.header_col, "")).get("bits", "")
    return bits.lower()


def get_btc_time(src: SourceRow) -> str:
    """Return the row's `btc_time`.

    Recovers it from `header_hex` when no `btc_time` column value is present.
    """
    btc_time = rec.get_value(src.row, src.fieldnames, ("btc_time",))
    if not btc_time and src.header_col:
        btc_time = rec.parse_header_fields(src.row.get(src.header_col, "")).get(
            "time", ""
        )
    return btc_time


def get_btc_height(src: SourceRow) -> str:
    """Return the row's BTC height from whichever height column is populated.

    `stale_descendant` rows always read `btc_height` directly (the
    reconciliation walk's inferred height); other rows try `btc_height`,
    `btc_bip34_height`, `btc_stale_height`, then `height` in that order and
    return the first non-empty value.
    """
    if src.source_kind == "stale_descendant":
        return src.row.get("btc_height", "").strip()
    for column in ("btc_height", "btc_bip34_height", "btc_stale_height", "height"):
        if column in src.fieldnames:
            value = src.row.get(column, "").strip()
            if value:
                return value
    return ""


def compute_self_pow(block_hash: str, bits: str, row: dict[str, str]) -> bool:
    """Determine whether `block_hash` satisfies its own PoW target.

    Recomputes the check from `bits` when present, via `hash_meets_bits`.
    Falls back to a source-provided `pow_valid` flag (`"true"/"1"/"yes"` vs
    `"false"/"0"/"no"`) only when `bits` is missing, and defaults to False for
    any other or unrecognized flag value.
    """
    if bits:
        return rec.hash_meets_bits(block_hash, bits)
    flag = row.get("pow_valid", "").strip().lower()
    if flag in {"true", "1", "yes"}:
        return True
    if flag in {"false", "0", "no"}:
        return False
    return False


def source_schema_for(chain: str, source_kind: str) -> str:
    """Classify a row's schema family for downstream strict/weak-orphan logic.

    Returns `stale_descendant` for reconciliation rows, `rsk`/`hathor`/`xaya`
    for those chains' bespoke inventories, `validated_stales` for the
    VALID-only loader input, and `standard` for the ordinary full-inventory
    schema.
    """
    if source_kind == "stale_descendant":
        return "stale_descendant"
    if chain == "rsk":
        return "rsk"
    if chain == "hathor":
        return "hathor"
    if chain == "xaya":
        return "xaya"
    if source_kind == "validated_stales":
        return "validated_stales"
    return "standard"


def normalized_chain_archive_dirs(
    chain_archive_dirs: Iterable[Path] = (),
) -> list[Path]:
    """Resolve each private chain-archive root to its `chains/` subdirectory.

    Expands `~` in each path and descends into a `chains/` child when one
    exists; otherwise the root itself is used as-is. Falsy entries are
    skipped.
    """
    roots: list[Path] = []
    for root in chain_archive_dirs:
        if not root:
            continue
        root = root.expanduser()
        chains_root = root / "chains"
        roots.append(chains_root if chains_root.is_dir() else root)
    return roots


def discover_sources(
    data_dir: Path,
    chain_archive_dirs: Iterable[Path] = (),
) -> tuple[set[str], dict[str, Path], dict[str, Path], list[Path]]:
    """Discover per-chain full-inventory and validated-stales CSVs.

    Combines chains found under `data_dir` (via
    `reconcile_unknown_stale_ancestry.discover_chain_names`, minus
    `NON_CHAIN_DOC_STEMS`) with any private chain archives passed via
    `chain_archive_dirs`, whose `*/classified/*_stale_blocks.csv` and
    `*/validated/*_validated_stales.csv` files are globbed in. Returns
    `(chain_names, stale_inventory_paths, unknown_inventory_paths,
    validated_stales_paths, normalized_archive_dirs)`. The stale and unknown
    inventories are the two halves of the classifier's bucket split.
    """
    chain_names, full_files, unknown_files, validated_files = rec.discover_chain_names(
        data_dir
    )
    chain_names = set(chain_names) - NON_CHAIN_DOC_STEMS
    archive_dirs = normalized_chain_archive_dirs(chain_archive_dirs)
    for archive_dir in archive_dirs:
        for path in archive_dir.glob("*/classified/*_stale_blocks.csv"):
            chain = path.name.removesuffix("_stale_blocks.csv")
            chain_names.add(chain)
            full_files[chain] = path
        for path in archive_dir.glob("*/classified/*_unknown_blocks.csv"):
            chain = path.name.removesuffix("_unknown_blocks.csv")
            chain_names.add(chain)
            unknown_files[chain] = path
        for path in archive_dir.glob("*/validated/*_validated_stales.csv"):
            chain = path.name.removesuffix("_validated_stales.csv")
            chain_names.add(chain)
            validated_files[chain] = path
    return chain_names, full_files, unknown_files, validated_files, archive_dirs


def iter_csv_source(
    path: Path,
    chain: str,
    source_kind: str,
    excluded_keys: set[tuple[int, str]] | None = None,
) -> Iterable[SourceRow]:
    """Yield a `SourceRow` for every data row in a per-chain CSV.

    Detects the header-hash/prev-hash/bits/header-hex column names once per
    file and resolves `source_schema` via `source_schema_for` before
    iterating rows (row numbers start at 2, accounting for the header line).
    """
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        hash_col = rec.first_present(fieldnames, rec.HASH_COLUMNS)
        prev_col = rec.first_present(fieldnames, rec.PREV_COLUMNS)
        bits_col = rec.first_present(fieldnames, rec.BITS_COLUMNS)
        header_col = rec.first_present(fieldnames, rec.HEADER_HEX_COLUMNS)
        schema = source_schema_for(chain, source_kind)
        for row_number, row in enumerate(reader, start=2):
            source_row = SourceRow(
                chain=chain,
                source_kind=source_kind,
                source_path=path,
                row_number=row_number,
                row=row,
                fieldnames=fieldnames,
                hash_col=hash_col,
                prev_col=prev_col,
                bits_col=bits_col,
                header_col=header_col,
                source_schema=schema,
            )
            if source_exclusion_key(source_row) in (excluded_keys or set()):
                continue
            yield source_row


def source_exclusion_key(src: SourceRow) -> tuple[int, str] | None:
    """Return an authoritative stale identity key for exclusion matching."""
    block_hash = rec.normalize_hash(src.row.get(src.hash_col, ""))
    if not rec.is_hash(block_hash):
        return None
    height_text = ""
    for column in ("btc_height", "btc_stale_height", "height"):
        if column in src.fieldnames:
            height_text = src.row.get(column, "").strip()
            if height_text:
                break
    if not height_text:
        parent_height = rec.int_or_none(src.row.get("btc_parent_height", ""))
        if parent_height is not None:
            height_text = str(parent_height + 1)
    try:
        return int(height_text), block_hash
    except ValueError:
        return None


def iter_source_rows(
    data_dir: Path,
    chain_archive_dirs: Iterable[Path] = (),
) -> Iterable[SourceRow]:
    """Yield `SourceRow`s for every discovered chain plus the promoted stale-descendants file.

    For each chain (sorted), yields its full-inventory rows first (if
    present) then its validated-stales rows (if present). Afterward, if
    `data/stale_descendants.csv` is found under `data_dir`, yields its rows
    too via `iter_stale_descendant_rows`.
    """
    chain_names, full_files, unknown_files, validated_files, _archive_dirs = (
        discover_sources(
            data_dir,
            chain_archive_dirs,
        )
    )
    excluded_keys = load_stale_exclusion_keys()
    for chain in sorted(chain_names):
        full_path = full_files.get(chain)
        if full_path is not None:
            yield from iter_csv_source(
                full_path, chain, "full_inventory", excluded_keys
            )
        unknown_path = unknown_files.get(chain)
        if unknown_path is not None:
            # The unknown half of the split; same source_kind — the per-row
            # classification filter routes it to the strict/weak orphan logic.
            yield from iter_csv_source(
                unknown_path, chain, "full_inventory", excluded_keys
            )
        validated_path = validated_files.get(chain)
        if validated_path is not None:
            yield from iter_csv_source(
                validated_path, chain, "validated_stales", excluded_keys
            )
    if PROMOTED_CSV.exists() and PROMOTED_CSV.parent == data_dir:
        yield from iter_stale_descendant_rows(PROMOTED_CSV)
    elif (data_dir / PROMOTED_CSV.name).exists():
        yield from iter_stale_descendant_rows(data_dir / PROMOTED_CSV.name)


def iter_stale_descendant_rows(path: Path) -> Iterable[SourceRow]:
    """Yield a `SourceRow` for every row in the stale-descendants promotion CSV.

    `chain` is taken from the row's `observed_chains` column when non-empty,
    otherwise the placeholder `"stale_descendants"` is used; `source_schema`
    is always `"stale_descendant"`.
    """
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        hash_col = rec.first_present(fieldnames, rec.HASH_COLUMNS)
        prev_col = rec.first_present(fieldnames, rec.PREV_COLUMNS)
        bits_col = rec.first_present(fieldnames, rec.BITS_COLUMNS)
        header_col = rec.first_present(fieldnames, rec.HEADER_HEX_COLUMNS)
        for row_number, row in enumerate(reader, start=2):
            observed_chains = row.get("observed_chains", "").strip()
            chain = observed_chains or "stale_descendants"
            yield SourceRow(
                chain=chain,
                source_kind="stale_descendant",
                source_path=path,
                row_number=row_number,
                row=row,
                fieldnames=fieldnames,
                hash_col=hash_col,
                prev_col=prev_col,
                bits_col=bits_col,
                header_col=header_col,
                source_schema="stale_descendant",
            )


def load_epoch_headers(path: Path) -> tuple[list[dict[str, Any]], dict[str, object]]:
    """Load the per-epoch time/bits/height table used for weak-orphan matching.

    Reads `path` as a JSON list of `{time, bits, height}` objects, coercing
    types and dropping malformed rows, and sorts the survivors by ascending
    `time`. Returns `(headers, metadata)` where `metadata` records whether the
    file was found, how many rows loaded, and a `status` of `missing`,
    `unreadable`, `loaded`, or `empty_or_unsupported` for the summary JSON.
    """
    metadata: dict[str, object] = {
        "path": rel(path),
        "found": path.exists(),
        "rows": 0,
        "status": "missing",
    }
    if not path.exists():
        return [], metadata
    try:
        with path.open() as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        metadata["status"] = "unreadable"
        metadata["error"] = str(exc)
        return [], metadata
    headers: list[dict[str, Any]] = []
    if isinstance(raw, list):
        for row in raw:
            if not isinstance(row, dict):
                continue
            if "time" not in row or "bits" not in row or "height" not in row:
                continue
            try:
                headers.append(
                    {
                        "time": int(row["time"]),
                        "bits": str(row["bits"]).lower(),
                        "height": int(row["height"]),
                    }
                )
            except (TypeError, ValueError):
                continue
    headers.sort(key=lambda row: int(row["time"]))
    metadata["rows"] = len(headers)
    metadata["status"] = "loaded" if headers else "empty_or_unsupported"
    return headers, metadata


def load_epoch_bits(path: Path) -> tuple[dict[int, str], dict[str, object]]:
    """Load the per-epoch-start-height nBits table used for strict-orphan matching.

    Delegates parsing to `reconcile_unknown_stale_ancestry.load_epoch_bits`
    and wraps the result with the same `metadata` shape as
    `load_epoch_headers` (found/rows/status), for the summary JSON.
    """
    metadata: dict[str, object] = {
        "path": rel(path),
        "found": path.exists(),
        "rows": 0,
        "status": "missing",
    }
    if not path.exists():
        return {}, metadata
    try:
        raw = rec.load_epoch_bits(path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        metadata["status"] = "unreadable"
        metadata["error"] = str(exc)
        return {}, metadata
    metadata["rows"] = len(raw)
    metadata["status"] = "loaded" if raw else "empty_or_unsupported"
    return raw, metadata


def normalize_mainchain_cache_value(value: object) -> dict[str, object] | None:
    """Normalize one raw mainchain-cache JSON value to the internal shape.

    Accepts a bare bool (legacy `exists`/`on_mainchain` shorthand) or a dict
    with an optional `confirmations` field (`confirmations >= 0` overrides
    `on_mainchain` when present). Returns None for a value of an unsupported
    shape.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return {"exists": value, "on_mainchain": value}
    if not isinstance(value, dict):
        return None
    confirmations = value.get("confirmations")
    on_mainchain = bool(value.get("on_mainchain"))
    if confirmations is not None:
        try:
            on_mainchain = int(confirmations) >= 0
        except (TypeError, ValueError):
            on_mainchain = bool(value.get("on_mainchain"))
    return {
        "exists": bool(value.get("exists", True)),
        "on_mainchain": on_mainchain,
        "confirmations": confirmations,
        "height": value.get("height"),
        "time": value.get("time"),
        "bits": value.get("bits"),
    }


def load_mainchain_caches(
    cache_dir: Path,
) -> tuple[dict[str, dict[str, object]], list[dict[str, object]]]:
    """Merge the known mainchain-status cache files into one hash->status dict.

    Reads each file in `MAINCHAIN_CACHE_FILES` (later files overwrite earlier
    entries for the same hash), normalizing every value via
    `normalize_mainchain_cache_value` and tagging it with its source
    `cache_file`. Returns `(cache, metadata)` where `metadata` is a per-file
    list recording entries seen/loaded, `unknown_entries` (explicit `null`
    values), and `unsupported_entries` (malformed hash or value shape).
    """
    cache: dict[str, dict[str, object]] = {}
    metadata: list[dict[str, object]] = []
    for filename in MAINCHAIN_CACHE_FILES:
        path = cache_dir / filename
        item: dict[str, object] = {
            "path": rel(path),
            "found": path.exists(),
            "entries_seen": 0,
            "entries_loaded": 0,
            "unknown_entries": 0,
            "unsupported_entries": 0,
            "status": "missing",
        }
        if not path.exists():
            metadata.append(item)
            continue
        try:
            with path.open() as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            item["status"] = "unreadable"
            item["error"] = str(exc)
            metadata.append(item)
            continue
        if not isinstance(raw, dict):
            item["status"] = "unsupported_shape"
            metadata.append(item)
            continue
        for block_hash, value in raw.items():
            item["entries_seen"] = int(item["entries_seen"]) + 1
            h = rec.normalize_hash(block_hash)
            if not rec.is_hash(h):
                item["unsupported_entries"] = int(item["unsupported_entries"]) + 1
                continue
            if value is None:
                item["unknown_entries"] = int(item["unknown_entries"]) + 1
                continue
            normalized = normalize_mainchain_cache_value(value)
            if normalized is None:
                item["unsupported_entries"] = int(item["unsupported_entries"]) + 1
                continue
            normalized["cache_file"] = filename
            normalized.setdefault("status_source", "cache")
            cache[h] = normalized
            item["entries_loaded"] = int(item["entries_loaded"]) + 1
        item["status"] = "loaded"
        metadata.append(item)
    return cache, metadata


def mainchain_status(
    block_hash: str,
    cache: dict[str, dict[str, object]],
) -> tuple[bool, str]:
    """Look up `block_hash` in the merged mainchain cache.

    Returns `(False, "not_checked")` when the hash is absent; otherwise
    `(on_mainchain, status)` where `status` is one of
    `rpc_on_mainchain`/`cache_on_mainchain`/`rpc_not_mainchain`/`cache_not_mainchain`
    depending on the cache entry's `on_mainchain` flag and whether it came
    from a live RPC check or a prior cache file.
    """
    value = cache.get(block_hash)
    if not value:
        return False, "not_checked"
    source = str(value.get("status_source", "cache"))
    if bool(value.get("on_mainchain")):
        return True, "rpc_on_mainchain" if source == "rpc" else "cache_on_mainchain"
    return False, "rpc_not_mainchain" if source == "rpc" else "cache_not_mainchain"


def decode_bip34_height(scriptsig_hex: str) -> int | None:
    """Decode a BIP34 coinbase-height push from `scriptsig_hex`.

    Returns None on empty/invalid hex or a scriptSig whose leading push does
    not decode to a BIP34 height (see `auxpow_parse.parse_coinbase_height`).
    """
    scriptsig_hex = (scriptsig_hex or "").strip()
    if not scriptsig_hex:
        return None
    try:
        scriptsig = bytes.fromhex(scriptsig_hex)
    except ValueError:
        return None
    return parse_coinbase_height(scriptsig)


def strict_height_evidence(
    src: SourceRow,
    epoch_bits: dict[int, str],
    time_lookup: EpochTimeLookup,
) -> StrictHeightEvidence:
    """Derive strict BIP34-height evidence for an unknown-classified row.

    Tries to decode a BIP34 coinbase height (from `coinbase_scriptsig_hex`
    for chains in `BTC_COINBASE_SCRIPTSIG_CHAINS`, then from any column in
    `STRICT_HEIGHT_COLUMNS`), accepting only heights at or above
    `BIP34_HEIGHT`. A candidate height is cross-checked against the row's
    timestamp-derived retarget epoch (via `time_lookup`) and against the
    epoch-bits cache's covered range before its expected nBits is resolved
    (see `resolve_height`). Returns an empty, `attempted=False`
    `StrictHeightEvidence` for RSK/Hathor/Xaya rows or when no candidate
    height is found.
    """
    if src.source_schema in {"rsk", "hathor", "xaya"}:
        return StrictHeightEvidence("", "", "", False, "")

    max_cached_height = max(epoch_bits) + 2015 if epoch_bits else None
    btc_time = get_btc_time(src)
    _expected_time_bits, _allowed_time_bits, time_epoch_height = (
        time_lookup.expected_for_time(btc_time)
    )
    time_epoch_start = rec.int_or_none(time_epoch_height)
    missing_time_epoch = bool(
        time_lookup.headers and btc_time and time_epoch_start is None
    )

    def resolve_height(height: int, source: str) -> StrictHeightEvidence:
        """Resolve one candidate height/source pair into `StrictHeightEvidence`.

        Rejects the height (via a `<source>_time_epoch_unavailable`,
        `_time_epoch_mismatch`, or `_out_of_epoch_cache_range` note) when the
        row's timestamp epoch is missing, disagrees with the height's own
        retarget epoch, or exceeds the epoch-bits cache's covered maximum;
        otherwise looks up the expected nBits for the height and notes
        `<source>_unresolved` if the epoch-bits table has no entry for it.
        """
        if missing_time_epoch:
            return StrictHeightEvidence(
                str(height),
                "",
                "",
                True,
                f"{source}_time_epoch_unavailable",
            )
        if time_epoch_start is not None and not (
            time_epoch_start <= height < time_epoch_start + 2016
        ):
            return StrictHeightEvidence(
                str(height),
                "",
                "",
                True,
                f"{source}_time_epoch_mismatch",
            )
        if max_cached_height is not None and height > max_cached_height:
            return StrictHeightEvidence(
                str(height),
                "",
                "",
                True,
                f"{source}_out_of_epoch_cache_range",
            )
        expected = rec.expected_bits_for_height(str(height), epoch_bits)
        if expected:
            return StrictHeightEvidence(str(height), source, expected, True, "")
        return StrictHeightEvidence(
            str(height),
            "",
            "",
            True,
            f"{source}_unresolved",
        )

    if src.chain in BTC_COINBASE_SCRIPTSIG_CHAINS:
        scriptsig_height = decode_bip34_height(
            src.row.get("coinbase_scriptsig_hex", "")
        )
        if scriptsig_height is not None and scriptsig_height >= BIP34_HEIGHT:
            return resolve_height(scriptsig_height, "coinbase_bip34_height")

    for column in STRICT_HEIGHT_COLUMNS:
        if column not in src.fieldnames:
            continue
        value = src.row.get(column, "").strip()
        height = rec.int_or_none(value)
        if height is None or height < BIP34_HEIGHT:
            continue
        return resolve_height(height, column)

    return StrictHeightEvidence("", "", "", False, "")


def base_output(src: SourceRow) -> dict[str, object]:
    """Build the base output row for `src` with all `OUTPUT_FIELDS` populated.

    Extracts hash/prev/height/time/bits via the `get_*` helpers and copies
    through the optional per-schema columns (`rsk_*`, `pool_label`,
    `is_uncle`/`uncle_index`, `root_stale_*`, `stale_fork_depth`,
    `promotion_subclass`, `observed_chains`); relevance/reason/notes and the
    evidence-computation fields start empty and are filled in by
    `classify_source_row`/`finish`.
    """
    return {
        "chain": src.chain,
        "source_path": rel(src.source_path),
        "source_row_number": src.row_number,
        "source_classification": source_classification(src),
        "btc_stale_relevance": "",
        "relevance_reason": "",
        "btc_header_hash": get_header_hash(src),
        "btc_prev_hash": get_prev_hash(src),
        "btc_height": get_btc_height(src),
        "strict_height_source": "",
        "btc_time": get_btc_time(src),
        "btc_bits": get_bits(src),
        "expected_nbits_by_height": "",
        "expected_nbits_by_time": "",
        "allowed_nbits_by_time_pm1_epoch": "",
        "self_pow_valid": "false",
        "known_stale_hash": "false",
        "known_mainchain": "false",
        "mainchain_verification_status": "not_checked",
        "validation_status": validation_status(src),
        "source_schema": src.source_schema,
        "notes": "",
        "rsk_height": src.row.get("rsk_height", "").strip(),
        "rsk_miner": src.row.get("rsk_miner", "").strip(),
        "pool_label": src.row.get("pool_label", "").strip(),
        "is_uncle": src.row.get("is_uncle", "").strip(),
        "uncle_index": src.row.get("uncle_index", "").strip(),
        "root_stale_hash": src.row.get("root_stale_hash", "").strip(),
        "root_stale_height": src.row.get("root_stale_height", "").strip(),
        "stale_fork_depth": src.row.get("stale_fork_depth", "").strip(),
        "promotion_subclass": src.row.get("promotion_subclass", "").strip(),
        "observed_chains": src.row.get("observed_chains", "").strip(),
    }


def finish(
    out: dict[str, object],
    relevance: str,
    reason: str,
    notes: Iterable[str] = (),
) -> dict[str, object]:
    """Stamp `out` with a final verdict and return it.

    Sets `btc_stale_relevance`/`relevance_reason` and joins the non-empty
    `notes` with `"; "` into `out["notes"]`. Mutates `out` in place.
    """
    out["btc_stale_relevance"] = relevance
    out["relevance_reason"] = reason
    out["notes"] = "; ".join(note for note in notes if note)
    return out


def classify_source_row(
    src: SourceRow,
    known_stale_hashes: set[str],
    rejected_descendant_hashes: set[str],
    epoch_bits: dict[int, str],
    time_lookup: EpochTimeLookup,
    mainchain_cache: dict[str, dict[str, object]],
) -> dict[str, object]:
    """Classify one source row into a `btc_stale_relevance` bucket.

    Applies, in order: header/prev-hash well-formedness, mainchain/known-stale
    lookups, and self-PoW validation, then branches on `classification` --
    stale-descendant rows resolve directly from their reconciliation verdict;
    validation-rejected direct stales, canonical/near, and
    known-mainchain/known-stale rows are excluded; confirmed `stale` rows get
    an empty relevance with reason
    `valid_direct_stale`; and `unknown`/`orphan` rows fall through to strict
    height evidence
    (`strict_btc_orphan` on an nBits match, `pending` above the epoch-bits
    horizon) and then timestamp-based weak evidence (`weak_btc_orphan` on a
    +/-1-epoch nBits match, `pending` above the epoch-headers horizon).
    Returns the finished output row (see `base_output`/`finish`); reads from
    but does not mutate the known-hash sets or caches.
    """
    out = base_output(src)
    classification = str(out["source_classification"])
    block_hash = str(out["btc_header_hash"])
    prev_hash = str(out["btc_prev_hash"])
    bits = str(out["btc_bits"])
    status = str(out["validation_status"])
    notes: list[str] = []

    if not rec.is_hash(block_hash):
        return finish(out, EXCLUDED, "malformed_header_hash", notes)

    known_mainchain, verification_status = mainchain_status(block_hash, mainchain_cache)
    if classification == "canonical":
        known_mainchain = True
    out["known_mainchain"] = csv_status(known_mainchain)
    out["mainchain_verification_status"] = verification_status
    out["known_stale_hash"] = csv_status(block_hash in known_stale_hashes)

    if not rec.is_hash(prev_hash):
        return finish(out, EXCLUDED, "malformed_prev_hash", notes)

    self_pow_valid = compute_self_pow(block_hash, bits, src.row)
    out["self_pow_valid"] = csv_status(self_pow_valid)
    if not self_pow_valid:
        return finish(out, EXCLUDED, "pow_target_mismatch", notes)

    if src.source_kind == "stale_descendant":
        if classification == "stale_descendant" and status == "VALID_STALE_DESCENDANT":
            return finish(out, "", "valid_stale_descendant", notes)
        return finish(out, EXCLUDED, "known_rejected_stale_descendant", notes)

    # The validation status is a direct-stale publication verdict. Unknown
    # inventory rows may carry the literal classifier state ``UNKNOWN``; that
    # is not a rejection and must not bypass the strict/weak evidence branch.
    if classification == "stale" and validation_rejects(status):
        return finish(out, EXCLUDED, "validation_rejected", notes)

    if classification in EXCLUDED_SOURCE_CLASSIFICATIONS:
        return finish(out, EXCLUDED, f"source_{classification}", notes)

    if classification == "stale":
        if known_mainchain:
            return finish(out, EXCLUDED, "known_mainchain", notes)
        return finish(out, "", "valid_direct_stale", notes)

    if classification not in UNKNOWN_SOURCE_CLASSIFICATIONS:
        return finish(out, EXCLUDED, "insufficient_evidence", notes)

    if block_hash in rejected_descendant_hashes:
        return finish(out, EXCLUDED, "known_rejected_stale_descendant", notes)
    if block_hash in known_stale_hashes:
        return finish(out, EXCLUDED, "known_stale_hash", notes)
    if known_mainchain:
        return finish(out, EXCLUDED, "known_mainchain", notes)

    strict = strict_height_evidence(src, epoch_bits, time_lookup)
    if strict.source and strict.height:
        out["btc_height"] = strict.height
    out["strict_height_source"] = strict.source
    out["expected_nbits_by_height"] = strict.expected_bits
    if strict.note:
        notes.append(strict.note)

    # Horizon gate (monitor-aligned): a decoded strict height above the nBits
    # table's covered maximum has no final verdict yet — the row is pending
    # until the table is extended, not weak/excluded.
    if strict.note.endswith("_out_of_epoch_cache_range"):
        return finish(out, PENDING, "above_nbits_height_horizon", notes)

    if strict.source and strict.expected_bits:
        if bits == strict.expected_bits:
            return finish(out, STRICT_ORPHAN, "strict_height_nbits_match", notes)
        return finish(out, EXCLUDED, "non_btc_epoch_bits", notes)

    expected_by_time, allowed_by_time, _time_epoch_height = (
        time_lookup.expected_for_time(str(out["btc_time"]))
    )
    out["expected_nbits_by_time"] = expected_by_time
    out["allowed_nbits_by_time_pm1_epoch"] = allowed_by_time

    if not time_lookup.headers:
        return finish(out, EXCLUDED, "insufficient_epoch_cache", notes)
    if not str(out["btc_time"]):
        return finish(out, EXCLUDED, "insufficient_evidence", notes)
    # Horizon gate (monitor-aligned): a timestamp past the epoch-header
    # table's covered maximum is pending, not excluded; below-floor
    # timestamps keep the excluded verdict.
    row_time = rec.int_or_none(str(out["btc_time"]))
    if row_time is not None and row_time > time_lookup.times[-1]:
        return finish(out, PENDING, "above_nbits_time_horizon", notes)
    if bits and bits in set(allowed_by_time.split("|")):
        return finish(out, WEAK_ORPHAN, "timestamp_epoch_nbits_match", notes)
    if expected_by_time:
        return finish(out, EXCLUDED, "non_btc_epoch_bits", notes)
    return finish(out, EXCLUDED, "insufficient_evidence", notes)


def build_known_stale_membership(
    data_dir: Path,
    chain_archive_dirs: Iterable[Path] = (),
) -> tuple[set[str], set[str], dict[str, object]]:
    """Build the set of BTC hashes already known to be stale, plus rejected descendants.

    Scans the upstream stale-blocks CSV (via
    `reconcile_unknown_stale_ancestry.scan_upstream_stales`), then every
    discovered chain's rows: `stale`-classified rows with a validation status
    that allows a direct stale are added to `known_stale_hashes`;
    stale-descendant rows are split into `valid_stale_descendant` hashes
    (also added to `known_stale_hashes`) and `rejected_descendant_hashes`.
    Returns `(known_stale_hashes, rejected_descendant_hashes, summary)` where
    `summary` reports per-source row/hash counts and rejected-descendant
    counts by status, for the summary JSON.
    """
    stale_by_hash: dict[str, list[rec.StaleObservation]] = defaultdict(list)
    all_hash_chains: dict[str, set[str]] = defaultdict(set)
    prevs_by_hash: dict[str, set[str]] = defaultdict(set)
    source_rows: Counter[str] = Counter()
    source_hashes: dict[str, set[str]] = defaultdict(set)
    rejected_descendant_hashes: set[str] = set()
    rejected_descendant_rows: Counter[str] = Counter()

    upstream_path = data_dir / "stale-blocks" / "stale-blocks.csv"
    upstream_count = rec.scan_upstream_stales(
        upstream_path,
        stale_by_hash,
        all_hash_chains,
        prevs_by_hash,
    )
    source_rows["upstream"] = upstream_count
    source_hashes["upstream"].update(stale_by_hash)

    for src in iter_source_rows(data_dir, chain_archive_dirs):
        block_hash = get_header_hash(src)
        if not rec.is_hash(block_hash):
            continue
        classification = source_classification(src)
        status = validation_status(src)
        if src.source_kind == "stale_descendant":
            if (
                classification == "stale_descendant"
                and status == "VALID_STALE_DESCENDANT"
            ):
                source_rows["valid_stale_descendant"] += 1
                source_hashes["valid_stale_descendant"].add(block_hash)
            elif classification == "stale_descendant":
                rejected_descendant_hashes.add(block_hash)
                rejected_descendant_rows[status or "rejected_or_unknown"] += 1
            continue
        if classification == "stale" and validation_allows_direct_stale(status):
            key = src.source_kind
            source_rows[key] += 1
            source_hashes[key].add(block_hash)

    known_stale_hashes = set(stale_by_hash)
    for hashes in source_hashes.values():
        known_stale_hashes.update(hashes)

    summary = {
        "unique_hashes": len(known_stale_hashes),
        "sources": [
            {
                "source": source,
                "rows_loaded": source_rows[source],
                "unique_hashes_loaded": len(source_hashes.get(source, set())),
            }
            for source in sorted(source_rows)
        ],
        "rejected_stale_descendants": {
            "unique_hashes": len(rejected_descendant_hashes),
            "rows_by_status": dict(sorted(rejected_descendant_rows.items())),
        },
    }
    return known_stale_hashes, rejected_descendant_hashes, summary


def collect_mainchain_rpc_candidates(
    data_dir: Path,
    chain_archive_dirs: Iterable[Path],
    mainchain_cache: dict[str, dict[str, object]],
    known_stale_hashes: set[str],
    rejected_descendant_hashes: set[str],
) -> list[str]:
    """Collect unknown-classified BTC hashes worth an RPC mainchain check.

    Iterates every source row, keeping the header hash of rows whose
    `classification` is `unknown`/`orphan` and that are absent from
    `mainchain_cache`, `known_stale_hashes`, and `rejected_descendant_hashes`.
    Returns the candidates sorted and deduplicated.
    """
    candidates: set[str] = set()
    for src in iter_source_rows(data_dir, chain_archive_dirs):
        classification = source_classification(src)
        if classification not in UNKNOWN_SOURCE_CLASSIFICATIONS:
            continue
        block_hash = get_header_hash(src)
        if not rec.is_hash(block_hash):
            continue
        if block_hash in mainchain_cache:
            continue
        if block_hash in known_stale_hashes or block_hash in rejected_descendant_hashes:
            continue
        candidates.add(block_hash)
    return sorted(candidates)


def apply_mainchain_rpc(
    data_dir: Path,
    chain_archive_dirs: Iterable[Path],
    mainchain_cache: dict[str, dict[str, object]],
    known_stale_hashes: set[str],
    rejected_descendant_hashes: set[str],
    rpc: BtcRpc,
    batch_size: int,
    max_hashes: int,
) -> dict[str, object]:
    """Query Bitcoin Core for unknown-classified hashes.

    Updates `mainchain_cache` in place. Collects candidates via
    `collect_mainchain_rpc_candidates`, caps them at
    `max_hashes` (0 or negative means no cap), fetches their status via
    `reconcile_unknown_stale_ancestry.fetch_mainchain_status`, and merges
    normalized results into `mainchain_cache` tagged `status_source: "rpc"`.
    Returns a summary dict with candidate/queried counts and whether the
    candidate list was truncated.
    """
    candidates = collect_mainchain_rpc_candidates(
        data_dir,
        chain_archive_dirs,
        mainchain_cache,
        known_stale_hashes,
        rejected_descendant_hashes,
    )
    limit = max_hashes if max_hashes > 0 else len(candidates)
    to_query = candidates[:limit]
    fetched = rec.fetch_mainchain_status(to_query, rpc, batch_size)
    for block_hash, value in fetched.items():
        h = rec.normalize_hash(block_hash)
        if not rec.is_hash(h):
            continue
        normalized = normalize_mainchain_cache_value(value)
        if normalized is None:
            continue
        normalized["status_source"] = "rpc"
        mainchain_cache[h] = normalized
    return {
        "enabled": True,
        "candidate_hashes": len(candidates),
        "queried_hashes": len(to_query),
        "truncated": len(candidates) > len(to_query),
        "batch_size": batch_size,
    }


def counter_records(
    counter: Counter[tuple], fieldnames: list[str]
) -> list[dict[str, object]]:
    """Convert a `Counter` keyed by tuples into sorted `{field: value, ..., count}` rows.

    Non-tuple keys are wrapped in a 1-tuple first. Rows are ordered by the
    sorted counter keys, not by count.
    """
    rows: list[dict[str, object]] = []
    for key, count in sorted(counter.items()):
        if not isinstance(key, tuple):
            key = (key,)
        row = {field: value for field, value in zip(fieldnames, key, strict=True)}
        row["count"] = count
        rows.append(row)
    return rows


def build_input_file_summary(
    data_dir: Path,
    chain_archive_dirs: Iterable[Path],
    processed_counts: Counter[tuple[str, str]],
) -> dict[str, object]:
    """Build the `input_files` section of the summary JSON.

    Combines `discover_sources` output with `processed_counts` (rows actually
    written per source file) into a report of every processed file, which
    chains have only a validated-stales file (no full inventory), which
    chains have no full inventory at all, and the resolved full-inventory /
    validated-stales / stale-descendants paths.
    """
    chain_names, full_files, _unknown_files, validated_files, archive_dirs = (
        discover_sources(
            data_dir,
            chain_archive_dirs,
        )
    )
    processed = [
        {"source_kind": source_kind, "path": path, "rows": count}
        for (source_kind, path), count in sorted(processed_counts.items())
    ]
    chains_validated_only = sorted(
        chain
        for chain in chain_names
        if chain in validated_files and chain not in full_files
    )
    chains_unavailable_full = sorted(
        chain for chain in chain_names if chain not in full_files
    )
    descendants_path = data_dir / PROMOTED_CSV.name
    return {
        "processed": processed,
        "chains_discovered": sorted(chain_names),
        "chain_archive_dirs": [rel(path) for path in archive_dirs],
        "chains_validated_only": chains_validated_only,
        "chains_unavailable_full_inventories": chains_unavailable_full,
        "full_inventory_paths": {
            chain: rel(path)
            for chain, path in sorted(full_files.items())
            if chain in chain_names
        },
        "validated_stale_paths": {
            chain: rel(path)
            for chain, path in sorted(validated_files.items())
            if chain in chain_names
        },
        "stale_descendants_path": rel(descendants_path)
        if descendants_path.exists()
        else "",
        "prior_resolved_chains": "out_of_scope_first_implementation",
    }


def run(args: argparse.Namespace) -> dict[str, object]:
    """Run the full relevance-classification pass and write the inventory CSV and summary JSON.

    Loads the epoch-bits/epoch-headers/mainchain caches, builds known-stale
    and rejected-descendant membership, optionally refreshes the mainchain
    cache via RPC (`--check-mainchain`), then classifies every source row
    with `classify_source_row` and streams the result to
    `results/analysis/btc-stale-relevance/btc-stale-relevance-inventory.csv`.
    Also accumulates
    per-chain/per-relevance/per-reason counts, tracks BTC-coinbase-scriptsig
    chains outside `BTC_COINBASE_SCRIPTSIG_CHAINS` as warnings, samples RSK
    weak-orphan rows, and writes the aggregated summary to
    `results/analysis/btc-stale-relevance/btc-stale-relevance-summary.json`
    (also returned).
    """
    args.results_dir.mkdir(parents=True, exist_ok=True)
    chain_archive_dirs = tuple(getattr(args, "chain_archive_dirs", ()) or ())

    # Loud gate: without the upstream stale-blocks dataset the known-stale
    # exclusion silently degrades to an empty membership set, and headers
    # that are already catalogued upstream get admitted as strict/weak
    # orphans (this exact failure shipped three known stales as "new
    # orphans" from a snapshot that lacked the gitignored clone).
    upstream_csv = args.data_dir / "stale-blocks" / "stale-blocks.csv"
    if not upstream_csv.exists() and not getattr(args, "allow_missing_upstream", False):
        raise SystemExit(
            f"upstream stale-blocks dataset missing: {upstream_csv}\n"
            "Known-stale exclusion would silently degrade: headers already "
            "catalogued upstream would be admitted as strict/weak orphans. "
            "Run scripts/fetch-data.sh to clone the dataset, or pass "
            "--allow-missing-upstream to accept verdicts that cannot exclude "
            "upstream-known stales."
        )

    epoch_reference_dir = getattr(args, "epoch_reference_dir", args.cache_dir)
    epoch_bits, epoch_bits_metadata = load_epoch_bits(
        epoch_reference_dir / EPOCH_BITS_CACHE
    )
    epoch_headers, epoch_headers_metadata = load_epoch_headers(
        epoch_reference_dir / EPOCH_HEADERS_CACHE
    )
    time_lookup = EpochTimeLookup.from_headers(epoch_headers)
    mainchain_cache, mainchain_cache_metadata = load_mainchain_caches(args.cache_dir)
    known_stale_hashes, rejected_descendant_hashes, membership_summary = (
        build_known_stale_membership(args.data_dir, chain_archive_dirs)
    )

    rpc_summary: dict[str, object] = {"enabled": False}
    if args.check_mainchain:
        rpc = BtcRpc(url=args.rpc_url, auth=get_btc_auth(args.rpc_user, args.rpc_pass))
        rpc_summary = apply_mainchain_rpc(
            args.data_dir,
            chain_archive_dirs,
            mainchain_cache,
            known_stale_hashes,
            rejected_descendant_hashes,
            rpc,
            args.rpc_batch_size,
            args.max_mainchain_rpc,
        )

    output_path = args.results_dir / OUTPUT_INVENTORY
    summary_path = args.results_dir / OUTPUT_SUMMARY
    processed_counts: Counter[tuple[str, str]] = Counter()
    source_class_counts: Counter[tuple[str, str]] = Counter()
    chain_relevance_counts: Counter[tuple[str, str]] = Counter()
    chain_source_relevance_counts: Counter[tuple[str, str, str]] = Counter()
    reason_counts: Counter[tuple[str, str]] = Counter()
    mainchain_status_counts: Counter[tuple[str, str]] = Counter()
    confirmed_per_chain: dict[str, set[str]] = defaultdict(set)
    confirmed_global: set[str] = set()
    confirmed_heights_by_hash: dict[str, set[str]] = defaultdict(set)
    coinbase_scriptsig_non_allowlist_chains: set[str] = set()
    strict_height_count = 0
    timestamp_only_count = 0
    rsk_weak_examples: list[dict[str, object]] = []

    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        for src in iter_source_rows(args.data_dir, chain_archive_dirs):
            if (
                "coinbase_scriptsig_hex" in src.fieldnames
                and src.row.get("coinbase_scriptsig_hex", "").strip()
                and src.chain not in BTC_COINBASE_SCRIPTSIG_CHAINS
                and src.source_schema
                not in {"rsk", "xaya", "hathor", "stale_descendant"}
            ):
                coinbase_scriptsig_non_allowlist_chains.add(src.chain)
            out = classify_source_row(
                src,
                known_stale_hashes,
                rejected_descendant_hashes,
                epoch_bits,
                time_lookup,
                mainchain_cache,
            )
            writer.writerow({field: out.get(field, "") for field in OUTPUT_FIELDS})

            source_path = str(out["source_path"])
            classification = str(out["source_classification"])
            relevance = str(out["btc_stale_relevance"])
            reason = str(out["relevance_reason"])
            chain = str(out["chain"])
            # The CSV keeps `btc_stale_relevance` empty for confirmed direct
            # stales/descendants (see `finish` call sites above): the
            # confirmation already lives on the primary `classification`
            # axis, so nothing distinguishes it there. The summary counters
            # below still need a distinguishing label, so they group
            # confirmed rows by a dedicated tag instead of the (empty) bucket.
            summary_relevance = (
                "confirmed" if reason in CONFIRMED_REASONS else relevance
            )
            processed_counts[(src.source_kind, source_path)] += 1
            source_class_counts[(chain, classification)] += 1
            chain_relevance_counts[(chain, summary_relevance)] += 1
            chain_source_relevance_counts[
                (chain, classification, summary_relevance)
            ] += 1
            reason_counts[(summary_relevance, reason)] += 1

            if relevance in {STRICT_ORPHAN, WEAK_ORPHAN}:
                mainchain_status_counts[
                    (relevance, str(out["mainchain_verification_status"]))
                ] += 1
            if out.get("strict_height_source"):
                strict_height_count += 1
            if relevance == WEAK_ORPHAN:
                timestamp_only_count += 1
                if chain == "rsk" and len(rsk_weak_examples) < 20:
                    rsk_weak_examples.append(
                        {
                            "btc_header_hash": out["btc_header_hash"],
                            "btc_prev_hash": out["btc_prev_hash"],
                            "btc_time": out["btc_time"],
                            "btc_bits": out["btc_bits"],
                            "rsk_height": out["rsk_height"],
                            "mainchain_verification_status": out[
                                "mainchain_verification_status"
                            ],
                        }
                    )
            if reason in CONFIRMED_REASONS:
                block_hash = str(out["btc_header_hash"])
                if block_hash:
                    confirmed_per_chain[chain].add(block_hash)
                    confirmed_global.add(block_hash)
                    height = str(out["btc_height"])
                    if height:
                        confirmed_heights_by_hash[block_hash].add(height)

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "outputs": {
            "inventory_csv": rel(output_path),
            "summary_json": rel(summary_path),
            "gitignored_scratch": True,
        },
        "input_files": build_input_file_summary(
            args.data_dir,
            chain_archive_dirs,
            processed_counts,
        ),
        "known_stale_membership": membership_summary,
        "epoch_caches": {
            "height_bits": epoch_bits_metadata,
            "time_headers": epoch_headers_metadata,
            "strict_orphan_computation": (
                "computed" if epoch_bits else "not_computed_missing_epoch_cache"
            ),
            "weak_orphan_computation": (
                "computed" if epoch_headers else "not_computed_missing_epoch_cache"
            ),
        },
        "mainchain_caches": mainchain_cache_metadata,
        "mainchain_rpc_check": rpc_summary,
        "row_counts": {
            "counting_unit": "source_rows_not_unique_hashes",
            "deduplication_note": (
                "Chains with both full_inventory and validated_stales inputs can emit the "
                "same confirmed BTC hash once per source row; use unique_confirmed_btc_stale "
                "for hash-level confirmed counts."
            ),
            "processed_by_source_file": [
                {"source_kind": kind, "path": path, "rows": count}
                for (kind, path), count in sorted(processed_counts.items())
            ],
            "by_chain_and_source_classification": counter_records(
                source_class_counts, ["chain", "source_classification"]
            ),
            "by_chain_and_relevance": counter_records(
                chain_relevance_counts, ["chain", "btc_stale_relevance"]
            ),
            "by_chain_source_classification_and_relevance": counter_records(
                chain_source_relevance_counts,
                ["chain", "source_classification", "btc_stale_relevance"],
            ),
            "by_relevance_reason": counter_records(
                reason_counts, ["btc_stale_relevance", "relevance_reason"]
            ),
            "strict_height_rows": strict_height_count,
            "timestamp_only_weak_rows": timestamp_only_count,
            "strict_weak_mainchain_verification": counter_records(
                mainchain_status_counts,
                ["btc_stale_relevance", "mainchain_verification_status"],
            ),
        },
        "unique_confirmed_btc_stale": {
            "global_unique_hashes": len(confirmed_global),
            "per_chain_unique_hashes": [
                {"chain": chain, "unique_hashes": len(hashes)}
                for chain, hashes in sorted(confirmed_per_chain.items())
            ],
            "height_conflicts": [
                {"btc_header_hash": block_hash, "btc_heights": sorted(heights)}
                for block_hash, heights in sorted(confirmed_heights_by_hash.items())
                if len(heights) > 1
            ],
        },
        "strict_coinbase_height_allowlist_warnings": [
            {
                "chain": chain,
                "warning": (
                    "coinbase_scriptsig_hex present but chain is not enabled for "
                    "BTC coinbase BIP34 strict-height decoding"
                ),
            }
            for chain in sorted(coinbase_scriptsig_non_allowlist_chains)
        ],
        "rsk_weak_examples": rsk_weak_examples,
        "caveats": [
            "Source classifications are preserved; this file emits only a derived relevance layer.",
            "Confirmed BTC stale rows still require valid header hash, prev hash, and self-PoW evidence.",
            "Private chain archives can be passed with --chain-archive-dir and are read without copying private inventories into this repo.",
            "The upstream stale-block CSV is a membership-only input, not a row-level output source.",
            "Row-count summaries count source rows, not unique hashes; unique_confirmed_btc_stale is the deduplicated confirmed-hash view.",
            "Missing full inventories are reported as unavailable, not counted as zero unknown rows.",
            "RSK cannot produce strict_btc_orphan in this implementation because it lacks BTC coinbase/BIP34 evidence.",
            "Xaya coinbase_scriptsig_hex is not decoded as BTC strict-height evidence in this implementation.",
            "Hathor full_coinbase_hex is not decoded as strict orphan evidence in this implementation.",
            "No recursive unknown-ancestry walk is performed here.",
        ],
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Covers the data/results/cache directories, private chain-archive roots,
    and the optional mainchain RPC check.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument(
        "--chain-archive-dir",
        dest="chain_archive_dirs",
        action="append",
        type=Path,
        default=[],
        help=(
            "Private chain archive root to scan for */classified/*_stale_blocks.csv "
            "and */validated/*_validated_stales.csv. May be repeated."
        ),
    )
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    parser.add_argument(
        "--epoch-reference-dir",
        type=Path,
        default=BITCOIN_EPOCH_REFERENCE_DIR,
        help=(
            "Committed public Bitcoin epoch reference directory. Runtime "
            "mainchain caches continue to use --cache-dir."
        ),
    )
    parser.add_argument(
        "--check-mainchain",
        action="store_true",
        help="Query Bitcoin Core for unknown-classified hashes absent from local caches.",
    )
    parser.add_argument(
        "--rpc-url",
        default=os.environ.get("BTC_RPC_URL", "http://127.0.0.1:8332"),
        help="Bitcoin Core JSON-RPC URL; forward a remote node with ssh -L 8332:localhost:8332 <host>.",
    )
    parser.add_argument("--rpc-user", default=None)
    parser.add_argument("--rpc-pass", default=None)
    parser.add_argument("--rpc-batch-size", type=int, default=500)
    parser.add_argument(
        "--allow-missing-upstream",
        action="store_true",
        help=(
            "Proceed without data/stale-blocks/stale-blocks.csv. The "
            "known-stale exclusion then cannot rule out upstream-known "
            "stales, so strict/weak verdicts from such a run must not be "
            "committed."
        ),
    )
    parser.add_argument(
        "--max-mainchain-rpc",
        type=int,
        default=5000,
        help="Maximum unknown-classified hashes to query when --check-mainchain is set; <=0 means no cap.",
    )
    return parser


def main() -> None:
    """Parse CLI arguments, run the classification pass via `run`, and print
    a compact JSON summary to stdout."""
    args = build_parser().parse_args()
    summary = run(args)
    print(
        json.dumps(
            {
                "inventory_csv": summary["outputs"]["inventory_csv"],
                "summary_json": summary["outputs"]["summary_json"],
                "processed_files": len(summary["input_files"]["processed"]),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
