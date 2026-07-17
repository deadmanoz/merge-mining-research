"""Load exact keys excluded from the direct-stale publication path.

Most rows are consensus-invalid under the recorded reason. A row may instead
carry ``exclusion_scope=direct_stale_only`` when valid-looking evidence belongs
to another classification, such as ``stale_descendant``.
The scope is mandatory so publication cannot silently assign semantics to a
missing value.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .config import STALE_EXCLUSIONS_CSV


def load_stale_exclusion_keys(
    path: Path = STALE_EXCLUSIONS_CSV,
) -> set[tuple[int, str]]:
    """Return exact ``(height, hash)`` keys excluded from direct-stale loaders."""
    if not path.exists():
        raise FileNotFoundError(f"stale exclusion overlay missing: {path}")

    keys: set[tuple[int, str]] = set()
    with path.open(newline="") as f:
        for row_number, row in enumerate(csv.DictReader(f), start=2):
            try:
                height = int(row["height"])
                block_hash = row["hash"].strip().lower()
                if height < 0 or len(block_hash) != 64:
                    raise ValueError
                bytes.fromhex(block_hash)
                scope = (row.get("exclusion_scope") or "").strip()
                if scope not in {"consensus_invalid", "direct_stale_only"}:
                    raise ValueError
                key = (height, block_hash)
            except (KeyError, ValueError) as exc:
                raise ValueError(
                    f"invalid stale exclusion row {row_number} in {path}"
                ) from exc
            if key in keys:
                raise ValueError(f"duplicate stale exclusion key {key} in {path}")
            keys.add(key)
    return keys


def load_consensus_invalid_stale_keys(
    path: Path = STALE_EXCLUSIONS_CSV,
) -> set[tuple[int, str]]:
    """Return exact keys whose evidence proves a Bitcoin consensus failure."""
    if not path.exists():
        raise FileNotFoundError(f"stale exclusion overlay missing: {path}")

    keys: set[tuple[int, str]] = set()
    with path.open(newline="") as f:
        for row_number, row in enumerate(csv.DictReader(f), start=2):
            try:
                scope = (row.get("exclusion_scope") or "").strip()
                if scope not in {"consensus_invalid", "direct_stale_only"}:
                    raise ValueError
                height = int(row["height"])
                block_hash = row["hash"].strip().lower()
                if height < 0 or len(block_hash) != 64:
                    raise ValueError
                bytes.fromhex(block_hash)
                key = (height, block_hash)
            except (KeyError, ValueError) as exc:
                raise ValueError(
                    f"invalid stale exclusion row {row_number} in {path}"
                ) from exc
            if scope != "consensus_invalid":
                continue
            if key in keys:
                raise ValueError(f"duplicate stale exclusion key {key} in {path}")
            keys.add(key)
    return keys


def exclude_stale_rows(
    rows: list[dict],
    *,
    path: Path = STALE_EXCLUSIONS_CSV,
) -> list[dict]:
    """Remove excluded exact stale keys from normalized loader rows."""
    excluded = load_stale_exclusion_keys(path)
    return [
        row
        for row in rows
        if (int(row["height"]), str(row["hash"]).lower()) not in excluded
    ]


def exclude_consensus_invalid_rows(
    rows: list[dict],
    *,
    path: Path = STALE_EXCLUSIONS_CSV,
) -> list[dict]:
    """Remove only consensus-invalid keys from a general stale catalogue.

    General catalogues may legitimately contain a key whose overlay scope is
    ``direct_stale_only``. Such a row remains stale evidence but must be
    represented as a stale descendant downstream.
    """
    excluded = load_consensus_invalid_stale_keys(path)
    return [
        row
        for row in rows
        if (int(row["height"]), str(row["hash"]).lower()) not in excluded
    ]
