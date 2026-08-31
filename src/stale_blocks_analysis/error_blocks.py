"""Load exact keys excluded from the direct-stale publication path.

Every row in ``data/error-blocks/error_blocks.csv`` is a consensus-invalid
full-proof-of-work Bitcoin block (an "error block"), so the exclusion key set
is derived directly from ``classification == "error_block"`` rows. This
dataset is the single source of truth for the gate.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .config import ERROR_BLOCKS_CSV

ERROR_BLOCK_CLASSIFICATION = "error_block"


def load_error_block_keys(
    path: Path = ERROR_BLOCKS_CSV,
) -> set[tuple[int, str]]:
    """Return exact ``(height, hash)`` keys from the error-block catalogue."""
    if not path.exists():
        raise FileNotFoundError(f"error blocks dataset missing: {path}")

    keys: set[tuple[int, str]] = set()
    with path.open(newline="") as f:
        for row_number, row in enumerate(csv.DictReader(f), start=2):
            try:
                classification = (row.get("classification") or "").strip()
                if classification != ERROR_BLOCK_CLASSIFICATION:
                    raise ValueError
                height = int(row["height"])
                block_hash = row["hash"].strip().lower()
                if height < 0 or len(block_hash) != 64:
                    raise ValueError
                bytes.fromhex(block_hash)
                key = (height, block_hash)
            except (KeyError, ValueError) as exc:
                raise ValueError(
                    f"invalid error block row {row_number} in {path}"
                ) from exc
            if key in keys:
                raise ValueError(f"duplicate error block key {key} in {path}")
            keys.add(key)
    if not keys:
        # Fail closed: an empty gate (an empty or header-only dataset) is never
        # valid for this committed dataset — a truncated file would otherwise
        # silently let every known error block re-enter publication loaders.
        raise ValueError(f"no error block rows in {path}")
    return keys


def exclude_error_block_rows(
    rows: list[dict],
    *,
    path: Path = ERROR_BLOCKS_CSV,
) -> list[dict]:
    """Remove exact error-block identities from normalized loader rows."""
    excluded = load_error_block_keys(path)
    return [
        row
        for row in rows
        if (int(row["height"]), str(row["hash"]).lower()) not in excluded
    ]
