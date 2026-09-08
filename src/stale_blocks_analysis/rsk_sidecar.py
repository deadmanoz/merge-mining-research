"""Shared semantic contract for RSK Monitor-publication sidecar cells."""

from __future__ import annotations

import re

RSK_SIDECAR_EXPORT_FIELDS = [
    "rsk_miner",
    "merge_mining_hash",
    "is_uncle",
    "uncle_index",
    "uncle_parent_height",
    "rsk_merkle_proof",
    "rsk_coinbase_tail",
]
RSK_SOURCE_BUNDLE_MARKER = "_rsk_source_bundle_complete"

I32_MAX = 2_147_483_647
_PUBLISHED_HEX = re.compile(r"^[0-9a-fA-F]+$")
_PUBLISHED_I32 = re.compile(r"^[+]?[0-9]+$")


def _published_hex_byte_length(value: str) -> int | None:
    """Count bytes in unprefixed hex the monitor's `hex::decode` will accept."""
    stripped = (value or "").strip()
    if not stripped or len(stripped) % 2 or not _PUBLISHED_HEX.fullmatch(stripped):
        return None
    return len(stripped) // 2


def _published_i32(value: str) -> int | None:
    """Parse a monitor-importable signed 32-bit cell (`i32::from_str`)."""
    stripped = (value or "").strip()
    if not _PUBLISHED_I32.fullmatch(stripped):
        return None
    parsed = int(stripped)
    if parsed < 0 or parsed > I32_MAX:
        return None
    return parsed


def validate_rsk_sidecar_cells(row: dict[str, str], *, row_id: str) -> None:
    """Reject RSK sidecar values that the monitor importer would skip."""
    miner_len = _published_hex_byte_length(row.get("rsk_miner") or "")
    if miner_len != 20:
        raise ValueError(f"{row_id}: rsk_miner must be unprefixed 20-byte hex")
    mm_len = _published_hex_byte_length(row.get("merge_mining_hash") or "")
    if mm_len != 32:
        raise ValueError(f"{row_id}: merge_mining_hash must be unprefixed 32-byte hex")
    is_uncle = (row.get("is_uncle") or "").strip()
    if is_uncle not in {"0", "1"}:
        raise ValueError(f"{row_id}: is_uncle must be 0 or 1")
    uncle_index = (row.get("uncle_index") or "").strip()
    uncle_parent_height = (row.get("uncle_parent_height") or "").strip()
    if is_uncle == "1":
        if (
            _published_i32(uncle_index) is None
            or _published_i32(uncle_parent_height) is None
        ):
            raise ValueError(
                f"{row_id}: uncle placement must be a non-negative signed 32-bit int"
            )
    elif uncle_index or uncle_parent_height:
        raise ValueError(f"{row_id}: uncle placement must be blank for is_uncle=0")
    for name in ("rsk_merkle_proof", "rsk_coinbase_tail"):
        value = (row.get(name) or "").strip()
        if value and _published_hex_byte_length(value) is None:
            raise ValueError(f"{row_id}: {name} must be blank or unprefixed hex")
