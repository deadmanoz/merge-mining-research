"""Shared schema and row seal for the Hathor acquisition dataset."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping


ACQUISITION_COLUMNS = [
    "hathor_height",
    "hathor_block_hash",
    "hathor_timestamp",
    "aux_pow_hex",
    "funds_graph_hex",
    "raw_hex",
    "endpoint",
    "http_status",
    "attempt_count",
    "record_sha256",
]


def acquisition_record_sha256(row: Mapping[str, object]) -> str:
    """Return the seal over every acquisition field except the seal itself."""
    digest = hashlib.sha256()
    for column in ACQUISITION_COLUMNS[:-1]:
        value = row.get(column)
        if value is None:
            raise ValueError(f"acquisition row is missing {column}")
        encoded = str(value).encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()
