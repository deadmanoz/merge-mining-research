"""Authenticate error parents extending a reviewed invalid fork root.

Root placement is a retained Bitcoin Core canonical-parent receipt. Header
identities, every predecessor edge, heights, full Bitcoin work, and the root's
minimum-version violation are rechecked offline. This does not validate bodies
or infer invalidity from an unknown source bucket.
"""

from __future__ import annotations

import csv
import re
import struct
from pathlib import Path

from .auxpow_chainid import hash_from_header_bytes
from .auxpow_parse import hash_meets_btc_difficulty
from .btc_stale_validation import block_version_error, expected_version_rule
from .bitcoin_epoch_reference import RETARGET_INTERVAL

ANCESTRY_EVIDENCE_COLUMNS = [
    "height",
    "hash",
    "path_header_hexes",
    "root_height",
    "root_hash",
    "root_rule",
    "root_parent_height",
    "root_parent_hash",
    "root_parent_header_hex",
    "root_parent_source",
    "root_evidence_url",
]
_REFERENCE = re.compile(
    r"https://github\.com/bitcoin-data/invalid-blocks/blob/[0-9a-f]{40}/"
    r"data/invalid-blocks\.jsonl#L[1-9][0-9]*"
)


def load_ancestry_evidence(path: Path) -> dict[tuple[int, str], dict[str, str]]:
    """Load exact records; absence is allowed when no row claims this rule."""
    if not path.exists():
        return {}
    records = {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ANCESTRY_EVIDENCE_COLUMNS:
            raise ValueError(f"unexpected ancestry-evidence columns in {path}")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError("missing or surplus ancestry-evidence fields")
            try:
                key = int(row["height"]), row["hash"]
                if key[0] < 0 or str(key[0]) != row["height"]:
                    raise ValueError
                if not re.fullmatch(r"[0-9a-f]{64}", key[1]):
                    raise ValueError
            except ValueError as exc:
                raise ValueError("malformed ancestry-evidence identity") from exc
            if key in records:
                raise ValueError("duplicate ancestry-evidence identity")
            records[key] = row
    return records


def validate_ancestry_evidence(
    row: dict[str, str],
    records: dict[tuple[int, str], dict[str, str]],
    nbits_by_epoch: dict[int, int],
) -> list[str]:
    """Re-derive an inherited invalid verdict through complete header bytes."""
    try:
        height = int(row["height"])
        record = records[(height, row["hash"])]
        headers = [
            bytes.fromhex(value) for value in record["path_header_hexes"].split("|")
        ]
        root_height = int(record["root_height"])
        parent_height = int(record["root_parent_height"])
        parent = bytes.fromhex(record["root_parent_header_hex"])
        if len(headers) < 2 or any(len(header) != 80 for header in [*headers, parent]):
            raise ValueError(
                "ancestry needs complete descendant, root and parent headers"
            )
        if (
            headers[0].hex() != row["btc_header_hex"]
            or height != root_height + len(headers) - 1
        ):
            raise ValueError(
                "ancestry path does not bind the catalogue identity and height"
            )
        if parent_height < 0 or parent_height + 1 != root_height:
            raise ValueError("invalid canonical-parent height placement")
        root = headers[-1]
        if hash_from_header_bytes(root)[::-1].hex() != record["root_hash"]:
            raise ValueError("invalid root identity")
        if hash_from_header_bytes(parent)[::-1].hex() != record[
            "root_parent_hash"
        ] or root[4:36] != hash_from_header_bytes(parent):
            raise ValueError("invalid canonical-parent header placement")
        if not re.fullmatch(
            r"bitcoin-core-rpc:[a-z0-9_-]+", record["root_parent_source"]
        ):
            raise ValueError("invalid canonical-parent receipt source")
        if not _REFERENCE.fullmatch(record["root_evidence_url"]):
            raise ValueError(
                "root verdict requires a commit-pinned invalid-blocks reference"
            )
        for index, header in enumerate(headers):
            if index + 1 < len(headers) and header[4:36] != hash_from_header_bytes(
                headers[index + 1]
            ):
                raise ValueError("broken ancestry predecessor edge")
            position = height - index
            expected = nbits_by_epoch[position // RETARGET_INTERVAL * RETARGET_INTERVAL]
            if struct.unpack_from("<I", header, 72)[
                0
            ] != expected or not hash_meets_btc_difficulty(
                hash_from_header_bytes(header), expected
            ):
                raise ValueError(
                    "ancestry header lacks full Bitcoin work at its position"
                )
        expected_parent = nbits_by_epoch[
            parent_height // RETARGET_INTERVAL * RETARGET_INTERVAL
        ]
        if struct.unpack_from("<I", parent, 72)[
            0
        ] != expected_parent or not hash_meets_btc_difficulty(
            hash_from_header_bytes(parent), expected_parent
        ):
            raise ValueError("canonical-parent receipt lacks full Bitcoin work")
        root_row = {"btc_header_hex": root.hex()}
        if record["root_rule"] != expected_version_rule(root_height) or not str(
            block_version_error(root_row, root_height) or ""
        ).startswith("REJECTED:"):
            raise ValueError("root minimum-version violation did not re-derive")
    except (KeyError, ValueError, struct.error) as exc:
        return [f"invalid ancestry evidence: {exc}"]
    return []
