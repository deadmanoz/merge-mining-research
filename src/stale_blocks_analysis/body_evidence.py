"""Authenticate bodies associated with reviewed, externally verified verdicts.

A pinned invalid-blocks reference records the source of the invalidity verdict.
This module checks that reference's form and authenticates the body identity;
it does not fetch the reference or reproduce its consensus-rule verification.
Admission therefore requires review of the referenced independent evidence.
"""

from __future__ import annotations

import csv
import hashlib
import re
import struct
from pathlib import Path

from .block_body import authenticate_block_body
from .config import BODY_ERROR_REJECTIONS, SEGWIT_ACTIVATION_HEIGHT

BODY_EVIDENCE_COLUMNS = [
    "height",
    "hash",
    "rule",
    "block_file",
    "block_sha256",
    "evidence_url",
]
# One external authority for this evidence class, pinned to a full commit id.
_EVIDENCE_URL = re.compile(
    r"https://github\.com/bitcoin-data/invalid-blocks/blob/[0-9a-f]{40}/"
    r"data/invalid-blocks\.jsonl#L[1-9][0-9]*"
)
_HEX_256 = re.compile(r"[0-9a-f]{64}")


def load_body_evidence(path: Path) -> dict[tuple[int, str], dict[str, str]]:
    """Read the sidecar; absence is allowed only for catalogues without body rules.

    ``validate_row`` rejects any body-rule row lacking an entry. Dataset
    validation additionally rejects unused sidecar entries.
    """
    if not path.exists():
        return {}
    records: dict[tuple[int, str], dict[str, str]] = {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != BODY_EVIDENCE_COLUMNS:
            raise ValueError(f"unexpected body-evidence columns in {path}")
        for line, row in enumerate(reader, 2):
            try:
                if None in row or any(value is None for value in row.values()):
                    raise ValueError("missing or surplus fields")
                height = int(row["height"])
                block_hash = row["hash"]
                if height < 0 or str(height) != row["height"]:
                    raise ValueError("noncanonical height")
                if not _HEX_256.fullmatch(block_hash):
                    raise ValueError("noncanonical hash")
                if row["rule"] not in BODY_ERROR_REJECTIONS:
                    raise ValueError("unsupported body rule")
                if row["block_file"] != f"blocks/{height}-{block_hash}.bin":
                    raise ValueError("body path does not match parent identity")
                if not _HEX_256.fullmatch(row["block_sha256"]):
                    raise ValueError("malformed body digest")
                if not _EVIDENCE_URL.fullmatch(row["evidence_url"]):
                    raise ValueError(
                        "evidence must reference a commit-pinned invalid-blocks row"
                    )
                key = (height, block_hash)
                if key in records:
                    raise ValueError("duplicate body-evidence key")
            except (KeyError, ValueError) as exc:
                raise ValueError(f"invalid body evidence {path}:{line}: {exc}") from exc
            records[key] = row
    return records


def validate_body_evidence(
    row: dict[str, str],
    rule: str,
    evidence: dict[tuple[int, str], dict[str, str]],
    blocks_dir: Path,
) -> list[str]:
    """Match an external rule verdict to this catalogue row's authenticated body."""
    try:
        key = (int(row["height"]), row["hash"])
    except (KeyError, ValueError):
        return ["body evidence requires a valid catalogue identity"]
    record = evidence.get(key)
    if record is None:
        return [f"missing body evidence for {key}"]
    if record["rule"] != rule:
        return [f"body-evidence rule {record['rule']} does not match {rule}"]
    # Derive the filename from the checked identity, never follow a supplied path.
    path = blocks_dir / f"{key[0]}-{key[1]}.bin"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return [f"required body {path.name} unavailable: {exc.strerror}"]
    failures: list[str] = []
    if hashlib.sha256(raw).hexdigest() != record["block_sha256"]:
        failures.append("block_sha256 does not match body bytes")
    if raw[:80].hex() != row.get("btc_header_hex") or len(raw) < 80:
        failures.append("body header does not match catalogue header")
    elif (
        hashlib.sha256(hashlib.sha256(raw[:80]).digest()).digest()[::-1].hex() != key[1]
    ):
        failures.append("body header does not hash to catalogue identity")
    try:
        _, body_failures = authenticate_block_body(
            raw, segwit_active=key[0] >= SEGWIT_ACTIVATION_HEIGHT
        )
        failures.extend(body_failures)
    except (ValueError, IndexError, struct.error) as exc:
        failures.append(f"body did not parse: {exc}")
    return failures
