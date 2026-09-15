"""Validator for the committed body-invalid-stales overlay.

``data/error-blocks/body_invalid_stales.csv`` records accepted VALID direct
stales whose complete block body is known consensus-invalid from an
independently observed full block (a P2P capture preserved in the pinned
``bitcoin-data/stale-blocks`` archive). The overlay exists because the
direct-stale publication profile sees only the header, coinbase, and canonical
parent context: a body rule such as ``bad-blk-sigops`` is invisible to it, so
the row legitimately carries an accepted VALID status while the block itself
could never have connected. See docs/error-blocks.md "Externally attested
body-invalid stales".

The overlay is an annotation, deliberately NOT part of the error-block
catalogue or its exclusion gate:

- Its ``rule`` names the Core reject family attested by the external full-body
  evidence. It is not a ``rules_violated`` token, and this module rejects any
  rule the offline catalogue validator re-derives from header/coinbase bytes:
  a violation that IS byte-recheckable belongs in ``error_blocks.csv``, not
  here.
- Membership does not remove the row from stale publication. Every overlay key
  must still be an accepted direct stale in ``data/validated-stales/`` and must
  be absent from the error-block catalogue; overlap in either direction fails
  validation.
- The sibling-chain witnesses prove only that the header existed and was mined
  on. The invalidity claim rests on the referenced full-body artifact, and the
  ``attested_sigop_cost`` figure is the external attestation, not something
  this validator can re-derive: the committed block bytes carry the legacy
  sigops of the embedded scripts, but the P2SH/witness portion of Bitcoin
  Core's sigop cost needs the spent prevout scripts, which no committed
  artifact holds.

What IS re-derived, when the pinned ``bitcoin-data/stale-blocks`` clone is
fetched (``scripts/fetch-data.sh``; CI always fetches, a bare checkout skips
the byte checks):

1. the referenced block file's SHA-256 equals ``block_sha256``;
2. the file's first 80 bytes hash (sha256d, display order) to ``hash``;
3. the transaction payload merkle-authenticates against the header (the
   legacy txids fold to header bytes 36-68), so a substituted or corrupted
   body cannot masquerade as re-derived evidence;
4. when any transaction carries witness data or the coinbase carries a
   commitment output, the BIP141 witness commitment re-derives (the wtxid
   merkle root plus the coinbase's exactly-one-32-byte witness reserved
   value hash to the coinbase's ``6a24aa21a9ed`` commitment output), since
   the txid tree does not cover witness bytes and the attested excess lives
   precisely in witness-path sigops -- a witness-stripped body fails here
   rather than skipping the check;
5. the legacy sigop count over every embedded input scriptSig and output
   scriptPubKey (Core's ``GetLegacySigOpCount`` semantics: CHECKSIG counts 1,
   CHECKMULTISIG counts the 20-key maximum) equals
   ``legacy_sigops_from_bytes``; and
6. that count, scaled by the witness factor, stays at or below the 80,000
   sigop-cost limit -- re-asserting the premise that the attested excess is
   not derivable from the block bytes alone.
"""

from __future__ import annotations

import csv
import hashlib
import struct
from pathlib import Path

from stale_blocks_analysis.auxpow_chainid import (
    hash_from_header_bytes,
    hash_to_display_hex,
)
from stale_blocks_analysis.block_body import authenticate_block_body
from stale_blocks_analysis.config import (
    ACCEPTED_STALE_VALIDATION_STATUSES,
    BLOCKS_DIR,
    BODY_INVALID_STALES_CSV,
    ERROR_BLOCKS_CSV,
    MAX_BLOCK_SIGOPS_COST,
    VALIDATED_STALES_DIR,
    WITNESS_SCALE_FACTOR,
)
from stale_blocks_analysis.error_block_validation import RULE_GATES, TIME_RULES
from stale_blocks_analysis.error_blocks import load_error_block_keys

EXPECTED_COLUMNS = [
    "height",
    "hash",
    "rule",
    "attested_sigop_cost",
    "legacy_sigops_from_bytes",
    "evidence_source",
    "evidence_url",
    "block_file",
    "block_sha256",
    "notes",
]

# Every rule token the offline catalogue validator can re-derive from
# committed bytes plus committed context. An overlay row must NOT use one:
# a byte-recheckable violation is an error block and belongs in
# ``error_blocks.csv`` under the catalogue's own evidence standard. The
# special-cased tokens are the ones ``error_block_validation.validate_row``
# handles outside RULE_GATES (sidecar-backed time rules and the epoch-table
# retarget rule); TIME_RULES tokens are not even catalogue-admissible, but
# they are catalogue *vocabulary*, not an external Core reject family.
CATALOGUE_RULE_TOKENS = (
    frozenset(RULE_GATES)
    | TIME_RULES
    | frozenset(
        {
            "time_below_mtp",
            "median_time_past_violation",
            "nbits_retarget_not_applied",
        }
    )
)


def _load_accepted_stale_keys(validated_stales_dir: Path) -> set[tuple[int, str]]:
    """Collect accepted direct-stale ``(height, hash)`` keys across all chains.

    The committed per-chain CSVs share the ``btc_height`` / ``btc_header_hash``
    parent columns (chain-specific child columns vary).
    """
    keys: set[tuple[int, str]] = set()
    for csv_path in sorted(validated_stales_dir.glob("*_validated_stales.csv")):
        with csv_path.open(newline="") as f:
            for row in csv.DictReader(f):
                if (row.get("classification") or "").strip() != "stale":
                    continue
                status = (row.get("validation_status") or "").strip()
                if status not in ACCEPTED_STALE_VALIDATION_STATUSES:
                    continue
                try:
                    height = int(str(row.get("btc_height", "") or "").strip())
                except ValueError:
                    continue
                block_hash = str(row.get("btc_header_hash", "") or "").strip().lower()
                if height >= 0 and len(block_hash) == 64:
                    keys.add((height, block_hash))
    return keys


def _validate_row_shape(
    row: dict[str, str],
) -> tuple[tuple[int, str] | None, list[str]]:
    """Check one row's field forms; return (parsed key or None, failures)."""
    failures: list[str] = []

    key: tuple[int, str] | None = None
    height_text = str(row.get("height", "") or "").strip()
    hash_text = str(row.get("hash", "") or "").strip()
    try:
        height = int(height_text)
        if height < 0 or str(height) != height_text:
            raise ValueError
    except ValueError:
        failures.append(f"malformed height value {height_text!r}")
        height = -1
    if (
        len(hash_text) != 64
        or hash_text != hash_text.lower()
        or any(char not in "0123456789abcdef" for char in hash_text)
    ):
        failures.append(f"malformed hash value {hash_text!r}")
    elif height >= 0:
        key = (height, hash_text)

    rule = str(row.get("rule", "") or "").strip()
    if not rule:
        failures.append("rule is empty")
    elif rule in CATALOGUE_RULE_TOKENS:
        failures.append(
            f"rule {rule} is catalogue vocabulary: a byte-recheckable "
            "violation belongs in error_blocks.csv, not the overlay"
        )

    attested_text = str(row.get("attested_sigop_cost", "") or "").strip()
    legacy_text = str(row.get("legacy_sigops_from_bytes", "") or "").strip()
    try:
        attested = int(attested_text)
        if attested <= MAX_BLOCK_SIGOPS_COST:
            failures.append(
                f"attested_sigop_cost {attested} does not exceed the "
                f"{MAX_BLOCK_SIGOPS_COST} limit (nothing body-invalid to attest)"
            )
    except ValueError:
        failures.append(f"malformed attested_sigop_cost value {attested_text!r}")
    try:
        legacy = int(legacy_text)
        if legacy < 0:
            raise ValueError
        if legacy * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST:
            failures.append(
                f"legacy_sigops_from_bytes {legacy} already exceeds the limit "
                "when scaled: the violation would be byte-derivable and the "
                "block would belong in error_blocks.csv"
            )
    except ValueError:
        failures.append(f"malformed legacy_sigops_from_bytes value {legacy_text!r}")

    if not str(row.get("evidence_source", "") or "").strip():
        failures.append("evidence_source is empty")
    evidence_url = str(row.get("evidence_url", "") or "").strip()
    if not evidence_url.startswith("https://"):
        failures.append(f"evidence_url {evidence_url!r} is not an https URL")

    if key is not None:
        expected_file = f"blocks/{key[0]}-{key[1]}.bin"
        block_file = str(row.get("block_file", "") or "").strip()
        if block_file != expected_file:
            failures.append(
                f"block_file {block_file!r} does not follow the pinned "
                f"stale-blocks layout {expected_file!r}"
            )
    sha_text = str(row.get("block_sha256", "") or "").strip()
    if (
        len(sha_text) != 64
        or sha_text != sha_text.lower()
        or any(char not in "0123456789abcdef" for char in sha_text)
    ):
        failures.append(f"malformed block_sha256 value {sha_text!r}")

    return key, failures


def _validate_row_bytes(
    row: dict[str, str], key: tuple[int, str], blocks_dir: Path
) -> list[str]:
    """Cross-check one row against the pinned block bytes, when fetched."""
    block_path = blocks_dir / f"{key[0]}-{key[1]}.bin"
    if not block_path.is_file():
        return [
            f"pinned block file {block_path.name} is missing from the "
            "fetched stale-blocks clone"
        ]
    raw = block_path.read_bytes()
    failures: list[str] = []
    digest = hashlib.sha256(raw).hexdigest()
    if digest != str(row.get("block_sha256", "") or "").strip():
        failures.append(f"block_sha256 does not match the pinned block file ({digest})")
    if len(raw) < 80 or hash_to_display_hex(hash_from_header_bytes(raw[:80])) != key[1]:
        failures.append("pinned block file's header does not hash to the row's hash")
        return failures
    # Authenticate the transaction payload against the header before trusting
    # any count derived from it: a file whose header is genuine but whose body
    # was substituted or corrupted would otherwise still "re-derive" a sigop
    # count. This covers both the legacy txid merkle root (header bytes 36-68)
    # and the BIP141 witness commitment, since altered witness bytes change
    # exactly the witness-path sigops these rows attribute the excess to.
    try:
        legacy, body_failures = authenticate_block_body(raw)
    except (ValueError, IndexError, struct.error) as exc:
        failures.append(f"pinned block bytes did not parse: {exc}")
        return failures
    if body_failures:
        failures.extend(body_failures)
        return failures
    committed_text = str(row.get("legacy_sigops_from_bytes", "") or "").strip()
    if committed_text != str(legacy):
        failures.append(
            f"legacy_sigops_from_bytes {committed_text} does not match the "
            f"count re-derived from the pinned block bytes ({legacy})"
        )
    return failures


def validate_dataset(
    path: Path = BODY_INVALID_STALES_CSV,
    *,
    validated_stales_dir: Path = VALIDATED_STALES_DIR,
    error_blocks_path: Path = ERROR_BLOCKS_CSV,
    blocks_dir: Path = BLOCKS_DIR,
) -> tuple[list[str], int, int]:
    """Validate the committed overlay; return (failures, rows, byte_checked).

    The byte cross-checks run only when the pinned ``bitcoin-data/stale-blocks``
    clone is fetched (``blocks_dir`` exists); every other invariant is checked
    unconditionally and the empty dataset fails closed, mirroring the
    error-block gate loader.
    """
    failures: list[str] = []
    accepted_keys = _load_accepted_stale_keys(validated_stales_dir)
    error_keys = load_error_block_keys(error_blocks_path)
    blocks_fetched = blocks_dir.is_dir()

    seen_keys: set[tuple[int, str]] = set()
    row_count = 0
    byte_checked = 0
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != EXPECTED_COLUMNS:
            failures.append(
                f"unexpected columns {reader.fieldnames!r}; the overlay "
                f"schema is {EXPECTED_COLUMNS!r}"
            )
            return failures, 0, 0
        for row in reader:
            row_count += 1
            row_id = f"{row.get('height', '?')}:{str(row.get('hash', ''))[-12:]}"
            # DictReader parks surplus fields (an unquoted comma in the final
            # column) under the None key and fills omitted trailing fields
            # with None. Either way the row does not conform to the declared
            # schema, so fail closed before validating field contents.
            if None in row or any(value is None for value in row.values()):
                failures.append(
                    f"{row_id}: row does not have exactly "
                    f"{len(EXPECTED_COLUMNS)} fields"
                )
                continue
            key, shape_failures = _validate_row_shape(row)
            failures.extend(f"{row_id}: {failure}" for failure in shape_failures)
            if key is None:
                continue
            if key in seen_keys:
                failures.append(f"{row_id}: duplicate overlay key {key}")
            seen_keys.add(key)
            if key not in accepted_keys:
                failures.append(
                    f"{row_id}: not an accepted direct stale in any "
                    f"{validated_stales_dir.name} CSV (the overlay only "
                    "annotates published stales)"
                )
            if key in error_keys:
                failures.append(
                    f"{row_id}: already in the error-block catalogue; the "
                    "overlay and the exclusion gate must stay disjoint"
                )
            if blocks_fetched:
                byte_failures = _validate_row_bytes(row, key, blocks_dir)
                if not byte_failures:
                    byte_checked += 1
                failures.extend(f"{row_id}: {failure}" for failure in byte_failures)
    if row_count == 0:
        # Fail closed: a header-only or empty overlay would otherwise pass as
        # success, silently dropping the committed annotations. Mirrors the
        # fail-closed empty-dataset checks in ``error_blocks`` and
        # ``error_block_validation``.
        failures.append(f"dataset is empty (no overlay rows in {path})")
    return failures, row_count, byte_checked


def main() -> int:
    failures, row_count, byte_checked = validate_dataset()
    if failures:
        print(f"{len(failures)} body-invalid overlay validation failure(s):")
        for failure in failures:
            print(f"  {failure}")
        return 1
    byte_note = (
        f"{byte_checked} re-derived from pinned block bytes"
        if byte_checked
        else "pinned stale-blocks clone not fetched; byte checks skipped"
    )
    print(
        f"all {row_count} committed body-invalid stale overlay rows "
        f"validate ({byte_note})"
    )
    return 0
