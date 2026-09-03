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
4. when any transaction carries witness data, the BIP141 witness commitment
   re-derives (the wtxid merkle root plus the coinbase witness reserved
   value hash to the coinbase's ``6a24aa21a9ed`` commitment output), since
   the txid tree does not cover witness bytes and the attested excess lives
   precisely in witness-path sigops;
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
from stale_blocks_analysis.bitcoin_binary import _varint, sha256d
from stale_blocks_analysis.config import (
    ACCEPTED_STALE_VALIDATION_STATUSES,
    BLOCKS_DIR,
    BODY_INVALID_STALES_CSV,
    ERROR_BLOCKS_CSV,
    VALIDATED_STALES_DIR,
)
from stale_blocks_analysis.error_block_validation import RULE_GATES, TIME_RULES
from stale_blocks_analysis.error_blocks import load_error_block_keys

MAX_BLOCK_SIGOPS_COST = 80_000
WITNESS_SCALE_FACTOR = 4
_MAX_PUBKEYS_PER_MULTISIG = 20

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

_OP_PUSHDATA1 = 0x4C
_OP_PUSHDATA2 = 0x4D
_OP_PUSHDATA4 = 0x4E
_OP_CHECKSIG = 0xAC
_OP_CHECKSIGVERIFY = 0xAD
_OP_CHECKMULTISIG = 0xAE
_OP_CHECKMULTISIGVERIFY = 0xAF


def count_legacy_sigops_in_script(script: bytes) -> int:
    """Count legacy sigops in one script (``CScript::GetSigOpCount(false)``).

    CHECKSIG/CHECKSIGVERIFY count 1; CHECKMULTISIG/CHECKMULTISIGVERIFY count
    the 20-key maximum (the inaccurate mode Core uses for the block-wide
    legacy count). A truncated push ends the walk with the count so far,
    matching Core's ``GetOp`` loop.
    """
    count = 0
    pos = 0
    end = len(script)
    while pos < end:
        opcode = script[pos]
        pos += 1
        if opcode <= 0x4B:
            pos += opcode
        elif opcode == _OP_PUSHDATA1:
            if pos + 1 > end:
                break
            pos += 1 + script[pos]
        elif opcode == _OP_PUSHDATA2:
            if pos + 2 > end:
                break
            pos += 2 + int.from_bytes(script[pos : pos + 2], "little")
        elif opcode == _OP_PUSHDATA4:
            if pos + 4 > end:
                break
            pos += 4 + int.from_bytes(script[pos : pos + 4], "little")
        elif opcode in (_OP_CHECKSIG, _OP_CHECKSIGVERIFY):
            count += 1
        elif opcode in (_OP_CHECKMULTISIG, _OP_CHECKMULTISIGVERIFY):
            count += _MAX_PUBKEYS_PER_MULTISIG
    return count


def _transaction_at(
    raw: bytes, pos: int, *, capture_coinbase: bool = False
) -> tuple[int, bytes, bytes, list[bytes] | None, bytes | None, int]:
    """Walk one transaction; return its evidence fields and the new position.

    Returns ``(legacy_sigops, txid, wtxid, coinbase_output_scripts,
    witness_reserved_value, new_pos)``. The txid is the sha256d of the
    transaction's LEGACY serialization (version, inputs, outputs, locktime --
    excluding any segwit marker, flag, and witness data); the wtxid is the
    sha256d of the FULL serialization (equal to the txid for a non-segwit
    transaction). Both are internal byte order, ready for merkle-tree use.
    ``capture_coinbase`` additionally collects the output scriptPubKeys and
    the first witness stack item of the first input (BIP141's witness
    reserved value) for the coinbase commitment check.
    """
    start = pos
    pos += 4  # nVersion
    is_segwit = raw[pos] == 0x00 and raw[pos + 1] == 0x01
    if is_segwit:
        pos += 2  # marker + flag
    body_start = pos
    vin_count, pos = _varint(raw, pos)
    count = 0
    for _ in range(vin_count):
        pos += 36  # outpoint
        script_len, pos = _varint(raw, pos)
        if pos + script_len > len(raw):
            raise ValueError("truncated input scriptSig")
        count += count_legacy_sigops_in_script(raw[pos : pos + script_len])
        pos += script_len + 4  # script + nSequence
    vout_count, pos = _varint(raw, pos)
    output_scripts: list[bytes] | None = [] if capture_coinbase else None
    for _ in range(vout_count):
        pos += 8  # value
        script_len, pos = _varint(raw, pos)
        if pos + script_len > len(raw):
            raise ValueError("truncated output scriptPubKey")
        script = raw[pos : pos + script_len]
        count += count_legacy_sigops_in_script(script)
        if output_scripts is not None:
            output_scripts.append(script)
        pos += script_len
    body_end = pos
    witness_reserved: bytes | None = None
    if is_segwit:
        for vin_index in range(vin_count):
            item_count, pos = _varint(raw, pos)
            for item_index in range(item_count):
                item_len, pos = _varint(raw, pos)
                if pos + item_len > len(raw):
                    raise ValueError("truncated witness item")
                if capture_coinbase and vin_index == 0 and item_index == 0:
                    witness_reserved = raw[pos : pos + item_len]
                pos += item_len
    locktime_start = pos
    pos += 4  # nLockTime
    if pos > len(raw):
        raise ValueError("truncated transaction")
    txid = sha256d(
        raw[start : start + 4]
        + raw[body_start:body_end]
        + raw[locktime_start : locktime_start + 4]
    )
    wtxid = sha256d(raw[start:pos]) if is_segwit else txid
    return count, txid, wtxid, output_scripts, witness_reserved, pos


def _merkle_root(txids: list[bytes]) -> bytes:
    """Fold internal-order txids into the block merkle root (Core's rule).

    Rejects the CVE-2012-2459 mutation: duplicating the final element of an
    odd-length level yields the SAME root as the unduplicated list, so a
    substituted body with appended duplicate transactions would otherwise
    still merkle-authenticate while changing the derived sigop count. Core
    flags an equal adjacent pair at any level (scanned before its own
    odd-level padding) as a mutated block; mirror that by failing closed.
    """
    level = txids
    while len(level) > 1:
        for index in range(0, len(level) - 1, 2):
            if level[index] == level[index + 1]:
                raise ValueError(
                    "mutated merkle tree (duplicated subtree, CVE-2012-2459)"
                )
        if len(level) % 2 == 1:
            level = [*level, level[-1]]
        level = [
            sha256d(level[index] + level[index + 1])
            for index in range(0, len(level), 2)
        ]
    return level[0]


_WITNESS_COMMITMENT_PREFIX = bytes.fromhex("6a24aa21a9ed")


def _witness_commitment_error(
    wtxids: list[bytes],
    coinbase_outputs: list[bytes],
    witness_reserved: bytes | None,
) -> str | None:
    """Re-derive the BIP141 witness commitment, or explain why it fails.

    The legacy txid merkle root does not cover witness bytes, so a body with
    altered witness data (and a matching updated ``block_sha256``) would still
    txid-merkle-authenticate while changing exactly the witness-path sigops
    these rows attribute the excess to. When any transaction carries witness
    data, Bitcoin requires the coinbase to commit to the wtxid merkle tree:
    the commitment is sha256d(witness merkle root || witness reserved value),
    where the coinbase's wtxid leaf is 32 zero bytes and the reserved value is
    the coinbase's sole 32-byte witness stack item, and it must appear in the
    LAST coinbase output whose scriptPubKey begins ``6a24aa21a9ed`` (Core's
    ``GetWitnessCommitmentIndex`` scan). The caller only invokes this when
    some transaction carries witness data.
    """
    commitment_script = None
    for script in coinbase_outputs:
        if len(script) >= 38 and script.startswith(_WITNESS_COMMITMENT_PREFIX):
            commitment_script = script
    if commitment_script is None:
        return "block carries witness data but no coinbase witness commitment"
    if witness_reserved is None or len(witness_reserved) != 32:
        return "coinbase witness reserved value is missing or not 32 bytes"
    witness_root = _merkle_root([b"\x00" * 32, *wtxids[1:]])
    commitment = sha256d(witness_root + witness_reserved)
    if commitment_script[6:38] != commitment:
        return "witness data does not authenticate against the coinbase commitment"
    return None


def parse_block_body(raw: bytes) -> tuple[int, bytes]:
    """Walk a serialized block; return (legacy sigops, derived merkle root).

    The sigop count sums ``count_legacy_sigops_in_script`` over every
    transaction's input scriptSigs and output scriptPubKeys -- the portion of
    Bitcoin Core's block sigop cost that is derivable from the block bytes
    alone. The P2SH and witness portions need the spent prevout scripts and
    are deliberately out of scope. The merkle root is derived from the
    transactions' legacy txids so a caller can authenticate the body against
    header bytes 36-68; ``authenticate_block_body`` additionally verifies the
    BIP141 witness commitment.
    """
    total, merkle_root, _witness_error = _walk_block(raw)
    return total, merkle_root


def authenticate_block_body(raw: bytes) -> tuple[int, list[str]]:
    """Fully authenticate a block body; return (legacy sigops, failures).

    Checks both the legacy txid merkle root against header bytes 36-68 and,
    when any transaction carries witness data, the BIP141 witness commitment
    (see ``_witness_commitment_error``). A body that fails either check must
    not be treated as re-derived evidence for the header.
    """
    total, merkle_root, witness_error = _walk_block(raw)
    failures: list[str] = []
    if merkle_root != raw[36:68]:
        failures.append(
            "pinned block file's transactions do not merkle-authenticate "
            "against its header"
        )
    if witness_error is not None:
        failures.append(f"pinned block file's {witness_error}")
    return total, failures


def _walk_block(raw: bytes) -> tuple[int, bytes, str | None]:
    """Walk every transaction; return (sigops, txid merkle root, witness error)."""
    if len(raw) < 81:
        raise ValueError("serialized block shorter than header plus tx count")
    pos = 80
    tx_count, pos = _varint(raw, pos)
    if tx_count == 0:
        raise ValueError("serialized block carries no transactions")
    total = 0
    txids: list[bytes] = []
    wtxids: list[bytes] = []
    coinbase_outputs: list[bytes] = []
    witness_reserved: bytes | None = None
    has_witness = False
    for tx_index in range(tx_count):
        capture = tx_index == 0
        sigops, txid, wtxid, outputs, reserved, pos = _transaction_at(
            raw, pos, capture_coinbase=capture
        )
        total += sigops
        txids.append(txid)
        wtxids.append(wtxid)
        if wtxid != txid:
            # A wtxid differing from the txid means the segwit serialization
            # (marker, flag, witness section) is present, coinbase included.
            has_witness = True
        if capture:
            coinbase_outputs = outputs or []
            witness_reserved = reserved
    if pos != len(raw):
        raise ValueError("trailing bytes after the final transaction")
    witness_error = (
        _witness_commitment_error(wtxids, coinbase_outputs, witness_reserved)
        if has_witness
        else None
    )
    return total, _merkle_root(txids), witness_error


def count_block_legacy_sigops(raw: bytes) -> int:
    """Count a serialized block's embedded legacy sigops (see parse_block_body)."""
    total, _merkle = parse_block_body(raw)
    return total


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
