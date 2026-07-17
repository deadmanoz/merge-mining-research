"""Child-side AuxPoW chain-ID inference helpers.

Namecoin-style AuxPoW commitments use a miner-chosen nonce and a deterministic
LCG to map each child chain ID into one slot of the chain-merkle tree.  Given
only a child proof, the LCG recovers ``chain_id mod 2^branch_len``.  That is a
candidate filter, not a complete chain-ID recovery mechanism.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Iterable

from .auxpow_registry import AuxPoWChain, CHAINS
from .bitcoin_binary import sha256d as _sha256d
from .coinbase_markers import AUXPOW_MAGIC, parse_auxpow_marker

LCG_MULTIPLIER = 1103515245
LCG_INCREMENT = 12345
UINT32_MASK = 0xFFFFFFFF

SIZE_MATCHED = "matched"
LEGACY_SINGLE_SLOT_VERIFIED = "legacy_single_slot_verified"
LEGACY_SINGLE_SLOT_UNVERIFIED = "legacy_single_slot_unverified"
MISSING_PARENT_COMMITMENT = "missing_parent_commitment"
ZERO_SIZE_BRANCH_MISMATCH = "zero_size_branch_mismatch"
NON_POWER_OF_TWO_SIZE = "non_power_of_two_size"
SIZE_BRANCH_MISMATCH = "size_branch_mismatch"
INVALID_NEGATIVE_SIZE = "invalid_negative_size"
CENSUS_ONLY_SIZE_WITHOUT_BRANCH = "census_only_size_without_branch"

INFERABLE_SIZE_STATUSES = {SIZE_MATCHED, LEGACY_SINGLE_SLOT_VERIFIED}


@dataclass(frozen=True)
class ParentCommitment:
    merkle_root: bytes | None
    merkle_size: int | None
    merkle_nonce: int | None
    source: str
    auxpow_offset: int | None = None
    census_height: int | None = None
    census_block_time: str | None = None


def _validate_hex64(hex64: str) -> str:
    """Return ``hex64`` unchanged if it is a 64-character hex string, else raise ``ValueError``."""
    if len(hex64) != 64:
        raise ValueError("expected a 64-character hex string")
    try:
        bytes.fromhex(hex64)
    except ValueError as exc:
        raise ValueError("expected hexadecimal characters") from exc
    return hex64


def _validate_hash_bytes(raw32: bytes) -> bytes:
    """Return ``raw32`` unchanged if it is exactly 32 bytes, else raise ``ValueError``."""
    if len(raw32) != 32:
        raise ValueError("expected exactly 32 hash bytes")
    return raw32


def hash_from_header_bytes(raw80: bytes) -> bytes:
    """Return the internal-order 32-byte hash of an 80-byte block header."""
    if len(raw80) != 80:
        raise ValueError("expected exactly 80 header bytes")
    return _sha256d(raw80)


def hash_from_display_hex(hex64: str) -> bytes:
    """Decode Bitcoin display hex into internal-order bytes."""
    return bytes.fromhex(_validate_hex64(hex64))[::-1]


def hash_from_display_bytes(raw32: bytes) -> bytes:
    """Decode display-order hash bytes into internal-order bytes."""
    return _validate_hash_bytes(raw32)[::-1]


def hash_from_internal_hex(hex64: str) -> bytes:
    """Decode an internal-order hex string without reversing it."""
    return bytes.fromhex(_validate_hex64(hex64))


def hash_from_internal_bytes(raw32: bytes) -> bytes:
    """Validate and pass through internal-order hash bytes."""
    return _validate_hash_bytes(raw32)


def hash_to_display_hex(hash_internal: bytes) -> str:
    """Encode an internal-order hash as display-order (RPC order) lowercase hex."""
    return _validate_hash_bytes(hash_internal)[::-1].hex()


def hash_to_internal_hex(hash_internal: bytes) -> str:
    """Encode an internal-order hash as internal-order lowercase hex, unreversed."""
    return _validate_hash_bytes(hash_internal).hex()


def auxpow_lcg_index(merkle_nonce: int, chain_id: int, branch_len: int) -> int:
    """Return Namecoin's expected chain-merkle slot for ``chain_id``.

    This mirrors the unsigned 32-bit arithmetic in the Namecoin/Daniel Kraft
    AuxPoW code before reducing by ``2^branch_len``.
    """
    if branch_len < 0:
        raise ValueError("branch_len must be non-negative")
    if merkle_nonce < 0 or merkle_nonce > UINT32_MASK:
        raise ValueError("merkle_nonce must fit in uint32")
    if chain_id < 0:
        raise ValueError("chain_id must be non-negative")
    if branch_len == 0:
        return 0
    rand = merkle_nonce & UINT32_MASK
    rand = (rand * LCG_MULTIPLIER + LCG_INCREMENT) & UINT32_MASK
    rand = (rand + chain_id) & UINT32_MASK
    rand = (rand * LCG_MULTIPLIER + LCG_INCREMENT) & UINT32_MASK
    return rand % (1 << branch_len)


def lcg_chain_id_residue(merkle_nonce: int, chain_index: int, branch_len: int) -> int:
    """Recover ``chain_id mod 2^branch_len`` from a child proof."""
    if branch_len < 0:
        raise ValueError("branch_len must be non-negative")
    if merkle_nonce < 0 or merkle_nonce > UINT32_MASK:
        raise ValueError("merkle_nonce must fit in uint32")
    if chain_index < 0:
        raise ValueError("chain_index must be non-negative")
    modulus = 1 << branch_len
    if modulus == 1:
        return 0
    if chain_index >= modulus:
        raise ValueError("chain_index must be less than 2^branch_len")
    rand1 = (merkle_nonce * LCG_MULTIPLIER + LCG_INCREMENT) % modulus
    inv = pow(LCG_MULTIPLIER % modulus, -1, modulus)
    return (inv * ((chain_index - LCG_INCREMENT) % modulus) - rand1) % modulus


def candidate_chains_for_residue(
    residue: int,
    branch_len: int,
    registry: Iterable[AuxPoWChain] = CHAINS,
) -> tuple[AuxPoWChain, ...]:
    """Return every ``registry`` chain whose ID is congruent to ``residue`` mod ``2**branch_len``.

    This is a candidate filter, not a unique identification: several chains
    can share the same residue.
    """
    modulus = 1 << branch_len
    if residue < 0 or residue >= modulus:
        raise ValueError("residue must be in [0, 2^branch_len)")
    return tuple(chain for chain in registry if chain.chain_id % modulus == residue)


def fold_merkle_branch(
    leaf_hash_internal: bytes,
    branch_hashes_internal: Iterable[bytes],
    index: int,
) -> bytes:
    """Fold a Bitcoin-style merkle branch using internal-order hashes."""
    if index < 0:
        raise ValueError("index must be non-negative")
    current = _validate_hash_bytes(leaf_hash_internal)
    n = index
    for sibling in branch_hashes_internal:
        sibling = _validate_hash_bytes(sibling)
        if n & 1:
            current = _sha256d(sibling + current)
        else:
            current = _sha256d(current + sibling)
        n >>= 1
    return current


def is_power_of_two(value: int) -> bool:
    """Return True if ``value`` is a positive power of two."""
    return value > 0 and value & (value - 1) == 0


def commitment_size_status(
    merkle_size: int | None,
    branch_len: int | None,
) -> str:
    """Classify a parent commitment's declared merkle tree size against a proof's branch length.

    Returns one of the module-level status constants: ``MISSING_PARENT_COMMITMENT``
    when ``merkle_size`` is unknown, ``INVALID_NEGATIVE_SIZE`` when it is
    negative, ``LEGACY_SINGLE_SLOT_UNVERIFIED``/``CENSUS_ONLY_SIZE_WITHOUT_BRANCH``
    when ``branch_len`` is unknown, ``LEGACY_SINGLE_SLOT_VERIFIED`` for a
    zero-size/zero-branch legacy single-chain commitment,
    ``ZERO_SIZE_BRANCH_MISMATCH`` for a zero size against a non-zero branch,
    ``SIZE_MATCHED`` when ``merkle_size == 2**branch_len``,
    ``NON_POWER_OF_TWO_SIZE`` for a non-power-of-two size, or
    ``SIZE_BRANCH_MISMATCH`` for any other power-of-two mismatch.
    """
    if merkle_size is None:
        return MISSING_PARENT_COMMITMENT
    if merkle_size < 0:
        return INVALID_NEGATIVE_SIZE
    if branch_len is None:
        if merkle_size == 0:
            return LEGACY_SINGLE_SLOT_UNVERIFIED
        return CENSUS_ONLY_SIZE_WITHOUT_BRANCH
    if branch_len < 0:
        raise ValueError("branch_len must be non-negative")
    if merkle_size == 0 and branch_len == 0:
        return LEGACY_SINGLE_SLOT_VERIFIED
    if merkle_size == 0:
        return ZERO_SIZE_BRANCH_MISMATCH
    expected_size = 1 << branch_len
    if merkle_size == expected_size:
        return SIZE_MATCHED
    if not is_power_of_two(merkle_size):
        return NON_POWER_OF_TWO_SIZE
    return SIZE_BRANCH_MISMATCH


def size_status_allows_inference(status: str) -> bool:
    """Return True if ``status`` (from ``commitment_size_status``) is precise
    enough to infer the chain-merkle branch length.
    """
    return status in INFERABLE_SIZE_STATUSES


def commitment_from_embedded_scriptsig(scriptsig: bytes) -> ParentCommitment:
    """Parse the AuxPoW merge-mining marker out of a raw coinbase ``scriptsig``.

    Returns a ``ParentCommitment`` with ``source="embedded"`` on success, or
    a commitment with no merkle fields and ``source`` set to
    ``"embedded_no_magic_unparsed"``/``"embedded_magic_truncated"`` when the
    magic is absent or the marker is truncated.
    """
    marker = parse_auxpow_marker(scriptsig)
    if marker is None:
        source = (
            "embedded_no_magic_unparsed"
            if scriptsig.find(AUXPOW_MAGIC) < 0
            else "embedded_magic_truncated"
        )
        return ParentCommitment(
            merkle_root=None,
            merkle_size=None,
            merkle_nonce=None,
            source=source,
        )
    return ParentCommitment(
        merkle_root=hash_from_display_bytes(marker.merkle_root),
        merkle_size=marker.merkle_size,
        merkle_nonce=marker.merkle_nonce,
        source="embedded",
        auxpow_offset=marker.offset,
    )


def census_commitment_for_parent(
    conn: sqlite3.Connection | Mapping[bytes, ParentCommitment],
    parent_header_hash_internal: bytes,
) -> ParentCommitment | None:
    """Look up a parent header's AuxPoW commitment in a supplied marker census.

    ``conn`` may be a live ``coinbase_mergemining_v1`` SQLite connection or a
    pre-built ``{internal_hash: ParentCommitment}`` mapping (for tests).
    Returns ``None`` if the parent hash is not in the census; returns a
    ``source="census_no_auxpow"`` commitment with no merkle fields if the
    census recorded the parent as carrying no AuxPoW marker; otherwise
    returns a ``source="census"`` commitment.
    """
    _validate_hash_bytes(parent_header_hash_internal)
    if isinstance(conn, Mapping):
        return conn.get(parent_header_hash_internal)

    row = conn.execute(
        """
        SELECT block_height, block_time, auxpow_present, auxpow_merkle_root,
               auxpow_merkle_size, auxpow_merkle_nonce, auxpow_offset
        FROM coinbase_mergemining_v1
        WHERE block_hash = ?
        """,
        (parent_header_hash_internal,),
    ).fetchone()
    if row is None:
        return None
    height, block_time, present, root, size, nonce, offset = row
    if not present:
        return ParentCommitment(
            merkle_root=None,
            merkle_size=None,
            merkle_nonce=None,
            source="census_no_auxpow",
            census_height=height,
            census_block_time=block_time,
        )
    return ParentCommitment(
        merkle_root=hash_from_display_bytes(bytes(root)) if root is not None else None,
        merkle_size=size,
        merkle_nonce=nonce,
        source="census",
        auxpow_offset=offset,
        census_height=height,
        census_block_time=block_time,
    )


def parent_commitment_for_proof(
    conn: sqlite3.Connection | Mapping[bytes, ParentCommitment] | None,
    parent_header_hash_internal: bytes,
    embedded_parent_coinbase_scriptsig: bytes,
) -> ParentCommitment:
    """Resolve a commitment, preferring a supplied census over the embedded scriptSig.

    Tries ``census_commitment_for_parent`` first when ``conn`` is given and
    has a matching row; otherwise falls back to
    ``commitment_from_embedded_scriptsig`` on ``embedded_parent_coinbase_scriptsig``.
    """
    if conn is not None:
        census = census_commitment_for_parent(conn, parent_header_hash_internal)
        if census is not None:
            return census
    return commitment_from_embedded_scriptsig(embedded_parent_coinbase_scriptsig)
