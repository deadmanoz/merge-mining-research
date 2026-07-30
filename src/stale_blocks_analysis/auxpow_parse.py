"""Pure-stdlib CAuxPow / Bitcoin wire deserialisation.

This module consolidates the CAuxPow deserialiser that was copy-pasted across
~11 per-chain extract scripts (i0coin, ixcoin, devcoin, unobtanium, myriadcoin,
crown, argentum, bitmark, fractal, huntercoin) plus the segwit-aware
class-based reader in ``extract_bitcoin_vault_auxpow.py``.

The AuxPoW binary format is identical across all Namecoin-family chains
(the Vince Durham / Daniel Kraft specification). Only network magic bytes and
AuxPoW activation heights differ, and those belong to the chain scripts, not
here.

Conventions:
- Positional ``(buf, pos) -> (value, pos)`` cursor style throughout, built on
  ``bitcoin_binary._varint``.
- Byte order is always explicit. Display hex (RPC / explorer order) is produced
  with the helpers in ``auxpow_chainid``; raw ``[::-1]`` is never used here.

DEPLOYMENT CONSTRAINT: this module is imported by extract scripts that run on
package-less / NixOS hosts. It MUST remain importable with the Python standard
library plus intra-package pure helpers only. Do not add third-party imports
(no ``requests``, ``numpy``, etc.).
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from typing import Optional

from .auxpow_chainid import (
    hash_from_display_hex,
    hash_from_header_bytes,
    hash_to_display_hex,
)
from .bitcoin_binary import _varint, sha256d  # noqa: F401  (re-exported for callers)
from .coinbase_markers import parse_bip34_height

# Namecoin AuxPoW version flag (nVersion bit 8). Re-exported for the migrators
# that currently define ``VERSION_AUXPOW = 1 << 8`` locally.
VERSION_AUXPOW = 1 << 8

CHILD_HEADER_FIELDS = [
    "child_block_hash",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
]

PARENT_EVIDENCE_FIELDS = [
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_height",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
]


def standard_auxpow_extraction_columns(child_height_field: str) -> list[str]:
    """Return the uniform Bitcoin-family AuxPoW extraction schema."""
    return [child_height_field, *CHILD_HEADER_FIELDS, *PARENT_EVIDENCE_FIELDS]


class ChildHeaderValidationError(ValueError):
    """Raised when child-header evidence contradicts its source identity."""


# ---------------------------------------------------------------------------
# Bitcoin transaction deserialisation (segwit-aware)
# ---------------------------------------------------------------------------


def _read_txin(buf: bytes, pos: int) -> tuple[dict, int]:
    """Read one transaction input at ``pos``; return ``(txin_dict, new_pos)``."""
    prev_hash = buf[pos : pos + 32]
    pos += 32
    prev_idx = struct.unpack_from("<I", buf, pos)[0]
    pos += 4
    script_len, pos = _varint(buf, pos)
    scriptsig = buf[pos : pos + script_len]
    pos += script_len
    sequence = struct.unpack_from("<I", buf, pos)[0]
    pos += 4
    return {
        "prev_hash": prev_hash,
        "prev_idx": prev_idx,
        "scriptsig": scriptsig,
        "sequence": sequence,
    }, pos


def _read_txout(buf: bytes, pos: int) -> tuple[dict, int]:
    """Read one transaction output at ``pos``; return ``(txout_dict, new_pos)``."""
    value = struct.unpack_from("<Q", buf, pos)[0]
    pos += 8
    script_len, pos = _varint(buf, pos)
    pkscript = buf[pos : pos + script_len]
    pos += script_len
    return {"value": value, "pkscript": pkscript}, pos


def read_transaction(buf: bytes, pos: int) -> tuple[dict, int]:
    """Deserialise a Bitcoin transaction. Returns ``(tx_dict, new_pos)``.

    Segwit-aware: handles the BIP144 marker (0x00) + flag byte and skips the
    witness stack. The AuxPoW parent coinbase is conventionally non-segwit, but
    the format is handled defensively because explorer-sourced parent blocks
    (e.g. Bitcoin Vault) can carry witness data.

    The returned dict carries:
      ``version``, ``vin`` (list of input dicts), ``vout`` (list of output
      dicts), ``locktime``, ``has_witness`` (bool) and ``raw`` (the
      witness-inclusive serialised tx bytes as consumed from ``buf``).
    """
    tx_start = pos
    version = struct.unpack_from("<i", buf, pos)[0]
    pos += 4

    has_witness = False
    # Peek the segwit marker. A real input count is never 0x00, so a 0x00 here
    # with a non-zero flag byte unambiguously signals the BIP144 extension.
    if pos + 1 < len(buf) and buf[pos] == 0x00 and buf[pos + 1] != 0x00:
        pos += 2  # consume marker + flag
        has_witness = True

    vin_count, pos = _varint(buf, pos)
    vins = []
    for _ in range(vin_count):
        txin, pos = _read_txin(buf, pos)
        vins.append(txin)

    vout_count, pos = _varint(buf, pos)
    vouts = []
    for _ in range(vout_count):
        txout, pos = _read_txout(buf, pos)
        vouts.append(txout)

    if has_witness:
        for _ in range(vin_count):
            stack_count, pos = _varint(buf, pos)
            for _ in range(stack_count):
                item_len, pos = _varint(buf, pos)
                pos += item_len

    locktime = struct.unpack_from("<I", buf, pos)[0]
    pos += 4

    return {
        "version": version,
        "vin": vins,
        "vout": vouts,
        "locktime": locktime,
        "has_witness": has_witness,
        "raw": buf[tx_start:pos],
    }, pos


# ---------------------------------------------------------------------------
# AuxPoW deserialisation (Namecoin / Durham / Kraft spec)
# ---------------------------------------------------------------------------


def read_merkle_branch(buf: bytes, pos: int) -> tuple[list[bytes], int]:
    """Read a ``vMerkleBranch`` (varint count + that many 32-byte hashes)."""
    count, pos = _varint(buf, pos)
    hashes = []
    for _ in range(count):
        hashes.append(buf[pos : pos + 32])
        pos += 32
    return hashes, pos


def read_auxpow(buf: bytes, pos: int) -> tuple[dict, int]:
    """Deserialise a CAuxPow structure. Returns ``(auxpow_dict, new_pos)``.

    Serialisation order (from auxpow.h READWRITE macros):
      CMerkleTx:
        CTransaction          (the parent-chain coinbase tx)
        hashBlock             (32 bytes, conventionally zero)
        vMerkleBranch         (varint count + hashes)
        nIndex                (int32)
      CAuxPow tail:
        vChainMerkleBranch    (varint count + hashes)
        nChainIndex           (int32)
        parentBlock           (80-byte CPureBlockHeader)

    The returned dict carries the parsed ``coinbase_tx`` dict, the raw
    ``hash_block`` / merkle-branch / index fields, and the 80-byte
    ``parent_header_raw``.
    """
    coinbase_tx, pos = read_transaction(buf, pos)
    hash_block = buf[pos : pos + 32]
    pos += 32
    merkle_branch, pos = read_merkle_branch(buf, pos)
    merkle_index = struct.unpack_from("<i", buf, pos)[0]
    pos += 4

    chain_merkle_branch, pos = read_merkle_branch(buf, pos)
    chain_index = struct.unpack_from("<i", buf, pos)[0]
    pos += 4
    parent_header_raw = buf[pos : pos + 80]
    pos += 80

    return {
        "coinbase_tx": coinbase_tx,
        "hash_block": hash_block,
        "merkle_branch": merkle_branch,
        "merkle_index": merkle_index,
        "chain_merkle_branch": chain_merkle_branch,
        "chain_index": chain_index,
        "parent_header_raw": parent_header_raw,
    }, pos


# Alias matching the Bitcoin Vault / class-based reader vocabulary. Both names
# read the same CAuxPow tail; migrators using either spelling can converge here.
parse_auxpow_tail = read_auxpow


# ---------------------------------------------------------------------------
# Parent block header parsing
# ---------------------------------------------------------------------------


def parse_parent_header(raw80: bytes) -> dict:
    """Parse an 80-byte Bitcoin parent block header.

    Returns a dict with explicit byte-order semantics:
      ``version``     - int32 (signed)
      ``prev_hash``   - display-hex (RPC order) of hashPrevBlock
      ``merkle_root`` - display-hex (RPC order) of hashMerkleRoot
      ``time``        - uint32 unix timestamp
      ``bits``        - compact target as an int (big-endian value)
      ``bits_hex``    - the same compact target as 8-char hex
      ``nonce``       - uint32
      ``hash``        - display-hex (RPC order) header hash
      ``header_hex``  - the raw 80 bytes as hex
    """
    if len(raw80) != 80:
        raise ValueError("expected exactly 80 header bytes")
    version = struct.unpack_from("<i", raw80, 0)[0]
    prev_hash = hash_to_display_hex(raw80[4:36])
    merkle_root = hash_to_display_hex(raw80[36:68])
    timestamp = struct.unpack_from("<I", raw80, 68)[0]
    bits = struct.unpack_from("<I", raw80, 72)[0]
    nonce = struct.unpack_from("<I", raw80, 76)[0]
    header_hash_internal = hash_from_header_bytes(raw80)
    return {
        "version": version,
        "prev_hash": prev_hash,
        "merkle_root": merkle_root,
        "time": timestamp,
        "bits": bits,
        "bits_hex": f"{bits:08x}",
        "nonce": nonce,
        "hash": hash_to_display_hex(header_hash_internal),
        "header_hex": raw80.hex(),
    }


def parse_child_header(
    raw80: bytes,
    *,
    expected_hash_display: str | None = None,
    nbits: int | None = None,
) -> dict:
    """Return normalized child-chain evidence from an authenticated header.

    ``child_block_hash`` is the internal/wire-order double-SHA256 digest used
    by the evidence-export contract. ``expected_hash_display``, when supplied,
    is the independent RPC or archive hash in display order. ``nbits``
    overrides the header field only for formats such as Xaya, where the
    effective PoW target lives in the adjacent ``PowData`` wrapper.
    """
    parsed = parse_parent_header(raw80)
    if expected_hash_display is not None:
        expected = expected_hash_display.strip().lower()
        if len(expected) != 64:
            raise ChildHeaderValidationError(
                "expected child block hash must be 32-byte hex"
            )
        try:
            bytes.fromhex(expected)
        except ValueError as exc:
            raise ChildHeaderValidationError(
                "expected child block hash must be 32-byte hex"
            ) from exc
        if parsed["hash"] != expected:
            raise ChildHeaderValidationError(
                "child header hash mismatch: "
                f"computed={parsed['hash']} source={expected}"
            )

    effective_nbits = parsed["bits"] if nbits is None else nbits
    # bool is an int subclass, so reject it before accepting integer targets.
    if isinstance(effective_nbits, bool) or not isinstance(effective_nbits, int):
        raise ChildHeaderValidationError("child nBits must be an integer")
    if not 0 <= effective_nbits <= 0xFFFFFFFF:
        raise ChildHeaderValidationError("child nBits is outside the uint32 range")

    return {
        "child_block_hash": hash_from_header_bytes(raw80).hex(),
        "child_header_hex": parsed["header_hex"],
        "child_block_time": parsed["time"],
        "child_nbits": f"{effective_nbits:08x}",
    }


def validate_child_header_fields(
    row: Mapping[str, object],
    *,
    nbits_from_header: bool = True,
) -> dict:
    """Validate and normalize a complete four-field child-header bundle.

    This accepts values decoded directly from a block as well as CSV strings.
    Serialization-specific gates may additionally require an exact unpadded
    representation before publishing an artifact.
    """
    values = _child_header_values(row)
    missing = [field for field, value in values.items() if not value]
    if missing:
        raise ChildHeaderValidationError(
            "incomplete child header evidence: missing " + ", ".join(missing)
        )
    raw80, child_time, nbits_value = _validate_child_header_encodings(values)
    assert raw80 is not None
    assert child_time is not None
    assert nbits_value is not None
    _validate_external_child_nbits(
        raw80,
        nbits_value,
        nbits_from_header=nbits_from_header,
    )
    expected = parse_child_header(
        raw80,
        nbits=None if nbits_from_header else nbits_value,
    )
    _validate_child_header_relationships(values, expected)
    return expected


def validate_available_child_header_fields(
    row: Mapping[str, object],
    *,
    nbits_from_header: bool = True,
) -> dict[str, str]:
    """Validate every populated field in a possibly partial child bundle.

    Sources outside the historical hydration set do not all expose the complete
    four-field contract. Each available value still uses the publication
    encoding, and an available serialized header authenticates every other
    populated field.
    """
    values = _child_header_values(row)
    raw80, _child_time, nbits_value = _validate_child_header_encodings(values)
    _validate_external_child_nbits(
        raw80,
        nbits_value,
        nbits_from_header=nbits_from_header,
    )
    if raw80 is not None:
        expected = parse_child_header(
            raw80,
            nbits=(
                nbits_value
                if not nbits_from_header and nbits_value is not None
                else None
            ),
        )
        _validate_child_header_relationships(values, expected)
    return {field: value for field, value in values.items() if value}


def _validate_external_child_nbits(
    raw80: bytes | None,
    nbits_value: int | None,
    *,
    nbits_from_header: bool,
) -> None:
    """Enforce the Xaya-style external-target invariants when evidence exists."""
    if nbits_from_header:
        return
    if raw80 is not None and struct.unpack_from("<I", raw80, 72)[0] != 0:
        raise ChildHeaderValidationError(
            "child header nBits must be zero when effective nBits is external"
        )
    if nbits_value == 0:
        raise ChildHeaderValidationError("external child nBits must be non-zero")


def _child_header_values(row: Mapping[str, object]) -> dict[str, str]:
    """Return stripped string values for the canonical child-header fields."""
    return {field: str(row.get(field, "")).strip() for field in CHILD_HEADER_FIELDS}


def _validate_child_header_encodings(
    values: Mapping[str, str],
) -> tuple[bytes | None, int | None, int | None]:
    """Validate populated child fields and return their parsed wire values."""
    child_hash = values["child_block_hash"]
    if child_hash and (len(child_hash) != 64 or child_hash != child_hash.lower()):
        raise ChildHeaderValidationError(
            "child_block_hash must be exactly 32-byte lowercase hex"
        )
    if child_hash:
        try:
            int(child_hash, 16)
        except ValueError as exc:
            raise ChildHeaderValidationError(
                "child_block_hash must be exactly 32-byte lowercase hex"
            ) from exc

    child_header_hex = values["child_header_hex"]
    if child_header_hex and len(child_header_hex) != 160:
        raise ChildHeaderValidationError("child_header_hex must be exactly 80 bytes")
    if child_header_hex and child_header_hex != child_header_hex.lower():
        raise ChildHeaderValidationError("child_header_hex must be lowercase hex")

    child_time_text = values["child_block_time"]
    if child_time_text and (
        not child_time_text.isascii()
        or not child_time_text.isdigit()
        or len(child_time_text) > 10
    ):
        raise ChildHeaderValidationError(
            "child_block_time must be an unsigned decimal uint32"
        )

    child_nbits = values["child_nbits"]
    if child_nbits and len(child_nbits) != 8:
        raise ChildHeaderValidationError("child_nbits must be exactly 4-byte hex")
    if child_nbits and child_nbits != child_nbits.lower():
        raise ChildHeaderValidationError("child_nbits must be lowercase hex")

    raw80 = None
    child_time = None
    nbits_value = None
    try:
        if child_header_hex:
            raw80 = bytes.fromhex(child_header_hex)
        if child_nbits:
            nbits_value = int(child_nbits, 16)
        if child_time_text:
            child_time = int(child_time_text)
    except ValueError as exc:
        raise ChildHeaderValidationError(
            "child header fields contain malformed numeric or hex data"
        ) from exc
    if child_time is not None and child_time > 0xFFFFFFFF:
        raise ChildHeaderValidationError(
            "child_block_time must be an unsigned decimal uint32"
        )
    if child_time is not None and str(child_time) != child_time_text:
        raise ChildHeaderValidationError(
            "child_block_time must use the exact unpadded decimal representation"
        )
    return raw80, child_time, nbits_value


def _validate_child_header_relationships(
    values: Mapping[str, str], expected: Mapping[str, object]
) -> None:
    """Authenticate populated decoded values against a parsed header."""
    if values["child_block_hash"] and (
        values["child_block_hash"] != expected["child_block_hash"]
    ):
        raise ChildHeaderValidationError(
            "child_header_hex does not match child_block_hash"
        )
    if values["child_block_time"] and (
        int(values["child_block_time"]) != expected["child_block_time"]
    ):
        raise ChildHeaderValidationError(
            "child_header_hex does not match child_block_time"
        )
    if values["child_nbits"] and values["child_nbits"] != expected["child_nbits"]:
        raise ChildHeaderValidationError("child header does not match child_nbits")


def serialize_block_header(
    *,
    version: int,
    previous_block_hash: str,
    merkle_root: str,
    timestamp: int,
    bits: int | str,
    nonce: int,
) -> bytes:
    """Serialize decoded Bitcoin-shaped header fields into 80 wire bytes."""
    if isinstance(bits, str):
        if len(bits) != 8 or bits != bits.lower():
            raise ValueError("bits must be exactly eight lowercase hex characters")
        try:
            bits_value = int(bits, 16)
        except ValueError as exc:
            raise ValueError(
                "bits must be exactly eight lowercase hex characters"
            ) from exc
    else:
        bits_value = bits
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or not -(1 << 31) <= version <= 0xFFFFFFFF
    ):
        raise ValueError("header version must fit signed or unsigned uint32")
    # Signed int32 versions and their uint32 forms intentionally serialize to
    # the same two's-complement wire bytes.
    uint32_fields = {
        "version": version & 0xFFFFFFFF,
        "timestamp": timestamp,
        "bits": bits_value,
        "nonce": nonce,
    }
    if any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 0xFFFFFFFF
        for value in uint32_fields.values()
    ):
        raise ValueError("header numeric fields must fit uint32")
    return (
        struct.pack("<I", uint32_fields["version"])
        + hash_from_display_hex(previous_block_hash)
        + hash_from_display_hex(merkle_root)
        + struct.pack("<I", uint32_fields["timestamp"])
        + struct.pack("<I", uint32_fields["bits"])
        + struct.pack("<I", uint32_fields["nonce"])
    )


# ---------------------------------------------------------------------------
# Proof-of-work / difficulty helpers
# ---------------------------------------------------------------------------


def nbits_to_target(bits: int) -> int:
    """Expand a compact ``nBits`` value into the full 256-bit target integer.

    Mirrors Bitcoin Core's ``CBigNum::SetCompact``: the top byte is the
    base-256 exponent, the low 23 bits are the mantissa, and bit 0x800000 is a
    sign bit (never set for real targets).
    """
    exp = bits >> 24
    mant = bits & 0x7FFFFF
    if bits & 0x800000:
        mant = -mant
    if exp <= 3:
        return mant >> (8 * (3 - exp))
    return mant << (8 * (exp - 3))


def hash_meets_btc_difficulty(header_hash_internal: bytes, bits: int) -> bool:
    """Return True if a header hash satisfies the ``bits`` target.

    ``header_hash_internal`` is the internal-order (little-endian display)
    32-byte hash, i.e. the direct ``sha256d`` output as returned by
    ``auxpow_chainid.hash_from_header_bytes``. The numeric comparison uses the
    big-endian integer value of that hash, matching how Bitcoin Core interprets
    ``uint256`` targets.
    """
    if len(header_hash_internal) != 32:
        raise ValueError("expected exactly 32 hash bytes")
    target = nbits_to_target(bits)
    if target <= 0:
        return False
    # Internal order is little-endian; the numeric hash value is big-endian.
    hash_int = int.from_bytes(header_hash_internal, "little")
    return hash_int <= target


def parse_coinbase_height(scriptsig: bytes) -> Optional[int]:
    """Return the BIP34 height encoded in a coinbase scriptSig, or None.

    Thin wrapper delegating to ``coinbase_markers.parse_bip34_height`` (a proper
    CScriptNum decode) so the extract scripts have a single import surface.
    """
    return parse_bip34_height(scriptsig)
