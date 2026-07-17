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
from typing import Optional

from .auxpow_chainid import (
    hash_from_header_bytes,
    hash_to_display_hex,
)
from .bitcoin_binary import _varint, sha256d  # noqa: F401  (re-exported for callers)
from .coinbase_markers import parse_bip34_height

# Namecoin AuxPoW version flag (nVersion bit 8). Re-exported for the migrators
# that currently define ``VERSION_AUXPOW = 1 << 8`` locally.
VERSION_AUXPOW = 1 << 8


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
