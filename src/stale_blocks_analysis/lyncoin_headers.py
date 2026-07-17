"""Fail-closed parsing and validation for Lyncoin's raw P2P header stream.

Lyncoin serialises the full Namecoin-family ``CAuxPow`` object as part of a
``CBlockHeader``.  Consequently a ``headers`` P2P response contains all of the
Bitcoin-parent evidence needed by the stale-block classifier, without waiting
for the child block bodies.  This module owns the bounded wire parser and the
pre-Flex consensus checks used by the recovery client.

The constants below are pinned to Lyncoin Core v4.0.0 source commit
``c289540da7ea3bb78f6e9eb661ad72b90476cc40``.  The supported recovery range is
height 0 through 260,499.  Height 260,500 activates the Flex hash family, which
is deliberately retained only as a one-header boundary proof.

This module is pure stdlib plus the package's existing pure helpers.  Keep it
safe to import on package-light recovery hosts.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Any

from .auxpow_chainid import auxpow_lcg_index, fold_merkle_branch
from .bitcoin_binary import sha256d
from .auxpow_parse import (
    VERSION_AUXPOW,
    hash_meets_btc_difficulty,
    parse_coinbase_height,
    parse_parent_header,
)

SOURCE_COMMIT = "c289540da7ea3bb78f6e9eb661ad72b90476cc40"
SOURCE_URL = f"https://github.com/lyncoin/lyncoin/tree/{SOURCE_COMMIT}"

NETWORK_MAGIC = bytes.fromhex("52030e2f")
DEFAULT_PORT = 5054
PROTOCOL_VERSION = 110_016
NODE_NETWORK = 1
MAX_HEADERS_RESULTS = 2_000
MAX_MESSAGE_PAYLOAD = 64 * 1024 * 1024

CHAIN_ID = 0x0B0D
FLEX_VERSION_FLAG = 0x8000
FLEX_HEIGHT = 260_500
AUXPOW_END_HEIGHT = FLEX_HEIGHT - 1
FLEX_BITS = 0x2000FFFF

POW_LIMIT = int("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
POW_LIMIT_BITS = 0x2000FFFF
N2023_HEIGHT = 48_950
N2023_BITS = 0x1908CF19
N2023_WINDOW = 10
N2023_TIMESPAN = 6_000
N2023_HEIGHT2 = 71_700
N2023_BITS2 = 0x185C7BAE
LEGACY_WINDOW = 2_016
LEGACY_TIMESPAN = 14 * 24 * 60 * 60

GENESIS_HASH_DISPLAY = (
    "000000002b8761c63862f5047afb9ac5fdd1c67e87cd376c387628bc772bb39d"
)
GENESIS_MERKLE_DISPLAY = (
    "90868a42e67370c4f543a97a896337db1f99c238b043115e9cdf8b0a09e6b1bc"
)
GENESIS_TIME = 1_672_403_913
GENESIS_BITS = 0x1D00FFFF
GENESIS_NONCE = 3_502_459_508
GENESIS_RAW = (
    struct.pack("<i", 1)
    + b"\x00" * 32
    + bytes.fromhex(GENESIS_MERKLE_DISPLAY)[::-1]
    + struct.pack("<III", GENESIS_TIME, GENESIS_BITS, GENESIS_NONCE)
)

CHECKPOINTS = {
    0: GENESIS_HASH_DISPLAY,
    1_000: "fad7864364b1bd1fa259b72ce7fbe29830615412f77675781f4e90f0996f607d",
    10_000: "000000000002ce00fce2f53c833902878c457c7ad04c411c7cb7c484e91327b5",
    20_000: "2ed35f5d1e12679cb9ee0761e055c84d6d9f016489732ef275a0bf8f0f6b1a30",
    30_000: "5427dbfe4804300d7a8f5a73ec1bda71ca1cdc0bbbba5e7518a6fa42358534e9",
    40_000: "ff3c7d78cb9054a3602867f23958f441aacc87d29ec0968df4904ae9dc85c184",
    50_000: "7aa3a580745059f06694d2b3e91037d7b764a48c49d39a6463e8ebb94460ef74",
    60_000: "9eb558eb1779eeda5ad1cac490acc82f866754756da22e0db0806e540538a13c",
    70_000: "84f0df6fbcfeb6d864af1ba85ac62ab6bda03adc6ad54008b26a0bba702a7d35",
    80_000: "3934eef0bda0567058223c6b89bc20f5564a0e771762587b1f87a494f050f86c",
    90_000: "7f8fd1e35f306a4bb994bf43b9c1fb89df9b1d356064237e7c4aaeb9161b3e7b",
    100_000: "96833a9b1298412904c0b49f1004a733883e84907b8b8479391ccb3de058ce86",
    200_000: "439e32050ce197fb1489912bd586ea8c2cee68c4c7407bb6e0567d4dd1776fb2",
}

BATCH_MAGIC = b"LYNHDR01"
BATCH_VERSION = 1
MAX_BATCH_METADATA = 256 * 1024
MAX_HEADER_SIZE = 8 * 1024 * 1024
MAX_SCRIPT_SIZE = 4 * 1024 * 1024
MAX_TX_INPUTS = 4_096
MAX_TX_OUTPUTS = 100_000
MAX_WITNESS_ITEMS = 100_000
MAX_MERKLE_BRANCH = 64

CANDIDATE_FIELDS = [
    "child_sequence",
    "child_height",
    "child_block_hash",
    "child_block_hash_display",
    "child_version",
    "child_block_time",
    "btc_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits_hex",
    "btc_bip34_height",
    "btc_nonce",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
]


class RecoveryValidationError(ValueError):
    """The remote stream or persisted recovery state failed validation."""


def hash_to_display(hash_internal: bytes) -> str:
    """Convert a 32-byte internal-order hash to display-order lowercase hex."""
    if len(hash_internal) != 32:
        raise RecoveryValidationError("expected a 32-byte internal hash")
    return hash_internal[::-1].hex()


def encode_compact_size(value: int) -> bytes:
    """Encode ``value`` as a Bitcoin-style CompactSize (varint).

    Raises ``RecoveryValidationError`` for a negative value or one that does
    not fit in a uint64.
    """
    if value < 0:
        raise RecoveryValidationError("CompactSize value cannot be negative")
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + struct.pack("<Q", value)
    raise RecoveryValidationError("CompactSize value exceeds uint64")


class WireReader:
    """A bounded cursor with canonical CompactSize decoding."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    @property
    def remaining(self) -> int:
        """Return the number of unread bytes left in the buffer."""
        return len(self.data) - self.pos

    def take(self, size: int) -> bytes:
        """Consume and return the next ``size`` bytes.

        Raises ``RecoveryValidationError`` if fewer than ``size`` bytes remain.
        """
        if size < 0 or size > self.remaining:
            raise RecoveryValidationError(
                f"truncated wire object at offset {self.pos}: need {size}, "
                f"have {self.remaining}"
            )
        start = self.pos
        self.pos += size
        return self.data[start : self.pos]

    def peek(self, offset: int = 0) -> int:
        """Return the byte ``offset`` past the cursor without consuming it."""
        index = self.pos + offset
        if index < self.pos or index >= len(self.data):
            raise RecoveryValidationError("truncated wire object while peeking")
        return self.data[index]

    def u32(self) -> int:
        """Consume and return a little-endian uint32."""
        return struct.unpack("<I", self.take(4))[0]

    def i32(self) -> int:
        """Consume and return a little-endian signed int32."""
        return struct.unpack("<i", self.take(4))[0]

    def u64(self) -> int:
        """Consume and return a little-endian uint64."""
        return struct.unpack("<Q", self.take(8))[0]

    def compact_size(self, maximum: int | None = None) -> int:
        """Decode a canonical Bitcoin CompactSize (varint).

        Rejects non-minimal encodings (a value that could have used a shorter
        prefix) and, when ``maximum`` is given, raises if the decoded value
        exceeds it.
        """
        prefix = self.take(1)[0]
        if prefix < 253:
            value = prefix
        elif prefix == 253:
            value = struct.unpack("<H", self.take(2))[0]
            if value < 253:
                raise RecoveryValidationError("non-canonical CompactSize uint16")
        elif prefix == 254:
            value = self.u32()
            if value <= 0xFFFF:
                raise RecoveryValidationError("non-canonical CompactSize uint32")
        else:
            value = self.u64()
            if value <= 0xFFFFFFFF:
                raise RecoveryValidationError("non-canonical CompactSize uint64")
        if maximum is not None and value > maximum:
            raise RecoveryValidationError(
                f"CompactSize value {value} exceeds limit {maximum}"
            )
        return value


@dataclass(frozen=True)
class TxInput:
    prev_hash: bytes
    prev_index: int
    script_sig: bytes
    sequence: int


@dataclass(frozen=True)
class TxOutput:
    value: int
    script_pubkey: bytes


@dataclass(frozen=True)
class ParsedTransaction:
    version: int
    inputs: tuple[TxInput, ...]
    outputs: tuple[TxOutput, ...]
    locktime: int
    has_witness: bool
    raw_with_witness: bytes
    raw_without_witness: bytes

    @property
    def txid_internal(self) -> bytes:
        """Return the internal-order txid, hashed over the witness-stripped serialization."""
        return sha256d(self.raw_without_witness)


@dataclass(frozen=True)
class ParsedAuxPow:
    coinbase: ParsedTransaction
    hash_block: bytes
    parent_merkle_branch: tuple[bytes, ...]
    parent_merkle_index: int
    chain_merkle_branch: tuple[bytes, ...]
    chain_index: int
    parent_header_raw: bytes


@dataclass(frozen=True)
class ParsedHeader:
    raw: bytes
    pure_header_raw: bytes
    version: int
    version_u32: int
    prev_hash_internal: bytes
    merkle_root_internal: bytes
    timestamp: int
    bits: int
    nonce: int
    auxpow: ParsedAuxPow | None

    @property
    def pre_flex_hash_internal(self) -> bytes:
        """Return the internal-order pre-Flex block hash (SHA256d of the 80-byte pure header)."""
        return sha256d(self.pure_header_raw)


@dataclass(frozen=True)
class HeaderSummary:
    height: int
    hash_internal: bytes
    version: int
    timestamp: int
    bits: int
    has_auxpow: bool

    @property
    def hash_display(self) -> str:
        """Return the block hash as display-order lowercase hex."""
        return hash_to_display(self.hash_internal)


@dataclass(frozen=True)
class DecodedBatch:
    metadata: dict[str, Any]
    raw_headers: tuple[bytes, ...]


def _parse_transaction(reader: WireReader) -> ParsedTransaction:
    """Deserialise one transaction from ``reader`` into a ``ParsedTransaction``.

    Handles the BIP144 witness marker/flag. ``raw_without_witness`` is
    rebuilt field-by-field regardless of whether witness data is present, so
    ``txid_internal`` is always computed over the correct (non-witness) bytes.
    """
    start = reader.pos
    version_raw = reader.take(4)
    version = struct.unpack("<i", version_raw)[0]

    has_witness = False
    if reader.remaining >= 2 and reader.peek() == 0 and reader.peek(1) != 0:
        reader.take(1)
        flags = reader.take(1)[0]
        if flags != 1:
            raise RecoveryValidationError(
                f"unsupported transaction witness flags 0x{flags:02x}"
            )
        has_witness = True

    input_count = reader.compact_size(MAX_TX_INPUTS)
    inputs: list[TxInput] = []
    stripped = bytearray(version_raw)
    stripped.extend(encode_compact_size(input_count))
    for _ in range(input_count):
        prev_hash = reader.take(32)
        prev_index_raw = reader.take(4)
        prev_index = struct.unpack("<I", prev_index_raw)[0]
        script_size = reader.compact_size(MAX_SCRIPT_SIZE)
        script_sig = reader.take(script_size)
        sequence_raw = reader.take(4)
        sequence = struct.unpack("<I", sequence_raw)[0]
        stripped.extend(prev_hash)
        stripped.extend(prev_index_raw)
        stripped.extend(encode_compact_size(script_size))
        stripped.extend(script_sig)
        stripped.extend(sequence_raw)
        inputs.append(TxInput(prev_hash, prev_index, script_sig, sequence))

    output_count = reader.compact_size(MAX_TX_OUTPUTS)
    outputs: list[TxOutput] = []
    stripped.extend(encode_compact_size(output_count))
    for _ in range(output_count):
        value_raw = reader.take(8)
        value = struct.unpack("<Q", value_raw)[0]
        script_size = reader.compact_size(MAX_SCRIPT_SIZE)
        script_pubkey = reader.take(script_size)
        stripped.extend(value_raw)
        stripped.extend(encode_compact_size(script_size))
        stripped.extend(script_pubkey)
        outputs.append(TxOutput(value, script_pubkey))

    if has_witness:
        for _ in range(input_count):
            item_count = reader.compact_size(MAX_WITNESS_ITEMS)
            for _ in range(item_count):
                item_size = reader.compact_size(MAX_SCRIPT_SIZE)
                reader.take(item_size)

    locktime_raw = reader.take(4)
    locktime = struct.unpack("<I", locktime_raw)[0]
    stripped.extend(locktime_raw)
    return ParsedTransaction(
        version=version,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        locktime=locktime,
        has_witness=has_witness,
        raw_with_witness=reader.data[start : reader.pos],
        raw_without_witness=bytes(stripped),
    )


def _parse_merkle_branch(reader: WireReader) -> tuple[bytes, ...]:
    """Read a CompactSize-prefixed merkle branch (internal-order 32-byte hashes).

    The branch length is bounded by ``MAX_MERKLE_BRANCH``.
    """
    count = reader.compact_size(MAX_MERKLE_BRANCH)
    return tuple(reader.take(32) for _ in range(count))


def _parse_auxpow(reader: WireReader) -> ParsedAuxPow:
    """Deserialise a CAuxPow object: coinbase tx, parent merkle branch/index,
    chain merkle branch/index, then the 80-byte parent header.
    """
    coinbase = _parse_transaction(reader)
    hash_block = reader.take(32)
    parent_branch = _parse_merkle_branch(reader)
    parent_index = reader.i32()
    chain_branch = _parse_merkle_branch(reader)
    chain_index = reader.i32()
    parent_header = reader.take(80)
    return ParsedAuxPow(
        coinbase=coinbase,
        hash_block=hash_block,
        parent_merkle_branch=parent_branch,
        parent_merkle_index=parent_index,
        chain_merkle_branch=chain_branch,
        chain_index=chain_index,
        parent_header_raw=parent_header,
    )


def _parse_extended_header(reader: WireReader) -> ParsedHeader:
    """Parse one Lyncoin extended header: the 80-byte pure header, plus a
    CAuxPow tail when ``nVersion`` carries the AuxPoW flag.

    Raises ``RecoveryValidationError`` if the serialized header exceeds
    ``MAX_HEADER_SIZE``.
    """
    start = reader.pos
    pure = reader.take(80)
    version = struct.unpack_from("<i", pure, 0)[0]
    version_u32 = struct.unpack_from("<I", pure, 0)[0]
    auxpow = _parse_auxpow(reader) if version_u32 & VERSION_AUXPOW else None
    raw = reader.data[start : reader.pos]
    if len(raw) > MAX_HEADER_SIZE:
        raise RecoveryValidationError(
            f"serialized extended header is {len(raw)} bytes, limit is "
            f"{MAX_HEADER_SIZE}"
        )
    return ParsedHeader(
        raw=raw,
        pure_header_raw=pure,
        version=version,
        version_u32=version_u32,
        prev_hash_internal=pure[4:36],
        merkle_root_internal=pure[36:68],
        timestamp=struct.unpack_from("<I", pure, 68)[0],
        bits=struct.unpack_from("<I", pure, 72)[0],
        nonce=struct.unpack_from("<I", pure, 76)[0],
        auxpow=auxpow,
    )


def parse_extended_header(raw: bytes) -> ParsedHeader:
    """Parse a single extended header from ``raw``, requiring it be fully consumed."""
    reader = WireReader(raw)
    parsed = _parse_extended_header(reader)
    if reader.remaining:
        raise RecoveryValidationError(
            f"extended header has {reader.remaining} trailing bytes"
        )
    return parsed


def parse_headers_payload(payload: bytes) -> tuple[ParsedHeader, ...]:
    """Parse one ``headers`` payload, including each mandatory zero tx count."""
    reader = WireReader(payload)
    count = reader.compact_size(MAX_HEADERS_RESULTS)
    headers: list[ParsedHeader] = []
    for _ in range(count):
        headers.append(_parse_extended_header(reader))
        tx_count = reader.compact_size()
        if tx_count != 0:
            raise RecoveryValidationError(
                f"headers response carried non-zero transaction count {tx_count}"
            )
    if reader.remaining:
        raise RecoveryValidationError(
            f"headers payload has {reader.remaining} trailing bytes"
        )
    return tuple(headers)


def encode_p2p_message(command: str, payload: bytes = b"") -> bytes:
    """Encode a full Lyncoin P2P message: magic, zero-padded 12-byte command,
    payload length, checksum, and payload.

    Raises ``RecoveryValidationError`` for an invalid command or a payload
    over ``MAX_MESSAGE_PAYLOAD``.
    """
    encoded = command.encode("ascii")
    if not encoded or len(encoded) > 12 or b"\x00" in encoded:
        raise RecoveryValidationError("invalid P2P command")
    if len(payload) > MAX_MESSAGE_PAYLOAD:
        raise RecoveryValidationError("P2P payload exceeds recovery limit")
    command_field = encoded.ljust(12, b"\x00")
    return (
        NETWORK_MAGIC
        + command_field
        + struct.pack("<I", len(payload))
        + sha256d(payload)[:4]
        + payload
    )


def decode_p2p_header(raw24: bytes) -> tuple[str, int, bytes]:
    """Parse and validate a 24-byte P2P message header.

    Returns ``(command, payload_size, checksum)``. Raises
    ``RecoveryValidationError`` on the wrong network magic, a malformed or
    non-ASCII command, or a payload length over ``MAX_MESSAGE_PAYLOAD``.
    """
    if len(raw24) != 24:
        raise RecoveryValidationError("P2P message header must be 24 bytes")
    if raw24[:4] != NETWORK_MAGIC:
        raise RecoveryValidationError(f"wrong Lyncoin network magic {raw24[:4].hex()}")
    command_raw = raw24[4:16]
    command_bytes, separator, padding = command_raw.partition(b"\x00")
    if separator and any(padding):
        raise RecoveryValidationError("non-zero P2P command padding")
    try:
        command = command_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RecoveryValidationError("non-ASCII P2P command") from exc
    if not command or not all(0x20 <= byte <= 0x7E for byte in command_bytes):
        raise RecoveryValidationError("invalid P2P command bytes")
    payload_size = struct.unpack_from("<I", raw24, 16)[0]
    if payload_size > MAX_MESSAGE_PAYLOAD:
        raise RecoveryValidationError(
            f"P2P payload length {payload_size} exceeds limit {MAX_MESSAGE_PAYLOAD}"
        )
    return command, payload_size, raw24[20:24]


def compact_to_target(bits: int, *, pow_limit: int = POW_LIMIT) -> int:
    """Decode Core's compact target and reject negative/overflow/range errors."""
    size = bits >> 24
    word = bits & 0x007FFFFF
    negative = word != 0 and bool(bits & 0x00800000)
    overflow = word != 0 and (
        size > 34 or (word > 0xFF and size > 33) or (word > 0xFFFF and size > 32)
    )
    if size <= 3:
        target = word >> (8 * (3 - size))
    else:
        target = word << (8 * (size - 3))
    if negative or overflow or target <= 0 or target > pow_limit:
        raise RecoveryValidationError(f"invalid compact target 0x{bits:08x}")
    return target


def target_to_compact(target: int) -> int:
    """Encode a positive 256-bit target integer as compact ``nBits``.

    Inverse of ``compact_to_target``.
    """
    if target <= 0:
        raise RecoveryValidationError("target must be positive")
    size = (target.bit_length() + 7) // 8
    if size <= 3:
        compact = target << (8 * (3 - size))
    else:
        compact = target >> (8 * (size - 3))
    compact &= 0xFFFFFF
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    return compact | (size << 24)


def expected_next_bits(history: list[HeaderSummary], height: int) -> int:
    """Mirror Lyncoin v4 ``GetNextWorkRequired`` through the pre-Flex era."""
    if height <= 0 or len(history) != height:
        raise RecoveryValidationError(
            f"difficulty history length {len(history)} does not match height {height}"
        )
    previous = history[-1]
    if height == N2023_HEIGHT:
        return N2023_BITS
    if height == N2023_HEIGHT2:
        return N2023_BITS2
    if height == FLEX_HEIGHT:
        return FLEX_BITS

    if height < N2023_HEIGHT:
        if height % LEGACY_WINDOW:
            return previous.bits
        first = history[height - LEGACY_WINDOW]
        actual_timespan = previous.timestamp - first.timestamp
        actual_timespan = max(LEGACY_TIMESPAN // 4, actual_timespan)
        actual_timespan = min(LEGACY_TIMESPAN * 4, actual_timespan)
        divisor = LEGACY_TIMESPAN
    elif height < N2023_HEIGHT2:
        if height % N2023_WINDOW:
            return previous.bits
        first = history[height - N2023_WINDOW]
        actual_timespan = previous.timestamp - first.timestamp
        actual_timespan = max(5_917, actual_timespan)
        actual_timespan = min(6_084, actual_timespan)
        divisor = N2023_TIMESPAN
    else:
        first = history[height - 2]
        actual_timespan = previous.timestamp - first.timestamp
        actual_timespan = max(37, actual_timespan)
        actual_timespan = min(39, actual_timespan)
        divisor = 38

    previous_target = compact_to_target(previous.bits)
    new_target = previous_target * actual_timespan // divisor
    new_target = min(new_target, POW_LIMIT)
    return target_to_compact(new_target)


def _chain_id(version: int) -> int:
    """Extract the AuxPoW chain ID from the high 16 bits of ``nVersion``."""
    return (version & 0xFFFFFFFF) >> 16


def _hash_meets_target(hash_internal: bytes, bits: int) -> bool:
    """Return True if internal-order ``hash_internal`` is at or below the ``bits`` target."""
    target = compact_to_target(bits)
    return int.from_bytes(hash_internal, "little") <= target


def validate_auxpow(header: ParsedHeader, height: int) -> None:
    """Validate ``header``'s CAuxPow object against Lyncoin v4 consensus rules.

    Checks the chain-merkle branch length bound, parent-merkle-index and
    chain-index sanity, that the parent header does not reuse Lyncoin's own
    chain ID, the parent coinbase merkle proof, that the child's merkle root
    is committed in the parent coinbase scriptSig (with correct placement
    relative to the merged-mining magic when present, or within the first 20
    bytes for the legacy no-magic form), the commitment's tree-size and
    LCG-derived chain-index, and that the parent header's own PoW meets the
    child's ``bits`` target. Raises ``RecoveryValidationError`` on the first
    violation found; returns ``None`` on success.
    """
    auxpow = header.auxpow
    if auxpow is None:
        raise RecoveryValidationError(f"height {height}: missing AuxPoW object")
    if len(auxpow.chain_merkle_branch) > 30:
        raise RecoveryValidationError(
            f"height {height}: AuxPoW chain merkle branch exceeds 30"
        )
    if auxpow.parent_merkle_index != 0:
        raise RecoveryValidationError(
            f"height {height}: parent coinbase merkle index is not zero"
        )
    if auxpow.chain_index < 0:
        raise RecoveryValidationError(
            f"height {height}: AuxPoW chain index is negative"
        )

    parent_version = struct.unpack_from("<i", auxpow.parent_header_raw, 0)[0]
    parent_chain_id = parent_version >> 16
    if parent_chain_id == CHAIN_ID:
        raise RecoveryValidationError(
            f"height {height}: AuxPoW parent reuses Lyncoin chain ID"
        )

    parent_merkle_root = auxpow.parent_header_raw[36:68]
    calculated_parent_root = fold_merkle_branch(
        auxpow.coinbase.txid_internal,
        auxpow.parent_merkle_branch,
        0,
    )
    if calculated_parent_root != parent_merkle_root:
        raise RecoveryValidationError(
            f"height {height}: parent coinbase merkle proof mismatch"
        )
    if not auxpow.coinbase.inputs:
        raise RecoveryValidationError(f"height {height}: AuxPoW coinbase has no inputs")

    child_hash = header.pre_flex_hash_internal
    chain_root = fold_merkle_branch(
        child_hash,
        auxpow.chain_merkle_branch,
        auxpow.chain_index,
    )
    committed_root = chain_root[::-1]
    script_sig = auxpow.coinbase.inputs[0].script_sig
    root_offset = script_sig.find(committed_root)
    if root_offset < 0:
        raise RecoveryValidationError(
            f"height {height}: child merkle root missing from parent coinbase"
        )

    merge_magic = bytes.fromhex("fabe6d6d")
    magic_offset = script_sig.find(merge_magic)
    if magic_offset >= 0:
        if script_sig.find(merge_magic, magic_offset + 1) >= 0:
            raise RecoveryValidationError(
                f"height {height}: duplicate merged-mining magic"
            )
        if root_offset != magic_offset + len(merge_magic):
            raise RecoveryValidationError(
                f"height {height}: merged-mining magic not adjacent to root"
            )
    elif root_offset > 20:
        raise RecoveryValidationError(
            f"height {height}: legacy child root occurs after byte 20"
        )

    suffix = root_offset + len(committed_root)
    if len(script_sig) - suffix < 8:
        raise RecoveryValidationError(
            f"height {height}: commitment lacks tree size and nonce"
        )
    merkle_size, merkle_nonce = struct.unpack_from("<II", script_sig, suffix)
    expected_size = 1 << len(auxpow.chain_merkle_branch)
    if merkle_size != expected_size:
        raise RecoveryValidationError(
            f"height {height}: commitment tree size {merkle_size} does not "
            f"match {expected_size}"
        )
    expected_index = auxpow_lcg_index(
        merkle_nonce,
        CHAIN_ID,
        len(auxpow.chain_merkle_branch),
    )
    if auxpow.chain_index != expected_index:
        raise RecoveryValidationError(
            f"height {height}: AuxPoW chain index {auxpow.chain_index} does "
            f"not match {expected_index}"
        )

    parent_hash = sha256d(auxpow.parent_header_raw)
    if not _hash_meets_target(parent_hash, header.bits):
        raise RecoveryValidationError(
            f"height {height}: parent PoW does not meet Lyncoin target"
        )


def validate_genesis(header: ParsedHeader) -> HeaderSummary:
    """Validate the genesis header against the pinned source bytes, hash, and PoW.

    Returns its ``HeaderSummary`` (height 0); raises ``RecoveryValidationError``
    on any mismatch.
    """
    if header.raw != GENESIS_RAW:
        raise RecoveryValidationError(
            "genesis header does not match pinned source bytes"
        )
    if header.auxpow is not None:
        raise RecoveryValidationError("genesis unexpectedly carries AuxPoW")
    block_hash = header.pre_flex_hash_internal
    if hash_to_display(block_hash) != GENESIS_HASH_DISPLAY:
        raise RecoveryValidationError("genesis hash does not match pinned source hash")
    if not _hash_meets_target(block_hash, header.bits):
        raise RecoveryValidationError("genesis proof of work is invalid")
    return HeaderSummary(
        height=0,
        hash_internal=block_hash,
        version=header.version,
        timestamp=header.timestamp,
        bits=header.bits,
        has_auxpow=False,
    )


def validate_pre_flex_header(
    header: ParsedHeader,
    height: int,
    history: list[HeaderSummary],
) -> HeaderSummary:
    """Validate one pre-Flex header at ``height`` against the running ``history``.

    Checks the supported height range, that ``history`` carries exactly
    ``height`` prior entries, the Flex version flag is absent, the legacy
    version-1 encoding is rejected, the chain ID, previous-hash linkage, the
    expected ``nBits`` from ``expected_next_bits``, either a valid AuxPoW
    commitment or solo PoW meeting the header's own target, and any pinned
    checkpoint hash. Returns the resulting ``HeaderSummary``; raises
    ``RecoveryValidationError`` on the first violation found.
    """
    if height <= 0 or height > AUXPOW_END_HEIGHT:
        raise RecoveryValidationError(
            f"height {height} is outside the supported pre-Flex range"
        )
    if len(history) != height:
        raise RecoveryValidationError(
            f"height {height}: history has {len(history)} entries"
        )
    if header.version_u32 & FLEX_VERSION_FLAG:
        raise RecoveryValidationError(
            f"height {height}: Flex version flag appears before activation"
        )
    if header.version == 1:
        raise RecoveryValidationError(
            f"height {height}: legacy version is forbidden after genesis"
        )
    if _chain_id(header.version_u32) != CHAIN_ID:
        raise RecoveryValidationError(
            f"height {height}: chain ID {_chain_id(header.version_u32)} does "
            f"not match {CHAIN_ID}"
        )
    previous = history[-1]
    if header.prev_hash_internal != previous.hash_internal:
        raise RecoveryValidationError(
            f"height {height}: previous-hash linkage mismatch"
        )

    expected_bits = expected_next_bits(history, height)
    if header.bits != expected_bits:
        raise RecoveryValidationError(
            f"height {height}: nBits 0x{header.bits:08x} does not match "
            f"source consensus 0x{expected_bits:08x}"
        )

    block_hash = header.pre_flex_hash_internal
    if header.auxpow is not None:
        validate_auxpow(header, height)
    elif not _hash_meets_target(block_hash, header.bits):
        raise RecoveryValidationError(
            f"height {height}: solo child PoW does not meet Lyncoin target"
        )

    display_hash = hash_to_display(block_hash)
    checkpoint = CHECKPOINTS.get(height)
    if checkpoint is not None and display_hash != checkpoint:
        raise RecoveryValidationError(
            f"height {height}: hash {display_hash} does not match official "
            f"checkpoint {checkpoint}"
        )
    return HeaderSummary(
        height=height,
        hash_internal=block_hash,
        version=header.version,
        timestamp=header.timestamp,
        bits=header.bits,
        has_auxpow=header.auxpow is not None,
    )


def validate_flex_boundary(
    header: ParsedHeader,
    previous: HeaderSummary,
) -> dict[str, Any]:
    """Validate the source-visible parts of height 260,500.

    Lyncoin's Flex hashes are outside this repository's pure-stdlib recovery
    scope.  We can still prove that the next serialized header links to the
    final pre-Flex hash and carries the source-pinned activation version/bits.
    """
    if previous.height != AUXPOW_END_HEIGHT:
        raise RecoveryValidationError("Flex boundary requires height 260,499")
    if header.prev_hash_internal != previous.hash_internal:
        raise RecoveryValidationError("Flex boundary does not link to height 260,499")
    if not header.version_u32 & FLEX_VERSION_FLAG:
        raise RecoveryValidationError("height 260,500 lacks the Flex version flag")
    if _chain_id(header.version_u32) != CHAIN_ID:
        raise RecoveryValidationError("height 260,500 has the wrong chain ID")
    if header.bits != FLEX_BITS:
        raise RecoveryValidationError(
            f"height 260,500 nBits 0x{header.bits:08x} does not match 0x{FLEX_BITS:08x}"
        )
    return {
        "height": FLEX_HEIGHT,
        "version": header.version,
        "version_u32": header.version_u32,
        "bits_hex": f"{header.bits:08x}",
        "time": header.timestamp,
        "prev_hash": previous.hash_display,
        "serialized_sha256": hashlib.sha256(header.raw).hexdigest(),
        "raw_header_hex": header.raw.hex(),
        "validation_scope": "linkage/version/chain_id/nBits only; Flex PoW not computed",
    }


def candidate_row(
    header: ParsedHeader,
    summary: HeaderSummary,
) -> dict[str, str | int] | None:
    """Return an existing-classifier-compatible BTC-parent candidate row."""
    auxpow = header.auxpow
    if auxpow is None:
        return None
    parent = parse_parent_header(auxpow.parent_header_raw)
    if parent["bits"] in (0, 0x7FFFFFFF):
        return None
    parent_hash = sha256d(auxpow.parent_header_raw)
    if not hash_meets_btc_difficulty(parent_hash, parent["bits"]):
        return None
    script_sig = auxpow.coinbase.inputs[0].script_sig
    bip34_height = parse_coinbase_height(script_sig)
    outputs = ";".join(output.script_pubkey.hex() for output in auxpow.coinbase.outputs)
    return {
        "child_sequence": summary.height + 1,
        "child_height": summary.height,
        "child_block_hash": summary.hash_internal.hex(),
        "child_block_hash_display": summary.hash_display,
        "child_version": summary.version,
        "child_block_time": summary.timestamp,
        "btc_hash": parent["hash"],
        "btc_prev_hash": parent["prev_hash"],
        "btc_time": parent["time"],
        "btc_bits_hex": parent["bits_hex"],
        "btc_bip34_height": bip34_height if bip34_height is not None else "",
        "btc_nonce": parent["nonce"],
        "coinbase_scriptsig_hex": script_sig.hex(),
        "coinbase_outputs": outputs,
        "btc_header_hex": parent["header_hex"],
    }


def encode_batch(metadata: dict[str, Any], raw_headers: list[bytes]) -> bytes:
    """Serialise ``metadata`` and ``raw_headers`` into the ``LYNHDR01`` batch format.

    Layout: magic, version, metadata length, canonical-JSON metadata bytes,
    header count, then each header as a length-prefixed blob. Raises
    ``RecoveryValidationError`` if the metadata or any header exceeds its
    size limit.
    """
    metadata_raw = json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(metadata_raw) > MAX_BATCH_METADATA:
        raise RecoveryValidationError("batch metadata exceeds size limit")
    output = bytearray(BATCH_MAGIC)
    output.extend(struct.pack("<II", BATCH_VERSION, len(metadata_raw)))
    output.extend(metadata_raw)
    output.extend(struct.pack("<I", len(raw_headers)))
    for raw in raw_headers:
        if not raw or len(raw) > MAX_HEADER_SIZE:
            raise RecoveryValidationError("invalid header length in batch")
        output.extend(struct.pack("<I", len(raw)))
        output.extend(raw)
    return bytes(output)


def decode_batch(raw: bytes) -> DecodedBatch:
    """Decode a ``LYNHDR01`` batch produced by ``encode_batch``.

    Validates magic, version, metadata JSON shape, and header count/sizes,
    and requires the buffer be fully consumed. Returns a ``DecodedBatch``;
    raises ``RecoveryValidationError`` on any malformed or trailing data.
    """
    reader = WireReader(raw)
    if reader.take(len(BATCH_MAGIC)) != BATCH_MAGIC:
        raise RecoveryValidationError("wrong Lyncoin header-batch magic")
    version = reader.u32()
    if version != BATCH_VERSION:
        raise RecoveryValidationError(f"unsupported batch version {version}")
    metadata_size = reader.u32()
    if metadata_size > MAX_BATCH_METADATA:
        raise RecoveryValidationError("batch metadata exceeds size limit")
    try:
        metadata = json.loads(reader.take(metadata_size).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryValidationError("invalid batch metadata JSON") from exc
    if not isinstance(metadata, dict):
        raise RecoveryValidationError("batch metadata must be a JSON object")
    count = reader.u32()
    if count > MAX_HEADERS_RESULTS:
        raise RecoveryValidationError("batch header count exceeds protocol limit")
    headers = []
    for _ in range(count):
        size = reader.u32()
        if size <= 0 or size > MAX_HEADER_SIZE:
            raise RecoveryValidationError("invalid serialized header size in batch")
        headers.append(reader.take(size))
    if reader.remaining:
        raise RecoveryValidationError(f"batch has {reader.remaining} trailing bytes")
    return DecodedBatch(metadata=metadata, raw_headers=tuple(headers))


# Validate the source-pinned genesis at import time.  A typo in any parameter
# should make the recovery client unavailable rather than silently shift its
# trust anchor.
if hash_to_display(sha256d(GENESIS_RAW)) != GENESIS_HASH_DISPLAY:
    raise RuntimeError("pinned Lyncoin genesis parameters do not hash correctly")
