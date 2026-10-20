"""Authenticate serialized Bitcoin bodies without asserting consensus validity.

Retains the overlay's transaction, merkle and witness-commitment parser.
Legacy sigop counts are not complete sigop costs: prevout scripts are absent.
"""

from __future__ import annotations

from .bitcoin_binary import _varint, sha256d
from .config import MAX_PUBKEYS_PER_MULTISIG

_OP_PUSHDATA1 = 0x4C
_OP_PUSHDATA2 = 0x4D
_OP_PUSHDATA4 = 0x4E
_OP_CHECKSIG = 0xAC
_OP_CHECKSIGVERIFY = 0xAD
_OP_CHECKMULTISIG = 0xAE
_OP_CHECKMULTISIGVERIFY = 0xAF


def _read_compact_size(raw: bytes, pos: int) -> tuple[int, int]:
    """Canonical CompactSize. A wider encoding would change only ``block_sha256`` while derived checks still passed."""
    value, new_pos = _varint(raw, pos)
    width = new_pos - pos
    if (
        (width == 3 and value < 0xFD)
        or (width == 5 and value <= 0xFFFF)
        or (width == 9 and value <= 0xFFFF_FFFF)
    ):
        raise ValueError("non-canonical CompactSize encoding")
    return value, new_pos


def count_legacy_sigops_in_script(script: bytes) -> int:
    """``GetSigOpCount(false)``: CHECKSIG is 1, CHECKMULTISIG is 20. A truncated push stops the walk."""
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
            count += MAX_PUBKEYS_PER_MULTISIG
    return count


def _transaction_at(
    raw: bytes, pos: int, *, capture_coinbase: bool = False
) -> tuple[int, bytes, bytes, list[bytes] | None, list[bytes] | None, int]:
    """Legacy txid excludes marker, flag, and witness. Wtxid covers the full serialization. Both are internal order.

    ``capture_coinbase`` keeps output scripts and the first input's witness
    stack so BIP141's one 32-byte item can be checked.
    """
    start = pos
    pos += 4  # nVersion
    is_segwit = raw[pos] == 0x00 and raw[pos + 1] == 0x01
    if is_segwit:
        pos += 2  # marker + flag
    body_start = pos
    vin_count, pos = _read_compact_size(raw, pos)
    count = 0
    for _ in range(vin_count):
        pos += 36  # outpoint
        script_len, pos = _read_compact_size(raw, pos)
        if pos + script_len > len(raw):
            raise ValueError("truncated input scriptSig")
        count += count_legacy_sigops_in_script(raw[pos : pos + script_len])
        pos += script_len + 4  # script + nSequence
    vout_count, pos = _read_compact_size(raw, pos)
    output_scripts: list[bytes] | None = [] if capture_coinbase else None
    for _ in range(vout_count):
        pos += 8  # value
        script_len, pos = _read_compact_size(raw, pos)
        if pos + script_len > len(raw):
            raise ValueError("truncated output scriptPubKey")
        script = raw[pos : pos + script_len]
        count += count_legacy_sigops_in_script(script)
        if output_scripts is not None:
            output_scripts.append(script)
        pos += script_len
    body_end = pos
    coinbase_witness: list[bytes] | None = None
    if is_segwit:
        for vin_index in range(vin_count):
            item_count, pos = _read_compact_size(raw, pos)
            for _item_index in range(item_count):
                item_len, pos = _read_compact_size(raw, pos)
                if pos + item_len > len(raw):
                    raise ValueError("truncated witness item")
                if capture_coinbase and vin_index == 0:
                    if coinbase_witness is None:
                        coinbase_witness = []
                    coinbase_witness.append(raw[pos : pos + item_len])
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
    return count, txid, wtxid, output_scripts, coinbase_witness, pos


def _merkle_root(txids: list[bytes]) -> bytes:
    """Merkle root in internal order. An equal adjacent pair at any level fails closed (CVE-2012-2459)."""
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
    coinbase_witness: list[bytes] | None,
) -> str | None:
    """BIP141 commitment, or why it fails.

    The commitment is sha256d(witness merkle root || reserved value). The
    coinbase wtxid leaf is 32 zero bytes, so the reserved value must be
    exactly one 32-byte witness item; a surplus item is rejected. The
    commitment is the last coinbase output whose script begins
    ``6a24aa21a9ed``. Called when any transaction has witness data or the
    coinbase carries a commitment output.
    """
    commitment_script = None
    for script in coinbase_outputs:
        if len(script) >= 38 and script.startswith(_WITNESS_COMMITMENT_PREFIX):
            commitment_script = script
    if commitment_script is None:
        return "block carries witness data but no coinbase witness commitment"
    if (
        coinbase_witness is None
        or len(coinbase_witness) != 1
        or len(coinbase_witness[0]) != 32
    ):
        return (
            "coinbase witness is not exactly one 32-byte reserved value "
            "(bad-witness-nonce-size)"
        )
    witness_root = _merkle_root([b"\x00" * 32, *wtxids[1:]])
    commitment = sha256d(witness_root + coinbase_witness[0])
    if commitment_script[6:38] != commitment:
        return "witness data does not authenticate against the coinbase commitment"
    return None


def parse_block_body(raw: bytes) -> tuple[int, bytes]:
    """Legacy sigops from the block bytes, plus the txid merkle root for header bytes 36-68.

    P2SH and witness sigop cost need prevout scripts and are out of scope.
    """
    total, merkle_root, _witness_error = _walk_block(raw)
    return total, merkle_root


def authenticate_block_body(
    raw: bytes, *, segwit_active: bool = True, transaction_offset: int = 80
) -> tuple[int, list[str]]:
    """Txid merkle root against header bytes 36-68, and the BIP141 commitment when witness data is present.

    Before activation, a commitment-looking output alone does not require
    witness data. Actual witness serialization still does, at any claimed
    height. ``transaction_offset`` selects the vector after a child proof
    envelope; the merkle root stays in the first 80 bytes.
    """
    total, merkle_root, witness_error = _walk_block(
        raw, segwit_active=segwit_active, transaction_offset=transaction_offset
    )
    failures: list[str] = []
    if merkle_root != raw[36:68]:
        failures.append(
            "pinned block file's transactions do not merkle-authenticate "
            "against its header"
        )
    if witness_error is not None:
        failures.append(f"pinned block file's {witness_error}")
    return total, failures


def _walk_block(
    raw: bytes, *, segwit_active: bool = True, transaction_offset: int = 80
) -> tuple[int, bytes, str | None]:
    """Walk every transaction; return (sigops, txid merkle root, witness error)."""
    if not 80 <= transaction_offset < len(raw):
        raise ValueError("serialized block lacks a transaction vector after its header")
    pos = transaction_offset
    tx_count, pos = _read_compact_size(raw, pos)
    if tx_count == 0:
        raise ValueError("serialized block carries no transactions")
    total = 0
    txids: list[bytes] = []
    wtxids: list[bytes] = []
    coinbase_outputs: list[bytes] = []
    coinbase_witness: list[bytes] | None = None
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
            coinbase_witness = reserved
    if pos != len(raw):
        raise ValueError("trailing bytes after the final transaction")
    # Core validates the commitment whenever the coinbase CARRIES one, not
    # only when witness serialization is observed: stripping every marker,
    # flag, and witness stack leaves each wtxid equal to its txid, and the
    # header merkle root and legacy sigop count unchanged, so an incomplete
    # body would otherwise skip this check entirely while its commitment
    # output still sits in the coinbase.
    has_commitment_output = any(
        len(script) >= 38 and script.startswith(_WITNESS_COMMITMENT_PREFIX)
        for script in coinbase_outputs
    )
    witness_error = (
        _witness_commitment_error(wtxids, coinbase_outputs, coinbase_witness)
        if has_witness or (segwit_active and has_commitment_output)
        else None
    )
    return total, _merkle_root(txids), witness_error


def count_block_legacy_sigops(raw: bytes) -> int:
    """Count a serialized block's embedded legacy sigops (see parse_block_body)."""
    total, _merkle = parse_block_body(raw)
    return total
