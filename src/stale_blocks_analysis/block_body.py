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
    """Read a CompactSize integer, enforcing Core's canonical minimal form.

    ``ReadCompactSize`` rejects a value serialized wider than necessary
    ("non-canonical ReadCompactSize()"), and those count/length bytes sit
    outside every txid and the witness commitment: a rewritten-but-equal
    encoding would change only ``block_sha256`` while every derived check
    still passed, so a block Core would refuse to even deserialize must not
    authenticate here.
    """
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
            count += MAX_PUBKEYS_PER_MULTISIG
    return count


def _transaction_at(
    raw: bytes, pos: int, *, capture_coinbase: bool = False
) -> tuple[int, bytes, bytes, list[bytes] | None, list[bytes] | None, int]:
    """Walk one transaction; return its evidence fields and the new position.

    Returns ``(legacy_sigops, txid, wtxid, coinbase_output_scripts,
    coinbase_witness_stack, new_pos)``. The txid is the sha256d of the
    transaction's LEGACY serialization (version, inputs, outputs, locktime --
    excluding any segwit marker, flag, and witness data); the wtxid is the
    sha256d of the FULL serialization (equal to the txid for a non-segwit
    transaction). Both are internal byte order, ready for merkle-tree use.
    ``capture_coinbase`` additionally collects the output scriptPubKeys and
    the complete witness stack of the first input, so the commitment check
    can enforce BIP141's exactly-one-32-byte-item rule on the coinbase.
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
    coinbase_witness: list[bytes] | None,
) -> str | None:
    """Re-derive the BIP141 witness commitment, or explain why it fails.

    The legacy txid merkle root does not cover witness bytes, so a body with
    altered witness data (and a matching updated ``block_sha256``) would still
    txid-merkle-authenticate while changing exactly the witness-path sigops
    these rows attribute the excess to. When any transaction carries witness
    data, Bitcoin requires the coinbase to commit to the wtxid merkle tree:
    the commitment is sha256d(witness merkle root || witness reserved value),
    where the coinbase's wtxid leaf is 32 zero bytes and the reserved value is
    the coinbase's witness stack, which BIP141 requires to be EXACTLY one
    32-byte item (Core's ``bad-witness-nonce-size``): the zeroed leaf means
    any extra coinbase witness item would escape the commitment entirely, so
    a surplus item is rejected, never ignored. The commitment must appear in the
    LAST coinbase output whose scriptPubKey begins ``6a24aa21a9ed`` (Core's
    ``GetWitnessCommitmentIndex`` scan). The caller invokes this when some
    transaction carries witness data OR the coinbase carries a commitment
    output, mirroring Core: a stripped body must not skip the check.
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


def authenticate_block_body(
    raw: bytes, *, segwit_active: bool = True
) -> tuple[int, list[str]]:
    """Fully authenticate a block body; return (legacy sigops, failures).

    Checks both the legacy txid merkle root against header bytes 36-68 and,
    when any transaction carries witness data, the BIP141 witness commitment
    (see ``_witness_commitment_error``). A body that fails either check must
    not be treated as re-derived evidence for the header. Before activation,
    a commitment-looking output alone does not require witness data. Actual
    witness serialization still requires authentication at any claimed height.
    """
    total, merkle_root, witness_error = _walk_block(raw, segwit_active=segwit_active)
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
    raw: bytes, *, segwit_active: bool = True
) -> tuple[int, bytes, str | None]:
    """Walk every transaction; return (sigops, txid merkle root, witness error)."""
    if len(raw) < 81:
        raise ValueError("serialized block shorter than header plus tx count")
    pos = 80
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
