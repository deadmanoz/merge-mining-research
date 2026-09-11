"""Pinned Qbit mainnet extended-header parser and proof validation.

Rules follow Qbit 70fea84f5becfb57463247af09790df5ddd424f8. This validates
the proof envelope, not Qbit body consensus or Bitcoin parent placement.
Height must come from a separately authenticated native-chain snapshot.
"""

from __future__ import annotations

import struct

from .auxpow_chainid import auxpow_lcg_index, fold_merkle_branch, hash_to_display_hex
from .auxpow_parse import nbits_to_target, parse_child_header, parse_parent_header
from .bitcoin_binary import sha256d
from .extract_driver import standard_auxpow_parse_row
from .lyncoin_headers import WireReader, _parse_transaction

SOURCE_REVISION = "70fea84f5becfb57463247af09790df5ddd424f8"
GENESIS = "0000000000004d60aa5d46013991d0a0e2995d89ee98e53068ae196d763e79f2"
CHAIN_ID = 47
POW_LIMIT = int("0000" + "f" * 60, 16)
MERGED_MINING_HEADER = bytes.fromhex("fabe6d6d")


def is_auxpow(version: int, height: int) -> bool:
    """Enforce mainnet's height-zero cadence version layout and version floor."""
    if isinstance(height, bool) or not isinstance(height, int) or height < 0:
        raise ValueError("Qbit height must be a nonnegative integer")
    if not 0 <= version <= 0xFFFFFFFF:
        raise ValueError("Qbit version outside uint32")
    if height > 0 and (version < 4 or version >= 0x80000000):
        raise ValueError("Qbit minimum block version is 4 after genesis")
    shaped = version & 0xE0000000 == 0x20000000
    if version & 0xFFFFFF00 and not shaped:
        raise ValueError("Qbit noncanonical top-bit version layout")
    if shaped and version & 0x00001E00:
        raise ValueError("Qbit reserved version bits")
    merged = shaped and bool(version & 0x100)
    if merged and (version >> 13) & 0xFFFF != CHAIN_ID:
        raise ValueError("Qbit mainnet AuxPoW chain ID mismatch")
    return merged


def parse_header(raw: bytes, *, height: int, expected_hash: str) -> dict:
    """Parse exactly one extended header, explicitly using Qbit's wire format.

    Reuse the bounded Bitcoin wire cursor and transaction decoder. Qbit omits
    classic CAuxPow's hashBlock field and forbids witness coinbase encoding.
    Mainnet accepts display-order commitments at every height; no EITHER mode.
    """
    return _parse(raw, height=height, expected_hash=expected_hash, full_block=False)


def parse_block(raw: bytes, *, height: int, expected_hash: str) -> dict:
    """Validate an RPC full block's header/proof; body consensus stays native.

    Preserve the complete raw block separately. Qbit has native transaction
    rules beyond Bitcoin's; this function does not assert body validity.
    """
    return _parse(raw, height=height, expected_hash=expected_hash, full_block=True)


def _parse(raw: bytes, *, height: int, expected_hash: str, full_block: bool) -> dict:
    reader = WireReader(raw)
    pure = reader.take(80)
    child = parse_child_header(pure, expected_hash_display=expected_hash)
    header = parse_parent_header(pure)
    if height == 0 and header["hash"] != GENESIS:
        raise ValueError("Qbit mainnet genesis mismatch")
    merged = is_auxpow(struct.unpack_from("<I", pure)[0], height)
    target = nbits_to_target(header["bits"])
    if not 0 < target <= POW_LIMIT:
        raise ValueError("invalid Qbit header target")
    result = {
        "child": child,
        "header": header,
        "mining_class": "auxpow" if merged else "direct",
    }
    if not merged:
        if reader.remaining and not full_block:
            raise ValueError("trailing bytes on direct Qbit header")
        if full_block and not reader.remaining:
            raise ValueError("missing Qbit block body")
        if int(header["hash"], 16) > target:
            raise ValueError("direct Qbit proof fails child target")
        result["extended_header_hex"] = raw[: reader.pos].hex()
        return result

    tx = _parse_transaction(reader)
    if tx.has_witness:
        raise ValueError("Qbit parent coinbase must use non-witness encoding")
    if (
        len(tx.inputs) != 1
        or tx.inputs[0].prev_hash != bytes(32)
        or tx.inputs[0].prev_index != 0xFFFFFFFF
    ):
        raise ValueError("Qbit proof transaction is not coinbase")
    parent_branch = [reader.take(32) for _ in range(reader.compact_size(31))]
    parent_index = reader.i32()
    chain_branch = [reader.take(32) for _ in range(reader.compact_size(30))]
    chain_index = reader.i32()
    parent_raw = reader.take(80)
    if reader.remaining and not full_block:
        raise ValueError("trailing bytes on Qbit AuxPoW header")
    if full_block and not reader.remaining:
        raise ValueError("missing Qbit block body")
    if parent_index != 0:
        raise ValueError("Qbit coinbase branch index must be zero")
    if not 0 <= chain_index < 1 << len(chain_branch):
        raise ValueError("Qbit chain index outside tree width")
    parent = parse_parent_header(parent_raw)
    root = fold_merkle_branch(tx.txid_internal, parent_branch, parent_index)
    if hash_to_display_hex(root) != parent["merkle_root"]:
        raise ValueError("Qbit parent coinbase Merkle root mismatch")
    chain_root = fold_merkle_branch(sha256d(pure), chain_branch, chain_index)
    display_root = bytes.fromhex(hash_to_display_hex(chain_root))
    script = tx.inputs[0].script_sig
    root_pos = script.find(display_root)
    if root_pos < 0:
        raise ValueError("Qbit display-order chain commitment missing")
    magic_pos = script.find(MERGED_MINING_HEADER)
    if magic_pos >= 0:
        if script.find(MERGED_MINING_HEADER, magic_pos + 1) >= 0:
            raise ValueError("multiple Qbit merged-mining markers")
        if magic_pos + 4 != root_pos:
            raise ValueError("Qbit marker must immediately precede commitment")
    elif root_pos > 20:
        raise ValueError("Qbit legacy commitment starts beyond byte 20")
    footer = script[root_pos + 32 : root_pos + 40]
    if len(footer) != 8:
        raise ValueError("truncated Qbit commitment footer")
    size, nonce = struct.unpack("<II", footer)
    if size != 1 << len(chain_branch):
        raise ValueError("Qbit commitment tree size mismatch")
    if chain_index != auxpow_lcg_index(nonce, CHAIN_ID, len(chain_branch)):
        raise ValueError("Qbit commitment chain slot mismatch")
    if int(parent["hash"], 16) > target:
        raise ValueError("Qbit parent proof fails child header target")
    auxpow = {
        "parent_header_raw": parent_raw,
        "coinbase_tx": {
            "vin": [{"scriptsig": tx.inputs[0].script_sig}],
            "vout": [
                {"value": out.value, "pkscript": out.script_pubkey}
                for out in tx.outputs
            ],
        },
    }
    parent_target = nbits_to_target(parent["bits"])
    result.update(
        extended_header_hex=raw[: reader.pos].hex(),
        parent=parent,
        parent_coinbase_hex=tx.raw_without_witness.hex(),
        parent_self_pow=0 < parent_target < 1 << 256
        and int(parent["hash"], 16) <= parent_target,
        row=standard_auxpow_parse_row("qbit_height", height, auxpow, child),
    )
    return result
