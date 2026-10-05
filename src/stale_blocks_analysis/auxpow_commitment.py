"""Authenticate Namecoin-family AuxPoW links from retained native records."""

import struct

from .auxpow_chainid import auxpow_lcg_index, fold_merkle_branch, hash_from_header_bytes
from .auxpow_parse import ChildHeaderValidationError
from .block_body import _transaction_at


def transaction_is_coinbase(tx: dict) -> bool:
    """Recognize a transaction's single null outpoint, without body validation."""
    inputs = tx["vin"]
    return (
        len(inputs) == 1
        and inputs[0]["prev_hash"] == b"\0" * 32
        and inputs[0]["prev_idx"] == 0xFFFFFFFF
    )


def validate_auxpow_commitment(
    child_header: bytes, auxpow: dict, chain_id: int
) -> None:
    """Authenticate the child-to-parent commitment, not complete consensus."""
    tx = auxpow["coinbase_tx"]
    if not tx["vin"]:
        raise ChildHeaderValidationError("AuxPoW parent transaction has no inputs")
    if auxpow["merkle_index"] != 0:
        raise ChildHeaderValidationError("AuxPoW parent transaction index is not zero")
    try:
        _, txid, _, _, _, end = _transaction_at(tx["raw"], 0)
    except (IndexError, struct.error, ValueError) as exc:
        raise ChildHeaderValidationError("malformed AuxPoW parent transaction") from exc
    if (
        end != len(tx["raw"])
        or fold_merkle_branch(txid, auxpow["merkle_branch"], 0)
        != auxpow["parent_header_raw"][36:68]
    ):
        raise ChildHeaderValidationError("AuxPoW parent transaction merkle mismatch")
    branch = auxpow["chain_merkle_branch"]
    index = auxpow["chain_index"]
    if len(branch) > 30 or index < 0 or index >= 1 << len(branch):
        raise ChildHeaderValidationError("invalid AuxPoW chain merkle index or depth")
    root = fold_merkle_branch(hash_from_header_bytes(child_header), branch, index)[::-1]
    script = tx["vin"][0]["scriptsig"]
    offset = script.find(root)
    magic = bytes.fromhex("fabe6d6d")
    marker = script.find(magic)
    if (
        offset < 0
        or (marker < 0 and offset > 20)
        or (
            marker >= 0
            and (script.find(magic, marker + 1) >= 0 or offset != marker + 4)
        )
    ):
        raise ChildHeaderValidationError("AuxPoW child commitment missing or misplaced")
    suffix = offset + 32
    if len(script) - suffix < 8:
        raise ChildHeaderValidationError("AuxPoW commitment lacks size and nonce")
    size, nonce = struct.unpack_from("<II", script, suffix)
    if size != 1 << len(branch) or index != auxpow_lcg_index(
        nonce, chain_id, len(branch)
    ):
        raise ChildHeaderValidationError(
            "AuxPoW commitment size or chain slot mismatch"
        )
