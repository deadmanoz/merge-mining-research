"""Common byte-level AuxPoW commitments and the native-record dict adapter."""

import struct
from dataclasses import dataclass
from typing import Literal, Sequence

from .auxpow_chainid import (
    auxpow_lcg_index,
    fold_merkle_branch,
    hash_from_header_bytes,
    hash_to_display_hex,
)
from .auxpow_parse import ChildHeaderValidationError
from .block_body import _transaction_at
from .coinbase_markers import AUXPOW_MAGIC


@dataclass(frozen=True)
class CommitmentFailure:
    """Neutral first failure; callers retain their own diagnostics and context."""

    reason: Literal[
        "missing_root",
        "duplicate_marker",
        "misplaced_marker",
        "late_legacy_root",
        "short_footer",
        "wrong_size",
        "wrong_slot",
    ]
    actual: int | None = None
    expected: int | None = None


def parent_merkle_matches(
    txid_internal: bytes,
    branch_internal: Sequence[bytes],
    index: int,
    parent_root_internal: bytes,
) -> bool:
    """Check transaction inclusion using internal-order hashes throughout.

    Parsing, transaction completeness and branch/index guards belong to callers.
    This does not establish coinbase identity or parent body consensus.
    """
    return (
        fold_merkle_branch(txid_internal, branch_internal, index)
        == parent_root_internal
    )


def child_commitment_failure(
    child_hash_internal: bytes,
    branch_internal: Sequence[bytes],
    index: int,
    script: bytes,
    chain_id: int,
) -> CommitmentFailure | None:
    """Check the display-order child root, placement, footer and chain slot.

    Use the first root and marker occurrences, including the legacy offset-20
    boundary. Callers own branch/index guards and protocol-specific rules;
    in particular, do not move a caller's later slot failure ahead of inclusion.
    """
    root_internal = fold_merkle_branch(child_hash_internal, branch_internal, index)
    root = bytes.fromhex(hash_to_display_hex(root_internal))
    offset = script.find(root)
    if offset < 0:
        return CommitmentFailure("missing_root")
    marker = script.find(AUXPOW_MAGIC)
    if marker >= 0:
        if script.find(AUXPOW_MAGIC, marker + 1) >= 0:
            return CommitmentFailure("duplicate_marker")
        if offset != marker + len(AUXPOW_MAGIC):
            return CommitmentFailure("misplaced_marker")
    elif offset > 20:
        return CommitmentFailure("late_legacy_root")
    suffix = offset + len(root)
    if len(script) - suffix < 8:
        return CommitmentFailure("short_footer")
    size, nonce = struct.unpack_from("<II", script, suffix)
    expected_size = 1 << len(branch_internal)
    if size != expected_size:
        return CommitmentFailure("wrong_size", size, expected_size)
    expected_index = auxpow_lcg_index(nonce, chain_id, len(branch_internal))
    if index != expected_index:
        return CommitmentFailure("wrong_slot", index, expected_index)
    return None


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
    if end != len(tx["raw"]) or not parent_merkle_matches(
        txid, auxpow["merkle_branch"], 0, auxpow["parent_header_raw"][36:68]
    ):
        raise ChildHeaderValidationError("AuxPoW parent transaction merkle mismatch")
    branch = auxpow["chain_merkle_branch"]
    index = auxpow["chain_index"]
    if len(branch) > 30 or index < 0 or index >= 1 << len(branch):
        raise ChildHeaderValidationError("invalid AuxPoW chain merkle index or depth")
    failure = child_commitment_failure(
        hash_from_header_bytes(child_header),
        branch,
        index,
        tx["vin"][0]["scriptsig"],
        chain_id,
    )
    if failure is not None:
        if failure.reason == "short_footer":
            message = "AuxPoW commitment lacks size and nonce"
        elif failure.reason in ("wrong_size", "wrong_slot"):
            message = "AuxPoW commitment size or chain slot mismatch"
        else:
            message = "AuxPoW child commitment missing or misplaced"
        raise ChildHeaderValidationError(message)
