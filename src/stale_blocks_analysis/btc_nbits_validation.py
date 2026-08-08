"""Helpers for validating stale-candidate nBits against Bitcoin mainchain."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


RpcBatch = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]


# The contamination verdict: the header's difficulty is not Bitcoin's at this
# height, so it belongs to another SHA-256 chain rather than being an invalid
# Bitcoin block. The one exception is an unapplied retarget at an epoch
# boundary, which the consensus rules catch separately.
NBITS_MISMATCH_PREFIX = "REJECTED: nBits mismatch with canonical BTC height"


def _response_map(
    responses: object, *, requested_ids: set[int]
) -> dict[int, dict[str, Any]] | None:
    """Return an id-keyed complete batch, or ``None`` when it is ambiguous."""
    if not isinstance(responses, list):
        return None
    mapped: dict[int, dict[str, Any]] = {}
    for response in responses:
        if not isinstance(response, dict):
            return None
        response_id = response.get("id")
        if (
            not isinstance(response_id, int)
            or isinstance(response_id, bool)
            or response_id not in requested_ids
            or response_id in mapped
        ):
            return None
        mapped[response_id] = response
    if set(mapped) != requested_ids:
        return None
    return mapped


def _hash_hex(value: object) -> str | None:
    """Normalize a well-formed 32-byte display-order hash."""
    if not isinstance(value, str) or len(value) != 64:
        return None
    try:
        bytes.fromhex(value)
    except ValueError:
        return None
    return value.lower()


def _bits_hex(value: object) -> str | None:
    """Normalize a well-formed four-byte compact target."""
    if not isinstance(value, str) or len(value) != 8:
        return None
    try:
        bytes.fromhex(value)
    except ValueError:
        return None
    return value.lower()


def validate_stale_nbits(
    stales: list[dict[str, str]],
    rpc_batch: RpcBatch,
    *,
    height_key: str = "btc_height",
    bits_key: str = "btc_bits",
    status_key: str = "validation_status",
    expected_key: str = "expected_nbits",
) -> None:
    """Mark stale rows VALID/REJECTED by canonical Bitcoin nBits at height.

    A stale block whose prev_hash is canonical must use the exact nBits that
    Bitcoin Core computes for the next height on that canonical chain. Checking
    only that the header hash satisfies its own encoded target is insufficient:
    BCH/BSV-family headers can satisfy their easier target while sharing a BTC
    ancestor.

    ``rpc_batch`` must accept JSON-RPC batch call dictionaries and return the
    decoded batch responses. Rows are updated in place.
    """
    if not stales:
        return

    heights: list[int | None] = []
    hash_calls: list[dict[str, Any]] = []
    for i, stale in enumerate(stales):
        try:
            height = int(stale.get(height_key, ""))
        except ValueError:
            height = None
        heights.append(height)
        if height is not None:
            hash_calls.append(
                {
                    "jsonrpc": "1.0",
                    "id": i,
                    "method": "getblockhash",
                    "params": [height],
                }
            )

    requested_hash_ids = {int(call["id"]) for call in hash_calls}
    try:
        raw_hash_responses = rpc_batch(hash_calls) if hash_calls else []
    except Exception:  # noqa: BLE001 - unavailable context is not invalid data
        raw_hash_responses = None
    hash_responses = _response_map(raw_hash_responses, requested_ids=requested_hash_ids)
    canonical_hashes: dict[int, str] = {}
    if hash_responses is not None:
        for response_id, response in hash_responses.items():
            if response.get("error") is None:
                block_hash = _hash_hex(response.get("result"))
                if block_hash is not None:
                    canonical_hashes[response_id] = block_hash

    header_calls = [
        {
            "jsonrpc": "1.0",
            "id": i,
            "method": "getblockheader",
            "params": [block_hash],
        }
        for i, block_hash in canonical_hashes.items()
    ]
    requested_header_ids = {int(call["id"]) for call in header_calls}
    try:
        raw_header_responses = rpc_batch(header_calls) if header_calls else []
    except Exception:  # noqa: BLE001 - unavailable context is not invalid data
        raw_header_responses = None
    header_responses = _response_map(
        raw_header_responses, requested_ids=requested_header_ids
    )
    expected_bits: dict[int, str] = {}
    if header_responses is not None:
        for response_id, response in header_responses.items():
            result = response.get("result")
            if response.get("error") is not None or not isinstance(result, dict):
                continue
            if _hash_hex(result.get("hash")) != canonical_hashes[response_id]:
                continue
            height = result.get("height")
            confirmations = result.get("confirmations")
            if (
                not isinstance(height, int)
                or isinstance(height, bool)
                or height != heights[response_id]
                or not isinstance(confirmations, int)
                or isinstance(confirmations, bool)
                or confirmations <= 0
            ):
                continue
            bits = _bits_hex(result.get("bits"))
            if bits is not None:
                expected_bits[response_id] = bits

    for i, stale in enumerate(stales):
        stale_bits = (stale.get(bits_key) or "").strip().lower()
        expected = expected_bits.get(i, "")
        stale[expected_key] = expected
        if heights[i] is None:
            stale[status_key] = "UNKNOWN: missing btc_height"
        elif not expected:
            stale[status_key] = "UNKNOWN: canonical nBits unavailable"
        elif stale_bits == expected:
            stale[status_key] = "VALID"
        else:
            stale[status_key] = (
                f"{NBITS_MISMATCH_PREFIX} (got {stale_bits}, expected {expected})"
            )
