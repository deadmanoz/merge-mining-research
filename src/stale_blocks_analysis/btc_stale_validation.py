"""Necessary Bitcoin header/context checks for direct-stale candidates.

Passing these checks is not proof that the complete Bitcoin block was
consensus-valid. The compact recovery artifacts normally contain the parent
header and coinbase evidence, not every transaction in the candidate block.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .btc_nbits_validation import validate_stale_nbits
from .coinbase_markers import parse_bip34_height
from .config import (
    BIP34_HEIGHT,
    BIP34_VERSION_2_HEIGHT,
    BIP65_HEIGHT,
    BIP66_HEIGHT,
)


RpcBatch = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
NOT_FOUND_ERROR_CODE = -5


def block_version_error(
    row: dict[str, Any],
    expected_height: int,
    *,
    header_hex_key: str = "btc_header_hex",
) -> str | None:
    """Return a rejection reason for a historical minimum-version failure."""
    if expected_height < BIP34_HEIGHT:
        return None

    header_version, header_error = _header_version(row, header_hex_key)
    if header_error is not None:
        return header_error

    if expected_height >= BIP65_HEIGHT:
        required_version, deployment = 4, "BIP65"
    elif expected_height >= BIP66_HEIGHT:
        required_version, deployment = 3, "BIP66"
    else:
        required_version, deployment = 2, "BIP34"
    if header_version is not None and header_version < required_version:
        return (
            "REJECTED: Bitcoin block version below historical minimum "
            f"(got {header_version}, required {required_version} after "
            f"{deployment} height {expected_height})"
        )
    return None


def stale_header_context_error(
    row: dict[str, Any],
    expected_height: int,
    *,
    parent_median_time_past: int | None = None,
    time_key: str = "btc_time",
    bip34_key: str = "btc_bip34_height",
    scriptsig_key: str = "coinbase_scriptsig_hex",
    header_hex_key: str = "btc_header_hex",
) -> str | None:
    """Return the first available-evidence consensus failure."""
    if parent_median_time_past is not None:
        mtp_error = median_time_past_error(
            row,
            parent_median_time_past,
            time_key=time_key,
        )
        if mtp_error is not None:
            return mtp_error
    version_error = block_version_error(
        row, expected_height, header_hex_key=header_hex_key
    )
    if version_error is not None:
        return version_error
    scriptsig_length_error = coinbase_scriptsig_length_error(
        row,
        scriptsig_key=scriptsig_key,
    )
    if scriptsig_length_error is not None:
        return scriptsig_length_error
    return bip34_height_error(
        row,
        expected_height,
        bip34_key=bip34_key,
        scriptsig_key=scriptsig_key,
        header_hex_key=header_hex_key,
    )


def median_time_past_error(
    row: dict[str, Any],
    parent_median_time_past: int,
    *,
    time_key: str = "btc_time",
) -> str | None:
    """Return a rejection reason when candidate time is not above parent MTP."""
    if (
        not isinstance(parent_median_time_past, int)
        or isinstance(parent_median_time_past, bool)
        or parent_median_time_past < 0
        or parent_median_time_past > 0xFFFFFFFF
    ):
        return "UNKNOWN: canonical parent median-time-past unavailable"

    time_text = str(row.get(time_key, "") or "").strip()
    try:
        candidate_time = int(time_text)
    except ValueError:
        return f"UNKNOWN: malformed {time_key} value {time_text!r}"
    if candidate_time < 0 or candidate_time > 0xFFFFFFFF:
        return f"UNKNOWN: malformed {time_key} value {time_text!r}"
    if candidate_time <= parent_median_time_past:
        return (
            "REJECTED: Bitcoin header time not greater than parent "
            "median-time-past "
            f"(got {candidate_time}, required > {parent_median_time_past})"
        )
    return None


def coinbase_scriptsig_length_error(
    row: dict[str, Any],
    *,
    scriptsig_key: str = "coinbase_scriptsig_hex",
) -> str | None:
    """Return a rejection reason for Bitcoin's 2..100 byte coinbase limit."""
    scriptsig_hex = str(row.get(scriptsig_key, "") or "").strip()
    if not scriptsig_hex:
        return "UNKNOWN: missing coinbase scriptSig for length validation"
    try:
        scriptsig = bytes.fromhex(scriptsig_hex)
    except ValueError:
        return "UNKNOWN: malformed coinbase scriptSig hex"
    length = len(scriptsig)
    if not 2 <= length <= 100:
        return (
            "REJECTED: Bitcoin coinbase scriptSig length outside consensus range "
            f"(got {length}, required 2..100)"
        )
    return None


def bip34_height_error(
    row: dict[str, Any],
    expected_height: int,
    *,
    bip34_key: str = "btc_bip34_height",
    scriptsig_key: str = "coinbase_scriptsig_hex",
    header_hex_key: str = "btc_header_hex",
) -> str | None:
    """Return a rejection reason for a mandatory BIP34-height failure.

    BIP34's coinbase-height rule applied to version 2 or newer blocks from
    height 224,413. At height 227,931, version 1 became invalid and the prefix
    became mandatory for every block. A pre-decoded column is corroborating
    metadata, not a substitute for the raw consensus input.
    """
    if expected_height < BIP34_VERSION_2_HEIGHT:
        return None

    header_version, header_error = _header_version(row, header_hex_key)

    if expected_height >= BIP34_HEIGHT:
        if header_error is not None:
            return header_error
        if header_version is not None and header_version < 2:
            return (
                "REJECTED: Bitcoin block version below 2 after BIP34 transition "
                f"(got {header_version}, height {expected_height})"
            )
    elif header_version is not None and header_version < 2:
        return None

    declared: int | None = None
    declared_text = str(row.get(bip34_key, "") or "").strip()
    if declared_text:
        try:
            declared = int(declared_text)
        except ValueError:
            return f"REJECTED: malformed {bip34_key} value {declared_text!r}"
        if declared < 0:
            return f"REJECTED: malformed {bip34_key} value {declared_text!r}"

    scriptsig_hex = str(row.get(scriptsig_key, "") or "").strip()
    if not scriptsig_hex:
        if expected_height < BIP34_HEIGHT and header_error is not None:
            return header_error
        return "REJECTED: missing coinbase scriptSig for BIP34 validation"
    try:
        scriptsig = bytes.fromhex(scriptsig_hex)
    except ValueError:
        if expected_height < BIP34_HEIGHT and header_error is not None:
            return header_error
        return "REJECTED: malformed coinbase scriptSig hex"

    expected_prefix = _bip34_height_prefix(expected_height)
    decoded = parse_bip34_height(scriptsig)
    if not scriptsig.startswith(expected_prefix):
        if header_error is not None:
            return header_error
        if decoded is None:
            return "REJECTED: missing BIP34 coinbase height"
        return (
            "REJECTED: BIP34 coinbase height mismatch "
            f"(got {decoded}, expected {expected_height})"
        )

    if declared is not None and decoded is not None and declared != decoded:
        return (
            "REJECTED: decoded BIP34 coinbase height disagrees with "
            f"{bip34_key} (decoded {decoded}, column {declared})"
        )

    return None


def _bip34_height_prefix(height: int) -> bytes:
    """Encode the exact ``CScript() << height`` prefix checked by Core."""
    if height == 0:
        return b"\x00"

    value = height
    encoded = bytearray()
    while value:
        encoded.append(value & 0xFF)
        value >>= 8
    if encoded[-1] & 0x80:
        encoded.append(0)
    if len(encoded) > 75:  # pragma: no cover - impossible for block heights
        raise ValueError("BIP34 height encoding exceeds direct-push range")
    return bytes([len(encoded)]) + bytes(encoded)


def _header_version(
    row: dict[str, Any], header_hex_key: str
) -> tuple[int | None, str | None]:
    header_hex = str(row.get(header_hex_key, "") or "").strip()
    if len(header_hex) != 160:
        return None, "UNKNOWN: missing Bitcoin header for header-context validation"
    try:
        header = bytes.fromhex(header_hex)
    except ValueError:
        return None, "UNKNOWN: malformed Bitcoin header for header-context validation"
    return int.from_bytes(header[:4], "little", signed=True), None


def validate_stale_header_context(
    stales: list[dict[str, Any]],
    rpc_batch: RpcBatch,
    *,
    height_key: str = "btc_height",
    bits_key: str = "btc_bits",
    status_key: str = "validation_status",
    expected_key: str = "expected_nbits",
    prev_hash_key: str = "btc_prev_hash",
    time_key: str = "btc_time",
    bip34_key: str = "btc_bip34_height",
    scriptsig_key: str = "coinbase_scriptsig_hex",
    header_hex_key: str = "btc_header_hex",
) -> None:
    """Apply necessary direct-stale parent, MTP, and available-evidence gates.

    A ``VALID`` result means only that the row passed this declared profile.
    It does not cover rules requiring unavailable complete-block evidence,
    including transaction merkle-root, weight, witness, sigop, finality, and
    UTXO/script validation.
    """
    validate_stale_nbits(
        stales,
        rpc_batch,
        height_key=height_key,
        bits_key=bits_key,
        status_key=status_key,
        expected_key=expected_key,
    )

    parent_calls = [
        {
            "jsonrpc": "1.0",
            "id": i,
            "method": "getblockheader",
            "params": [str(stale.get(prev_hash_key, "") or "")],
        }
        for i, stale in enumerate(stales)
        if str(stale.get(prev_hash_key, "") or "")
    ]
    requested_parent_ids = {call["id"] for call in parent_calls}
    if parent_calls:
        try:
            raw_parent_responses = rpc_batch(parent_calls)
        except Exception:  # noqa: BLE001 - an unavailable RPC is not invalid data
            for i, stale in enumerate(stales):
                if i in requested_parent_ids:
                    _set_parent_context_unknown(stale, status_key)
            return
    else:
        raw_parent_responses = []

    if not isinstance(raw_parent_responses, list) or any(
        not isinstance(response, dict) for response in raw_parent_responses
    ):
        for i, stale in enumerate(stales):
            if i in requested_parent_ids:
                _set_parent_context_unknown(stale, status_key)
        return

    parent_responses: dict[int, dict[str, Any]] = {}
    malformed_batch = False
    for response in raw_parent_responses:
        response_id = response.get("id")
        if (
            not isinstance(response_id, int)
            or isinstance(response_id, bool)
            or response_id < 0
            or response_id >= len(stales)
            or response_id in parent_responses
        ):
            malformed_batch = True
            break
        parent_responses[response_id] = response
    if malformed_batch:
        for i, stale in enumerate(stales):
            if i in requested_parent_ids:
                _set_parent_context_unknown(stale, status_key)
        return

    for i, stale in enumerate(stales):
        try:
            expected_height = int(str(stale.get(height_key, "") or ""))
        except ValueError:
            continue
        prev_hash = str(stale.get(prev_hash_key, "") or "").lower()
        if not prev_hash:
            _set_parent_context_unknown(stale, status_key)
            continue

        response = parent_responses.get(i)
        if response is None:
            _set_parent_context_unknown(stale, status_key)
            continue
        error = response.get("error")
        if error is not None:
            if isinstance(error, dict) and error.get("code") == NOT_FOUND_ERROR_CODE:
                stale[status_key] = (
                    "REJECTED: direct-stale predecessor is not the expected "
                    "active-chain Bitcoin block"
                )
            else:
                _set_parent_context_unknown(stale, status_key)
            continue

        parent = response.get("result")
        if not isinstance(parent, dict):
            _set_parent_context_unknown(stale, status_key)
            continue
        if str(parent.get("hash", "")).lower() != prev_hash:
            _set_parent_context_unknown(stale, status_key)
            continue
        confirmations = parent.get("confirmations")
        if not isinstance(confirmations, int) or isinstance(confirmations, bool):
            _set_parent_context_unknown(stale, status_key)
            continue
        if confirmations <= 0:
            stale[status_key] = (
                "REJECTED: direct-stale predecessor is not the expected "
                "active-chain Bitcoin block"
            )
            continue

        parent_height = parent.get("height")
        if not isinstance(parent_height, int) or isinstance(parent_height, bool):
            _set_parent_context_unknown(stale, status_key)
            continue
        if parent_height + 1 != expected_height:
            _set_parent_context_unknown(stale, status_key)
            continue

        parent_mtp = parent.get("mediantime")
        if not isinstance(parent_mtp, int) or isinstance(parent_mtp, bool):
            _set_parent_context_unknown(stale, status_key)
            continue

        error = stale_header_context_error(
            stale,
            expected_height,
            parent_median_time_past=parent_mtp,
            time_key=time_key,
            bip34_key=bip34_key,
            scriptsig_key=scriptsig_key,
            header_hex_key=header_hex_key,
        )
        if error is not None:
            current = str(stale.get(status_key, "") or "")
            if not (current.startswith("REJECTED:") and error.startswith("UNKNOWN:")):
                stale[status_key] = error


def _set_parent_context_unknown(stale: dict[str, Any], status_key: str) -> None:
    """Record unavailable parent context without erasing a proven rejection."""
    current = str(stale.get(status_key, "") or "")
    if not current.startswith("REJECTED:"):
        stale[status_key] = "UNKNOWN: canonical parent context unavailable"
