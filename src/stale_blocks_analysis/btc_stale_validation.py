"""Necessary header and context checks for direct-stale candidates.

Passing this profile is not full-block validation. The artifacts normally
carry the parent header and coinbase, not every transaction.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .btc_nbits_validation import validate_stale_nbits
from .bitcoin_binary import bip34_height_prefix
from .coinbase_markers import parse_bip34_height
from .config import (
    BIP34_HEIGHT,
    BIP34_VERSION_2_HEIGHT,
    BIP65_HEIGHT,
    BIP66_HEIGHT,
)


RpcBatch = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
NOT_FOUND_ERROR_CODE = -5

# The one verdict that is not a judgement on the block: it says the row is not
# a direct stale, because its predecessor is not on Bitcoin's active chain.
# Phase 2 accepts a parent that resolves; this gate re-checks it and can find
# the parent is itself stale. Such a row is an unknown, not a stale that
# failed, and the driver reclassifies it.
PLACEMENT_REJECTION = (
    "REJECTED: direct-stale predecessor is not the expected active-chain Bitcoin block"
)


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
    """BIP34 height prefix: version 2 from 224,413, mandatory for every block from 227,931.

    A pre-decoded column does not replace the raw scriptSig.
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

    expected_prefix = bip34_height_prefix(expected_height)
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


BIP34_HEIGHT_MISMATCH_PREFIX = "REJECTED: BIP34 coinbase height mismatch"
# The coinbase carries no decodable height push at all. Distinct from a
# mismatch (a height is there, it is the wrong one) but equally a violation
# once BIP34 makes the prefix mandatory, and equally derivable from the bytes.
BIP34_HEIGHT_MISSING_PREFIX = "REJECTED: missing BIP34 coinbase height"

RETARGET_INTERVAL = 2016

MTP_RULE = "time_below_mtp"
NBITS_RETARGET_RULE = "nbits_retarget_not_applied"

VERSION_RULES = frozenset(
    {
        "bip34_block_version_below_2",
        "bip66_block_version_below_3",
        "bip65_block_version_below_4",
    }
)
LENGTH_RULES = frozenset(
    {
        "coinbase_scriptsig_length_above_100",
        "coinbase_scriptsig_length_below_2",
    }
)


def expected_version_rule(height: int) -> str:
    """Version token at ``height``: v2 from BIP34, v3 from BIP66, v4 from BIP65.

    A v1 or v2 header in the BIP65 era is ``bip65_block_version_below_4``.
    """
    if height >= BIP65_HEIGHT:
        return "bip65_block_version_below_4"
    if height >= BIP66_HEIGHT:
        return "bip66_block_version_below_3"
    return "bip34_block_version_below_2"


def expected_length_rule(
    row: dict[str, Any],
    *,
    scriptsig_key: str = "coinbase_scriptsig_hex",
) -> str | None:
    """Length token for a present scriptSig outside 2..100 bytes, else None.

    An empty scriptSig is missing evidence (RSK never exposes one), not a
    zero-byte violation. Malformed hex is likewise unusable.
    """
    scriptsig_text = str(row.get(scriptsig_key, "") or "").strip()
    if not scriptsig_text:
        return None
    try:
        length = len(bytes.fromhex(scriptsig_text))
    except ValueError:
        return None
    if length > 100:
        return "coinbase_scriptsig_length_above_100"
    if length < 2:
        return "coinbase_scriptsig_length_below_2"
    return None


def nbits_retarget_not_applied_error(
    row: dict[str, Any],
    expected_height: int,
    nbits_by_epoch: dict[int, int],
    *,
    bits_key: str = "btc_bits",
    expected_key: str = "expected_nbits",
) -> str | None:
    """Epoch-start bits equal the previous epoch, not the new ``expected_nbits``.

    A mid-epoch mismatch is contamination, not this rule. Prefer the row's
    own ``expected_nbits``; the committed table is the fallback, and the
    previous epoch is always read from the table. ``ValueError`` on an
    unevaluable claim. Returning None would let that row look clean.
    """
    try:
        bits = int(str(row.get(bits_key, "") or "").strip(), 16)
    except ValueError as exc:
        raise ValueError(f"malformed {bits_key} for {NBITS_RETARGET_RULE}") from exc
    if expected_height % RETARGET_INTERVAL != 0:
        return None
    epoch_bits: int | None
    try:
        epoch_bits = int(str(row.get(expected_key, "") or "").strip(), 16)
    except ValueError:
        epoch_bits = nbits_by_epoch.get(expected_height)
    previous_bits = nbits_by_epoch.get(expected_height - RETARGET_INTERVAL)
    if epoch_bits is None or previous_bits is None:
        missing = []
        if epoch_bits is None:
            missing.append(f"canonical bits for {expected_height}")
        if previous_bits is None:
            missing.append(
                f"epoch table entry for {expected_height - RETARGET_INTERVAL}"
            )
        raise ValueError(
            f"cannot re-derive {NBITS_RETARGET_RULE}: no {' and no '.join(missing)}"
        )
    if bits == epoch_bits or bits != previous_bits:
        return None
    return (
        f"REJECTED: {NBITS_RETARGET_RULE} at epoch start {expected_height} "
        f"(got previous-epoch bits {bits:08x}, expected {epoch_bits:08x})"
    )


def consensus_violations(
    row: dict[str, Any],
    expected_height: int,
    *,
    parent_median_time_past: int | None = None,
    nbits_by_epoch: dict[int, int] | None = None,
    scriptsig_key: str = "coinbase_scriptsig_hex",
    header_hex_key: str = "btc_header_hex",
) -> list[str]:
    """Rules the bytes prove. Empty is not a validity claim.

    A gate ``REJECTED`` is an error block only when a rule re-derives.
    Unusable evidence and a placement failure produce no token. Every firing
    rule is returned, in gate order, so the first is the primary reason.
    Omit ``parent_median_time_past`` or ``nbits_by_epoch`` to skip that rule.
    """
    rules: list[str] = []

    if nbits_by_epoch is not None:
        retarget_error = nbits_retarget_not_applied_error(
            row, expected_height, nbits_by_epoch
        )
        if retarget_error is not None:
            rules.append(NBITS_RETARGET_RULE)

    if parent_median_time_past is not None:
        mtp_error = median_time_past_error(row, parent_median_time_past)
        if mtp_error is not None and mtp_error.startswith("REJECTED:"):
            rules.append(MTP_RULE)

    version_error = block_version_error(
        row, expected_height, header_hex_key=header_hex_key
    )
    if version_error is not None and version_error.startswith("REJECTED:"):
        rules.append(expected_version_rule(expected_height))

    if coinbase_scriptsig_length_error(row, scriptsig_key=scriptsig_key) is not None:
        length_rule = expected_length_rule(row, scriptsig_key=scriptsig_key)
        if length_rule is not None:
            rules.append(length_rule)

    # At BIP34+ heights ``bip34_height_error`` rejects a too-low version before
    # it examines the coinbase prefix, so a version-1 header's real violation is
    # the version -- already recorded above -- and not the coinbase height.
    if version_error is None:
        bip34_error = bip34_height_error(
            row,
            expected_height,
            scriptsig_key=scriptsig_key,
            header_hex_key=header_hex_key,
        )
        # Only the genuine raw-prefix mismatch is a consensus violation. The
        # gate's other REJECTED forms are unusable evidence or a disagreement
        # between the scriptSig and the optional metadata column.
        v2_era = expected_height < BIP34_HEIGHT
        if bip34_error is not None and bip34_error.startswith(
            BIP34_HEIGHT_MISMATCH_PREFIX
        ):
            rules.append(
                "bip34_v2_coinbase_height_mismatch"
                if v2_era
                else "bip34_coinbase_height_mismatch"
            )
        elif bip34_error is not None and bip34_error.startswith(
            BIP34_HEIGHT_MISSING_PREFIX
        ):
            # A present, well-formed coinbase carrying no height push at all.
            # Once the prefix is mandatory that is as much a violation as the
            # wrong height, and it is proven by the same committed bytes.
            rules.append(
                "bip34_v2_coinbase_height_missing"
                if v2_era
                else "bip34_coinbase_height_missing"
            )

    return rules


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
    """``VALID`` means this profile passed, not merkle, weight, witness, sigop, finality, or UTXO validity."""
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
                stale[status_key] = PLACEMENT_REJECTION
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
            stale[status_key] = PLACEMENT_REJECTION
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
        # Retain the parent's median-time-past on the row. It is not a column
        # and cannot be recovered later without the node, but the caller needs
        # it to re-derive which consensus rules the row broke. The leading
        # underscore keeps it out of every CSV writer.
        stale["_parent_median_time_past"] = parent_mtp

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
