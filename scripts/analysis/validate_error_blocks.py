#!/usr/bin/env python3
"""Offline re-derivation validator for the committed error-blocks dataset.

Every row in ``data/error-blocks/error_blocks.csv`` claims to be a
consensus-invalid full-PoW Bitcoin block. This validator re-checks each claim
from the committed bytes, with no live RPC:

1. Full proof of work: the 80-byte header's sha256d digest must meet the
   header's own ``btc_bits`` target. A header that fails this is a share, not
   an error block. The digest must ALSO meet the canonical ``expected_nbits``
   target (the Bitcoin difficulty in force at the claimed position): a header
   with easy non-Bitcoin embedded bits plus a correct canonical
   ``expected_nbits`` is a share at the canonical difficulty, not a full-PoW
   error block (the BCH/BSV-contamination concern).
2. Each rule token in ``rules_violated`` must re-derive: the matching gate in
   ``stale_blocks_analysis.btc_stale_validation`` must return a failure string
   for the row's committed header/coinbase bytes. A gate returning ``None``
   means the claimed violation does not reproduce from the evidence. A firing
   gate proves only that A violation exists, not that the DECLARED token is
   the right one: the version/length tokens are recomputed from the height /
   actual scriptSig length, and a BIP34 coinbase-height token additionally
   requires the header version to pass the version requirement for the height
   (at BIP34+ heights ``bip34_height_error`` rejects a too-low version before
   examining the coinbase prefix, so a version-1 header labelled with a
   coinbase-height token would otherwise pass for the wrong reason).
   ``rejection_reason`` must be non-empty and equal to the FIRST token of
   ``rules_violated``: the dataset contract makes it the primary rule of the
   pipe-joined set, so a row whose ``rejection_reason`` is a secondary rule
   or unrelated token is inconsistent even when every rule re-derives.
   The reverse direction holds for the three mechanically-derivable-from-bytes
   rules: the version, BIP34 coinbase-height, and coinbase scriptSig-length
   violations are re-derived unconditionally, and one that is present but NOT
   claimed in ``rules_violated`` is flagged as an unclaimed violation (a row
   may not omit a real secondary violation). Context-dependent rules (MTP,
   retarget) are not held to exact-set equality: only these three
   byte-derivable rules are.
3. ``expected_nbits`` must equal the canonical epoch bits in the committed
   retarget-epoch reference table. Additionally, for every row NOT claiming
   ``nbits_retarget_not_applied``, the header's EMBEDDED ``btc_bits`` field
   must equal ``expected_nbits``: Bitcoin requires the nBits field to equal
   the value in force for that height, so a wrong-but-stricter bits field is
   itself a consensus violation even when the digest meets both the stricter
   embedded target and the easier canonical target. The
   ``nbits_retarget_not_applied`` rule is the deliberate exception (its
   embedded bits are the previous epoch's by design).
4. The audit columns derived from the committed bytes must agree with those
   bytes: ``hash`` (the header digest), ``btc_prev_hash`` (header bytes 4-36,
   reversed to display order), ``btc_header_version`` (header bytes
   0-4 LE signed), ``btc_time`` (header bytes 68-72 LE), ``btc_bits`` (header
   bytes 72-76 LE), and ``coinbase_height`` (the BIP34 height prefix decoded
   from ``coinbase_scriptsig_hex``). A tampered audit column that disagrees
   with its bytes is flagged. The ``coinbase_height`` cross-check only
   applies where a BIP34 prefix is actually derivable from the scriptSig; a
   pre-BIP34 row (or one whose scriptSig has no decodable height push) has
   no derivable value to compare against, so that specific check is skipped.

Time rules need canonical-chain context that is not available offline.
``time_below_mtp`` and ``median_time_past_violation`` are re-derived from the
committed ``data/error-blocks/mtp_context.csv`` sidecar (the canonical
parent's median-time-past, keyed by ``(height, hash)``), with the candidate
nTime derived from the header bytes (bytes 68-72 LE), never trusted from the
``btc_time`` column. The remaining time
rule (``time_beyond_future_limit``) needs network-adjusted time, which is not
committed, so it can never be re-derived offline. It is therefore REJECTED,
not deferred-accepted: a row carrying the token fails validation, because an
error block must have a mechanically-recheckable violation and this rule is
not offline-recheckable. The ``TIME_RULES`` set is the explicit extension
point for any further not-offline-recheckable time rules; every token in it
fails closed.

``nbits_retarget_not_applied`` is re-derived offline against the committed
retarget-epoch reference table: at an epoch-start height the block's
``btc_bits`` must equal the table value at that height, and this rule fires
when the block instead carries the PREVIOUS epoch's bits (it failed to apply
the retarget). The canonical-target PoW requirement (the digest must meet the
harder new-epoch ``expected_nbits`` target, not just the embedded
previous-epoch bits) is covered uniformly for every row by check 1 above; for
this rule the digest meets BOTH targets. This is distinct from a plain ``nBits
mismatch`` rejection at
a non-boundary height, which is the contamination gate's target class (a
share/near row), not an error block: the error-block case is specifically the
retarget-not-applied at an epoch boundary where the header still meets full
proof of work.

Scope note: this validator does NOT verify active-parent placement — it does
not check that the claimed parent (``btc_prev_hash``) is a canonical/active
Bitcoin block. That check needs canonical chain context (a live RPC view of
the active chain) and is enforced by the online classification pipeline at
classification time, not by this offline re-derivation. The offline validator
proves the named consensus violation from the committed bytes;
active-parent/canonical placement is a separate, online gate.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from stale_blocks_analysis.auxpow_chainid import hash_to_display_hex
from stale_blocks_analysis.auxpow_parse import (
    hash_meets_btc_difficulty,
    parse_coinbase_height,
)
from stale_blocks_analysis.btc_stale_validation import (
    LENGTH_RULES as _LENGTH_RULE_TOKENS,
)
from stale_blocks_analysis.btc_stale_validation import (
    VERSION_RULES as _VERSION_RULE_TOKENS,
)
from stale_blocks_analysis.btc_stale_validation import (
    bip34_height_error,
    block_version_error,
    coinbase_scriptsig_length_error,
    consensus_violations,
    expected_length_rule as _expected_length_token,
    expected_version_rule as _expected_version_token,
    median_time_past_error,
    nbits_retarget_not_applied_error as _nbits_retarget_not_applied_error,
)
from stale_blocks_analysis.config import (
    BITCOIN_EPOCH_REFERENCE_DIR,
    ERROR_BLOCKS_CSV,
    ERROR_BLOCKS_MTP_CONTEXT_CSV,
)

EPOCH_LENGTH = 2016
NBITS_BY_EPOCH_JSON = BITCOIN_EPOCH_REFERENCE_DIR / "btc_nbits_by_epoch.json"

# Rules whose re-derivation needs canonical-chain context (network-adjusted
# time) that is not available offline. A token in this set can never be
# re-derived from the committed bytes, so it can never be a valid committed
# error block: the validator fails closed on it rather than silently accepting
# the row. ``time_below_mtp`` and ``median_time_past_violation`` are re-derived
# from the committed MTP context sidecar and are NOT in this set.
TIME_RULES = frozenset(
    {
        "time_beyond_future_limit",
    }
)

Gate = Callable[[dict[str, Any], int], str | None]


def _load_nbits_by_epoch() -> dict[int, int]:
    with open(NBITS_BY_EPOCH_JSON) as f:
        table = json.load(f)
    return {
        int(epoch_start): int(hexbits, 16) for epoch_start, hexbits in table.items()
    }


def _load_mtp_context() -> dict[tuple[int, str], int]:
    """Load the committed parent median-time-past sidecar, keyed by (height, hash)."""
    out: dict[tuple[int, str], int] = {}
    with open(ERROR_BLOCKS_MTP_CONTEXT_CSV, newline="") as f:
        for row_number, row in enumerate(csv.DictReader(f), start=2):
            try:
                out[(int(row["height"]), row["hash"])] = int(
                    row["parent_median_time_past"]
                )
            except (KeyError, ValueError) as exc:
                raise ValueError(
                    f"invalid MTP context row {row_number} in "
                    f"{ERROR_BLOCKS_MTP_CONTEXT_CSV}"
                ) from exc
    return out


RULE_GATES: dict[str, Gate] = {
    "bip34_block_version_below_2": block_version_error,
    "bip66_block_version_below_3": block_version_error,
    "bip65_block_version_below_4": block_version_error,
    "coinbase_scriptsig_length_above_100": lambda row, height: (
        coinbase_scriptsig_length_error(row)
    ),
    "coinbase_scriptsig_length_below_2": lambda row, height: (
        coinbase_scriptsig_length_error(row)
    ),
    "bip34_coinbase_height_mismatch": bip34_height_error,
    "bip34_v2_coinbase_height_mismatch": bip34_height_error,
    "bip34_coinbase_height_missing": bip34_height_error,
    "bip34_v2_coinbase_height_missing": bip34_height_error,
}

# The version-rule and length-rule tokens are not independent labels: each is
# fully determined by the violation itself (the height for the version rules,
# the actual scriptSig length for the length rules). A gate returning REJECTED
# proves A violation exists but not that the DECLARED token is the right one —
# a BIP65-era version-2 header labelled ``bip66_block_version_below_3`` fires
# the same gate as the correct ``bip65_block_version_below_4``, and a 1-byte
# scriptSig fires the same length gate whether labelled above_100 or below_2.
# These sets let the validator recompute the correct token and require the
# declared one to match the actual violation.
# The token vocabulary and its derivation live in
# ``stale_blocks_analysis.btc_stale_validation`` so the classifier and this
# validator apply one implementation: what the classifier labels an error
# block is exactly what this validator will re-derive. Imported above as
# ``_VERSION_RULE_TOKENS`` / ``_LENGTH_RULE_TOKENS``.
# The BIP34 coinbase-height tokens name the coinbase-height serialization as
# the violation. But ``bip34_height_error`` is two-stage: at BIP34+ heights
# (>= BIP34_HEIGHT) a version-1 header is rejected for its VERSION before the
# coinbase prefix is ever examined, so the gate fires for such a header
# regardless of its coinbase bytes. A row labelled with a coinbase-height
# token whose header version is ALSO too low for its height is inconsistent:
# the real/primary violation is the version, not the coinbase height.
_BIP34_COINBASE_HEIGHT_TOKENS = frozenset(
    {
        "bip34_coinbase_height_mismatch",
        "bip34_v2_coinbase_height_mismatch",
        "bip34_coinbase_height_missing",
        "bip34_v2_coinbase_height_missing",
    }
)
# The genuine raw-prefix BIP34 coinbase-height mismatch: the scriptSig's
# encoded height push is actually wrong for the claimed height. This is the
# same prefix the sweeps key on (``_BIP34_HEIGHT_MISMATCH_PREFIX`` /
# ``BIP34_HEIGHT_MISMATCH_PREFIX`` there). ``bip34_height_error``'s other
# REJECTED forms are NOT a coinbase-height consensus violation: unusable
# evidence ("malformed ...", "missing ...") or the metadata cross-check
# disagreement ("decoded BIP34 coinbase height disagrees with
# btc_bip34_height", where the scriptSig encodes the height correctly and only
# the optional column disagrees). Only the raw-prefix mismatch proves a BIP34
# coinbase-height violation. Imported above from ``btc_stale_validation``.
# The metadata cross-check rejection: the scriptSig encodes the height
# CORRECTLY and only the optional ``btc_bip34_height`` column disagrees with
# the decoded prefix. That is inconsistent metadata, not a Bitcoin consensus
# violation (the raw coinbase bytes are correct), so it is neither derived nor
# accepted as proof of a BIP34 coinbase-height rule.
_BIP34_METADATA_CROSSCHECK_PREFIX = (
    "REJECTED: decoded BIP34 coinbase height disagrees with"
)


def _actual_violation_token(rule: str, row: dict[str, Any], height: int) -> str | None:
    """Recompute the correct token for the actual violation, or None.

    Only the version and length rules have a height/length-determined token;
    for any other rule (or when the length cannot be re-derived) there is no
    consistency check to apply, so None is returned.
    """
    if rule in _VERSION_RULE_TOKENS:
        return _expected_version_token(height)
    if rule in _LENGTH_RULE_TOKENS:
        return _expected_length_token(row)
    return None


def _derivable_violation_tokens(row: dict[str, Any], height: int) -> list[str]:
    """Derive the supported byte-recheckable violations present in the row.

    The reverse direction of the per-rule gates: the version, BIP34
    coinbase-height, and coinbase scriptSig-length violations are fully
    determined by the committed header/coinbase bytes, so they are re-derived
    unconditionally and each must be claimed in ``rules_violated``. Only a
    rule-specific REJECTED verdict counts as a present violation; an UNKNOWN,
    malformed-evidence, or missing-evidence (``missing coinbase scriptSig``)
    verdict means the evidence was unusable, which the claimed-rule path
    already fails closed on. Context-dependent rules (MTP,
    retarget) are deliberately not derived here.

    The BIP34 coinbase-height token is only derived when the header version
    passes the version requirement for the height: at BIP34+ heights
    ``bip34_height_error`` rejects a too-low version before examining the
    coinbase prefix, so a version-1 header's real violation is the version
    (already derived above), not the coinbase height.

    Delegates to ``consensus_violations``, the shared derivation the classifier
    uses to label a row ``error_block``. Calling it without a parent
    median-time-past evaluates exactly the three byte-derivable rules this
    reverse check covers and none of the context-dependent ones, so what the
    classifier labels and what this validator demands cannot drift apart.
    """
    return consensus_violations(row, height)


def nbits_retarget_not_applied_error(
    row: dict[str, Any], nbits_by_epoch: dict[int, int]
) -> str | None:
    """Re-derive the ``nbits_retarget_not_applied`` violation offline.

    Thin adapter over the shared gate in ``btc_stale_validation``: the dataset
    row carries its height in ``height`` while the classifier passes its
    authoritative height explicitly, so only the height lookup differs. Raises
    ``ValueError`` when the claim cannot be evaluated (malformed row fields, or
    an epoch table that lacks either height); the validator fails closed on an
    unevaluable claim.
    """
    try:
        height = int(str(row.get("height", "") or "").strip())
    except ValueError as exc:
        raise ValueError(
            "malformed height or btc_bits for nbits_retarget_not_applied"
        ) from exc
    return _nbits_retarget_not_applied_error(row, height, nbits_by_epoch)


def validate_row(
    row: dict[str, str],
    *,
    nbits_by_epoch: dict[int, int] | None = None,
    mtp_context: dict[tuple[int, str], int] | None = None,
) -> list[str]:
    """Return re-derivation failure messages for one error-block row."""
    if nbits_by_epoch is None:
        nbits_by_epoch = _load_nbits_by_epoch()
    if mtp_context is None:
        mtp_context = _load_mtp_context()

    failures: list[str] = []

    height_text = str(row.get("height", "") or "").strip()
    try:
        height = int(height_text)
    except ValueError:
        return [f"malformed height value {height_text!r}"]

    # (a) Full proof of work against the header's own target.
    header_hex = str(row.get("btc_header_hex", "") or "").strip()
    bits_text = str(row.get("btc_bits", "") or "").strip()
    derived_time: int | None = None
    header_digest: bytes | None = None
    embedded_bits: int | None = None
    try:
        header = bytes.fromhex(header_hex)
        bits = int(bits_text, 16)
    except ValueError:
        failures.append("malformed btc_header_hex or btc_bits")
    else:
        embedded_bits = bits
        if len(header) != 80:
            failures.append(f"btc_header_hex is {len(header)} bytes, expected 80")
        else:
            digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
            header_digest = digest
            if not hash_meets_btc_difficulty(digest, bits):
                failures.append(
                    "header hash does not meet its own target (not full PoW)"
                )
            # The hash, btc_prev_hash, btc_header_version, btc_time, and
            # btc_bits columns are derived values: they must agree with the
            # committed header bytes, or the row's (height, hash) exclusion
            # key, parent-placement, version-rule, time-rule, and PoW claims
            # describe a different block than the header does.
            derived_hash = digest[::-1].hex()
            if str(row.get("hash", "") or "").strip().lower() != derived_hash:
                failures.append("hash column does not match btc_header_hex digest")
            derived_prev_hash = hash_to_display_hex(header[4:36])
            prev_hash_text = str(row.get("btc_prev_hash", "") or "").strip().lower()
            if prev_hash_text != derived_prev_hash:
                failures.append(
                    "btc_prev_hash column does not match the header's embedded "
                    "previous-block hash"
                )
            derived_version = int.from_bytes(header[0:4], "little", signed=True)
            version_text = str(row.get("btc_header_version", "") or "").strip()
            try:
                if int(version_text) != derived_version:
                    failures.append(
                        "btc_header_version column does not match the header's "
                        "embedded nVersion"
                    )
            except ValueError:
                failures.append(f"malformed btc_header_version value {version_text!r}")
            derived_time = int.from_bytes(header[68:72], "little")
            time_text = str(row.get("btc_time", "") or "").strip()
            try:
                if int(time_text) != derived_time:
                    failures.append(
                        "btc_time column does not match the header's embedded nTime"
                    )
            except ValueError:
                failures.append(f"malformed btc_time value {time_text!r}")
            derived_bits = int.from_bytes(header[72:76], "little")
            if derived_bits != bits:
                failures.append(
                    "btc_bits column does not match the header's embedded nBits"
                )

    # The coinbase_height audit column is derived from the BIP34 height
    # prefix of the committed coinbase scriptSig: it must agree with the
    # bytes, or the row's coinbase-height claims describe a different
    # coinbase than the scriptSig does. The cross-check is only applied
    # where a BIP34 prefix is actually derivable from the scriptSig: a
    # pre-BIP34 row (or one whose scriptSig has no decodable height push)
    # has no derivable value to compare against, so it is skipped.
    scriptsig_text = str(row.get("coinbase_scriptsig_hex", "") or "").strip()
    try:
        scriptsig = bytes.fromhex(scriptsig_text)
    except ValueError:
        scriptsig = b""
        # A malformed NONEMPTY scriptSig is not missing evidence: the row
        # claims to carry parent-coinbase bytes but they cannot be parsed, so
        # no coinbase-dependent check (the BIP34-prefix cross-check here, the
        # length gate, the BIP34 height gate) can evaluate them. Fail closed
        # rather than silently treating the evidence as absent. (An EMPTY
        # scriptSig stays missing evidence: the row may simply not expose the
        # parent coinbase.)
        if scriptsig_text:
            failures.append("malformed nonempty coinbase_scriptsig_hex")
    derived_coinbase_height = parse_coinbase_height(scriptsig) if scriptsig else None
    if derived_coinbase_height is not None:
        coinbase_height_text = str(row.get("coinbase_height", "") or "").strip()
        try:
            if int(coinbase_height_text) != derived_coinbase_height:
                failures.append(
                    "coinbase_height column does not match the coinbase "
                    "scriptSig's BIP34 height prefix"
                )
        except ValueError:
            failures.append(f"malformed coinbase_height value {coinbase_height_text!r}")

    # Parse expected_nbits once: it feeds both the canonical-target PoW check
    # below and the epoch-table check in section (c). A malformed value is
    # reported once, here.
    expected_text = str(row.get("expected_nbits", "") or "").strip()
    expected_nbits: int | None = None
    try:
        expected_nbits = int(expected_text, 16)
    except ValueError:
        failures.append(f"malformed expected_nbits value {expected_text!r}")

    # (a2) Full proof of work against the CANONICAL expected_nbits target.
    # Meeting only the embedded btc_bits is not enough: an error block must be
    # full-PoW at the Bitcoin difficulty in force at the claimed position (a
    # BCH/BSV-like header with easy non-Bitcoin embedded bits plus a correct
    # canonical expected_nbits would otherwise pass). For
    # nbits_retarget_not_applied rows the embedded bits are deliberately the
    # previous epoch's and the digest meets BOTH targets, so this check is
    # consistent with that rule's specific canonical-target check below.
    if header_digest is not None and expected_nbits is not None:
        if not hash_meets_btc_difficulty(header_digest, expected_nbits):
            failures.append(
                "header hash does not meet the canonical expected_nbits "
                "target (not full Bitcoin PoW)"
            )

    # (b) Every claimed rule violation must re-derive via its gate.
    rules_text = str(row.get("rules_violated", "") or "").strip()
    rules = [rule for rule in rules_text.split("|") if rule]
    if not rules:
        failures.append("rules_violated is empty")

    # (c2) The header's EMBEDDED btc_bits field must equal the canonical
    # expected_nbits. Bitcoin requires the nBits field to equal the value in
    # force for that height; a wrong-but-stricter bits field meets its own
    # (stricter) target AND the canonical (easier) target, and passes the
    # epoch-table check, yet is itself a consensus violation distinct from the
    # digest not meeting the target. The nbits_retarget_not_applied rule is the
    # deliberate exception: its embedded bits are the previous epoch's by
    # design, so the check is skipped for that token.
    if (
        embedded_bits is not None
        and expected_nbits is not None
        and "nbits_retarget_not_applied" not in rules
        and embedded_bits != expected_nbits
    ):
        failures.append(
            f"embedded btc_bits {bits_text} does not match canonical "
            f"expected_nbits {expected_text}"
        )

    # The dataset contract: rejection_reason is the PRIMARY (first) rule of
    # the pipe-joined rules_violated set. A row whose rejection_reason is
    # empty, missing, or any token other than the first is inconsistent even
    # when every rule in rules_violated re-derives.
    rejection_reason = str(row.get("rejection_reason", "") or "").strip()
    if not rejection_reason:
        failures.append("rejection_reason is empty")
    elif rules and rejection_reason != rules[0]:
        failures.append(
            f"rejection_reason {rejection_reason} is not the primary (first) "
            f"rule of rules_violated ({rules[0]})"
        )
    for rule in rules:
        if rule in TIME_RULES:
            # Fail closed: the rule needs network-adjusted time that is not
            # committed, so it can never be re-derived offline and can never
            # be a valid committed error block (see TIME_RULES above).
            failures.append(
                f"rule {rule} is not offline-recheckable and cannot be a "
                "committed error block"
            )
            continue
        if rule in ("time_below_mtp", "median_time_past_violation"):
            # Special case, not a RULE_GATES entry: median_time_past_error
            # needs a per-row parent_mtp argument the Gate signature
            # (Callable[[dict, int], str | None]) cannot carry.
            # Re-derive from the committed parent median-time-past sidecar.
            # The candidate nTime is derived from the header bytes (bytes
            # 68-72 LE), never trusted from the btc_time column.
            parent_mtp = mtp_context.get((height, str(row.get("hash", ""))))
            if parent_mtp is None:
                failures.append(
                    f"rule {rule} has no committed MTP context for "
                    f"({height}, {str(row.get('hash', ''))[-12:]})"
                )
                continue
            if derived_time is None:
                # The header was already flagged malformed above; the rule
                # cannot be re-derived without its nTime.
                failures.append(
                    f"rule {rule} cannot re-derive: no parseable header nTime"
                )
                continue
            mtp_result = median_time_past_error(
                {**row, "btc_time": str(derived_time)},
                parent_mtp,
                time_key="btc_time",
            )
            if mtp_result is None:
                failures.append(f"rule {rule} did not re-derive")
                continue
            # Same consistency rule as the other gates: only a rule-specific
            # REJECTED verdict is proof of the declared violation. An
            # UNKNOWN: verdict (an invalid sidecar value, e.g. -1 or above
            # the uint32 max) means the evidence was unusable — fail closed.
            if mtp_result.startswith("UNKNOWN:"):
                failures.append(
                    f"rule {rule} could not be evaluated (gate returned UNKNOWN)"
                )
            continue
        if rule == "nbits_retarget_not_applied":
            # Special case, not a RULE_GATES entry: the retarget-boundary
            # check needs the epoch table, which the Gate signature cannot
            # carry. None of the btc_stale_validation gates cover
            # retarget-boundary bits, so the check lives in this module.
            # The canonical-target PoW requirement for this rule is now
            # covered uniformly for ALL rows by section (a2) above, so only
            # the epoch-table re-derivation remains here.
            try:
                derived = nbits_retarget_not_applied_error(row, nbits_by_epoch)
            except ValueError as exc:
                failures.append(f"rule nbits_retarget_not_applied: {exc}")
                continue
            if derived is None:
                failures.append("rule nbits_retarget_not_applied did not re-derive")
            continue
        gate = RULE_GATES.get(rule)
        if gate is None:
            failures.append(f"no gate registered for rule {rule}")
            continue
        gate_result = gate(row, height)
        if gate_result is None:
            failures.append(f"rule {rule} did not re-derive")
            continue
        # A non-None gate result only counts as proof of the declared rule
        # when it is a rule-specific REJECTED verdict for THAT rule. An
        # UNKNOWN: verdict means the evidence was unusable/missing (not a
        # proven violation), and a REJECTED that is clearly a
        # malformed-evidence verdict (e.g. bip34_height_error's "malformed
        # coinbase scriptSig hex") or a missing-evidence verdict
        # (bip34_height_error's "missing coinbase scriptSig for BIP34
        # validation") means the evidence could not be parsed or was absent
        # (also not a proven consensus violation: a genuine BIP34 violation
        # requires a PRESENT, wrongly-encoded scriptSig). Fail closed on all
        # three: unusable evidence is not proof.
        if gate_result.startswith("UNKNOWN:"):
            failures.append(
                f"rule {rule} could not be evaluated (gate returned UNKNOWN)"
            )
            continue
        if "malformed" in gate_result:
            failures.append(
                f"rule {rule} could not be evaluated (gate returned a "
                "malformed-evidence verdict, not a proven violation)"
            )
            continue
        # bip34_height_error's "REJECTED: missing coinbase scriptSig for
        # BIP34 validation" is likewise a missing-evidence verdict, not a
        # proven consensus violation: a genuine BIP34 coinbase-height
        # violation requires the scriptSig to be PRESENT and wrongly-encoded.
        # An empty scriptSig is absent evidence (the row may simply not
        # expose the parent coinbase), so fail closed on it too.
        if "missing coinbase scriptSig" in gate_result:
            failures.append(
                f"rule {rule} could not be evaluated (gate returned a "
                "missing-evidence verdict, not a proven violation)"
            )
            continue
        # A BIP34 coinbase-height token is proven only by the genuine
        # raw-prefix height mismatch (the scriptSig's encoded height push is
        # actually wrong for the claimed height) — the same form the sweeps
        # key on. bip34_height_error's metadata cross-check rejection
        # ("REJECTED: decoded BIP34 coinbase height disagrees with
        # btc_bip34_height") fires when the scriptSig encodes the height
        # CORRECTLY and only the optional btc_bip34_height column disagrees:
        # that is inconsistent metadata, not a Bitcoin consensus violation
        # (the raw coinbase bytes are correct), so it is not proof of the
        # declared coinbase-height rule. (A too-low header VERSION rejection
        # is handled by the version-inconsistency check below.)
        if rule in _BIP34_COINBASE_HEIGHT_TOKENS and gate_result.startswith(
            _BIP34_METADATA_CROSSCHECK_PREFIX
        ):
            failures.append(
                f"rule {rule} could not be evaluated (gate returned a "
                "metadata cross-check rejection, not a genuine raw-prefix "
                "coinbase-height mismatch)"
            )
            continue
        # The gate fired, but that only proves A violation exists — not that
        # the DECLARED token is the right one. For the version and length
        # rules the correct token is determined by the height / actual
        # scriptSig length; require the declared token to match the actual
        # violation so a mislabelled row is flagged.
        actual_token = _actual_violation_token(rule, row, height)
        if actual_token is not None and actual_token != rule:
            failures.append(
                f"declared rule {rule} inconsistent with actual violation "
                f"{actual_token}"
            )
        # A BIP34 coinbase-height token names the coinbase-height
        # serialization as the violation. That is only the case when the
        # header version PASSES the version requirement for the height: at
        # BIP34+ heights bip34_height_error rejects a too-low version before
        # examining the coinbase prefix, so a version-1 header labelled with
        # a coinbase-height token fails for the wrong reason (the real
        # violation is the version). Require the version to pass so the
        # coinbase height is the only remaining failure.
        if rule in _BIP34_COINBASE_HEIGHT_TOKENS and (
            block_version_error(row, height) is not None
        ):
            failures.append(
                f"declared rule {rule} inconsistent with actual violation: "
                "header version is also too low for the height (the real "
                "violation is the version, not the coinbase height)"
            )

    # (b2) The reverse direction for the mechanically-derivable-from-bytes
    # rules: a version, BIP34 coinbase-height, or scriptSig-length violation
    # that is present in the committed bytes but NOT claimed in
    # rules_violated is flagged. A row may not omit a real secondary
    # violation (e.g. a too-long coinbase scriptSig alongside a declared
    # version violation). Context-dependent rules (MTP, retarget) are not
    # held to exact-set equality.
    for token in _derivable_violation_tokens(row, height):
        if token not in rules:
            failures.append(f"unclaimed violation: {token}")

    # (c) expected_nbits must match the canonical epoch bits table. The value
    # was already parsed above (a malformed value was reported there); only
    # the epoch-table comparison remains.
    epoch_start = (height // EPOCH_LENGTH) * EPOCH_LENGTH
    if expected_nbits is not None:
        epoch_bits = nbits_by_epoch.get(epoch_start)
        if epoch_bits is None:
            failures.append(
                f"epoch start {epoch_start} missing from nbits reference table"
            )
        elif expected_nbits != epoch_bits:
            failures.append(
                f"expected_nbits {expected_text} does not match epoch table "
                f"value {epoch_bits:08x} at epoch start {epoch_start}"
            )

    return failures


def validate_dataset(path: Path = ERROR_BLOCKS_CSV) -> list[str]:
    """Re-derive every row in the committed error-blocks CSV."""
    nbits_by_epoch = _load_nbits_by_epoch()
    mtp_context = _load_mtp_context()
    failures: list[str] = []
    seen_keys: set[tuple[int, str]] = set()
    row_count = 0
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            row_count += 1
            row_id = f"{row.get('height', '?')}:{str(row.get('hash', ''))[-12:]}"
            if (row.get("classification") or "").strip() != "error_block":
                failures.append(f"{row_id}: classification must be error_block")
            try:
                key = (int(row["height"]), row["hash"].strip().lower())
                if key[0] < 0 or len(key[1]) != 64:
                    raise ValueError
                bytes.fromhex(key[1])
            except (KeyError, ValueError):
                # ``validate_row`` emits the detailed audit failure for a
                # malformed key. Duplicate detection applies only when the
                # identity itself is parseable, matching the gate loader.
                key = None
            if key is not None:
                if key in seen_keys:
                    failures.append(
                        f"{row_id}: duplicate error-block key {key} in {path}"
                    )
                seen_keys.add(key)
            for failure in validate_row(
                row, nbits_by_epoch=nbits_by_epoch, mtp_context=mtp_context
            ):
                failures.append(f"{row_id}: {failure}")
    if row_count == 0:
        # Fail closed: a header-only or empty dataset yields an empty failure
        # list, which the CLI would otherwise report as success — a truncated
        # committed dataset would silently pass validation. This mirrors the
        # fail-closed empty-dataset checks in the gate loader
        # (``stale_blocks_analysis.error_blocks``) and the builder.
        failures.append(f"dataset is empty (no error-block rows in {path})")
    return failures


def main() -> int:
    failures = validate_dataset()
    if failures:
        print(f"{len(failures)} error-block re-derivation failure(s):")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print("all committed error blocks re-derive from committed bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
