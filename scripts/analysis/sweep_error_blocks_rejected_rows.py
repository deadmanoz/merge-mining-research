#!/usr/bin/env python3
"""Sweep REJECTED rows in per-chain classified inventories for error blocks.

Re-examines every ``REJECTED:`` row across the reachable chain classified
inventories (the authoritative copies live on the chain archive host, set via
the ``ERROR_BLOCKS_ARCHIVE_HOST`` env var; see ``CHAIN_INVENTORIES``). The
sweep answers one question per
rejected row: is this an error block — a full-proof-of-work Bitcoin header
that fails a *contextual* consensus rule — or a share/near row that fails the
*target* itself?

The distinction is re-verified per row, never inherited from the rejection
label:

- The rejection reason is classified as CONTEXTUAL (error-block candidate
  class) or TARGET (not an error block unless full PoW re-verifies).
- Full proof of work is re-derived from the committed bytes: sha256d of the
  80-byte ``btc_header_hex`` must meet the header's own embedded nBits
  target (decoded from the header bytes, never the ``btc_bits`` column) via
  ``hash_meets_btc_difficulty``.
- A contextual row's NAMED failure is re-derived from the committed
  header/coinbase bytes with the same ``btc_stale_validation`` gates the
  validator uses (``bip34_height_error``, ``block_version_error``,
  ``coinbase_scriptsig_length_error``): only a row whose named gate returns
  a REJECTED string is a confirmed error-block candidate. A contextual row
  whose named failure does not re-derive is tallied separately
  (``contextual_not_rederived``), and the median-time-past rejection needs
  canonical parent context that is not committed in the inventories, so it
  is tallied as ``contextual_not_offline_rederivable`` — neither is
  confirmed on the label alone.
- A contextual row must ALSO meet the *canonical expected* ``nBits`` target,
  not just the header's own embedded bits: a contextual row whose named
  failure re-derives but whose digest meets only an easy self-declared
  target is a share/contamination, tallied separately
  (``contextual_canonical_target_fail``), never a confirmed error block (the
  same rule the offline validator enforces). The canonical target is the
  shared corroborated check (``reverify_against_canonical_target``): the
  inventory's ``expected_nbits`` is corroborated against the committed
  retarget-epoch reference table and the check fails closed (unevaluable,
  never confirmed) on a disagreement or a missing epoch start, so a
  malformed/artificially-easy inventory value cannot promote a row.

A row is a sweep finding (a NEW confirmed error block) when it meets full PoW
AND the canonical expected ``nBits`` target AND its named contextual failure
re-derives AND its ``(height, hash)`` key is
not already in the committed dataset (``ERROR_BLOCKS_CSV``); identity and
membership use the header-derived display hash, never the
``btc_header_hash`` column. A contextual row from a
canonical-fill-scratch inventory (syscoin, or any chain in
``_sweep_common._SCRATCH_CHAINS``) is NEVER promoted: its ``btc_height`` is
not verified against the canonical chain (the height-trust model the other
error-block sweeps enforce), so a full-PoW contextual scratch row that would
otherwise be a finding is tallied separately as ``untrustworthy_height``.
Target-class rows are
additionally checked against the *canonical expected* ``nBits`` target:
re-verifying an nBits-mismatch row against its own ``btc_bits`` is circular
(a row rejected for wrong nBits trivially meets its own declared target), so
a target-class row whose digest meets the expected target is reported
separately as an error-block candidate for manual review — the sweep does
not promote it on its own. The target-class check uses the inventory's
``expected_nbits`` VERBATIM (the target the row was rejected against): the
anomaly signal is precisely the digest meeting that named target, so it is
deliberately NOT epoch-table-corroborated the way the contextual promotion
check is.

Inventory access is injectable: ``main`` defaults to reading each
authoritative inventory with ``ssh -o BatchMode=yes $ERROR_BLOCKS_ARCHIVE_HOST
cat <path>``, and ``--chain-archive-root`` instead reads a local mirror
directory laid out as ``<root>/<chain>/<filename>``. Tests inject a reader
directly.

FAIL CLOSED: an unreachable inventory is recorded as ``unreachable`` in the
report and the sweep continues; if NO inventory is reachable the script exits
non-zero. The committed report is only ever written from a COMPLETE sweep:
if any inventory is unreachable, writing the committed default report fails
closed (no committed write) unless ``--allow-partial`` together with a
disposable ``--output-dir`` writes the partial report there instead.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from _sweep_common import (  # noqa: E402
    ARCHIVE_HOST,
    InventoryReader,
    _SCRATCH_CHAINS,
    header_display_hash,
    load_dataset_keys,
    load_nbits_by_epoch,
    local_mirror_reader,
    require_full_coverage_for_committed,
    resolve_output_path,
    reverify_against_canonical_target,
    reverify_full_pow,
    ssh_inventory_reader,
    validate_partial_args,
)
from stale_blocks_analysis.auxpow_parse import hash_meets_btc_difficulty  # noqa: E402
from stale_blocks_analysis.btc_stale_validation import (  # noqa: E402
    bip34_height_error,
    block_version_error,
    coinbase_scriptsig_length_error,
)

# Authoritative per-chain classified inventories on the chain archive host.
# (chain, absolute path on ARCHIVE_HOST). Verified 2026-07-30: 44 REJECTED
# rows across these 7 inventories. This 7-chain REJECTED-row coverage map is
# deliberately NOT the shared 19-chain STALE_INVENTORIES map in
# _sweep_common.
CHAIN_INVENTORIES: dict[str, str] = {
    "devcoin": "~/mmr-child-header-regen-20260729/staging/chains/devcoin/classified/devcoin_stale_blocks.csv",
    "ixcoin": "~/mmr-child-header-regen-20260729/staging/chains/ixcoin/classified/ixcoin_stale_blocks.csv",
    "i0coin": "~/mmr-child-header-regen-20260729/staging/chains/i0coin/classified/i0coin_stale_blocks.csv",
    "groupcoin": "~/mmr-child-header-regen-20260729/staging/chains/groupcoin/classified/groupcoin_stale_blocks.csv",
    "emercoin": "~/mmr-child-header-regen-20260729/staging/chains/emercoin/classified/emercoin_stale_blocks.csv",
    "unobtanium": "~/mmr-child-header-regen-20260729/staging/chains/unobtanium/classified/unobtanium_stale_blocks.csv",
    "syscoin": "~/canonical-fill-scratch/syscoin/syscoin_stale_blocks.csv",
}

# Rejection-reason classes, matched on the text after "REJECTED: ".
# CONTEXTUAL: the header met the full Bitcoin PoW target but violates a
# consensus rule that needs chain/mempool context — the error-block class.
CONTEXTUAL_REASONS = (
    "BIP34 coinbase height mismatch",
    "Bitcoin block version below historical minimum",
    "Bitcoin coinbase scriptSig length outside consensus range",
    "Bitcoin header time not greater than parent median-time-past",
)
# TARGET: the header does not meet the expected target — a share/near row,
# not an error block unless full-PoW re-verification says otherwise.
TARGET_REASONS = (
    "nBits mismatch with canonical BTC height",
    "nBits mismatch",
)

# The MTP rejection needs the canonical parent's median-time-past, which is
# not committed in the classified inventories: it cannot be re-derived
# offline, so an MTP-labelled row is tallied separately and never confirmed
# as an error block by this sweep.
MTP_REASON_PREFIX = "Bitcoin header time not greater than parent median-time-past"

# The only ``bip34_height_error`` verdict that is a genuine raw coinbase-height
# serialization failure: the scriptSig's encoded height push is actually wrong
# for the claimed height. The gate's other REJECTED forms are NOT a
# coinbase-height consensus failure — a too-low header VERSION ("Bitcoin block
# version below 2 after BIP34 transition"), unusable evidence ("malformed ...",
# "missing ..."), or a metadata cross-check disagreement ("decoded BIP34
# coinbase height disagrees with btc_bip34_height", where the scriptSig encodes
# the height correctly and only the optional column disagrees). Only the
# raw-prefix mismatch confirms a BIP34-labelled contextual row.
BIP34_HEIGHT_MISMATCH_PREFIX = "REJECTED: BIP34 coinbase height mismatch"

DEFAULT_REPORT = Path("results/analysis/error-blocks/rejected-rows-report.md")


@dataclass
class RejectedRow:
    """One REJECTED inventory row with its derived sweep verdicts."""

    chain: str
    height: int
    block_hash: str
    reason: str
    reason_class: str  # "contextual" | "target" | "unrecognized"
    meets_full_pow: bool | None  # None when the header/bits cannot be parsed
    # Whether the digest meets the canonical expected-nBits target. For a
    # CONTEXTUAL row this is the corroborated canonical target (the
    # inventory's expected_nbits corroborated against the committed epoch
    # table, failing closed on a disagreement or a missing epoch start):
    # decisive for promotion. For a TARGET row this is the digest against
    # the inventory's expected_nbits verbatim (the target the row was
    # rejected against): the anomaly signal, where a disagreement with the
    # epoch table is itself part of what manual review must see. None when
    # the target cannot be evaluated.
    meets_expected_pow: bool | None = None
    # Whether the named contextual failure re-derives from the committed
    # header/coinbase bytes via its btc_stale_validation gate. None when the
    # failure needs canonical context that is not available offline (the
    # median-time-past rejection) or the row is not contextual.
    contextual_rederived: bool | None = None
    in_dataset: bool = False

    @property
    def is_error_block_candidate(self) -> bool:
        # Confirmed only when the named contextual failure actually
        # re-derives from the bytes — never on the rejection label alone —
        # AND the digest meets the CANONICAL expected-nBits target, not just
        # the header's own embedded bits: a contextual row meeting only an
        # easy self-declared target is a share/contamination, not a confirmed
        # error block (the same rule the offline validator enforces).
        return (
            self.reason_class == "contextual"
            and self.meets_full_pow is True
            and self.meets_expected_pow is True
            and self.contextual_rederived is True
        )

    @property
    def is_new_finding(self) -> bool:
        return self.is_error_block_candidate and not self.in_dataset

    @property
    def is_pow_passing_target_anomaly(self) -> bool:
        # An nBits-mismatch row that meets the *canonical expected* target is
        # not a share: it is full-PoW at the real Bitcoin difficulty with a
        # wrong nBits field (a contextual failure wearing a target-class
        # label). Meeting only its own (wrong) bits is circular — a row
        # rejected for wrong nBits trivially meets its own declared target.
        return self.reason_class == "target" and self.meets_expected_pow is True


@dataclass
class ChainReport:
    """Per-chain sweep tally."""

    chain: str
    inventory: str
    reachable: bool = True
    error: str = ""
    total_rows: int = 0
    rejected_rows: int = 0
    contextual: int = 0
    target: int = 0
    unrecognized: int = 0
    pow_pass: int = 0
    pow_fail: int = 0
    pow_unparseable: int = 0
    # Full-PoW contextual rows whose named failure did NOT re-derive from the
    # committed bytes: not confirmed error blocks.
    contextual_not_rederived: int = 0
    # Full-PoW MTP-labelled rows: the named failure needs canonical parent
    # context that is not committed in the inventories, so it cannot be
    # re-derived offline and the row is not confirmed.
    contextual_not_offline_rederivable: int = 0
    # Full-PoW contextual rows whose named failure re-derives but whose digest
    # does NOT meet the canonical expected-nBits target: share/contamination
    # observations, not confirmed error blocks.
    contextual_canonical_target_fail: int = 0
    # Full-PoW contextual rows from a canonical-fill-scratch inventory (any
    # chain in _SCRATCH_CHAINS) whose named failure re-derives AND whose
    # digest meets the canonical expected-nBits target: the scratch
    # inventory's btc_height is NOT canonical-verified, so the row is not
    # promoted to a confirmed finding on an unverified height (the
    # height-trust model the other error-block sweeps enforce).
    untrustworthy_height: int = 0
    already_in_dataset: int = 0
    new_findings: list[RejectedRow] = field(default_factory=list)
    # Distinct (height, hash) NEW-finding keys: the same new BTC error block
    # can be witnessed in several sibling-chain inventories, so the
    # new_findings observation list overcounts distinct blocks.
    new_finding_keys: set[tuple[int, str]] = field(default_factory=set)
    target_anomalies: list[RejectedRow] = field(default_factory=list)


def classify_reason(validation_status: str) -> tuple[str, str]:
    """Split ``REJECTED: <reason>`` into (reason, reason_class).

    The reason class is ``contextual``, ``target``, or ``unrecognized``.
    Matching is by prefix against the known reason strings; the parenthetical
    detail (``(got ...)``) is ignored.
    """
    status = validation_status.strip()
    if not status.startswith("REJECTED:"):
        raise ValueError(f"not a REJECTED status: {validation_status!r}")
    reason = status[len("REJECTED:") :].strip()
    for prefix in CONTEXTUAL_REASONS:
        if reason.startswith(prefix):
            return reason, "contextual"
    for prefix in TARGET_REASONS:
        if reason.startswith(prefix):
            return reason, "target"
    return reason, "unrecognized"


def rederive_contextual_failure(
    reason: str, row: dict[str, str], height: int
) -> bool | None:
    """Re-derive the named contextual failure from the committed bytes.

    Returns True when the gate matching the rejection label returns a
    REJECTED string (the failure reproduces from the header/coinbase
    evidence), False when it does not, and None when the named failure needs
    canonical-chain context that is not committed in the inventories (the
    median-time-past rejection) and so cannot be re-derived offline. The
    gates are the same ``btc_stale_validation`` functions the validator
    uses; an UNKNOWN: verdict (missing/malformed evidence) is not a
    re-derived failure.
    """
    if reason.startswith(MTP_REASON_PREFIX):
        return None
    if reason.startswith("BIP34 coinbase height mismatch"):
        # Confirm the failure is genuinely the raw coinbase-height
        # serialization, not another rejection the same gate can return. The
        # header version must PASS the version gate (a post-BIP34 version-1
        # header makes bip34_height_error reject for the VERSION rule, not the
        # coinbase height), and the verdict must be the genuine raw-prefix
        # height mismatch — not a malformed-evidence rejection and not the
        # metadata cross-check disagreement (the optional btc_bip34_height
        # column disagreeing with a correctly-encoded scriptSig), neither of
        # which is a coinbase-height consensus failure.
        if block_version_error(row, height) is not None:
            return False
        verdict = bip34_height_error(row, height)
        return verdict is not None and verdict.startswith(BIP34_HEIGHT_MISMATCH_PREFIX)
    if reason.startswith("Bitcoin block version below historical minimum"):
        verdict = block_version_error(row, height)
    elif reason.startswith("Bitcoin coinbase scriptSig length outside consensus range"):
        verdict = coinbase_scriptsig_length_error(row)
    else:
        # An unrecognized contextual label has no gate to re-derive against.
        return False
    return verdict is not None and verdict.startswith("REJECTED:")


def reverify_pow_against_target(header_hex: str, bits_text: str) -> bool | None:
    """Re-verify the header against an externally supplied target.

    Used only for the canonical-target anomaly check on target-class rows:
    the ``expected_nbits`` column is the canonical target the row was
    rejected against, and meeting it marks an error-block candidate for
    manual review. The value is used VERBATIM, not corroborated against the
    epoch table: for a target-class row the anomaly is precisely that the
    digest meets the target the inventory named, so a disagreeing
    ``expected_nbits`` is part of the signal manual review must see (the
    717696 retarget-boundary class). The corroborated, fail-closed variant
    (``reverify_against_canonical_target``) governs the contextual-row
    promotion check instead. Returns True/False, or None when the header hex
    or the target cannot be parsed.
    """
    try:
        header = bytes.fromhex((header_hex or "").strip())
        bits = int((bits_text or "").strip(), 16)
    except ValueError:
        return None
    if len(header) != 80:
        return None
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return hash_meets_btc_difficulty(digest, bits)


def sweep_chain(
    chain: str,
    inventory: str,
    reader: InventoryReader,
    dataset_keys: set[tuple[int, str]],
    nbits_by_epoch: dict[int, int] | None = None,
) -> ChainReport:
    """Sweep one chain inventory; unreachable inventories fail soft."""
    report = ChainReport(chain=chain, inventory=inventory)
    try:
        text = reader(chain, inventory)
    except (OSError, subprocess.SubprocessError) as exc:
        report.reachable = False
        report.error = str(exc)
        return report

    if nbits_by_epoch is None:
        nbits_by_epoch = load_nbits_by_epoch()

    rows = list(csv.DictReader(io.StringIO(text)))
    report.total_rows = len(rows)
    for row in rows:
        status = (row.get("validation_status") or "").strip()
        if not status.startswith("REJECTED:"):
            continue
        report.rejected_rows += 1
        reason, reason_class = classify_reason(status)
        try:
            height = int((row.get("btc_height") or "").strip())
        except ValueError:
            height = -1
        block_hash = header_display_hash(row.get("btc_header_hex") or "") or ""
        meets_pow = reverify_full_pow(row.get("btc_header_hex") or "")
        # The canonical-target check differs by reason class. For a
        # CONTEXTUAL row the promotion check must corroborate the inventory's
        # expected_nbits against the committed epoch table and fail closed on
        # a disagreement or a missing epoch start: a malformed/artificially-
        # easy inventory value must not let a contextual row pass
        # meets_expected_pow into new_findings. For a TARGET row the decisive
        # check is the canonical expected target the row was rejected against
        # (not the header's own allegedly-wrong bits), used verbatim: the
        # anomaly signal IS the digest meeting that named target.
        if reason_class == "contextual":
            meets_expected = reverify_against_canonical_target(
                row.get("btc_header_hex") or "", row, height, nbits_by_epoch
            )
        else:
            meets_expected = reverify_pow_against_target(
                row.get("btc_header_hex") or "", row.get("expected_nbits") or ""
            )
        # A contextual row is confirmed only when its NAMED failure
        # re-derives from the committed bytes — never on the label alone.
        contextual_rederived = (
            rederive_contextual_failure(reason, row, height)
            if reason_class == "contextual"
            else None
        )
        rejected = RejectedRow(
            chain=chain,
            height=height,
            block_hash=block_hash,
            reason=reason,
            reason_class=reason_class,
            meets_full_pow=meets_pow,
            meets_expected_pow=meets_expected,
            contextual_rederived=contextual_rederived,
            in_dataset=(height, block_hash) in dataset_keys,
        )
        if reason_class == "contextual":
            report.contextual += 1
        elif reason_class == "target":
            report.target += 1
        else:
            report.unrecognized += 1
        if meets_pow is True:
            report.pow_pass += 1
        elif meets_pow is False:
            report.pow_fail += 1
        else:
            report.pow_unparseable += 1
        if (
            reason_class == "contextual"
            and meets_pow is True
            and contextual_rederived is not True
        ):
            if contextual_rederived is None:
                report.contextual_not_offline_rederivable += 1
            else:
                report.contextual_not_rederived += 1
        if (
            reason_class == "contextual"
            and meets_pow is True
            and contextual_rederived is True
            and meets_expected is not True
        ):
            # The named failure re-derives and the header meets its own
            # embedded target, but the digest fails (or cannot be evaluated
            # against) the canonical expected-nBits target: a
            # share/contamination observation, not a confirmed error block.
            report.contextual_canonical_target_fail += 1
        if rejected.is_error_block_candidate:
            if chain in _SCRATCH_CHAINS:
                # A scratch inventory's btc_height is NOT canonical-verified,
                # so a contextual row is never promoted to a confirmed finding
                # on an unverified height (the height-trust model the other
                # error-block sweeps enforce): tally it separately.
                report.untrustworthy_height += 1
            elif rejected.in_dataset:
                report.already_in_dataset += 1
            else:
                report.new_findings.append(rejected)
                report.new_finding_keys.add((rejected.height, rejected.block_hash))
        if rejected.is_pow_passing_target_anomaly:
            report.target_anomalies.append(rejected)
    return report


def render_report(reports: list[ChainReport], generated_at: str) -> str:
    """Render the dated Markdown sweep report, including negative results."""
    reachable = [r for r in reports if r.reachable]
    unreachable = [r for r in reports if not r.reachable]
    total_rejected = sum(r.rejected_rows for r in reachable)
    total_contextual = sum(r.contextual for r in reachable)
    total_target = sum(r.target for r in reachable)
    total_not_rederived = sum(r.contextual_not_rederived for r in reachable)
    total_not_offline = sum(r.contextual_not_offline_rederivable for r in reachable)
    total_canonical_fail = sum(r.contextual_canonical_target_fail for r in reachable)
    total_untrustworthy = sum(r.untrustworthy_height for r in reachable)
    total_new = sum(len(r.new_findings) for r in reachable)
    distinct_new = len({key for r in reachable for key in r.new_finding_keys})
    total_anomalies = sum(len(r.target_anomalies) for r in reachable)
    total_anomalies_in_dataset = sum(
        1 for r in reachable for row in r.target_anomalies if row.in_dataset
    )
    total_anomalies_unpromoted = total_anomalies - total_anomalies_in_dataset

    lines = [
        "# Error-blocks rejected-row mining sweep",
        "",
        f"Generated: {generated_at}",
        "",
        "Re-examination of every `REJECTED:` row across the reachable per-chain",
        "classified inventories on the chain archive host. A row is an error",
        "block when it fails a *contextual* consensus rule while meeting the",
        "full Bitcoin proof-of-work target; rows failing the *target* are",
        "shares/near rows, not error blocks. The distinction is re-verified",
        "per row from the committed header bytes via",
        "`hash_meets_btc_difficulty`, never inherited from the rejection",
        "label: a contextual row is confirmed only when its named failure",
        "re-derives from the committed header/coinbase bytes via the same",
        "`btc_stale_validation` gates the validator uses AND its digest meets",
        "the canonical expected-nBits target, not just the header's own",
        "embedded bits (a contextual row meeting only an easy self-declared",
        "target is a share/contamination, the same rule the offline validator",
        "enforces). Membership is",
        "checked against the committed `data/error-blocks/error_blocks.csv`",
        "dataset by `(height, hash)` with the header-derived display hash,",
        "never the `btc_header_hash` column.",
        "",
        "## Summary",
        "",
        f"- Inventories reachable: {len(reachable)}/{len(reports)}",
        f"- REJECTED rows examined: {total_rejected}",
        f"- Contextual-class rejections: {total_contextual}",
        f"- Target-class rejections: {total_target}",
        f"- NEW confirmed error blocks (full PoW + canonical target + "
        f"contextual re-derived, not in dataset): {total_new} "
        f"observations across {distinct_new} distinct (height, hash) "
        "blocks (the same new BTC error block can be witnessed in several "
        "sibling-chain inventories)",
        f"- Full-PoW contextual rows whose named failure did NOT re-derive "
        f"(not confirmed): {total_not_rederived}",
        f"- Full-PoW median-time-past rows (named failure needs canonical "
        f"parent context, not re-derivable offline, not confirmed): "
        f"{total_not_offline}",
        f"- Full-PoW contextual rows re-deriving their named failure but "
        f"failing the canonical expected-nBits target (share/contamination, "
        f"not confirmed): {total_canonical_fail}",
        f"- Full-PoW contextual rows from a canonical-fill-scratch inventory "
        f"(unverified btc_height, not promoted): {total_untrustworthy}",
        f"- Target-class rows meeting the canonical expected target despite "
        f"the nBits label (error-block candidates, manual review, not "
        f"auto-promoted): {total_anomalies} "
        f"({total_anomalies_unpromoted} un-promoted, "
        f"{total_anomalies_in_dataset} already in the dataset)",
        "",
    ]
    if unreachable:
        lines += [
            "## Unreachable inventories",
            "",
        ]
        for r in unreachable:
            lines.append(f"- **{r.chain}** (`{r.inventory}`): {r.error}")
        lines.append("")

    lines += [
        "## Per-chain results",
        "",
        "| chain | total rows | REJECTED | contextual | target | unrecognized "
        "| full-PoW pass | full-PoW fail | not re-derived | not offline-"
        "rederivable | untrustworthy height | already in dataset | NEW |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in reports:
        if not r.reachable:
            lines.append(
                f"| {r.chain} | — | — | — | — | — | — | — | — | — | — | — | unreachable |"
            )
            continue
        lines.append(
            f"| {r.chain} | {r.total_rows} | {r.rejected_rows} | {r.contextual} "
            f"| {r.target} | {r.unrecognized} | {r.pow_pass} | {r.pow_fail} "
            f"| {r.contextual_not_rederived} "
            f"| {r.contextual_not_offline_rederivable} "
            f"| {r.untrustworthy_height} "
            f"| {r.already_in_dataset} | {len(r.new_findings)} |"
        )
    lines.append("")

    lines += ["## Negative results", ""]
    zero_rejected = [r.chain for r in reachable if r.rejected_rows == 0]
    if zero_rejected:
        lines.append(
            "- Chains with zero REJECTED rows: " + ", ".join(zero_rejected) + "."
        )
    else:
        lines.append("- No reachable chain had zero REJECTED rows.")
    all_target_fail = [
        r.chain
        for r in reachable
        if r.target > 0 and not r.target_anomalies and r.rejected_rows > 0
    ]
    if all_target_fail:
        lines.append(
            "- Chains where every target-class rejection failed the canonical "
            "expected-target re-verification (correctly excluded shares/near "
            "rows): " + ", ".join(all_target_fail) + "."
        )
    if total_new == 0:
        lines.append(
            "- No NEW error blocks: every full-PoW contextual-failure row "
            "whose named failure re-derives and whose digest meets the "
            "canonical expected-nBits target is already catalogued in the "
            "committed dataset."
        )
    if total_canonical_fail:
        lines.append(
            f"- {total_canonical_fail} full-PoW contextual rows re-derived "
            "their named failure but their digest does NOT meet the canonical "
            "expected-nBits target (they meet only an easy self-declared "
            "embedded target): share/contamination observations, NOT "
            "confirmed error blocks."
        )
    if total_not_rederived:
        lines.append(
            f"- {total_not_rederived} full-PoW contextual rows did NOT have "
            "their named failure re-derive from the committed bytes (the "
            "rejection label did not reproduce under the "
            "`btc_stale_validation` gates): they are NOT confirmed error "
            "blocks."
        )
    if total_not_offline:
        lines.append(
            f"- {total_not_offline} full-PoW rows carry the median-time-past "
            "rejection, which needs canonical parent context that is not "
            "committed in the inventories: not re-derivable offline, NOT "
            "confirmed."
        )
    if total_untrustworthy:
        lines.append(
            f"- {total_untrustworthy} full-PoW contextual rows re-derived "
            "their named failure and met the canonical expected-nBits target "
            "but come from a canonical-fill-scratch inventory "
            "(syscoin/elastos/fractal), whose `btc_height` is NOT verified "
            "against the canonical chain: NOT promoted on an unverified "
            "height."
        )
    lines.append("")

    if total_new:
        lines += ["## NEW confirmed error blocks", ""]
        for r in reachable:
            for row in r.new_findings:
                lines.append(
                    f"- {row.chain} height {row.height} hash "
                    f"`{row.block_hash}` — {row.reason} "
                    f"(provenance: `sweep-rejected-rows:{row.chain}:"
                    f"{r.inventory}`)"
                )
        lines.append("")

    if total_anomalies:
        lines += [
            "## Target-class rows meeting the canonical expected target",
            "",
            "These rows were rejected for an nBits/target mismatch, yet their",
            "header digests meet the *canonical expected* `nBits` target —",
            "full proof of work at the real Bitcoin difficulty with a wrong",
            "`nBits` field (a contextual failure wearing a target-class",
            "label). Re-verifying an nBits-mismatch row against its own",
            "`btc_bits` is circular, so the canonical expected target is the",
            "decisive check. They are error-block candidates listed for",
            "manual review and are NOT promoted by this sweep. A row already",
            "in the committed dataset is marked as such (already catalogued /",
            "promoted): it is reported here because the sweep re-derives the",
            "anomaly from the inventory, but it is NOT an un-promoted manual",
            "candidate.",
            "",
        ]
        for r in reachable:
            for row in r.target_anomalies:
                status = (
                    " — ALREADY IN THE DATASET (catalogued/promoted)"
                    if row.in_dataset
                    else ""
                )
                lines.append(
                    f"- {row.chain} height {row.height} hash "
                    f"`{row.block_hash}` — {row.reason}{status}"
                )
        lines.append("")

    lines += [
        "## Rejection-reason detail",
        "",
    ]
    for r in reachable:
        if r.rejected_rows == 0:
            continue
        lines.append(f"### {r.chain} (`{r.inventory}`)")
        lines.append("")
    # Reason detail is aggregated per chain from the tallies above; the
    # row-level dump stays in the private archive.
    lines += [
        "Row-level rejection detail remains in the authoritative inventories on",
        "the chain archive host; this report is the compact committed summary.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--chain-archive-root",
        type=Path,
        default=None,
        help="read inventories from a local mirror (<root>/<chain>/<filename>) "
        f"instead of ssh {ARCHIVE_HOST}",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    if validate_partial_args(args):
        return 2

    reader: InventoryReader = (
        local_mirror_reader(args.chain_archive_root)
        if args.chain_archive_root is not None
        else ssh_inventory_reader
    )
    dataset_keys = load_dataset_keys()

    reports = [
        sweep_chain(chain, path, reader, dataset_keys)
        for chain, path in CHAIN_INVENTORIES.items()
    ]

    reachable = [r for r in reports if r.reachable]
    if not reachable:
        for r in reports:
            print(f"error: {r.chain}: {r.error}", file=sys.stderr)
        print(
            "sweep failed: no inventories reachable (no report written)",
            file=sys.stderr,
        )
        return 1

    # A partial sweep (some inventories unreachable) must not overwrite the
    # committed report without --allow-partial.
    if require_full_coverage_for_committed(args, reports):
        return 1

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report_text = render_report(reports, generated_at)

    output = resolve_output_path(args, DEFAULT_REPORT)
    if output is None:
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report_text)
    print(f"wrote sweep report to {output}")

    total_new = sum(len(r.new_findings) for r in reachable)
    total_anomalies = sum(len(r.target_anomalies) for r in reachable)
    total_untrustworthy = sum(r.untrustworthy_height for r in reachable)
    print(
        f"swept {sum(r.rejected_rows for r in reachable)} REJECTED rows across "
        f"{len(reachable)}/{len(reports)} reachable inventories: "
        f"{total_new} NEW error block(s), {total_untrustworthy} "
        "untrustworthy-height scratch row(s), "
        f"{total_anomalies} target-class "
        "row(s) meeting the canonical expected target"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
