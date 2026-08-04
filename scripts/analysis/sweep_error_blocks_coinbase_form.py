#!/usr/bin/env python3
"""Sweep catalogued stale candidates for coinbase-form error blocks.

The committed error-blocks dataset carries exactly ONE
``coinbase_scriptsig_length_above_100`` member across a 15-year corpus,
which is suspicious: either miners almost never broadcast a full-PoW block
whose coinbase scriptSig breaks Bitcoin's 2..100 byte consensus limit, or
prior coverage simply never checked the form systematically. This sweep
applies the coinbase-form rules to EVERY catalogued stale candidate across
all reachable chains — including rows currently accepted as VALID stales —
to find error blocks hiding among them and to answer the single-member
question with corpus-wide numbers.

The rules (gates reused from ``stale_blocks_analysis.btc_stale_validation``,
never reimplemented; each returns None (pass) or a REJECTED/UNKNOWN string):

- Coinbase scriptSig length (``coinbase_scriptsig_length_error``): the
  scriptSig must be 2..100 bytes (Bitcoin consensus). The rule token is
  ``coinbase_scriptsig_length_above_100`` (the historical name; the gate
  enforces the full 2..100 bound, so this sweep tallies above-100 and
  below-2 violations separately). This check is HEIGHT-INDEPENDENT: the
  2..100 bound held at every height, so it RUNS against every source,
  including the canonical-fill-scratch inventories whose claimed height is
  untrustworthy — but a length violation from such a non-authoritative
  source is only ever an unresolved observation (its untrusted placement
  cannot key a dataset row), never a promoted ``new_findings`` entry.
  Evidence caveat: an EMPTY ``coinbase_scriptsig_hex`` means "this chain's
  proof does not expose the real parent coinbase" (missing evidence — RSK,
  and unrecovered rows), not "the coinbase scriptSig was zero bytes". A true
  zero-byte scriptSig (a below-2 violation) cannot be distinguished from
  missing evidence by the value alone in these inventories, so the below-2
  rule is only checkable where a non-empty scriptSig is present; empty rows
  are skipped as unusable, never flagged as below-2 violations (which would
  false-positive on RSK). A zero-byte scriptSig on a coinbase-bearing chain
  WOULD be a below-2 violation, but this sweep cannot tell it apart from an
  RSK-style not-exposed placeholder by the value alone, so it stays
  undetectable here.
- BIP34 height serialization (``bip34_height_error``): from
  ``BIP34_HEIGHT`` the coinbase scriptSig must start with the exact
  serialized height push. The version/BIP sweep already covered BIP34
  height *presence*; this sweep's distinct angle is the scriptSig *form*,
  reusing the same gate for consistency. This check is HEIGHT-DEPENDENT:
  it only runs where the claimed height is authoritative (the 16
  regen-chain stale inventories and the committed validated-stales).
  Because ``bip34_height_error`` is two-stage (it rejects a too-low header
  VERSION before examining the coinbase prefix), a coinbase-height token
  is only emitted when the header version passes the version requirement
  for the height: a version-1 header at a post-BIP34 height fires the gate
  for its version, and that finding is owned by the version/BIP sweep — it
  is NOT double-reported here as a coinbase-height mismatch (the same
  consistency rule the offline validator enforces).

Each candidate is re-verified from the committed bytes, never trusted on a
label: sha256d of the 80-byte ``btc_header_hex`` must meet the header's own
``btc_bits`` target via ``hash_meets_btc_difficulty``. A row failing full PoW
is a share/near, not an error block. A PoW-passing row that fails a gate is
an error-block finding; membership against the committed
``data/error-blocks/error_blocks.csv`` dataset is checked by
``(height, hash)``.

Candidate sources (all read through the injectable reader):

- The 16 regen-chain stale inventories on the chain archive host
  (``STALE_INVENTORIES``): authoritative ``btc_height`` — both checks run.
- syscoin/elastos/fractal canonical-fill-scratch stale inventories: their
  ``btc_height`` is NOT verified against the canonical chain (the Task 8
  height-trust caveat), so only the height-independent length check runs;
  the BIP34-form check is skipped (``untrustworthy_height`` tally). A
  length violation found here has no trustworthy (height, hash) key, so it
  is tallied as an unresolved observation, never a NEW finding.
- The committed ``data/validated-stales/<chain>_validated_stales.csv``
  (local, ``VALIDATED_STALES_GLOB``): the ACCEPTED stales, authoritative
  height — both checks run, cross-checking whether any accepted stale is
  actually a coinbase-form error block. Chains whose validated-stales CSV
  carries no usable rows (empty file, or every row missing
  ``btc_header_hex`` / ``coinbase_scriptsig_hex`` — RSK does not expose the
  real parent coinbase) are tallied as ``no_usable_rows`` negatives.

Inventory access is injectable: ``main`` defaults to reading each archive
inventory with ``ssh -o BatchMode=yes $ERROR_BLOCKS_ARCHIVE_HOST cat <path>``
and the committed validated-stales from the local filesystem;
``--chain-archive-root`` instead reads a local mirror directory laid out as
``<root>/<chain>/<filename>`` (validated-stales included). Tests inject
readers directly.

FAIL CLOSED: an unreachable inventory is recorded and the sweep continues;
if NO inventory is reachable the script exits non-zero. The committed report
is only ever written from a COMPLETE sweep: if any inventory is unreachable,
writing the committed default report fails closed (no committed write) unless
``--allow-partial`` together with a disposable ``--output-dir`` writes the
partial report there instead.
"""

from __future__ import annotations

import argparse
import csv
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
    STALE_INVENTORIES,
    STALE_INVENTORY_BASELINE_ROWS,
    VALIDATED_STALE_INVENTORY_BASELINE_ROWS,
    VALIDATED_STALES_GLOB,
    _REGEN_CHAINS,
    claimed_height,
    combined_reader,
    header_display_hash,
    load_dataset_keys,
    load_nbits_by_epoch,
    local_mirror_reader,
    local_validated_reader,
    require_full_coverage_for_committed,
    resolve_output_path,
    reverify_against_canonical_target,
    reverify_full_pow,
    ssh_inventory_reader,
    validate_partial_args,
    validated_stales_inventories,
)
from stale_blocks_analysis.btc_stale_validation import (  # noqa: E402
    bip34_height_error,
    block_version_error,
    coinbase_scriptsig_length_error,
)
from stale_blocks_analysis.config import BIP34_HEIGHT, BIP34_VERSION_2_HEIGHT  # noqa: E402,F401

DEFAULT_REPORT = Path("results/analysis/error-blocks/coinbase-form-report.md")

INVENTORY_BASELINE_ROWS = {
    **{f"{chain}:stale": rows for chain, rows in STALE_INVENTORY_BASELINE_ROWS.items()},
    **{
        f"{chain}:validated": rows
        for chain, rows in VALIDATED_STALE_INVENTORY_BASELINE_ROWS.items()
    },
}

# Gate tokens, keyed to the offline validator's RULE_GATES entries. The
# length gate enforces the full 2..100 bound; the sweep distinguishes the
# two violation classes by the actual scriptSig length (above-100 keeps the
# historical token, below-2 gets its own), and tallies them separately. The
# BIP34 token distinguishes the version-2 transition window
# [BIP34_VERSION_2_HEIGHT, BIP34_HEIGHT) from mandatory BIP34
# (>= BIP34_HEIGHT), matching the dataset/validator vocabulary.
_TOKEN_LENGTH_ABOVE_100 = "coinbase_scriptsig_length_above_100"
_TOKEN_LENGTH_BELOW_2 = "coinbase_scriptsig_length_below_2"
_TOKEN_BIP34_V2 = "bip34_v2_coinbase_height_mismatch"
_TOKEN_BIP34 = "bip34_coinbase_height_mismatch"

# The only ``bip34_height_error`` verdict that is a genuine raw coinbase-height
# serialization failure: the scriptSig's encoded height push is actually wrong
# for the claimed height. The gate's other REJECTED forms are NOT a
# coinbase-height consensus failure — unusable evidence ("malformed ...",
# "missing ...") or a metadata cross-check disagreement ("decoded BIP34
# coinbase height disagrees with btc_bip34_height", where the scriptSig encodes
# the height correctly and only the optional column disagrees). Only the
# raw-prefix mismatch is a BIP34 coinbase-height violation.
_BIP34_HEIGHT_MISMATCH_PREFIX = "REJECTED: BIP34 coinbase height mismatch"


@dataclass
class Candidate:
    """One sweep candidate (stale-inventory or accepted-stale row)."""

    chain: str
    source: str  # "stale" | "validated"
    inventory: str
    height: int
    block_hash: str
    scriptsig_length: int  # re-derived from the scriptSig bytes
    meets_full_pow: bool
    # Whether the claimed height is authoritative: True for the 16
    # regen-chain stale inventories (classifier-derived from an active-chain
    # prev) and for the committed validated-stales (they passed the
    # active-parent gate). The canonical-fill-scratch stale inventories do
    # not carry a canonical-verified height, so only the height-independent
    # length check runs there.
    authoritative_height: bool
    # Whether the header digest meets the CANONICAL expected-nBits target at
    # the claimed height (the inventory's expected_nbits column, else the
    # epoch table at the height's epoch start). None when neither source
    # yields a parseable target. Meeting only the header's own embedded bits
    # is not enough: an easy self-declared-target header is a
    # share/contamination, not a confirmed error block (the same rule the
    # offline validator enforces).
    meets_expected_pow: bool | None = None
    violation: str = ""  # a RULE_GATES token, or "" when the gates pass
    gate_detail: str = ""  # the gate's REJECTED: reason text
    in_dataset: bool = False

    @property
    def is_error_block_candidate(self) -> bool:
        return (
            self.meets_full_pow
            and self.meets_expected_pow is True
            and bool(self.violation)
        )

    @property
    def is_new_finding(self) -> bool:
        return self.is_error_block_candidate and not self.in_dataset


@dataclass
class ChainReport:
    """Per-chain, per-source sweep tally."""

    chain: str
    source: str  # "stale" | "validated"
    inventory: str
    reachable: bool = True
    error: str = ""
    total_rows: int = 0
    no_height: int = 0
    pow_pass: int = 0
    pow_fail: int = 0
    pow_unparseable: int = 0
    untrustworthy_height: int = 0  # length-checked only (scratch inventories)
    no_usable_rows: bool = False
    length_violations_above_100: int = 0
    length_violations_below_2: int = 0
    bip34_violations: int = 0
    # Full-PoW gate violations whose digest does NOT meet the canonical
    # expected-nBits target at the claimed height: share/contamination
    # observations, never confirmed error blocks.
    canonical_target_fail: int = 0
    # The LENGTH-violation subset of canonical_target_fail: tracked
    # separately because the single-member conclusion compares length
    # violations against catalogued length violations, and a length
    # violation that failed the canonical target is excluded from the
    # error-block set (it must not count as an uncatalogued length
    # violation there).
    length_canonical_target_fail: int = 0
    already_in_dataset: int = 0
    # Catalogued LENGTH violations (a subset of already_in_dataset, which also
    # counts BIP34 violations): used by the single-member conclusion, which
    # must compare length violations against catalogued length violations
    # only, not against every catalogued violation.
    length_in_dataset: int = 0
    # Distinct (height, hash) violation keys already in the dataset: the same
    # BTC error block is recorded by several sibling chains, so the
    # observation tally above overcounts distinct blocks.
    in_dataset_keys: set[tuple[int, str]] = field(default_factory=set)
    new_findings: list[Candidate] = field(default_factory=list)
    # Distinct (height, hash) NEW-finding keys: the same new BTC error block
    # can be witnessed in several sibling-chain inventories, so the
    # new_findings observation list overcounts distinct blocks.
    new_finding_keys: set[tuple[int, str]] = field(default_factory=set)
    # Full-PoW length violations without a trustworthy claimed height (no
    # parseable height, or a parseable height from a non-authoritative
    # scratch source): real observations, but without a trustworthy
    # (height, hash) key they can neither be deduplicated against the
    # dataset nor promoted into a validator-compatible row, so they are
    # tallied separately instead of entering new_findings.
    unresolved_length_observations: list[Candidate] = field(default_factory=list)


def scriptsig_length(scriptsig_hex: str) -> int | None:
    """Return the byte length of a coinbase scriptSig hex, or None."""
    try:
        return len(bytes.fromhex((scriptsig_hex or "").strip()))
    except ValueError:
        return None


def apply_length_gate(row: dict[str, str]) -> tuple[str, str] | None:
    """Apply the height-independent 2..100 byte scriptSig length gate.

    Returns (rule_token, gate_detail) on a REJECTED verdict, or None when
    the row passes. An UNKNOWN: verdict (missing/malformed evidence) is not
    a violation — the row passes as far as this sweep can tell. The token
    distinguishes the two violation classes by the actual scriptSig length:
    above-100 keeps the historical ``coinbase_scriptsig_length_above_100``
    token; below-2 gets ``coinbase_scriptsig_length_below_2``.
    """
    length_error = coinbase_scriptsig_length_error(row)
    if length_error is not None and length_error.startswith("REJECTED:"):
        length = scriptsig_length(row.get("coinbase_scriptsig_hex", ""))
        token = (
            _TOKEN_LENGTH_ABOVE_100
            if length is not None and length > 100
            else _TOKEN_LENGTH_BELOW_2
        )
        return token, length_error
    return None


def apply_bip34_gate(row: dict[str, str], height: int) -> tuple[str, str] | None:
    """Apply the height-dependent BIP34 height-serialization gate.

    Returns (rule_token, gate_detail) on a REJECTED verdict, or None when
    the row passes (including heights below BIP34 activation, where the
    rule does not apply). An UNKNOWN: verdict is not a violation. The token
    is ``bip34_v2_coinbase_height_mismatch`` in the version-2 transition
    window [BIP34_VERSION_2_HEIGHT, BIP34_HEIGHT) and
    ``bip34_coinbase_height_mismatch`` from BIP34_HEIGHT, matching the
    dataset/validator vocabulary.

    A coinbase-height token is only emitted for the genuine raw-prefix height
    mismatch (the scriptSig's encoded height push is actually wrong) AND when
    the header version PASSES the version requirement for the height:
    ``bip34_height_error`` is two-stage and rejects a too-low VERSION before
    examining the coinbase prefix, so a version-1 header at a post-BIP34
    height fires the gate for the wrong reason. Such a row's real violation is
    its version — owned and reported by the version/BIP sweep as a version
    token — so this sweep deliberately does NOT double-report it as a
    coinbase-height mismatch (mirroring the offline validator's consistency
    rule, which rejects a coinbase-height token whose header version is also
    too low). The gate's other REJECTED forms are also excluded: a malformed/
    missing-evidence verdict is unusable evidence, and the metadata cross-
    check disagreement (the optional ``btc_bip34_height`` column disagreeing
    with a correctly-encoded scriptSig) is an inconsistent-metadata
    observation, not a Bitcoin consensus failure.
    """
    bip34_error = bip34_height_error(row, height)
    if bip34_error is not None and bip34_error.startswith(
        _BIP34_HEIGHT_MISMATCH_PREFIX
    ):
        if block_version_error(row, height) is not None:
            # The header version is also too low for the height: the real
            # violation is the version, not the coinbase height. The
            # version/BIP sweep owns that finding; do not token it here.
            return None
        token = _TOKEN_BIP34 if height >= BIP34_HEIGHT else _TOKEN_BIP34_V2
        return token, bip34_error
    return None


def sweep_inventory(
    chain: str,
    source: str,
    inventory: str,
    authoritative_height: bool,
    reader: InventoryReader,
    dataset_keys: set[tuple[int, str]],
    nbits_by_epoch: dict[int, int] | None = None,
) -> ChainReport:
    """Sweep one inventory; an unreachable inventory fails soft."""
    report = ChainReport(chain=chain, source=source, inventory=inventory)
    try:
        text = reader(chain, inventory)
    except (OSError, subprocess.SubprocessError) as exc:
        report.reachable = False
        report.error = str(exc)
        return report

    if nbits_by_epoch is None:
        nbits_by_epoch = load_nbits_by_epoch()

    usable_rows = 0
    for row in csv.DictReader(io.StringIO(text)):
        report.total_rows += 1
        header_hex = (row.get("btc_header_hex") or "").strip()
        scriptsig_hex = (row.get("coinbase_scriptsig_hex") or "").strip()
        if not header_hex or not scriptsig_hex:
            # A row without the committed header/coinbase bytes cannot be
            # re-verified or gated; it is not a usable candidate. An EMPTY
            # coinbase_scriptsig_hex means "this chain's proof does not
            # expose the real parent coinbase" (missing evidence — RSK, and
            # unrecovered rows), NOT "the coinbase scriptSig was zero bytes":
            # a true zero-byte scriptSig (a below-2 violation) cannot be
            # distinguished from missing evidence by the value alone in these
            # inventories, so the below-2 rule is only checkable where a
            # non-empty scriptSig is present. Treating empty as a below-2
            # violation would produce false positives on RSK rows. A zero-byte
            # scriptSig on a coinbase-bearing chain WOULD be a violation, but
            # it is indistinguishable from an RSK-style placeholder here, so
            # it stays undetectable (a structural limitation, not a choice
            # made per row).
            continue
        usable_rows += 1
        meets_pow = reverify_full_pow(header_hex)
        length = scriptsig_length(scriptsig_hex)
        if meets_pow is None or length is None:
            report.pow_unparseable += 1
            continue
        if not meets_pow:
            report.pow_fail += 1
            continue  # a share/near row, not an error block
        report.pow_pass += 1

        # (a) The length check is height-independent: it runs for every
        # source, scratch inventories included.
        verdict = apply_length_gate(row)
        if verdict is not None:
            token, detail = verdict
            # Candidate identity (and hence dataset membership) is keyed on
            # the display hash derived from the header bytes, never the
            # inventory's btc_header_hash column: the PoW check already
            # parsed the header, so this digest is authoritative.
            block_hash = header_display_hash(header_hex)
            if block_hash is None:
                report.pow_unparseable += 1
                continue
            height = claimed_height(row)
            if length > 100:
                report.length_violations_above_100 += 1
            else:
                report.length_violations_below_2 += 1
            if height is None or not authoritative_height:
                # No usable authoritative height: the observation has no
                # trustworthy (height, hash) key, so it can be neither
                # deduplicated against the dataset nor promoted into a
                # validator-compatible row. This covers both a missing/
                # unparseable claimed height AND a parseable height from a
                # non-authoritative source (the canonical-fill-scratch
                # inventories, whose btc_height is not canonical-verified):
                # an untrusted placement must not produce a dataset-keyed,
                # validator-facing finding. Tally it as unresolved rather
                # than a confirmed new finding.
                report.unresolved_length_observations.append(
                    Candidate(
                        chain=chain,
                        source=source,
                        inventory=inventory,
                        height=height or 0,
                        block_hash=block_hash,
                        scriptsig_length=length,
                        meets_full_pow=True,
                        authoritative_height=authoritative_height,
                        violation=token,
                        gate_detail=detail,
                    )
                )
                continue
            cand = Candidate(
                chain=chain,
                source=source,
                inventory=inventory,
                height=height,
                block_hash=block_hash,
                scriptsig_length=length,
                meets_full_pow=True,
                authoritative_height=authoritative_height,
                meets_expected_pow=reverify_against_canonical_target(
                    header_hex, row, height, nbits_by_epoch
                ),
                violation=token,
                gate_detail=detail,
                in_dataset=(height, block_hash) in dataset_keys,
            )
            if cand.meets_expected_pow is not True:
                # The digest fails (or cannot be evaluated against) the
                # canonical expected-nBits target at the claimed height: a
                # share/contamination observation, not a confirmed error block.
                report.canonical_target_fail += 1
                report.length_canonical_target_fail += 1
            elif cand.in_dataset:
                report.already_in_dataset += 1
                report.length_in_dataset += 1
                report.in_dataset_keys.add((cand.height, cand.block_hash))
            elif cand.is_new_finding:
                report.new_findings.append(cand)
                report.new_finding_keys.add((cand.height, cand.block_hash))
            # A scriptSig outside 2..100 bytes cannot also carry a valid
            # BIP34 prefix worth reporting; one violation per row suffices.
            continue

        # (b) The BIP34-form check is height-dependent: it needs an
        # authoritative claimed height.
        if not authoritative_height:
            report.untrustworthy_height += 1
            continue
        height = claimed_height(row)
        if height is None:
            report.no_height += 1
            continue
        verdict = apply_bip34_gate(row, height)
        if verdict is None:
            continue
        token, detail = verdict
        # Candidate identity (and hence dataset membership) is keyed on the
        # display hash derived from the header bytes, never the inventory's
        # btc_header_hash column: the PoW check already parsed the header, so
        # this digest is authoritative.
        block_hash = header_display_hash(header_hex)
        if block_hash is None:
            report.pow_unparseable += 1
            continue
        cand = Candidate(
            chain=chain,
            source=source,
            inventory=inventory,
            height=height,
            block_hash=block_hash,
            scriptsig_length=length,
            meets_full_pow=True,
            authoritative_height=True,
            meets_expected_pow=reverify_against_canonical_target(
                header_hex, row, height, nbits_by_epoch
            ),
            violation=token,
            gate_detail=detail,
            in_dataset=(height, block_hash) in dataset_keys,
        )
        report.bip34_violations += 1
        if cand.meets_expected_pow is not True:
            # The digest fails (or cannot be evaluated against) the canonical
            # expected-nBits target at the claimed height: a
            # share/contamination observation, not a confirmed error block.
            report.canonical_target_fail += 1
        elif cand.in_dataset:
            report.already_in_dataset += 1
            report.in_dataset_keys.add((cand.height, cand.block_hash))
        elif cand.is_new_finding:
            report.new_findings.append(cand)
            report.new_finding_keys.add((cand.height, cand.block_hash))
    if report.total_rows > 0 and usable_rows == 0:
        report.no_usable_rows = True
    return report


def render_report(reports: list[ChainReport], generated_at: str) -> str:
    """Render the dated Markdown sweep report, including negative results."""
    reachable = [r for r in reports if r.reachable]
    unreachable = [r for r in reports if not r.reachable]
    total_rows = sum(r.total_rows for r in reachable)
    total_no_height = sum(r.no_height for r in reachable)
    total_pow_pass = sum(r.pow_pass for r in reachable)
    total_pow_fail = sum(r.pow_fail for r in reachable)
    total_pow_unparseable = sum(r.pow_unparseable for r in reachable)
    total_untrustworthy = sum(r.untrustworthy_height for r in reachable)
    total_above_100 = sum(r.length_violations_above_100 for r in reachable)
    total_below_2 = sum(r.length_violations_below_2 for r in reachable)
    total_bip34 = sum(r.bip34_violations for r in reachable)
    total_canonical_fail = sum(r.canonical_target_fail for r in reachable)
    total_in_dataset = sum(r.already_in_dataset for r in reachable)
    total_length_in_dataset = sum(r.length_in_dataset for r in reachable)
    distinct_in_dataset = len({key for r in reachable for key in r.in_dataset_keys})
    total_new = sum(len(r.new_findings) for r in reachable)
    distinct_new = len({key for r in reachable for key in r.new_finding_keys})
    # New LENGTH findings specifically (a subset of total_new, which also
    # mixes in BIP34-form findings): the single-member conclusion is about
    # scriptSig-length coverage, so it gates on this, not on total_new.
    total_new_length = sum(
        1
        for r in reachable
        for cand in r.new_findings
        if cand.violation in (_TOKEN_LENGTH_ABOVE_100, _TOKEN_LENGTH_BELOW_2)
    )
    total_unresolved = sum(len(r.unresolved_length_observations) for r in reachable)

    lines = [
        "# Error-blocks coinbase-form sweep",
        "",
        f"Generated: {generated_at}",
        "",
        "Proactive application of Bitcoin's coinbase-form consensus rules to",
        "every catalogued stale candidate across all reachable chains —",
        "including rows currently accepted as VALID stales — to find error",
        "blocks hiding among them: full-proof-of-work Bitcoin headers whose",
        "coinbase scriptSig breaks the 2..100 byte consensus limit or whose",
        "BIP34 height serialization is wrong. The committed error-blocks",
        "dataset carries exactly ONE `coinbase_scriptsig_length_above_100`",
        "member across a 15-year corpus; this sweep determines whether that",
        "single-member situation is real or an artifact of incomplete prior",
        "coverage.",
        "",
        "Rules applied (gates reused from",
        "`stale_blocks_analysis.btc_stale_validation`, never reimplemented):",
        "",
        "- Coinbase scriptSig length (`coinbase_scriptsig_length_error`):",
        "  the scriptSig must be 2..100 bytes (Bitcoin consensus). The rule",
        "  token is `coinbase_scriptsig_length_above_100` (the historical",
        "  name; the gate enforces the full 2..100 bound, so above-100 and",
        "  below-2 violations are tallied separately). This check is",
        "  HEIGHT-INDEPENDENT: the bound held at every height, so it applies",
        "  to every source, including the canonical-fill-scratch",
        "  inventories whose claimed height is untrustworthy.",
        "  Evidence caveat: an EMPTY `coinbase_scriptsig_hex` is treated as",
        "  MISSING evidence (\u201cthis chain's proof does not expose the real",
        "  parent coinbase\u201d — RSK, and unrecovered rows), NOT as a",
        "  zero-byte scriptSig. A genuine zero-byte scriptSig (a below-2",
        "  violation) cannot be distinguished from missing evidence by the",
        "  value alone in these inventories, so empty rows are skipped as",
        "  unusable and NEVER flagged as below-2 violations (which would",
        "  false-positive on RSK). The below-2 rule is therefore only",
        "  enforceable where a NON-EMPTY scriptSig is present; a zero-byte",
        "  scriptSig on a coinbase-bearing chain WOULD be a violation, but",
        "  this sweep cannot detect it from these inventories.",
        f"- BIP34 height serialization (`bip34_height_error`): from",
        f"  `BIP34_HEIGHT = {BIP34_HEIGHT}` the coinbase scriptSig must",
        "  start with the exact serialized height push",
        "  (`bip34_coinbase_height_mismatch`). The version/BIP sweep already",
        "  covered BIP34 height *presence*; this sweep's distinct angle is",
        "  the scriptSig *form*, reusing the same gate for consistency.",
        "  This check is HEIGHT-DEPENDENT: it only runs where the claimed",
        "  height is authoritative.",
        "",
        "The rule tokens match the offline validator's `RULE_GATES` keys,",
        "so a promoted finding re-derives in `validate_error_blocks.py`.",
        "Full PoW is re-derived per row from the committed header bytes via",
        "`hash_meets_btc_difficulty` (sha256d of the 80-byte header meets",
        "the header's own embedded nBits target), never inherited from a",
        "classification label. A confirmed finding must ALSO meet the",
        "canonical expected-nBits target at the claimed height (the",
        "inventory's `expected_nbits` column, else the committed epoch table",
        "at the height's epoch start): a gate violation whose digest meets",
        "only an easy self-declared embedded target is a share/contamination",
        "observation, tallied separately as `canonical_target_fail`, never a",
        "confirmed error block (the same rule the offline validator",
        "enforces). A PoW-passing, canonical-target-passing row that fails a",
        "gate is an error-block finding; membership is checked against the",
        "committed `data/error-blocks/error_blocks.csv` dataset by",
        "`(height, hash)`.",
        "",
        "Candidate sources and claimed-height trust:",
        "",
        "- The 16 regen-chain stale inventories on the chain archive host:",
        "  authoritative `btc_height` — both checks run.",
        "- syscoin/elastos/fractal canonical-fill-scratch stale inventories:",
        "  their `btc_height` is NOT verified against the canonical chain",
        "  (the Task 8 height-trust caveat), so only the height-independent",
        "  length check runs; the BIP34-form check is skipped",
        "  (`untrustworthy height` tally).",
        "- The committed `data/validated-stales/<chain>_validated_stales.csv`",
        "  (the ACCEPTED stales): their `btc_height` passed the",
        "  active-parent gate, so it is authoritative; applying the gates",
        "  here cross-checks whether any accepted stale is actually a",
        "  coinbase-form error block. Chains whose CSV carries no usable",
        "  rows (empty, or every row missing the header/coinbase bytes —",
        "  RSK does not expose the real parent coinbase) are",
        "  `no usable rows` negatives.",
        "",
        "## Summary",
        "",
        f"- Inventories reachable: {len(reachable)}/{len(reports)}",
        f"- Rows examined: {total_rows}",
        f"- Rows skipped for an unparseable header/scriptSig (no PoW or "
        f"length check possible): {total_pow_unparseable}",
        f"- Full-PoW pass: {total_pow_pass}",
        f"- Full-PoW fail (share/near rows, excluded): {total_pow_fail}",
        f"- Full-PoW candidates length-checked only (scratch inventories, "
        f"height untrustworthy for BIP34): {total_untrustworthy}",
        f"- Full-PoW candidates skipped for no parseable claimed height "
        f"(BIP34 check only): {total_no_height}",
        f"- scriptSig length violations above 100 bytes: {total_above_100}",
        f"- scriptSig length violations below 2 bytes: {total_below_2}",
        f"- BIP34 height-serialization violations: {total_bip34}",
        f"- Violation observations failing the canonical expected-nBits "
        f"target (share/contamination, not confirmed): {total_canonical_fail}",
        f"- Already catalogued in the dataset: {total_in_dataset} "
        f"observations across {distinct_in_dataset} distinct (height, hash) "
        "blocks (the same BTC error block is recorded by several sibling "
        "chains)",
        f"- NEW confirmed error blocks: {total_new} "
        f"observations across {distinct_new} distinct (height, hash) "
        "blocks (the same new BTC error block can be witnessed in several "
        "sibling-chain inventories)",
        f"- Unresolved length-violation observations (full PoW, no trustworthy "
        f"claimed height — not promotable, not counted as NEW): "
        f"{total_unresolved}",
        "",
        "## The single-member question",
        "",
    ]
    total_length = total_above_100 + total_below_2
    total_length_canonical_fail = sum(r.length_canonical_target_fail for r in reachable)
    # The single-member conclusion compares the length violations that meet
    # the canonical expected-nBits target against the catalogued length
    # violations. A length violation that FAILED the canonical target is a
    # share/contamination observation (tallied canonical_target_fail): it is
    # excluded from the error-block set, so it does not affect the
    # conclusion — subtracting it keeps such a row from selecting the
    # "coverage incomplete" branch (which points to a NEW-findings section
    # that does not exist for a canonical-target failure).
    total_length_meeting_target = total_length - total_length_canonical_fail
    lines.append(
        f"The dataset carried exactly one `coinbase_scriptsig_length_above_100` "
        f"member before this sweep. Across the whole reachable corpus "
        f"({total_pow_pass} full-PoW candidates in {len(reachable)} "
        f"inventories), this sweep found {total_length} scriptSig-length "
        f"violation observation(s): {total_above_100} above 100 bytes, "
        f"{total_below_2} below 2 bytes. "
        + (
            "Every one of them is already catalogued, so the single-member "
            "situation is REAL: miners essentially never broadcast a "
            "full-PoW block whose coinbase scriptSig breaks the 2..100 byte "
            "consensus limit; the one catalogued case is the only observed "
            "instance, not a coverage artifact."
            if total_new_length == 0
            and total_unresolved == 0
            and total_length_meeting_target <= total_length_in_dataset
            else "See the NEW findings below: prior coverage was incomplete."
        )
    )
    lines.append("")

    if unreachable:
        lines += ["## Unreachable inventories", ""]
        for r in unreachable:
            lines.append(f"- **{r.chain}** ({r.source}, `{r.inventory}`): {r.error}")
        lines.append("")

    lines += [
        "## Per-inventory results",
        "",
        "| chain | source | rows | full-PoW pass | length-checked only | "
        "above 100 | below 2 | BIP34-form violations | already in dataset "
        "| NEW |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in reports:
        if not r.reachable:
            lines.append(
                f"| {r.chain} | {r.source} | — | — | — | — | — | — | — | unreachable |"
            )
            continue
        lines.append(
            f"| {r.chain} | {r.source} | {r.total_rows} | {r.pow_pass} "
            f"| {r.untrustworthy_height} | {r.length_violations_above_100} "
            f"| {r.length_violations_below_2} | {r.bip34_violations} "
            f"| {r.already_in_dataset} | {len(r.new_findings)} |"
        )
    lines.append("")

    lines += ["## Negative results", ""]
    zero_violation = [
        f"{r.chain} ({r.source})"
        for r in reachable
        if r.pow_pass > 0
        and r.length_violations_above_100 == 0
        and r.length_violations_below_2 == 0
        and r.bip34_violations == 0
    ]
    if zero_violation:
        lines.append(
            "- Inventories with full-PoW candidates but no coinbase-form "
            "violation: " + ", ".join(zero_violation) + "."
        )
    else:
        lines.append(
            "- No reachable inventory with full-PoW candidates was violation-free."
        )
    no_usable = [f"{r.chain} ({r.source})" for r in reachable if r.no_usable_rows]
    if no_usable:
        lines.append(
            "- Inventories with no usable rows (empty, or every row missing "
            "the committed header/coinbase bytes; RSK does not expose the "
            "real parent coinbase): " + ", ".join(no_usable) + "."
        )
    if total_no_height:
        lines.append(
            f"- {total_no_height} full-PoW candidates were skipped for the "
            "BIP34-form check for lacking a parseable claimed height (no "
            "`btc_height`, a malformed value, or an implausible value above "
            "the canonical tip). The height-independent length check still "
            "ran for these rows."
        )
    if total_pow_unparseable:
        lines.append(
            f"- {total_pow_unparseable} rows were skipped for an "
            "unparseable committed header or scriptSig (no PoW "
            "re-verification or length check possible)."
        )
    if total_untrustworthy:
        lines.append(
            f"- {total_untrustworthy} full-PoW candidates in the "
            "canonical-fill-scratch stale inventories "
            "(syscoin/elastos/fractal) carried a non-authoritative claimed "
            "height: they were evaluated for the height-independent "
            "scriptSig-length rule but NOT for the BIP34 "
            "height-serialization rule. They are length-checked negatives "
            "for the BIP34 check, not violations."
        )
    if total_below_2 == 0:
        lines.append(
            "- No below-2 scriptSig length violations exist anywhere in the "
            "corpus: the only length-violation class observed is above 100 "
            "bytes."
        )
    if total_canonical_fail:
        lines.append(
            f"- {total_canonical_fail} full-PoW gate-violation observation(s) "
            "failed (or could not be evaluated against) the canonical "
            "expected-nBits target at the claimed height: they meet only an "
            "easy self-declared embedded target, so they are "
            "share/contamination observations, NOT confirmed error blocks."
        )
    if total_new == 0:
        lines.append(
            "- No NEW confirmed coinbase-form error blocks: every full-PoW "
            "violation found is already catalogued in the committed "
            "dataset."
        )
    if total_unresolved:
        lines.append(
            f"- {total_unresolved} full-PoW scriptSig-length violation(s) "
            "lacked a trustworthy claimed height (no parseable height, or a "
            "parseable height from a non-authoritative scratch inventory): "
            "without a trustworthy `(height, hash)` key "
            "they can be neither deduplicated against the dataset nor "
            "promoted into a validator-compatible row, so they are "
            "unresolved observations, not confirmed findings."
        )
        for r in reachable:
            for cand in r.unresolved_length_observations:
                lines.append(
                    f"  - {cand.chain} ({cand.source}) hash "
                    f"`{cand.block_hash}` — {cand.violation} "
                    f"({cand.gate_detail})"
                )
    lines.append("")

    if total_new:
        lines += ["## NEW confirmed coinbase-form error blocks", ""]
        for r in reachable:
            for cand in r.new_findings:
                lines.append(
                    f"- {cand.chain} ({cand.source}) height {cand.height} "
                    f"hash `{cand.block_hash}` — {cand.violation} "
                    f"({cand.gate_detail}) (provenance: "
                    f"`sweep-coinbase-form:{cand.chain}:{cand.inventory}`)"
                )
        lines.append("")

    lines += [
        "Row-level candidate detail remains in the authoritative inventories",
        "on the chain archive host and in the committed validated-stales",
        "CSVs; this report is the compact committed summary.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--chain-archive-root",
        type=Path,
        default=None,
        help="read ALL inventories (archive stale inventories and committed "
        "validated-stales alike) from a local mirror "
        f"(<root>/<chain>/<filename>) instead of ssh {ARCHIVE_HOST} + local "
        "validated-stales paths",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    if validate_partial_args(args):
        return 2

    if args.chain_archive_root is not None:
        reader: InventoryReader = local_mirror_reader(args.chain_archive_root)
    else:
        reader = combined_reader(ssh_inventory_reader, local_validated_reader)
    dataset_keys = load_dataset_keys()

    reports: list[ChainReport] = []
    # Source 1/2: the archive stale inventories (regen chains authoritative,
    # scratch chains length-check-only).
    for chain, path in STALE_INVENTORIES.items():
        reports.append(
            sweep_inventory(
                chain,
                "stale",
                path,
                authoritative_height=chain in _REGEN_CHAINS,
                reader=reader,
                dataset_keys=dataset_keys,
            )
        )
    # Source 3: the committed validated-stales (accepted stales; the
    # btc_height passed the active-parent gate, so it is authoritative).
    for chain, path in validated_stales_inventories(VALIDATED_STALES_GLOB).items():
        reports.append(
            sweep_inventory(
                chain,
                "validated",
                path,
                authoritative_height=True,
                reader=reader,
                dataset_keys=dataset_keys,
            )
        )

    reachable = [r for r in reports if r.reachable]
    if not reachable:
        for r in reports:
            print(f"error: {r.chain} ({r.source}): {r.error}", file=sys.stderr)
        print(
            "sweep failed: no inventories reachable (no report written)",
            file=sys.stderr,
        )
        return 1

    # A partial sweep (some inventories unreachable) must not overwrite the
    # committed report without --allow-partial.
    if require_full_coverage_for_committed(
        args,
        reports,
        expected_inventory_rows=INVENTORY_BASELINE_ROWS,
        inventory_row_counts=lambda report: {
            f"{report.chain}:{report.source}": report.total_rows
        },
    ):
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
    print(
        f"swept {sum(r.total_rows for r in reachable)} rows across "
        f"{len(reachable)}/{len(reports)} reachable inventories: "
        f"{sum(r.pow_unparseable for r in reachable)} pow-unparseable, "
        f"{sum(r.pow_pass for r in reachable)} full-PoW pass, "
        f"{sum(r.untrustworthy_height for r in reachable)} "
        f"length-checked-only, "
        f"{sum(r.length_violations_above_100 for r in reachable)} "
        f"above-100 violations, "
        f"{sum(r.length_violations_below_2 for r in reachable)} "
        f"below-2 violations, "
        f"{sum(r.bip34_violations for r in reachable)} BIP34-form "
        f"violations, "
        f"{sum(r.already_in_dataset for r in reachable)} already in "
        f"dataset, {total_new} NEW error block(s), "
        f"{sum(len(r.unresolved_length_observations) for r in reachable)} "
        "unresolved length observation(s) without a trustworthy height"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
