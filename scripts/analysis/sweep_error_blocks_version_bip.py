#!/usr/bin/env python3
"""Sweep catalogued stale candidates for version/BIP34-rule error blocks.

The committed error-blocks dataset was built primarily from
namecoin/devcoin/ixcoin-family observations. This sweep proactively applies
Bitcoin's historical minimum-version and BIP34 coinbase-height rules to EVERY
catalogued stale candidate across all reachable chains — including rows
currently accepted as VALID stales — to find error blocks hiding among them:
full-proof-of-work Bitcoin headers that fail one of these consensus rules at
their claimed height.

The rules (enforcement heights from ``stale_blocks_analysis.config``):

- ``BIP34_VERSION_2_HEIGHT = 224413``: version >= 2 blocks need the BIP34
  coinbase-height prefix (``bip34_v2_coinbase_height_mismatch``).
- ``BIP34_HEIGHT = 227931``: the prefix is mandatory for ALL blocks and
  version 1 is invalid (``bip34_coinbase_height_mismatch``).
- ``BIP66_HEIGHT = 363725``: minimum block version 3
  (``bip66_block_version_below_3``).
- ``BIP65_HEIGHT = 388381``: minimum block version 4
  (``bip65_block_version_below_4``).

The gates are reused from ``stale_blocks_analysis.btc_stale_validation``
(``block_version_error`` and ``bip34_height_error``), never reimplemented;
each returns None (pass) or a REJECTED/UNKNOWN string. The rule tokens match
the offline validator's ``RULE_GATES`` keys, so a promoted finding
re-derives in ``validate_error_blocks.py``.

Each candidate is re-verified from the committed bytes, never trusted on a
label: sha256d of the 80-byte ``btc_header_hex`` must meet the header's own
``btc_bits`` target via ``hash_meets_btc_difficulty``. A row failing full PoW
is a share/near, not an error block. A confirmed finding must ALSO meet the
canonical ``expected_nbits`` target at the claimed height (the inventory's
``expected_nbits`` column, else the committed epoch table at the height's
epoch start): a gate violation whose digest meets only an easy self-declared
embedded target is a share/contamination observation, tallied separately as
``canonical_target_fail``, never a confirmed error block (the same rule the
offline validator enforces). A PoW-passing, canonical-target-passing row that
fails a gate at its claimed height is an error-block finding; membership
against the committed ``data/error-blocks/error_blocks.csv`` dataset is
checked by ``(height, hash)``.

Candidate sources (all read through the injectable reader):

- The 16 regen-chain stale inventories on the chain archive host
  (``STALE_INVENTORIES``): authoritative ``btc_height`` (the classifier set
  it from an active-chain prev).
- syscoin/elastos/fractal canonical-fill-scratch stale inventories: their
  ``btc_height`` is NOT verified against the canonical chain (the Task 8
  height-trust caveat), so PoW-passing rows are tallied as
  ``untrustworthy_height`` negatives and never evaluated as violations.
- The committed ``data/validated-stales/<chain>_validated_stales.csv``
  (local, ``VALIDATED_STALES_GLOB``): the ACCEPTED stales. Their
  ``btc_height`` passed the active-parent gate, so it is authoritative;
  applying the gates here cross-checks whether any accepted stale is
  actually an error block. The version gate is coinbase-independent, so
  header-only rows (RSK does not expose the real parent coinbase) are still
  evaluated for the version rule; they are simply BIP34-unevaluable. Chains
  whose validated-stales CSV carries no usable rows (empty file, or every
  row missing ``btc_header_hex``) are tallied as ``no_usable_rows``
  negatives.

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
    add_common_sweep_args,
    check_sweep_coverage,
    choose_inventory_reader,
    claimed_height,
    combined_reader,
    header_display_hash,
    load_dataset_keys,
    load_nbits_by_epoch,
    local_validated_reader,
    reverify_against_canonical_target,
    reverify_full_pow,
    ssh_inventory_reader,
    validate_partial_args,
    validated_stales_inventories,
    write_sweep_report,
)
from stale_blocks_analysis.btc_stale_validation import (  # noqa: E402
    bip34_height_error,
    block_version_error,
)
from stale_blocks_analysis.config import (  # noqa: E402
    BIP34_HEIGHT,
    BIP34_VERSION_2_HEIGHT,
    BIP65_HEIGHT,
    BIP66_HEIGHT,
)

DEFAULT_REPORT = Path("results/analysis/error-blocks/version-bip-report.md")

INVENTORY_BASELINE_ROWS = {
    **{f"{chain}:stale": rows for chain, rows in STALE_INVENTORY_BASELINE_ROWS.items()},
    **{
        f"{chain}:validated": rows
        for chain, rows in VALIDATED_STALE_INVENTORY_BASELINE_ROWS.items()
    },
}

# Gate tokens, keyed to the offline validator's RULE_GATES entries.
_TOKEN_BIP65 = "bip65_block_version_below_4"
_TOKEN_BIP66 = "bip66_block_version_below_3"
_TOKEN_BIP34_VERSION = "bip34_block_version_below_2"
_TOKEN_BIP34 = "bip34_coinbase_height_mismatch"
_TOKEN_BIP34_V2 = "bip34_v2_coinbase_height_mismatch"

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
    header_version: int  # re-derived from the header bytes
    meets_full_pow: bool
    # Whether the claimed height is authoritative: True for the 16
    # regen-chain stale inventories (classifier-derived from an active-chain
    # prev) and for the committed validated-stales (they passed the
    # active-parent gate). The canonical-fill-scratch stale inventories do
    # not carry a canonical-verified height.
    authoritative_height: bool
    # Whether the header digest meets the CANONICAL expected-nBits target at
    # the claimed height (the inventory's expected_nbits column, else the
    # epoch table at the height's epoch start). None when neither source
    # yields a parseable target. Meeting only the header's own embedded bits
    # is not enough: an easy self-declared-target header is a
    # share/contamination, not a confirmed error block (the same rule the
    # offline validator enforces).
    meets_expected_pow: bool | None = None
    violation: str = ""  # a RULE_GATES token, or "" when both gates pass
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
    untrustworthy_height: int = 0
    no_usable_rows: bool = False
    version_violations: int = 0
    bip34_violations: int = 0
    # Full-PoW gate violations whose digest does NOT meet the canonical
    # expected-nBits target at the claimed height: share/contamination
    # observations, never confirmed error blocks.
    canonical_target_fail: int = 0
    already_in_dataset: int = 0
    # Distinct (height, hash) violation keys already in the dataset: the same
    # BTC error block is recorded by several sibling chains, so the
    # observation tally above overcounts distinct blocks.
    in_dataset_keys: set[tuple[int, str]] = field(default_factory=set)
    new_findings: list[Candidate] = field(default_factory=list)
    # Distinct (height, hash) NEW-finding keys: the same new BTC error block
    # can be witnessed in several sibling-chain inventories, so the
    # new_findings observation list overcounts distinct blocks.
    new_finding_keys: set[tuple[int, str]] = field(default_factory=set)


def parse_header_version(header_hex: str) -> int | None:
    """Return the nVersion field of an 80-byte header hex, or None."""
    try:
        raw = bytes.fromhex((header_hex or "").strip())
    except ValueError:
        return None
    if len(raw) != 80:
        return None
    return int.from_bytes(raw[0:4], "little", signed=True)


def apply_version_bip_gates(row: dict[str, str], height: int) -> tuple[str, str] | None:
    """Apply the version and BIP34 gates at the claimed height.

    Returns (rule_token, gate_detail) for the failing gate, or None when the
    row passes both gates (including heights below BIP34 activation, where
    neither rule applies). The gates are the shared
    ``stale_blocks_analysis.btc_stale_validation`` functions; an UNKNOWN:
    verdict (missing/malformed evidence) is not a violation — the row passes
    as far as this sweep can tell. The version gate
    (``block_version_error``) is coinbase-independent — it needs only the
    header version and the height — so it runs for any row with a usable
    header, including header-only rows whose chain does not expose the real
    parent coinbase (RSK). The BIP34 coinbase-height gate DOES need the
    coinbase, so it only runs when the row carries a scriptSig; a row
    without one is BIP34-unevaluable (a documented negative), never a BIP34
    finding. A BIP34 coinbase-height token is emitted
    only for the genuine raw-prefix height mismatch (the scriptSig's encoded
    height push is actually wrong). The gate's other REJECTED forms are not a
    BIP34 height violation: a malformed/missing-evidence verdict is unusable
    evidence, and the metadata cross-check disagreement (the optional
    ``btc_bip34_height`` column disagreeing with a correctly-encoded
    scriptSig) is an inconsistent-metadata observation, not a Bitcoin
    consensus failure.
    """
    version_error = block_version_error(row, height)
    if version_error is not None and version_error.startswith("REJECTED:"):
        # Map the token by the same thresholds the gate uses: the gate
        # requires version 2 (BIP34) at [BIP34_HEIGHT, BIP66_HEIGHT), 3
        # (BIP66) at [BIP66_HEIGHT, BIP65_HEIGHT), and 4 (BIP65) above. A v1
        # header at a BIP34-era height violates the v2 minimum, so it is the
        # BIP34 token, not bip66_block_version_below_3.
        if height >= BIP65_HEIGHT:
            token = _TOKEN_BIP65
        elif height >= BIP66_HEIGHT:
            token = _TOKEN_BIP66
        else:
            token = _TOKEN_BIP34_VERSION
        return token, version_error
    if not (row.get("coinbase_scriptsig_hex") or "").strip():
        # No coinbase scriptSig (e.g. RSK, whose proof does not expose the
        # real parent coinbase): the BIP34 coinbase-height rule is
        # unevaluable. The version rule above already ran; there is no BIP34
        # finding to make.
        return None
    bip34_error = bip34_height_error(row, height)
    if bip34_error is not None and bip34_error.startswith(
        _BIP34_HEIGHT_MISMATCH_PREFIX
    ):
        # Only the genuine raw-prefix height mismatch is a BIP34 coinbase-height
        # violation. The gate's other REJECTED forms are not: a malformed/
        # missing-evidence verdict is unusable evidence, and the metadata
        # cross-check disagreement (the optional btc_bip34_height column
        # disagreeing with a correctly-encoded scriptSig) is an inconsistent-
        # metadata observation, not a Bitcoin consensus failure.
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
        if not header_hex:
            # A row without the committed header bytes cannot be re-verified
            # or gated at all; it is not a usable candidate. A missing
            # coinbase scriptSig does NOT make the row unusable: the version
            # gate is coinbase-independent (RSK does not expose the real
            # parent coinbase, but its headers still carry a checkable
            # version), so header-only rows are evaluated for the version
            # rule and are simply BIP34-unevaluable.
            continue
        usable_rows += 1
        height = claimed_height(row)
        if height is None:
            report.no_height += 1
            continue
        version = parse_header_version(header_hex)
        meets_pow = reverify_full_pow(header_hex)
        if version is None or meets_pow is None:
            report.pow_unparseable += 1
            continue
        if not meets_pow:
            report.pow_fail += 1
            continue  # a share/near row, not an error block
        report.pow_pass += 1
        if not authoritative_height:
            report.untrustworthy_height += 1
            continue
        verdict = apply_version_bip_gates(row, height)
        if verdict is None:
            continue
        # Candidate identity (and hence dataset membership) is keyed on the
        # display hash derived from the header bytes, never the inventory's
        # btc_header_hash column: the PoW check already parsed the header, so
        # this digest is authoritative.
        block_hash = header_display_hash(header_hex)
        if block_hash is None:
            report.pow_unparseable += 1
            continue
        token, detail = verdict
        cand = Candidate(
            chain=chain,
            source=source,
            inventory=inventory,
            height=height,
            block_hash=block_hash,
            header_version=version,
            meets_full_pow=True,
            authoritative_height=True,
            meets_expected_pow=reverify_against_canonical_target(
                header_hex, row, height, nbits_by_epoch
            ),
            violation=token,
            gate_detail=detail,
            in_dataset=(height, block_hash) in dataset_keys,
        )
        if token in (_TOKEN_BIP66, _TOKEN_BIP65, _TOKEN_BIP34_VERSION):
            report.version_violations += 1
        else:
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
    total_version = sum(r.version_violations for r in reachable)
    total_bip34 = sum(r.bip34_violations for r in reachable)
    total_canonical_fail = sum(r.canonical_target_fail for r in reachable)
    total_in_dataset = sum(r.already_in_dataset for r in reachable)
    distinct_in_dataset = len({key for r in reachable for key in r.in_dataset_keys})
    total_new = sum(len(r.new_findings) for r in reachable)
    distinct_new = len({key for r in reachable for key in r.new_finding_keys})

    lines = [
        "# Error-blocks version/BIP sweep",
        "",
        f"Generated: {generated_at}",
        "",
        "Proactive application of Bitcoin's historical minimum-version and",
        "BIP34 coinbase-height rules to every catalogued stale candidate",
        "across all reachable chains — including rows currently accepted as",
        "VALID stales — to find error blocks hiding among them: full-proof-",
        "of-work Bitcoin headers that fail one of these consensus rules at",
        "their claimed height. The committed error-blocks dataset was built",
        "primarily from namecoin/devcoin/ixcoin-family observations; this",
        "sweep covers the chains not systematically swept before.",
        "",
        "Rules applied (enforcement heights from",
        "`stale_blocks_analysis.config`):",
        "",
        f"- `BIP34_VERSION_2_HEIGHT = {BIP34_VERSION_2_HEIGHT}`: version >= 2",
        "  blocks need the BIP34 coinbase-height prefix",
        "  (`bip34_v2_coinbase_height_mismatch`).",
        f"- `BIP34_HEIGHT = {BIP34_HEIGHT}`: the prefix is mandatory for ALL",
        "  blocks and version 1 is invalid (`bip34_coinbase_height_mismatch`).",
        f"- `BIP66_HEIGHT = {BIP66_HEIGHT}`: minimum block version 3",
        "  (`bip66_block_version_below_3`).",
        f"- `BIP65_HEIGHT = {BIP65_HEIGHT}`: minimum block version 4",
        "  (`bip65_block_version_below_4`).",
        "",
        "The gates are reused from",
        "`stale_blocks_analysis.btc_stale_validation`",
        "(`block_version_error`, `bip34_height_error`), never reimplemented,",
        "and the rule tokens match the offline validator's `RULE_GATES` keys,",
        "so a promoted finding re-derives in `validate_error_blocks.py`. Full",
        "PoW is re-derived per row from the committed header bytes via",
        "`hash_meets_btc_difficulty` (sha256d of the 80-byte header meets the",
        "header's own embedded nBits target), never inherited from a",
        "classification label. A confirmed finding must ALSO meet the",
        "canonical expected-nBits target at the claimed height (the",
        "inventory's `expected_nbits` column, else the committed epoch table",
        "at the height's epoch start): a gate violation whose digest meets",
        "only an easy self-declared embedded target is a",
        "share/contamination observation, not a confirmed error block (the",
        "same rule the offline validator enforces). A PoW-passing,",
        "canonical-target-passing row that fails a gate at its",
        "claimed height is an error-block finding; membership is checked",
        "against the committed `data/error-blocks/error_blocks.csv` dataset",
        "by `(height, hash)`.",
        "",
        "Candidate sources and claimed-height trust:",
        "",
        "- The 16 regen-chain stale inventories on the chain archive host:",
        "  authoritative `btc_height` (the classifier set it from an",
        "  active-chain prev).",
        "- syscoin/elastos/fractal canonical-fill-scratch stale inventories:",
        "  their `btc_height` is NOT verified against the canonical chain",
        "  (the Task 8 height-trust caveat), so PoW-passing rows are tallied",
        "  as `untrustworthy height` negatives, never evaluated as",
        "  violations.",
        "- The committed `data/validated-stales/<chain>_validated_stales.csv`",
        "  (the ACCEPTED stales): their `btc_height` passed the active-parent",
        "  gate, so it is authoritative; applying the gates here cross-checks",
        "  whether any accepted stale is actually an error block. The version",
        "  gate is coinbase-independent, so header-only rows (RSK does not",
        "  expose the real parent coinbase) are still evaluated for the",
        "  version rule; they are simply BIP34-unevaluable. Chains whose CSV",
        "  carries no usable rows (empty, or every row missing the committed",
        "  header bytes) are `no usable rows` negatives.",
        "",
        "## Summary",
        "",
        f"- Inventories reachable: {len(reachable)}/{len(reports)}",
        f"- Rows examined: {total_rows}",
        f"- Rows skipped for no parseable claimed height: {total_no_height}",
        f"- Rows skipped for an unparseable header (no PoW check possible): "
        f"{total_pow_unparseable}",
        f"- Full-PoW pass: {total_pow_pass}",
        f"- Full-PoW fail (share/near rows, excluded): {total_pow_fail}",
        f"- Full-PoW candidates with an untrustworthy claimed height "
        f"(scratch inventories, not evaluated): {total_untrustworthy}",
        f"- Version-rule violation observations (BIP66/BIP65): {total_version}",
        f"- BIP34 coinbase-height violation observations (v2 + mandatory): "
        f"{total_bip34}",
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
        "",
    ]
    if unreachable:
        lines += ["## Unreachable inventories", ""]
        for r in unreachable:
            lines.append(f"- **{r.chain}** ({r.source}, `{r.inventory}`): {r.error}")
        lines.append("")

    lines += [
        "## Per-inventory results",
        "",
        "| chain | source | rows | full-PoW pass | untrustworthy height | "
        "version violations | BIP34 violations | already in dataset | NEW |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in reports:
        if not r.reachable:
            lines.append(
                f"| {r.chain} | {r.source} | — | — | — | — | — | — | unreachable |"
            )
            continue
        lines.append(
            f"| {r.chain} | {r.source} | {r.total_rows} | {r.pow_pass} "
            f"| {r.untrustworthy_height} | {r.version_violations} "
            f"| {r.bip34_violations} | {r.already_in_dataset} "
            f"| {len(r.new_findings)} |"
        )
    lines.append("")

    lines += ["## Negative results", ""]
    zero_violation = [
        f"{r.chain} ({r.source})"
        for r in reachable
        if r.pow_pass > 0
        and not r.untrustworthy_height
        and r.version_violations == 0
        and r.bip34_violations == 0
    ]
    if zero_violation:
        lines.append(
            "- Inventories with authoritative-height full-PoW candidates but "
            "no version/BIP34 violation: " + ", ".join(zero_violation) + "."
        )
    else:
        lines.append(
            "- No reachable inventory with authoritative-height full-PoW "
            "candidates was violation-free."
        )
    no_usable = [f"{r.chain} ({r.source})" for r in reachable if r.no_usable_rows]
    if no_usable:
        lines.append(
            "- Inventories with no usable rows (empty, or every row missing "
            "the committed header bytes): " + ", ".join(no_usable) + "."
        )
    if total_no_height:
        lines.append(
            f"- {total_no_height} rows were skipped for lacking a parseable "
            "claimed height (no `btc_height`, a malformed value, or an "
            "implausible value above the canonical tip)."
        )
    if total_pow_unparseable:
        lines.append(
            f"- {total_pow_unparseable} rows were skipped for an unparseable "
            "committed header (no PoW re-verification possible)."
        )
    if total_untrustworthy:
        lines.append(
            f"- {total_untrustworthy} full-PoW candidates in the "
            "canonical-fill-scratch stale inventories "
            "(syscoin/elastos/fractal) carried a non-authoritative claimed "
            "height: their `btc_height` is not verified against the "
            "canonical chain, so no valid version/BIP check is possible. "
            "They are negatives, not violations."
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
            "- No NEW confirmed version/BIP error blocks: every full-PoW "
            "violation meeting the canonical expected-nBits target is "
            "already catalogued in the committed dataset."
        )
    lines.append("")

    if total_new:
        lines += ["## NEW confirmed version/BIP error blocks", ""]
        for r in reachable:
            for cand in r.new_findings:
                lines.append(
                    f"- {cand.chain} ({cand.source}) height {cand.height} "
                    f"hash `{cand.block_hash}` — {cand.violation} "
                    f"({cand.gate_detail}) (provenance: "
                    f"`sweep-version-bip:{cand.chain}:{cand.inventory}`)"
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
    add_common_sweep_args(
        parser,
        default_report=DEFAULT_REPORT,
        archive_help=(
            "read ALL inventories (archive stale inventories and committed "
            "validated-stales alike) from a local mirror "
            f"(<root>/<chain>/<filename>) instead of ssh {ARCHIVE_HOST} + local "
            "validated-stales paths"
        ),
    )
    args = parser.parse_args(argv)

    if validate_partial_args(args):
        return 2

    reader = choose_inventory_reader(
        args,
        default_reader=combined_reader(ssh_inventory_reader, local_validated_reader),
    )
    dataset_keys = load_dataset_keys()

    reports: list[ChainReport] = []
    # Source 1/2: the archive stale inventories (regen chains authoritative,
    # scratch chains untrustworthy-height).
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

    if check_sweep_coverage(
        args,
        reports,
        expected_inventory_rows=INVENTORY_BASELINE_ROWS,
        inventory_row_counts=lambda report: {
            f"{report.chain}:{report.source}": report.total_rows
        },
    ):
        return 1

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    write_rc = write_sweep_report(
        args,
        default_report=DEFAULT_REPORT,
        render=lambda output: render_report(reports, generated_at),
    )
    if write_rc:
        return write_rc

    reachable = [r for r in reports if r.reachable]
    total_new = sum(len(r.new_findings) for r in reachable)
    print(
        f"swept {sum(r.total_rows for r in reachable)} rows across "
        f"{len(reachable)}/{len(reports)} reachable inventories: "
        f"{sum(r.no_height for r in reachable)} no-height, "
        f"{sum(r.pow_unparseable for r in reachable)} pow-unparseable, "
        f"{sum(r.pow_pass for r in reachable)} full-PoW pass, "
        f"{sum(r.untrustworthy_height for r in reachable)} "
        f"untrustworthy-height, "
        f"{sum(r.version_violations for r in reachable)} version violations, "
        f"{sum(r.bip34_violations for r in reachable)} BIP34 violations, "
        f"{sum(r.already_in_dataset for r in reachable)} already in dataset, "
        f"{total_new} NEW error block(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
