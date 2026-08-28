#!/usr/bin/env python3
"""Shared mechanical layer for the error-block sweep scripts.

The four error-block sweeps (``sweep_error_blocks_rejected_rows.py``,
``sweep_error_blocks_time_rule.py``, ``sweep_error_blocks_version_bip.py``,
``sweep_error_blocks_coinbase_form.py``) share an identical mechanical
substrate: dataset-key loading, inventory reading over ssh/local mirrors,
the regen-chain inventory maps, the claimed-height plausibility bound, and
the ``--allow-partial`` / ``--output-dir`` fail-closed output guard (a
partial sweep's ``--output-dir`` must be a disposable directory outside the
committed artifact locations). That
substrate lives here, once, along with the shared CLI flags, reader
choice, coverage preflight, and report write path. The per-sweep gate
logic, candidate/report dataclasses, and report rendering stay in each
sweep.

Reconciliation note: the rejected-rows sweep originally read inventories
over ssh with a 120s timeout while the other three sweeps used 600s. The
600s timeout is the current behavior (the classified inventories are large
enough that 120s was marginal), so the shared ``ssh_inventory_reader``
carries ``timeout=600``.

Not shared (left per-sweep deliberately):

- The time-rule sweep's ``reverify_full_pow``: it returns
  ``tuple[bool, int, int] | None`` (it additionally re-derives nTime/bits),
  not the shared bool variant below. The bool-returning own-target
  re-verification IS shared (``reverify_full_pow`` below) and used by the
  rejected-rows, version/BIP, and coinbase-form sweeps.
- ``claimed_height`` in the time-rule sweep: it returns
  ``(height, why)`` and corroborates against the decoded BIP34 coinbase
  height. The shared ``claimed_height`` below is the simpler
  ``int | None`` variant used by the version/BIP and coinbase-form sweeps.
- The rejected-rows sweep's ``CHAIN_INVENTORIES``: a different, smaller
  inventory map (REJECTED-row coverage), not the 19-chain
  ``STALE_INVENTORIES`` map shared by the other sweeps. It also covers
  namecoin, which is not one of the regen-staging chains, so its row
  baseline is stated in the sweep rather than taken from
  ``STALE_INVENTORY_BASELINE_ROWS``.
- The time-rule sweep's MTP-fetch machinery (``_REMOTE_MTP_HELPER``,
  ``ssh_mtp_fetcher``, the cache helpers) and ``UNKNOWN_INVENTORY_GLOB``.

The canonical-target re-verification (``reverify_against_canonical_target``
plus its ``load_nbits_by_epoch`` epoch-table loader) IS shared: a confirmed
error-block finding in any sweep must meet the canonical ``expected_nbits``
target at the claimed height, not just the header's easy self-declared
embedded target.

Import mechanism: these scripts run as ``__main__`` and are loaded via
``importlib.util.spec_from_file_location`` in tests, so a package-relative
import is not available. The sweeps follow the established
``scripts/analysis`` sibling-import pattern (see
``classify_btc_stale_relevance.py``): insert the script directory into
``sys.path`` and ``import _sweep_common``.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from stale_blocks_analysis.auxpow_parse import hash_meets_btc_difficulty
from stale_blocks_analysis.bitcoin_epoch_reference import (
    load_nbits_by_epoch as package_load_nbits_by_epoch,
)
from stale_blocks_analysis.config import (
    BITCOIN_EPOCH_REFERENCE_DIR,
    ERROR_BLOCKS_CSV,
    ERROR_BLOCKS_DIR,
)
from stale_blocks_analysis.error_blocks import load_stale_exclusion_keys

# Private chain-archive host alias, redacted from the tracked tree per the
# repo's leak-redaction guidance. Operators set ERROR_BLOCKS_ARCHIVE_HOST to
# the real host; the placeholder default fails closed (the ssh reader errors
# with a clear message) when the env var is unset.
ARCHIVE_HOST = os.environ.get("ERROR_BLOCKS_ARCHIVE_HOST", "<chain-archive-host>")

# Generous forward margin over the canonical tip (~900k at sweep time): a
# claimed height above this is contamination (these inventories carry
# garbage-integer btc_height rows), not a checkable candidate.
MAX_PLAUSIBLE_HEIGHT = 2_000_000

_REGEN_STAGING = "~/mmr-child-header-regen-20260729/staging/chains"
_REGEN_CHAINS = (
    "argentum",
    "bitmark",
    "coiledcoin",
    "crown",
    "devcoin",
    "elcash",
    "emercoin",
    "geistgeld",
    "groupcoin",
    "huntercoin",
    "i0coin",
    "ixcoin",
    "myriadcoin",
    "terracoin",
    "unobtanium",
    "xaya",
)

# Authoritative stale-classified inventories on the chain archive host: the
# 16 regen-staging chains plus syscoin/elastos/fractal from canonical-fill
# scratch (height-trust caveat: the scratch inventories' btc_height is not
# canonical-verified; see the sweep module docstrings). Verified 2026-07-30.
STALE_INVENTORIES: dict[str, str] = {
    **{
        chain: f"{_REGEN_STAGING}/{chain}/classified/{chain}_stale_blocks.csv"
        for chain in _REGEN_CHAINS
    },
    "syscoin": "~/canonical-fill-scratch/syscoin/syscoin_stale_blocks.csv",
    "elastos": "~/canonical-fill-scratch/elastos/elastos_stale_blocks.csv",
    "fractal": "~/canonical-fill-scratch/fractal/fractal_stale_blocks.csv",
}

# Minimum row counts from the complete 2026-07-30 error-block sweep inputs.
# A completed publication sweep may grow beyond these values, but it may not
# silently replace a committed report with fewer rows: that would make an
# empty/header-only or truncated inventory look like a clean negative result.
# Zero is an intentional baseline only for Geistgeld's stale and several
# header-only validated-stale inputs, where no candidate rows are expected.
STALE_INVENTORY_BASELINE_ROWS: dict[str, int] = {
    "argentum": 2,
    "bitmark": 1,
    "coiledcoin": 27,
    "crown": 23,
    "devcoin": 484,
    "elcash": 3,
    "emercoin": 97,
    "geistgeld": 0,
    "groupcoin": 32,
    "huntercoin": 13,
    "i0coin": 176,
    "ixcoin": 478,
    "myriadcoin": 40,
    "terracoin": 35,
    "unobtanium": 44,
    "xaya": 40,
    "syscoin": 18_360,
    "elastos": 9_156,
    "fractal": 524,
}

UNKNOWN_INVENTORY_BASELINE_ROWS: dict[str, int] = {
    "argentum": 634_277,
    "bitmark": 81_921,
    "coiledcoin": 13_308,
    "crown": 383_622,
    "devcoin": 75_141,
    "elcash": 2_711,
    "emercoin": 16_545,
    "geistgeld": 2_290,
    "groupcoin": 2_713,
    "huntercoin": 29,
    "i0coin": 86_249,
    "ixcoin": 253_974,
    "myriadcoin": 166_844,
    "terracoin": 523_315,
    "unobtanium": 430_931,
    "xaya": 17_642,
}

VALIDATED_STALE_INVENTORY_BASELINE_ROWS: dict[str, int] = {
    "argentum": 2,
    "bitcoin-vault": 9,
    "bitmark": 1,
    "coiledcoin": 27,
    "crown": 23,
    "devcoin": 468,
    "doichain": 0,
    "elastos": 153,
    "elcash": 3,
    "emercoin": 96,
    "fractal": 31,
    "geistgeld": 0,
    "groupcoin": 30,
    "hathor": 6,
    "huntercoin": 13,
    "i0coin": 166,
    "ixcoin": 465,
    "lyncoin": 0,
    "myriadcoin": 40,
    "namecoin": 1_625,
    "rsk": 298,
    "sixeleven": 0,
    "syscoin": 78,
    "terracoin": 35,
    "unobtanium": 43,
    "xaya": 40,
}

# The scratch stale inventories carry a btc_height that is NOT verified
# against the canonical chain, so a height-dependent check against it is
# uninterpretable there.
_SCRATCH_CHAINS = ("syscoin", "elastos", "fractal")

# Committed accepted-stale loader inputs (local): the cross-check that no
# accepted VALID stale is actually an error block. Their btc_height passed
# the active-parent gate, so it is authoritative.
VALIDATED_STALES_GLOB = "data/validated-stales/*_validated_stales.csv"

EPOCH_LENGTH = 2016

# Callable that returns the inventory CSV text for (chain, path), or raises.
InventoryReader = Callable[[str, str], str]


def load_dataset_keys(path: Path = ERROR_BLOCKS_CSV) -> set[tuple[int, str]]:
    """Load the committed error-blocks dataset keys as (height, hash).

    Applies the same fail-closed validation as the publication gate loader
    (``stale_blocks_analysis.error_blocks._load_keys``, reached via
    ``load_stale_exclusion_keys``): a blank/non-``error_block`` classification,
    a malformed height or hash, a duplicate key, or an empty/header-only
    dataset all raise. The sweeps treat any rediscovered catalogued row absent
    from this key set as NEW, so a silently tolerated bad row (or an empty key
    set) would make a sweep mis-report catalogued error blocks as NEW findings.
    """
    return load_stale_exclusion_keys(path)


def ssh_inventory_reader(chain: str, path: str) -> str:
    """Read an inventory from the chain archive host via ssh cat."""
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", ARCHIVE_HOST, "cat", path],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        raise OSError(
            f"ssh {ARCHIVE_HOST} cat {path} failed (rc={result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return result.stdout


def local_validated_reader(chain: str, path: str) -> str:
    """Read a committed validated-stales CSV from the local filesystem."""
    return Path(path).read_text()


def combined_reader(
    archive_reader: InventoryReader, validated_reader: InventoryReader
) -> InventoryReader:
    """Dispatch validated-stales paths locally, archive paths via ssh."""

    def read(chain: str, path: str) -> str:
        if Path(path).name.endswith("_validated_stales.csv"):
            return validated_reader(chain, path)
        return archive_reader(chain, path)

    return read


def local_mirror_reader(root: Path) -> InventoryReader:
    """Read inventories from a local mirror: <root>/<chain>/<filename>."""

    def read(chain: str, path: str) -> str:
        mirror_path = root / chain / Path(path).name
        return mirror_path.read_text()

    return read


def validated_stales_inventories(glob_pattern: str) -> dict[str, str]:
    """Map chain name to path for each committed validated-stales CSV."""
    out: dict[str, str] = {}
    for path in sorted(Path().glob(glob_pattern)):
        chain = path.name[: -len("_validated_stales.csv")]
        out[chain] = str(path)
    return out


def header_display_hash(header_hex: str) -> str | None:
    """Return the display-order sha256d hash of an 80-byte header, or None.

    Candidate identity and dataset membership are keyed on this header-derived
    hash, never the inventory's ``btc_header_hash`` column: a valid header
    paired with a fabricated/stale hash column must not be mis-reported or
    evade dedup.
    """
    try:
        header = bytes.fromhex((header_hex or "").strip())
    except ValueError:
        return None
    if len(header) != 80:
        return None
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return digest[::-1].hex()


def reverify_full_pow(header_hex: str) -> bool | None:
    """Re-verify that the 80-byte header meets its own embedded nBits target.

    Returns True/False, or None when the header cannot be parsed. The bits
    are re-derived from the header bytes, never trusted from a column (a
    mismatched ``btc_bits`` column could otherwise create or hide a finding).
    """
    try:
        header = bytes.fromhex((header_hex or "").strip())
    except ValueError:
        return None
    if len(header) != 80:
        return None
    bits = int.from_bytes(header[72:76], "little")
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return hash_meets_btc_difficulty(digest, bits)


def load_nbits_by_epoch() -> dict[int, int]:
    """Load the committed retarget-epoch reference table (epoch start -> bits).

    Zero-argument sweep-facing wrapper: the four sweeps always read the one
    committed reference directory, so the parsing itself is delegated to the
    package loader rather than duplicated here.
    """
    return package_load_nbits_by_epoch(BITCOIN_EPOCH_REFERENCE_DIR)


def reverify_against_canonical_target(
    header_hex: str,
    row: dict[str, str],
    height: int,
    nbits_by_epoch: dict[int, int],
) -> bool | None:
    """Re-verify the header digest against the CANONICAL expected-nBits target.

    The canonical target is the inventory's ``expected_nbits`` column when it
    parses AND agrees with the committed epoch table, else the committed epoch
    table value at the claimed height's epoch start. Returns True/False, or
    None when the header cannot be parsed, the epoch table lacks the height's
    epoch start, or a parseable inventory ``expected_nbits`` DISAGREES with
    the epoch table value. Meeting only the header's own embedded bits is
    circular for an error-block claim: an easy self-declared-target header
    that fails the canonical Bitcoin target is a share/contamination, not a
    confirmed error block.

    A parseable inventory ``expected_nbits`` is corroborated against the
    committed epoch table before use: a stale inventory carrying an erroneous
    or artificially-easy ``expected_nbits`` could otherwise make a sweep
    report a false NEW confirmed error block. When the epoch table has the
    height's epoch start and the inventory value disagrees with it, the
    inventory is untrustworthy, so the check fails closed (returns None)
    rather than use the suspect value. When the epoch table lacks the epoch
    start the claimed height cannot be corroborated at all, so the check also
    fails closed (returns None).
    """
    try:
        header = bytes.fromhex((header_hex or "").strip())
    except ValueError:
        return None
    if len(header) != 80:
        return None
    epoch_bits = nbits_by_epoch.get((height // EPOCH_LENGTH) * EPOCH_LENGTH)
    if epoch_bits is None:
        # The epoch table cannot corroborate this height: fail closed.
        return None
    bits: int | None = None
    try:
        bits = int((row.get("expected_nbits") or "").strip(), 16)
    except ValueError:
        bits = None
    if bits is not None:
        if bits != epoch_bits:
            # A parseable inventory expected_nbits that disagrees with the
            # committed epoch table is suspect: fail closed rather than trust
            # a possibly stale/artificially-easy value.
            return None
    else:
        bits = epoch_bits
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return hash_meets_btc_difficulty(digest, bits)


def claimed_height(row: dict[str, str]) -> int | None:
    """Return the plausible claimed height from the ``btc_height`` column."""
    height_text = (row.get("btc_height") or "").strip()
    if not height_text:
        return None
    try:
        height = int(height_text)
    except ValueError:
        return None
    if height <= 0 or height > MAX_PLAUSIBLE_HEIGHT:
        return None
    return height


# Committed artifact locations a partial sweep must never write into: the
# committed sweep reports live under results/analysis/error-blocks and the
# committed dataset/sidecar under data/error-blocks. A partial
# (--allow-partial) --output-dir must be a genuinely disposable location
# outside both, so a partial report can never overwrite ANY committed
# artifact (not just the sweep's own default report filename).
_COMMITTED_ARTIFACT_DIRS = (
    Path("results/analysis/error-blocks"),
    ERROR_BLOCKS_DIR,
)


def validate_partial_args(args: object) -> int:
    """Enforce the --allow-partial / --output-dir pairing; 0 ok, 2 misuse."""
    if args.allow_partial:
        if args.output_dir is None:
            print("--allow-partial requires --output-dir", file=sys.stderr)
            return 2
        output_dir = args.output_dir.resolve()
        for committed_dir in _COMMITTED_ARTIFACT_DIRS:
            resolved = committed_dir.resolve()
            if output_dir == resolved or output_dir.is_relative_to(resolved):
                print(
                    "--allow-partial --output-dir must be a disposable "
                    f"directory outside committed artifact locations: {output_dir} "
                    f"is (or is inside) the committed {committed_dir}",
                    file=sys.stderr,
                )
                return 2
    elif args.output_dir is not None:
        print("--output-dir is only valid with --allow-partial", file=sys.stderr)
        return 2
    return 0


def _report_label(report: object) -> str:
    """Human label for one sweep report: chain plus source when present."""
    chain = getattr(report, "chain", "?")
    source = getattr(report, "source", "")
    return f"{chain} ({source})" if source else str(chain)


def require_full_coverage_for_committed(
    args: object,
    reports: list[object],
    *,
    expected_inventory_rows: Mapping[str, int] | None = None,
    inventory_row_counts: Callable[[object], Mapping[str, int]] | None = None,
) -> int:
    """Fail closed when a partial sweep would overwrite the committed report.

    The committed default report must only ever present a COMPLETE sweep:
    writing it requires every inventory to be reachable. A partially-available
    sweep (some inventories unreachable, empty, or below its published row
    baseline) must NOT overwrite the committed report without
    ``--allow-partial``. Returns 0 when the write may proceed
    (``--allow-partial``, or every inventory is complete); returns 1 after
    printing the incomplete inventories when it must fail closed.
    """
    if getattr(args, "allow_partial", False):
        return 0
    unreachable = [r for r in reports if not getattr(r, "reachable", True)]
    if not unreachable:
        if expected_inventory_rows is None or inventory_row_counts is None:
            return 0
        actual_rows: dict[str, int] = {}
        for report in reports:
            for inventory, rows in inventory_row_counts(report).items():
                if inventory in actual_rows:
                    raise ValueError(
                        f"duplicate sweep inventory coverage key: {inventory}"
                    )
                actual_rows[inventory] = rows
        incomplete = []
        for inventory, expected_rows in expected_inventory_rows.items():
            actual = actual_rows.pop(inventory, None)
            if actual is None:
                incomplete.append(f"{inventory} missing from the sweep")
            elif actual < expected_rows:
                incomplete.append(
                    f"{inventory} has {actual} rows, expected at least {expected_rows}"
                )
        incomplete.extend(
            f"{inventory} has no published row baseline" for inventory in actual_rows
        )
        if not incomplete:
            return 0
        for detail in incomplete:
            print(f"error: incomplete inventory: {detail}", file=sys.stderr)
        print(
            "sweep failed: refusing to write the committed report from an "
            "incomplete inventory sweep; re-run with --allow-partial "
            "--output-dir <dir> for a diagnostic partial report",
            file=sys.stderr,
        )
        return 1

    for r in unreachable:
        print(
            f"error: {_report_label(r)}: {getattr(r, 'error', '')}",
            file=sys.stderr,
        )
    names = ", ".join(_report_label(r) for r in unreachable)
    print(
        "sweep failed: refusing to write the committed report from a partial "
        f"sweep ({len(unreachable)} unreachable inventories: {names}); "
        "re-run with --allow-partial --output-dir <dir> for a diagnostic "
        "partial report",
        file=sys.stderr,
    )
    return 1


def add_common_sweep_args(
    parser: argparse.ArgumentParser,
    *,
    default_report: Path,
    archive_help: str,
) -> None:
    """Register the four flags shared by every error-block sweep.

    Time-rule still adds ``--mtp-cache`` itself. ``archive_help`` stays
    per-sweep so the two-source sweeps can describe the mirror override
    for both archive and validated-stales paths.
    """
    parser.add_argument(
        "--chain-archive-root",
        type=Path,
        default=None,
        help=archive_help,
    )
    parser.add_argument("--output", type=Path, default=default_report)
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=None)


def choose_inventory_reader(
    args: object, *, default_reader: InventoryReader
) -> InventoryReader:
    """Use a local archive mirror when requested, else the sweep's default."""
    root = getattr(args, "chain_archive_root", None)
    if root is not None:
        return local_mirror_reader(root)
    return default_reader


def check_sweep_coverage(
    args: object,
    reports: list[object],
    *,
    expected_inventory_rows: Mapping[str, int] | None = None,
    inventory_row_counts: Callable[[object], Mapping[str, int]] | None = None,
) -> int:
    """Refuse an empty or incomplete sweep before any later I/O.

    This is a preflight: time-rule must call it before ``fetch_mtp_context``.
    Returns 0 when the sweep may continue, or 1 after printing the
    unreachable-all or incomplete-coverage refusal.
    """
    reachable = [r for r in reports if getattr(r, "reachable", True)]
    if not reachable:
        for report in reports:
            print(
                f"error: {_report_label(report)}: {getattr(report, 'error', '')}",
                file=sys.stderr,
            )
        print(
            "sweep failed: no inventories reachable (no report written)",
            file=sys.stderr,
        )
        return 1
    return require_full_coverage_for_committed(
        args,
        reports,
        expected_inventory_rows=expected_inventory_rows,
        inventory_row_counts=inventory_row_counts,
    )


def write_sweep_report(
    args: object,
    *,
    default_report: Path,
    render: Callable[[Path], str],
) -> int:
    """Resolve the output path, render, and write. No coverage check, no MTP.

    ``render`` receives the resolved output Path so time-rule can read
    ``prior_text`` from the file it is about to replace. Returns 0, or 2
    when ``resolve_output_path`` refuses the write.
    """
    output = resolve_output_path(args, default_report)
    if output is None:
        return 2
    report_text = render(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report_text)
    print(f"wrote sweep report to {output}")
    return 0


def resolve_output_path(args: object, default_report: Path) -> Path | None:
    """Resolve the report output path under the fail-closed partial guard.

    With ``--allow-partial`` the report is written inside the disposable
    ``--output-dir``; a partial report is never written to the committed
    default path (returns None after printing the refusal). The disposable
    requirement itself (the ``--output-dir`` must lie outside the committed
    artifact locations) is enforced by ``validate_partial_args`` at argument
    parsing time. Without ``--allow-partial`` the output is ``args.output``
    unchanged.
    """
    output = args.output
    if args.allow_partial:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        output = (args.output_dir / output.name).resolve()
        if output == default_report.resolve():
            print(
                "refusing to write partial report to the committed path",
                file=sys.stderr,
            )
            return None
    return output
