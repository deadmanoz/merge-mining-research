#!/usr/bin/env python3
"""Shared inventory, PoW, and output guards for the error-block sweeps.

A confirmed finding must meet the canonical expected-nBits target, not only the header's embedded target. ``--allow-partial`` may write only outside committed artifact directories. The time-rule sweep keeps its own ``reverify_full_pow`` and ``claimed_height``. Tests load sweeps by file path, so this module is imported as a ``scripts/analysis`` sibling.
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
from stale_blocks_analysis.error_blocks import load_error_block_keys

# Placeholder host fails closed until ERROR_BLOCKS_ARCHIVE_HOST is set.
ARCHIVE_HOST = os.environ.get("ERROR_BLOCKS_ARCHIVE_HOST", "<chain-archive-host>")
CHAIN_ARCHIVE_ROOT = os.environ.get(
    "ERROR_BLOCKS_CHAIN_ARCHIVE_ROOT", "<chain-archive>"
)

# Heights above this are garbage-integer contamination, not checkable candidates.
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
    "i0coin",
    "ixcoin",
    "myriadcoin",
    "terracoin",
    "unobtanium",
)

# Scratch inventories (syscoin, elastos, fractal) do not have a
# canonical-verified btc_height.
STALE_INVENTORIES: dict[str, str] = {
    **{
        chain: f"{_REGEN_STAGING}/{chain}/classified/{chain}_stale_blocks.csv"
        for chain in _REGEN_CHAINS
    },
    "huntercoin": f"{CHAIN_ARCHIVE_ROOT}/huntercoin/classified/huntercoin_stale_blocks.csv",
    "xaya": f"{CHAIN_ARCHIVE_ROOT}/xaya/classified/xaya_stale_blocks.csv",
    "syscoin": "~/canonical-fill-scratch/syscoin/syscoin_stale_blocks.csv",
    "elastos": "~/canonical-fill-scratch/elastos/elastos_stale_blocks.csv",
    "fractal": "~/canonical-fill-scratch/fractal/fractal_stale_blocks.csv",
}

# A sweep may exceed these counts but must not publish fewer: a short
# inventory is not a clean negative. Zero is expected for some header-only inputs.
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
    "huntercoin": 78,
    "i0coin": 176,
    "ixcoin": 478,
    "myriadcoin": 40,
    "terracoin": 35,
    "unobtanium": 44,
    "xaya": 44,
    "syscoin": 18_381,
    "elastos": 9_182,
    "fractal": 534,
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
    "huntercoin": 150_853,
    "i0coin": 86_249,
    "ixcoin": 253_974,
    "myriadcoin": 166_844,
    "terracoin": 523_315,
    "unobtanium": 430_931,
    "xaya": 19_294,
}

VALIDATED_STALE_INVENTORY_BASELINE_ROWS: dict[str, int] = {
    "argentum": 2,
    "bitcoin-vault": 9,
    "bitmark": 1,
    "coiledcoin": 27,
    "crown": 23,
    "devcoin": 468,
    "doichain": 0,
    "elastos": 177,
    "elcash": 3,
    "emercoin": 96,
    "fractal": 40,
    "geistgeld": 0,
    "groupcoin": 30,
    "hathor": 6,
    "huntercoin": 78,
    "i0coin": 166,
    "ixcoin": 465,
    "lyncoin": 0,
    "myriadcoin": 40,
    "namecoin": 1_649,
    "rsk": 337,
    "sixeleven": 0,
    "syscoin": 98,
    "terracoin": 35,
    "unobtanium": 43,
    "xaya": 42,
}

# Scratch btc_height is not canonical-verified; height-dependent checks do not apply.
_SCRATCH_CHAINS = ("syscoin", "elastos", "fractal")
AUTHORITATIVE_HEIGHT_CHAINS = frozenset(STALE_INVENTORIES).difference(_SCRATCH_CHAINS)

# Accepted stales. Their btc_height passed the active-parent gate.
VALIDATED_STALES_GLOB = "data/validated-stales/*_validated_stales.csv"

EPOCH_LENGTH = 2016

# Callable that returns the inventory CSV text for (chain, path), or raises.
InventoryReader = Callable[[str, str], str]


def load_dataset_keys(path: Path = ERROR_BLOCKS_CSV) -> set[tuple[int, str]]:
    """Load committed error-block keys as ``(height, hash)``.

    A blank classification, malformed key, duplicate, or empty dataset raises. An empty key set would report catalogued blocks as new findings.
    """
    return load_error_block_keys(path)


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
    """Display-order sha256d of an 80-byte header.

    Membership is keyed on this digest, never the inventory hash column.
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
    """Whether the header meets its own embedded nBits.

    Bits are taken from the header bytes, not the ``btc_bits`` column.
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
    """Load the committed epoch-start nBits table."""
    return package_load_nbits_by_epoch(BITCOIN_EPOCH_REFERENCE_DIR)


def reverify_against_canonical_target(
    header_hex: str,
    row: dict[str, str],
    height: int,
    nbits_by_epoch: dict[int, int],
) -> bool | None:
    """Whether the header meets the canonical expected nBits at ``height``.

    Use inventory ``expected_nbits`` only when it matches the epoch table. Disagreement or a missing epoch returns None. An easy self-declared target is a share, not a confirmed error block.
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
            # Inventory expected_nbits that disagrees with the epoch table fails closed.
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


# Partial output must stay outside committed report and dataset directories.
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
    """Refuse to overwrite the committed report unless every inventory is complete.

    ``--allow-partial`` is the only way past an unreachable, empty, or short inventory.
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
    """Register the flags shared by every error-block sweep."""
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
    """Refuse an empty or incomplete sweep before later I/O.

    The time-rule sweep must call this before fetching median-time-past.
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
    """Write the rendered report. Returns 2 when the output path is refused."""
    output = resolve_output_path(args, default_report)
    if output is None:
        return 2
    report_text = render(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report_text)
    print(f"wrote sweep report to {output}")
    return 0


def resolve_output_path(args: object, default_report: Path) -> Path | None:
    """Resolve the report path. A partial run never writes the committed default path."""
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
