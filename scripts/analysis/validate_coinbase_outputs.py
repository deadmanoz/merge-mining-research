#!/usr/bin/env python3
"""Validate committed coinbase output rendering without modifying datasets."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from stale_blocks_analysis.coinbase_output_claims import (
    parse_coinbase_output_claims,
    render_coinbase_outputs_column,
)
from stale_blocks_analysis.config import DATA_DIR

OP_RETURN_LABEL = "OP_RETURN"
# These retained datasets do not contain the nulldata payload bytes.
LEGACY_OP_RETURN_LABEL = {"terracoin", "bitcoin-vault", "syscoin"}


def split_entries(cell: str) -> list[str]:
    """Split entries for validation without shifting unknown output positions.

    An empty leading or interior field is a real output slot whose evidence is
    unknown, and the column renderer emits it for a claim vector with a hole;
    dropping one would renumber every later payout. Trailing empties carry no
    representable evidence (the renderer never emits them) and are stripped as
    separator noise.
    """
    parts = cell.replace("|", ";").split(";")
    while parts and not parts[-1].strip():
        parts.pop()
    return parts


def split_value(entry: str) -> tuple[str, str | None]:
    """Split ``payout:value``; an absent or empty amount returns None.

    ``data/stale_descendants.csv`` carries both ``<hex>:<sats>`` and a
    value-less ``<hex>:`` shape, so an empty trailing field means the
    extraction preserved no amount rather than a zero one.
    """
    if ":" in entry:
        payout, _, value = entry.rpartition(":")
        return payout, (value or None)
    return entry, None


def is_canonical_entry(entry: str, *, allow_op_return_label: bool = False) -> bool:
    """True when an entry already satisfies the canonical contract.

    Canonical is defined as round-tripping through the package's own parser
    and column renderer, so the checker cannot drift from the code that
    produces the data. The bare ``OP_RETURN`` label is the one alias the
    parser normalizes away, and it survives only where the payload was lost
    at acquisition.
    """
    if not entry.strip():
        return (
            True  # an unknown output slot, kept so later payouts keep their positions
        )
    payout, _ = split_value(entry.lstrip("~"))
    if payout == OP_RETURN_LABEL:
        return allow_op_return_label
    try:
        return render_coinbase_outputs_column(parse_coinbase_output_claims(entry)) == (
            entry
        )
    except ValueError:
        return False


def cell_problems(path: Path, cell: str) -> list[str]:
    """Every way one committed cell can violate the contract.

    Shared by the validator and committed-data test so both enforce the
    cell-level rules (separator and marker policy) and not just the tokens.
    """
    problems: list[str] = []
    if "|" in cell:
        # split_entries() tolerates the legacy separator so it can read
        # pre-migration cells, so it has to be rejected here or a wholly
        # pipe-joined cell would pass on its tokens alone.
        problems.append(f"{path.name}: legacy pipe separator in {cell[:40]}")
    entries = split_entries(cell)
    marked = [entry.startswith("~") for entry in entries if entry.strip()]
    # Accepted loader vectors no longer have an address-filtered acquisition.
    # Historical external evidence can still use the shared claims parser.
    if any(marked):
        problems.append(f"{path.name}: filtered output projection in loader data")
    try:
        # Publication parses the cell as a whole, which enforces rules no
        # per-entry check sees, such as a filtered projection containing a gap.
        parse_coinbase_output_claims(cell)
    except ValueError as exc:
        problems.append(f"{path.name}: cell does not parse: {exc}")
    allow_label = any(chain in path.name for chain in LEGACY_OP_RETURN_LABEL)
    bad = [
        entry
        for entry in entries
        if not is_canonical_entry(entry, allow_op_return_label=allow_label)
    ]
    if bad:
        problems.append(f"{path.name}: non-canonical entries {bad[:3]}")
    return problems


def target_files() -> list[Path]:
    files = sorted((DATA_DIR / "validated-stales").glob("*_validated_stales.csv"))
    files.append(DATA_DIR / "stale_descendants.csv")
    return [path for path in files if path.exists()]


def main() -> None:
    problems = []
    for path in target_files():
        with path.open(newline="") as handle:
            for row in csv.DictReader(handle):
                problems.extend(cell_problems(path, row.get("coinbase_outputs") or ""))
    if problems:
        for problem in problems[:20]:
            print(f"problem: {problem}", file=sys.stderr)
        raise SystemExit(f"{len(problems)} coinbase output problem(s)")
    print("all committed coinbase_outputs are canonical")


if __name__ == "__main__":
    main()
