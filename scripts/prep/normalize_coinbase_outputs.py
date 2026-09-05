#!/usr/bin/env python3
"""Normalize committed `coinbase_outputs` columns to one rendering contract.

The column records the BTC parent coinbase's payout list, but each acquisition
path rendered it differently. Most chains emitted raw scriptPubKey hex,
Terracoin emitted Bitcoin addresses with BTC-denominated amounts, Bitcoin
Vault emitted Bitcoin addresses with integer-satoshi amounts (its binary
parse reads the little-endian uint64 directly), Hathor and the
stale-descendant module emitted hex with satoshi amounts, and Namecoin and
Syscoin emitted the *child* node's base58 and bech32
(`N...`/`M...` under version 52, `6...` under version 13, `S...` under version
63, `nc1...`), which renders Bitcoin payouts as if they were child-chain
addresses.

The canonical form is semicolon-joined, in coinbase order, each entry
``<payout>`` or ``<payout>:<value_sats>``:

* the Bitcoin mainnet address for the address-bearing standard templates
  (P2PKH, P2SH, P2WPKH, P2WSH, P2TR),
* raw scriptPubKey hex for every other script (P2PK, nulldata, bare
  multisig, nonstandard).

Values are integer satoshis and appear only where the extraction preserved
them.

This transformation is rendering-only and hash160/witness-program preserving:
no payout identity, ordering, or amount changes. Terracoin, Bitcoin Vault, and
Syscoin recorded a bare ``OP_RETURN`` label instead of the nulldata script, so
their witness-commitment payloads were discarded at acquisition; those labels
are left in place and the checker tolerates them as a documented legacy value.

Usage:
    normalize_coinbase_outputs.py [--check]
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from stale_blocks_analysis.bitcoin_binary import canonical_output_token
from stale_blocks_analysis.coinbase_output_claims import (
    CHILD_DECODED_ACQUISITION_CHAINS,
    FILTERED_ACQUISITION_CHAINS,
    address_to_script_pubkey,
    amount_to_sats,
    parse_coinbase_output_claims,
    render_coinbase_outputs_column,
)
from stale_blocks_analysis.config import DATA_DIR

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
OP_RETURN_LABEL = "OP_RETURN"
# Acquisitions that decoded the parent coinbase through the child node's RPC
# and kept only outputs with a decoded address, so the surviving entries are an
# ordered *filtered* projection whose ordinals are not transaction positions.
# Marked "~" per the coinbase_output_claims contract, which owns both sets.
# Terracoin, Bitcoin Vault, and Syscoin retained a placeholder for nulldata,
# so their positions stay exact.
FILTERED_ACQUISITION = FILTERED_ACQUISITION_CHAINS
# Acquisitions whose committed payouts reached us as the child node's decoded
# address rather than a script we hold. Such a decode renders P2PKH and P2PK
# to the same address, so only the recipient hash is established and the
# payout must stay a recipient-only claim even in Bitcoin's version-0 form
# (Terracoin's committed cells predate the hex-reading backfill and carry the
# decode-era addresses). Bitcoin Vault is absent: its extraction binary-parses
# raw block hex, so its addresses render scripts it holds.
CHILD_DECODED_ACQUISITION = CHILD_DECODED_ACQUISITION_CHAINS


def split_entries(cell: str) -> list[str]:
    """Split a cell on either historical separator, keeping non-trailing gaps.

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


def canonical_payout(payout: str, *, child_decoded: bool = False) -> str:
    """Map one legacy payout token to the canonical rendering.

    ``child_decoded`` marks a source whose addresses came from the child
    node's decode, where a P2PKH-family address establishes only the recipient
    hash and cannot be promoted to an exact script.
    """
    if (
        payout == ""
        or payout == OP_RETURN_LABEL
        or payout.endswith("*")
        or (payout.startswith("pkh(") and payout.endswith(")"))
    ):
        # Already canonical and not an address: a zero-length script, the
        # legacy nulldata label, a script prefix, or a recipient-only claim.
        # The renderer emits the prefix and empty forms, so a rewrite over
        # freshly published data must round-trip them rather than abort.
        return payout
    if payout:
        try:
            return canonical_output_token(bytes.fromhex(payout))
        except ValueError:
            pass
    script = address_to_script_pubkey(payout)
    if script is None:
        raise ValueError(f"unrecognised payout token: {payout}")
    if child_decoded and script.startswith(b"\x76\xa9\x14"):
        # The child node renders P2PKH and P2PK to the same address, so only
        # the recipient hash is established; an address would assert P2PKH.
        return f"pkh({script[3:23].hex()})"
    return canonical_output_token(script)


# Acquisitions that recorded a bare OP_RETURN label instead of the nulldata
# script, losing the payload before commit. Any other producer emitting the
# label is a regression that discards witness commitments, so the exception is
# scoped to these datasets rather than allowed everywhere.
LEGACY_OP_RETURN_LABEL = {"terracoin", "bitcoin-vault", "syscoin"}


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


def _cell_is_address_decoded(cell: str) -> bool:
    """True when this cell's payouts reached us as decoded addresses.

    A cell holding raw scripts came from bytes we hold, so its payouts are
    exact whatever the chain's usual acquisition was. An already-canonical
    cell states the answer itself: the recipient-only ``pkh(...)`` form is
    what an address decode produces.
    """
    entries = split_entries(cell)
    if not entries:
        return False
    payouts = [split_value(entry.lstrip("~"))[0] for entry in entries]
    if all(is_canonical_entry(entry, allow_op_return_label=True) for entry in entries):
        return any(payout.startswith("pkh(") for payout in payouts)
    for payout in payouts:
        if payout in ("", OP_RETURN_LABEL) or payout.startswith("pkh("):
            continue
        try:
            bytes.fromhex(payout)
        except ValueError:
            continue
        return False  # a raw script: the bytes are ours, not a node's decode
    return True


def is_filtered_cell(path: Path, cell: str) -> bool:
    """True when this cell came from an address-filtered acquisition.

    Only chains whose acquisition decoded through the child node's RPC and
    dropped the outputs it could not name can be filtered, and within those a
    cell qualifies only when its payouts really did arrive as addresses. A
    cell that still holds raw scripts is a complete vector whose ordinals are
    real transaction positions, so marking it would wrongly licence
    subsequence alignment during evidence merging.
    """
    if not any(chain in path.name for chain in FILTERED_ACQUISITION):
        return False
    if all(
        is_canonical_entry(entry, allow_op_return_label=True)
        for entry in split_entries(cell)
    ):
        entries = split_entries(cell)
        return bool(entries) and entries[0].startswith("~")
    return _cell_is_address_decoded(cell)


def is_child_decoded_cell(path: Path, cell: str) -> bool:
    """True when this cell's addresses came from the child node's decode."""
    if not any(chain in path.name for chain in CHILD_DECODED_ACQUISITION):
        return False
    return _cell_is_address_decoded(cell)


def cell_problems(path: Path, cell: str) -> list[str]:
    """Every way one committed cell can violate the contract.

    Shared by ``--check`` and the committed-data test so both enforce the
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
    # The marker decides position_exact downstream, so a cell must be wholly
    # marked or wholly unmarked, and only a filtered acquisition may carry it.
    if any(marked) and not all(marked):
        problems.append(f"{path.name}: cell mixes ~ and unmarked entries")
    if any(marked) and not any(chain in path.name for chain in FILTERED_ACQUISITION):
        problems.append(f"{path.name}: ~ marker outside a filtered source")
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


def rewrite_cell(
    cell: str, *, filtered: bool = False, child_decoded: bool = False
) -> str:
    """Rewrite one legacy cell into the canonical rendering."""
    rebuilt = []
    prefix = "~" if filtered else ""
    for entry in split_entries(cell):
        if not entry.strip():
            rebuilt.append("")
            continue
        payout, value = split_value(entry)
        token = canonical_payout(payout.lstrip("~"), child_decoded=child_decoded)
        rendered = token if value is None else f"{token}:{amount_to_sats(value)}"
        rebuilt.append(prefix + rendered)
    return ";".join(rebuilt)


# Artifacts the ancestry publisher owns: the generic rewriter checks them but
# must never write them, or it would bypass the ancestry, consensus, witness,
# and transactional installation gates of `just reconcile-stale-ancestry`.
CHECK_ONLY = frozenset({"stale_descendants.csv"})


def target_files() -> list[Path]:
    files = sorted((DATA_DIR / "validated-stales").glob("*_validated_stales.csv"))
    files.append(DATA_DIR / "stale_descendants.csv")
    return [path for path in files if path.exists()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed columns are canonical; write nothing",
    )
    args = parser.parse_args()

    problems: list[str] = []
    planned: list[tuple[Path, list[str], list[dict[str, str]], int]] = []

    for path in target_files():
        with path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            columns = reader.fieldnames or []
            rows = list(reader)
        if "coinbase_outputs" not in columns:
            continue
        changed = 0
        check_only = path.name in CHECK_ONLY
        for row in rows:
            cell = row.get("coinbase_outputs") or ""
            if not cell:
                continue
            if args.check or check_only:
                # A non-canonical cell in a publisher-owned artifact is
                # reported, never rewritten here: regenerate it through
                # `just reconcile-stale-ancestry` instead.
                problems.extend(cell_problems(path, cell))
                continue
            try:
                rebuilt = rewrite_cell(
                    cell,
                    filtered=is_filtered_cell(path, cell),
                    child_decoded=is_child_decoded_cell(path, cell),
                )
            except (ValueError, ArithmeticError) as exc:
                problems.append(f"{path.name}: {exc}")
                continue
            if rebuilt != cell:
                row["coinbase_outputs"] = rebuilt
                changed += 1
        if not args.check and not check_only:
            planned.append((path, columns, rows, changed))

    # Fail closed: a partially rewritten data tree is worse than none.
    if problems:
        for problem in problems[:20]:
            print(f"problem: {problem}", file=sys.stderr)
        raise SystemExit(f"{len(problems)} problem(s); nothing written")

    if args.check:
        print("all committed coinbase_outputs are canonical")
        return

    total = 0
    for path, columns, rows, changed in planned:
        if not changed:
            continue
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        print(f"  {path.relative_to(PROJECT_ROOT)}: rewrote {changed} rows")
        total += changed
    print(f"normalized {total} rows")


if __name__ == "__main__":
    main()
