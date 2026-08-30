#!/usr/bin/env python3
"""Build data/new_stale_blocks_for_upstream.csv from committed inputs."""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

from stale_blocks_analysis.config import ACCEPTED_STALE_VALIDATION_STATUSES
from stale_blocks_analysis.error_blocks import (
    load_consensus_invalid_stale_keys,
    load_stale_exclusion_keys,
)
from stale_blocks_analysis.stale_descendants import load_stale_descendant_parents

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_OUTPUT = DATA_DIR / "new_stale_blocks_for_upstream.csv"
UPSTREAM_STALES = DATA_DIR / "stale-blocks" / "stale-blocks.csv"


def _display_path(path: Path) -> str:
    """Render *path* relative to the repo root, or the raw path if it lies outside.

    Lets ``--output`` / ``--data-dir`` point anywhere (e.g. a scratch dir for the
    sidecar reproducibility check) without ``relative_to`` raising ``ValueError``.
    """
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def valid_committed_row(row: dict[str, str]) -> bool:
    """Return True if a committed direct-stale row is eligible for the sidecar.

    Descendant parents enter through their canonical loader separately. A
    direct ``stale`` row qualifies only with one of the exact accepted
    validation statuses. Every other classification or status is excluded.
    """
    classification = row.get("classification", "")
    status = row.get("validation_status", "")
    if classification != "stale":
        return False
    return status in ACCEPTED_STALE_VALIDATION_STATUSES


def row_key_and_header(
    row: dict[str, str],
) -> tuple[tuple[int, str], str | None] | None:
    """Extract ``((height, hash), header_hex_or_None)`` from a row, tolerating
    the several per-chain column-naming conventions (``btc_height`` /
    ``btc_stale_height`` / ``height``, ``btc_header_hash`` / ``btc_hash`` /
    ``hash``, ``btc_header_hex`` / ``header``). Returns None if height or hash
    is missing.
    """
    height = (
        row.get("btc_height") or row.get("btc_stale_height") or row.get("height") or ""
    )
    block_hash = (
        row.get("btc_header_hash") or row.get("btc_hash") or row.get("hash") or ""
    )
    header = row.get("btc_header_hex") or row.get("header") or ""
    if not height or not block_hash:
        return None
    return (int(height), block_hash.strip().lower()), header or None


def load_upstream_keys(path: Path) -> set[tuple[int, str]]:
    """Load the upstream ``stale-blocks.csv``'s ``(height, hash)`` keys.

    Raises ``SystemExit`` if ``path`` does not exist.
    """
    if not path.exists():
        raise SystemExit(f"upstream stale CSV not found: {path}")
    excluded = load_consensus_invalid_stale_keys()
    with path.open(newline="") as f:
        return {
            (int(row["height"]), row["hash"].strip().lower())
            for row in csv.DictReader(f)
            if (int(row["height"]), row["hash"].strip().lower()) not in excluded
        }


def iter_committed_inputs(data_dir: Path):
    """Yield each committed direct-stale loader input under ``data_dir``.

    Descendant parents are loaded through ``load_stale_descendant_parents``
    instead of being treated as another permissive CSV schema.
    """
    yield from sorted(data_dir.glob("validated-stales/*_validated_stales.csv"))


def collect_candidates(
    data_dir: Path,
    *,
    upstream_path: Path | None = None,
) -> tuple[dict[tuple[int, str], str], dict[str, set[tuple[int, str]]], Counter[str]]:
    """Scan every committed input under ``data_dir`` for VALID sidecar candidates.

    Direct stales come from their committed per-chain loaders; accepted
    descendants come from the strict canonical parent loader. Rows missing a
    header are tracked per source rather than dropped silently. A key seen
    with two different headers across sources is a warning and the later value
    is discarded. Returns
    ``(candidates, missing_header, warnings)`` where ``candidates`` maps
    ``(height, hash) -> header_hex`` and ``warnings`` counts each distinct
    warning message.
    """
    candidates: dict[tuple[int, str], str] = {}
    missing_header: dict[str, set[tuple[int, str]]] = {}
    warnings: Counter[str] = Counter()
    excluded = load_stale_exclusion_keys()

    def add_candidate(key: tuple[int, str], header: str | None, source: str) -> None:
        if key in excluded:
            return
        if header is None:
            missing_header.setdefault(source, set()).add(key)
            return
        previous = candidates.get(key)
        if previous and previous != header:
            warnings[f"{source}: conflicting header"] += 1
            return
        candidates[key] = header

    for path in iter_committed_inputs(data_dir):
        source = _display_path(path)
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                if not valid_committed_row(row):
                    continue
                parsed = row_key_and_header(row)
                if parsed is None:
                    warnings[f"{source}: missing height/hash"] += 1
                    continue
                key, header = parsed
                add_candidate(key, header, source)

    parents_path = data_dir / "stale_descendants.csv"
    if parents_path.exists():
        source = _display_path(parents_path)
        for parent in load_stale_descendant_parents(
            parents_path,
            data_dir=data_dir,
            upstream_path=upstream_path,
        ).values():
            add_candidate(
                (parent.height, parent.block_hash),
                parent.row["btc_header_hex"],
                source,
            )
    return candidates, missing_header, warnings


def build(
    output: Path,
    data_dir: Path,
    upstream_path: Path,
) -> dict[str, int]:
    """Compute and write the upstream-new stale sidecar CSV to ``output``.

    Rows are the committed VALID candidates whose ``(height, hash)`` is absent
    from the upstream ``stale-blocks.csv``, sorted by descending height then
    hash, with columns ``height, hash, header``. A candidate missing a header
    that would otherwise qualify as upstream-new is counted as a warning
    rather than silently dropped. Returns a stats dict:
    ``{committed_valid_candidates, upstream_known, sidecar_rows, warnings}``.
    """
    upstream = load_upstream_keys(upstream_path)
    candidates, missing_header, warnings = collect_candidates(
        data_dir,
        upstream_path=upstream_path,
    )
    for source, keys in missing_header.items():
        needed = [key for key in keys if key not in upstream and key not in candidates]
        if needed:
            warnings[f"{source}: missing header for upstream-new row"] += len(needed)
    rows = [
        (height, block_hash, header)
        for (height, block_hash), header in candidates.items()
        if (height, block_hash) not in upstream
    ]
    rows.sort(key=lambda r: (-r[0], r[1]))

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["height", "hash", "header"])
        writer.writerows(rows)

    for warning, count in sorted(warnings.items()):
        print(f"warning: {warning}: {count}")
    return {
        "committed_valid_candidates": len(candidates),
        "upstream_known": len(upstream),
        "sidecar_rows": len(rows),
        "warnings": sum(warnings.values()),
    }


def main() -> None:
    """Parse CLI args, build the sidecar CSV, and print a one-line summary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--upstream", type=Path, default=UPSTREAM_STALES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    stats = build(args.output, args.data_dir, args.upstream)
    print(
        f"wrote {_display_path(args.output)}: "
        f"{stats['sidecar_rows']:,} upstream-new rows "
        f"from {stats['committed_valid_candidates']:,} committed candidates "
        f"({stats['warnings']} warnings)"
    )


if __name__ == "__main__":
    main()
