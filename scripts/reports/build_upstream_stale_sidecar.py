#!/usr/bin/env python3
"""Build data/new_stale_blocks_for_upstream.csv from committed inputs."""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

from stale_blocks_analysis.error_blocks import (
    load_consensus_invalid_stale_keys,
    load_stale_exclusion_keys,
)

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
    """Return True if a committed loader-input row is eligible for the sidecar.

    A ``stale_descendant`` row qualifies only with
    ``validation_status == "VALID_STALE_DESCENDANT"``. A ``stale`` row
    qualifies with an empty status, ``"VALID"``, or any ``"VALID ..."``
    variant. Every other classification (``canonical``, ``unknown``, etc.) or
    a non-VALID status is excluded.
    """
    classification = row.get("classification", "")
    status = row.get("validation_status", "")
    if classification == "stale_descendant":
        return status == "VALID_STALE_DESCENDANT"
    if classification != "stale":
        return False
    if status and status != "VALID" and not status.startswith("VALID "):
        return False
    return True


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
    """Yield every committed loader-input CSV under ``data_dir``.

    Every ``*_validated_stales.csv`` (sorted), plus
    ``rsk_validated_stales.csv`` and ``stale_descendants.csv`` when present.
    """
    yield from sorted(data_dir.glob("validated-stales/*_validated_stales.csv"))
    for name in [
        "validated-stales/rsk_validated_stales.csv",
        "stale_descendants.csv",
    ]:
        path = data_dir / name
        if path.exists():
            yield path


def load_header_cache(paths: list[Path]) -> dict[tuple[int, str], str]:
    """Build a ``(height, hash) -> header_hex`` cache from prior sidecar-shaped CSVs.

    Used to backfill headers for committed rows that lack
    ``btc_header_hex``/``header``. The first non-empty header seen for a key
    wins; missing files are skipped.
    """
    cache: dict[tuple[int, str], str] = {}
    for path in paths:
        if not path.exists():
            continue
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                parsed = row_key_and_header(row)
                if parsed is None:
                    continue
                key, header = parsed
                if header:
                    cache.setdefault(key, header)
    return cache


def collect_candidates(
    data_dir: Path,
    header_cache: dict[tuple[int, str], str],
) -> tuple[dict[tuple[int, str], str], dict[str, set[tuple[int, str]]], Counter[str]]:
    """Scan every committed input under ``data_dir`` for VALID sidecar candidates.

    For each ``valid_committed_row``, resolves a header from the row itself
    or ``header_cache``; rows still missing a header are tracked per source in
    ``missing_header`` rather than dropped silently. A key seen with two
    different headers across sources is a warning and the later value is
    discarded (the first-seen header wins). Returns
    ``(candidates, missing_header, warnings)`` where ``candidates`` maps
    ``(height, hash) -> header_hex`` and ``warnings`` counts each distinct
    warning message.
    """
    candidates: dict[tuple[int, str], str] = {}
    missing_header: dict[str, set[tuple[int, str]]] = {}
    warnings: Counter[str] = Counter()
    excluded = load_stale_exclusion_keys()
    for path in iter_committed_inputs(data_dir):
        source = _display_path(path)
        with path.open(newline="") as f:
            for row_number, row in enumerate(csv.DictReader(f), start=2):
                if not valid_committed_row(row):
                    continue
                parsed = row_key_and_header(row)
                if parsed is None:
                    warnings[f"{source}: missing height/hash"] += 1
                    continue
                key, header = parsed
                if key in excluded:
                    continue
                if header is None:
                    header = header_cache.get(key)
                if header is None:
                    missing_header.setdefault(source, set()).add(key)
                    continue
                previous = candidates.get(key)
                if previous and previous != header:
                    warnings[f"{source}: conflicting header"] += 1
                    continue
                candidates[key] = header
    return candidates, missing_header, warnings


def build(
    output: Path,
    data_dir: Path,
    upstream_path: Path,
    header_cache_paths: list[Path],
) -> dict[str, int]:
    """Compute and write the upstream-new stale sidecar CSV to ``output``.

    Rows are the committed VALID candidates whose ``(height, hash)`` is absent
    from the upstream ``stale-blocks.csv``, sorted by descending height then
    hash, with columns ``height, hash, header``. A candidate missing a header
    that would otherwise qualify as upstream-new is counted as a warning
    rather than silently dropped. Returns a stats dict:
    ``{committed_valid_candidates, header_cache_entries, upstream_known,
    sidecar_rows, warnings}``.
    """
    upstream = load_upstream_keys(upstream_path)
    header_cache = load_header_cache(header_cache_paths)
    candidates, missing_header, warnings = collect_candidates(data_dir, header_cache)
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
        "header_cache_entries": len(header_cache),
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
    parser.add_argument(
        "--header-cache",
        type=Path,
        action="append",
        default=[],
        help=(
            "Existing height/hash/header CSV to use when compact committed "
            "inputs lack btc_header_hex. Can be passed multiple times."
        ),
    )
    args = parser.parse_args()
    header_cache_paths = args.header_cache or (
        [args.output] if args.output.exists() else []
    )
    stats = build(args.output, args.data_dir, args.upstream, header_cache_paths)
    print(
        f"wrote {_display_path(args.output)}: "
        f"{stats['sidecar_rows']:,} upstream-new rows "
        f"from {stats['committed_valid_candidates']:,} committed candidates "
        f"using {stats['header_cache_entries']:,} cached headers "
        f"({stats['warnings']} warnings)"
    )


if __name__ == "__main__":
    main()
