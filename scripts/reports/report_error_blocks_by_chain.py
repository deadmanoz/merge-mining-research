#!/usr/bin/env python3
"""Generate per-chain error-block observation views.

Reads the consolidated committed dataset
``data/error-blocks/error_blocks.csv`` and writes one CSV per chain under
``results/analysis/error-blocks/by-chain/``. A row appears in each chain that
witnessed it, keyed off the pipe-joined ``source_chains`` column; the
per-chain ``source_child_observations`` entry for that chain is surfaced as a
convenience column.

These are generated DIAGNOSTICS for readability, not committed loader inputs:
the consolidated dataset is the single source of truth, and the per-chain
views merely re-split it. The output directory is gitignored; regenerate with
``just error-blocks-report``. Row order follows the dataset, so regeneration
is deterministic.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stale_blocks_analysis.config import ERROR_BLOCKS_CSV, RESULTS_DIR  # noqa: E402

DEFAULT_OUTPUT_DIR = RESULTS_DIR / "analysis" / "error-blocks" / "by-chain"
CHAIN_OBSERVATION_FIELD = "chain_child_observation"
# The only filename shape this generator writes; used to recognize a directory
# that holds nothing but previously-generated views.
_GENERATED_VIEW_SUFFIX = "_error_blocks.csv"


def _is_safe_to_replace(output_dir: Path) -> bool:
    """Whether ``output_dir`` may be deleted and replaced by regeneration.

    Conservative guard against ``shutil.rmtree`` deleting arbitrary data: a
    directory may only be replaced when it is clearly a generated-views
    location — it does not exist yet, it is empty (a normal first-run state
    with no content to protect), or it holds nothing but previously-generated
    ``*_error_blocks.csv`` view files. Anything else (a worktree, an existing
    parent directory, a dir containing non-generated content) is refused. The
    default by-chain directory is held to the same standard: being the
    recognized default location does not make arbitrary local content under it
    disposable.
    """
    if not output_dir.exists():
        return True
    if not output_dir.is_dir():
        return False
    entries = list(output_dir.iterdir())
    return all(
        entry.is_file() and entry.name.endswith(_GENERATED_VIEW_SUFFIX)
        for entry in entries
    )


def _split_pipe(value: str) -> list[str]:
    return [part.strip() for part in value.split("|") if part.strip()]


def _validate_chain_name(chain: str) -> str:
    """Return ``chain`` unchanged if it is a safe output filename stem.

    The chain name comes from the dataset's ``source_chains`` column and is
    joined onto the staging directory to build each ``*_error_blocks.csv``
    view path. A value that is absolute, contains ``..``, or contains a path
    separator would escape the staging directory and write/overwrite a file
    outside it, so reject those outright (fail closed) rather than sanitize
    them into a silently different name.
    """
    if (
        not chain
        or Path(chain).is_absolute()
        or ".." in chain
        or "/" in chain
        or "\\" in chain
    ):
        raise ValueError(
            f"unsafe chain name in source_chains: {chain!r} (must be a plain "
            "filename stem: not absolute, no '..', no path separators)"
        )
    return chain


def _chain_observation(row: dict[str, str], chain: str) -> str:
    """Return this chain's ``<chain>:<child_height>`` observation entry."""
    for entry in _split_pipe(row.get("source_child_observations", "")):
        observed_chain, _, observation = entry.partition(":")
        if observed_chain.strip() == chain:
            return observation.strip()
    return ""


def build_by_chain_views(
    dataset: Path = ERROR_BLOCKS_CSV,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, int]:
    """Write one CSV per witnessing chain; return ``{chain: row_count}``."""
    with dataset.open(newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    if not fieldnames:
        raise ValueError(f"error blocks dataset has no header: {dataset}")

    out_fields = [
        *fieldnames[: fieldnames.index("source_chains")],
        CHAIN_OBSERVATION_FIELD,
        *fieldnames[fieldnames.index("source_chains") :],
    ]

    per_chain: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        for chain in _split_pipe(row.get("source_chains", "")):
            chain = _validate_chain_name(chain)
            view_row = dict(row)
            view_row[CHAIN_OBSERVATION_FIELD] = _chain_observation(row, chain)
            per_chain.setdefault(chain, []).append(view_row)

    # Stage-and-replace: write the per-chain views to a fresh temp dir, then
    # swap it into place. Regeneration only writes chains present in the
    # current dataset, so a chain that lost its last observation must not
    # leave a stale CSV behind — replacing the whole directory keeps it a
    # faithful re-split of the dataset.
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.tmp-", dir=output_dir.parent)
    )
    try:
        counts: dict[str, int] = {}
        for chain in sorted(per_chain):
            chain_rows = per_chain[chain]
            path = staging / f"{chain}_error_blocks.csv"
            with path.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=out_fields)
                writer.writeheader()
                writer.writerows(chain_rows)
            counts[chain] = len(chain_rows)
        if output_dir.exists():
            if not _is_safe_to_replace(output_dir):
                raise ValueError(
                    f"refusing to replace output directory {output_dir}: it "
                    "holds content other than previously-generated "
                    f"*{_GENERATED_VIEW_SUFFIX} view files"
                )
            shutil.rmtree(output_dir)
        staging.replace(output_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=ERROR_BLOCKS_CSV,
        help="consolidated error-blocks dataset (default: committed CSV)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="diagnostic output directory (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    counts = build_by_chain_views(args.dataset, args.output_dir)
    total = sum(counts.values())
    for chain, count in sorted(counts.items()):
        print(f"{chain}: {count}")
    print(
        f"wrote {len(counts)} per-chain views ({total} observations) to {args.output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
