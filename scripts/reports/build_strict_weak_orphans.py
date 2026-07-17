#!/usr/bin/env python3
"""Build the per-chain strict/weak BTC-orphan CSVs.

Filters each committed monitor-evidence export
(``results/monitor-evidence/<chain>_monitor_evidence.csv``, written by
``scripts/reports/build_monitor_evidence.py``) down to its
``classification=unknown`` rows — exactly the rows admitted with a
``strict_btc_orphan`` or ``weak_btc_orphan`` verdict — and writes them per
chain under ``results/strict-weak-orphans/``, mirroring the per-chain
convention of the ``data/validated-stales/<chain>_validated_stales.csv`` loader inputs.

Verdicts are per header, not per observation: the same header seen by
several chains carries the strongest verdict any chain's evidence
establishes (see ``load_orphan_relevance_verdicts``), so a chain's file
lists that chain's observations of strict/weak headers. Every complete-coverage
per-chain monitor-evidence export gets a ``<chain>_strict_weak_orphans.csv``
(header-only when the chain has no admitted rows). Canonical-only partial
sources and stale-only publication inputs are excluded because a zero-row file
would falsely imply completed strict/weak coverage. A
``strict-weak-orphans-counts.csv`` summary. Row order and schema follow the
monitor-evidence export unchanged, so regeneration is deterministic.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stale_blocks_analysis.config import (  # noqa: E402
    RELEVANCE_STRICT_BTC_ORPHAN,
    RELEVANCE_WEAK_BTC_ORPHAN,
    RESULTS_DIR,
)
from stale_blocks_analysis.full_evidence import MONITOR_OUTPUT_DIR  # noqa: E402

DEFAULT_OUTPUT_DIR = RESULTS_DIR / "strict-weak-orphans"
COUNTS_FIELDS = ["chain", "strict_btc_orphan", "weak_btc_orphan", "total"]
STALE_DESCENDANTS_EXPORT = "stale-descendants_monitor_evidence.csv"
PARTIAL_CANONICAL_SCOPE = "partial_canonical_subset"
STALE_ONLY_SCOPE = "stale_only_publication"
INCOMPLETE_SCOPES = {PARTIAL_CANONICAL_SCOPE, STALE_ONLY_SCOPE}
MONITOR_COUNTS_FILE = "monitor-evidence-counts.csv"


def _artifact_scopes(monitor_evidence_dir: Path) -> dict[str, str] | None:
    """Read source-level coverage scopes from the monitor counts sidecar."""
    path = monitor_evidence_dir / MONITOR_COUNTS_FILE
    if not path.exists():
        return None
    with path.open(newline="") as f:
        return {
            row.get("chain", ""): row.get("artifact_scope", "")
            for row in csv.DictReader(f)
        }


def build_strict_weak_exports(
    monitor_evidence_dir: Path,
    output_dir: Path,
) -> dict[str, dict[str, int]]:
    """Write per-chain strict/weak CSVs; return per-chain bucket counts."""
    exports = sorted(monitor_evidence_dir.glob("*_monitor_evidence.csv"))
    exports = [p for p in exports if p.name != STALE_DESCENDANTS_EXPORT]
    if not exports:
        raise SystemExit(
            f"No <chain>_monitor_evidence.csv files under {monitor_evidence_dir}; "
            "run `just monitor-evidence` first"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, dict[str, int]] = {}
    artifact_scopes = _artifact_scopes(monitor_evidence_dir)
    for export in exports:
        chain = export.name.replace("_monitor_evidence.csv", "")
        with export.open(newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = list(reader.fieldnames or [])
            source_rows = list(reader)
        path = output_dir / f"{chain}_strict_weak_orphans.csv"
        if not source_rows and (
            artifact_scopes is None or chain not in artifact_scopes
        ):
            path.unlink(missing_ok=True)
            raise SystemExit(
                f"{export}: empty export requires {MONITOR_COUNTS_FILE} "
                "with an artifact_scope"
            )
        if (
            artifact_scopes is not None
            and artifact_scopes.get(chain) in INCOMPLETE_SCOPES
        ):
            path.unlink(missing_ok=True)
            continue
        if (
            (artifact_scopes is None or chain not in artifact_scopes)
            and source_rows
            and all(
                row.get("artifact_scope") in INCOMPLETE_SCOPES for row in source_rows
            )
        ):
            path.unlink(missing_ok=True)
            continue
        rows = [row for row in source_rows if row.get("classification") == "unknown"]
        strict = sum(
            1
            for row in rows
            if row.get("btc_stale_relevance", "").strip() == RELEVANCE_STRICT_BTC_ORPHAN
        )
        weak = sum(
            1
            for row in rows
            if row.get("btc_stale_relevance", "").strip() == RELEVANCE_WEAK_BTC_ORPHAN
        )
        if strict + weak != len(rows):
            raise SystemExit(
                f"{export}: {len(rows) - strict - weak} unknown row(s) without a "
                "strict/weak verdict — the export is inconsistent"
            )
        with path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        counts[chain] = {
            "strict_btc_orphan": strict,
            "weak_btc_orphan": weak,
            "total": len(rows),
        }

    counts_path = output_dir / "strict-weak-orphans-counts.csv"
    with counts_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COUNTS_FIELDS)
        writer.writeheader()
        for chain in sorted(counts):
            writer.writerow({"chain": chain, **counts[chain]})
    return counts


def main() -> None:
    """Build the per-chain strict/weak CSVs and print the bucket summary."""
    parser = argparse.ArgumentParser(
        description="Build per-chain strict/weak BTC-orphan CSVs"
    )
    parser.add_argument(
        "--monitor-evidence-dir",
        type=Path,
        default=MONITOR_OUTPUT_DIR,
        help="Directory holding the <chain>_monitor_evidence.csv exports",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Output directory for the per-chain CSVs",
    )
    args = parser.parse_args()
    counts = build_strict_weak_exports(args.monitor_evidence_dir, args.output_dir)
    total_strict = sum(c["strict_btc_orphan"] for c in counts.values())
    total_weak = sum(c["weak_btc_orphan"] for c in counts.values())
    nonzero = {c: v for c, v in counts.items() if v["total"]}
    print(
        f"strict/weak orphans: {total_strict} strict + {total_weak} weak "
        f"observations across {len(nonzero)} chains -> {args.output_dir}"
    )
    for chain, c in sorted(nonzero.items()):
        print(
            f"  {chain}: {c['strict_btc_orphan']} strict + {c['weak_btc_orphan']} weak"
        )


if __name__ == "__main__":
    main()
