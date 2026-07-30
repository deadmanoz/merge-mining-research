#!/usr/bin/env python3
"""Report authenticated child-header coverage for the historical chains."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stale_blocks_analysis.auxpow_parse import (  # noqa: E402
    CHILD_HEADER_FIELDS,
    ChildHeaderValidationError,
    validate_child_header_fields,
)
from stale_blocks_analysis.config import (  # noqa: E402
    CHAIN_SPECS,
    HISTORICAL_CHILD_HEADER_CHAINS,
    STALE_DESCENDANTS_CSV,
)
from stale_blocks_analysis.stale_blocks import (  # noqa: E402
    load_stale_descendant_observation_keys,
)

REPORT_FIELDS = (
    "chain",
    "artifact_status",
    "artifact_path",
    "total_rows",
    "hydrated_rows",
    "unrecoverable_rows",
    "unrecoverable_reasons",
    "stale_descendant_observations",
    "hydrated_stale_descendant_observations",
    "unrecoverable_stale_descendant_observations",
    "stale_descendant_unrecoverable_reasons",
    "min_child_time",
    "max_child_time",
    "child_parent_delta_status",
    "child_parent_delta_coverage",
    "min_child_parent_delta",
    "max_child_parent_delta",
)

REQUIRED_EVIDENCE_FIELDS = frozenset({*CHILD_HEADER_FIELDS, "btc_header_hash"})
GIT_LFS_POINTER_PREFIX = "version https://git-lfs.github.com/spec/v1"


def load_stale_descendant_observations(path: Path) -> dict[str, frozenset[str]]:
    """Return accepted descendant parent-hash observations by target chain."""
    targets: dict[str, set[str]] = {
        chain: set() for chain in HISTORICAL_CHILD_HEADER_CHAINS
    }
    for chain, block_hash in load_stale_descendant_observation_keys(path):
        if chain in targets:
            targets[chain].add(block_hash)
    return {chain: frozenset(hashes) for chain, hashes in targets.items()}


def _artifact_path(input_dir: Path, chain: str) -> Path | None:
    """Return one unambiguous supported artifact path for ``chain``."""
    paths = [
        input_dir / f"{chain}_evidence.csv",
        input_dir / f"{chain}_monitor_evidence.csv",
    ]
    present = [path for path in paths if path.is_file()]
    if len(present) > 1:
        raise ValueError(
            f"ambiguous child-header coverage input for {chain}: "
            f"{present[0].name} and {present[1].name} are both present"
        )
    return present[0] if present else None


def _missing_reason(row: dict[str, str]) -> str:
    missing = [
        field for field in CHILD_HEADER_FIELDS if not (row.get(field) or "").strip()
    ]
    if len(missing) == len(CHILD_HEADER_FIELDS):
        return "missing_child_header_evidence"
    return "incomplete_child_header_evidence:" + ",".join(missing)


def summarize_artifact(
    chain: str,
    path: Path | None,
    stale_descendant_observations: frozenset[str] | None = None,
) -> dict[str, str]:
    """Return one deterministic coverage row, failing on contradictions."""
    stale_descendant_observations = stale_descendant_observations or frozenset()
    if path is None:
        descendant_count = len(stale_descendant_observations)
        return {
            "chain": chain,
            "artifact_status": "missing",
            "artifact_path": "",
            "total_rows": "0",
            "hydrated_rows": "0",
            "unrecoverable_rows": "0",
            "unrecoverable_reasons": json.dumps(
                {"artifact_missing": 1}, sort_keys=True, separators=(",", ":")
            ),
            "stale_descendant_observations": str(descendant_count),
            "hydrated_stale_descendant_observations": "0",
            "unrecoverable_stale_descendant_observations": str(descendant_count),
            "stale_descendant_unrecoverable_reasons": json.dumps(
                {"artifact_missing": descendant_count} if descendant_count else {},
                sort_keys=True,
                separators=(",", ":"),
            ),
            "min_child_time": "",
            "max_child_time": "",
            "child_parent_delta_status": "not_applicable",
            "child_parent_delta_coverage": "0/0",
            "min_child_parent_delta": "",
            "max_child_parent_delta": "",
        }

    total = 0
    hydrated = 0
    reasons: Counter[str] = Counter()
    child_times: list[int] = []
    deltas: list[int] = []
    matched_descendants: set[str] = set()
    hydrated_descendants: set[str] = set()
    descendant_missing_reasons: dict[str, set[str]] = {}
    with path.open(newline="") as handle:
        first_line = handle.readline()
        if first_line.rstrip("\r\n") == GIT_LFS_POINTER_PREFIX:
            raise ValueError(
                f"{path}: Git LFS evidence payload is not materialized; "
                "run git lfs pull before building coverage"
            )
        handle.seek(0)
        reader = csv.DictReader(handle)
        missing_fields = REQUIRED_EVIDENCE_FIELDS.difference(reader.fieldnames or ())
        if missing_fields:
            raise ValueError(
                f"{path}: missing required evidence columns: "
                + ", ".join(sorted(missing_fields))
            )
        for row_number, row in enumerate(reader, start=2):
            total += 1
            parent_hash = (
                (row.get("btc_header_hash") or row.get("btc_hash") or "")
                .strip()
                .lower()
            )
            is_descendant_observation = parent_hash in stale_descendant_observations
            if is_descendant_observation:
                matched_descendants.add(parent_hash)
            if not all((row.get(field) or "").strip() for field in CHILD_HEADER_FIELDS):
                reason = _missing_reason(row)
                reasons[reason] += 1
                if is_descendant_observation:
                    descendant_missing_reasons.setdefault(parent_hash, set()).add(
                        reason
                    )
                continue
            try:
                parsed = validate_child_header_fields(
                    row,
                    nbits_from_header=CHAIN_SPECS[chain].child_nbits_from_header,
                )
            except ChildHeaderValidationError as exc:
                raise ChildHeaderValidationError(f"{path}:{row_number}: {exc}") from exc
            hydrated += 1
            if is_descendant_observation:
                hydrated_descendants.add(parent_hash)
            child_time = int(parsed["child_block_time"])
            child_times.append(child_time)
            btc_time_text = (row.get("btc_time") or "").strip()
            if btc_time_text:
                try:
                    deltas.append(child_time - int(btc_time_text))
                except ValueError as exc:
                    raise ValueError(
                        f"{path}:{row_number}: btc_time must be an integer"
                    ) from exc

    unrecoverable = total - hydrated
    if hydrated == 0:
        delta_status = "not_applicable"
    elif len(deltas) != hydrated:
        delta_status = "incomplete"
    elif all(delta == 0 for delta in deltas):
        delta_status = "degenerate"
    else:
        delta_status = "non_degenerate"
    descendant_reasons: Counter[str] = Counter()
    for parent_hash in stale_descendant_observations - hydrated_descendants:
        if parent_hash not in matched_descendants:
            descendant_reasons["artifact_row_missing"] += 1
            continue
        target_reasons = descendant_missing_reasons.get(parent_hash)
        reason = (
            "|".join(sorted(target_reasons))
            if target_reasons
            else "missing_child_header_evidence"
        )
        descendant_reasons[reason] += 1
    descendant_total = len(stale_descendant_observations)
    descendant_hydrated = len(hydrated_descendants)
    return {
        "chain": chain,
        "artifact_status": "present",
        "artifact_path": path.name,
        "total_rows": str(total),
        "hydrated_rows": str(hydrated),
        "unrecoverable_rows": str(unrecoverable),
        "unrecoverable_reasons": json.dumps(
            dict(sorted(reasons.items())), separators=(",", ":")
        ),
        "stale_descendant_observations": str(descendant_total),
        "hydrated_stale_descendant_observations": str(descendant_hydrated),
        "unrecoverable_stale_descendant_observations": str(
            descendant_total - descendant_hydrated
        ),
        "stale_descendant_unrecoverable_reasons": json.dumps(
            dict(sorted(descendant_reasons.items())), separators=(",", ":")
        ),
        "min_child_time": str(min(child_times)) if child_times else "",
        "max_child_time": str(max(child_times)) if child_times else "",
        "child_parent_delta_status": delta_status,
        "child_parent_delta_coverage": f"{len(deltas)}/{hydrated}",
        "min_child_parent_delta": str(min(deltas)) if deltas else "",
        "max_child_parent_delta": str(max(deltas)) if deltas else "",
    }


def build_report(
    input_dir: Path,
    output: Path,
    stale_descendants_path: Path = STALE_DESCENDANTS_CSV,
) -> list[dict[str, str]]:
    """Validate target artifacts, then atomically replace the coverage CSV."""
    descendant_observations = load_stale_descendant_observations(stale_descendants_path)
    rows = [
        summarize_artifact(
            chain,
            _artifact_path(input_dir, chain),
            descendant_observations[chain],
        )
        for chain in HISTORICAL_CHILD_HEADER_CHAINS
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, staged_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    staged = Path(staged_name)
    try:
        with os.fdopen(fd, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=REPORT_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged, output)
        directory_fd = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        staged.unlink(missing_ok=True)
        raise
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Directory containing the staged refreshed evidence artifacts",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Explicit staged coverage CSV path",
    )
    parser.add_argument(
        "--stale-descendants",
        type=Path,
        default=STALE_DESCENDANTS_CSV,
        help=(
            "Accepted stale-descendant sidecar used to account for each "
            "source-chain observation"
        ),
    )
    args = parser.parse_args()
    rows = build_report(args.input_dir, args.output, args.stale_descendants)
    hydrated = sum(int(row["hydrated_rows"]) for row in rows)
    total = sum(int(row["total_rows"]) for row in rows)
    descendant_hydrated = sum(
        int(row["hydrated_stale_descendant_observations"]) for row in rows
    )
    descendant_total = sum(int(row["stale_descendant_observations"]) for row in rows)
    print(f"child-header coverage: {hydrated:,}/{total:,} rows hydrated")
    print(
        "stale-descendant observation coverage: "
        f"{descendant_hydrated:,}/{descendant_total:,} hydrated"
    )
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
