#!/usr/bin/env python3
"""Publish the accepted stale-descendant parent and observation interfaces."""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from stale_blocks_analysis.config import DATA_DIR, ERROR_BLOCKS_CSV
from stale_blocks_analysis.error_observations import (
    ERROR_OBSERVATION_LEDGER,
    validate_error_observation_ledger,
)
from stale_blocks_analysis.stale_descendants import (
    OBSERVATIONS_PATH,
    PARENTS_PATH,
    load_stale_descendant_observations,
    load_stale_descendant_parents,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ANCESTRY_SCRIPT = PROJECT_ROOT / "scripts/analysis/reconcile_unknown_stale_ancestry.py"
ERROR_VALIDATION_SCRIPT = PROJECT_ROOT / "scripts/analysis/validate_error_blocks.py"
ERROR_LEDGER = ERROR_BLOCKS_CSV.parent / ERROR_OBSERVATION_LEDGER

_PROTECTED_ANCESTRY_OPTIONS = frozenset(
    {
        "--allow-partial",
        "--cache-dir",
        "--check-mainchain",
        "--data-dir",
        "--epoch-reference-dir",
        "--error-candidates-csv",
        "--max-depth",
        "--parent-verdicts-csv",
        "--results-dir",
        "--max-mainchain-rpc",
        "--observations-csv",
    }
)


def _reject_protected_options(argv: list[str]) -> None:
    """Keep callers from weakening or redirecting the publication workflow."""
    for token in argv:
        option = token.split("=", 1)[0]
        if option in _PROTECTED_ANCESTRY_OPTIONS or (
            len(option) > 2
            and option.startswith("--")
            and any(
                protected.startswith(option)
                for protected in _PROTECTED_ANCESTRY_OPTIONS
            )
        ):
            raise ValueError(f"{option} is fixed by the publication workflow")


def _run(command: list[str]) -> None:
    """Run one internal stage and preserve its diagnostics on the terminal."""
    completed = subprocess.run(command, cwd=PROJECT_ROOT, check=False)
    if completed.returncode:
        # Do not echo the argv: it may contain an explicitly supplied RPC
        # password. The child process has already printed its own diagnostic.
        raise RuntimeError(f"publication stage exited {completed.returncode}")


def _csv_row_count(path: Path) -> int:
    """Count staged data rows without assuming one physical line per row."""
    with path.open(newline="") as handle:
        return sum(1 for _row in csv.DictReader(handle))


def _install_transaction(staged_by_target: dict[Path, Path]) -> None:
    """Install a validated multi-file set with adjacent rollback copies.

    POSIX has no cross-directory multi-file rename. Every replacement is first
    copied beside its target, every old target gets an adjacent recovery copy,
    and any in-process failure restores all files already replaced. An
    interrupted process deliberately leaves ``.previous-*`` files as recovery
    evidence instead of pretending the transaction completed.
    """
    pid = os.getpid()
    prepared: dict[Path, Path] = {}
    backups: dict[Path, Path] = {}
    installed: list[Path] = []
    try:
        for target, staged in staged_by_target.items():
            if not target.is_file():
                raise ValueError(f"publication target is missing: {target}")
            next_path = target.with_name(f".{target.name}.next-{pid}")
            backup = target.with_name(f".{target.name}.previous-{pid}")
            if next_path.exists() or backup.exists():
                raise ValueError(
                    f"stale transaction recovery file blocks publication: {target}"
                )
            shutil.copy2(staged, next_path)
            shutil.copy2(target, backup)
            prepared[target] = next_path
            backups[target] = backup
        for target, next_path in prepared.items():
            os.replace(next_path, target)
            installed.append(target)
    except Exception:
        for target in reversed(installed):
            backup = backups[target]
            if backup.exists():
                os.replace(backup, target)
        raise
    else:
        for backup in backups.values():
            backup.unlink(missing_ok=True)
    finally:
        for next_path in prepared.values():
            next_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    """Stage, validate, and install the two stale-descendant interfaces."""
    passthrough = list(sys.argv[1:] if argv is None else argv)
    try:
        _reject_protected_options(passthrough)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        _run([sys.executable, str(ERROR_VALIDATION_SCRIPT)])
        error_catalogue, error_observations = validate_error_observation_ledger(
            catalogue_path=ERROR_BLOCKS_CSV,
            ledger_path=ERROR_LEDGER,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(
            f"error: canonical error-module validation failed: {exc}", file=sys.stderr
        )
        return 1

    with tempfile.TemporaryDirectory(prefix="mmr-reconcile-publication-") as raw_tmp:
        staging = Path(raw_tmp)
        staged_parent = staging / PARENTS_PATH.name
        staged_descendant_ledger = staging / OBSERVATIONS_PATH.name
        staged_error_candidates = staging / "error-candidates.csv"
        staged_results = staging / "diagnostics"
        staged_cache = staging / "mainchain-cache"

        ancestry_command = [
            sys.executable,
            str(ANCESTRY_SCRIPT),
            "--check-mainchain",
            "--cache-dir",
            str(staged_cache),
            "--data-dir",
            str(DATA_DIR),
            "--results-dir",
            str(staged_results),
            "--parent-verdicts-csv",
            str(staged_parent),
            "--observations-csv",
            str(staged_descendant_ledger),
            "--error-candidates-csv",
            str(staged_error_candidates),
            *passthrough,
        ]
        try:
            _run(ancestry_command)

            parents = load_stale_descendant_parents(staged_parent)
            observations = load_stale_descendant_observations(
                staged_descendant_ledger,
                parents_path=staged_parent,
            )
            parent_count = len(parents)
            observation_count = len(observations)

            error_candidate_count = _csv_row_count(staged_error_candidates)
            if error_candidate_count:
                raise ValueError(
                    "reconciliation emitted "
                    f"{error_candidate_count} blocking consensus-invalid ancestry "
                    "diagnostic row(s); review and correct incomplete or low-work "
                    "source evidence, and admit only authenticated full-PoW "
                    "violations to the canonical error catalogue and observation "
                    "ledger before publication"
                )
            _install_transaction(
                {
                    OBSERVATIONS_PATH: staged_descendant_ledger,
                    PARENTS_PATH: staged_parent,
                }
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"error: reconciliation publication failed: {exc}", file=sys.stderr)
            return 1

    print(
        f"published {parent_count} stale-descendant parents, "
        f"{observation_count} child observations; validated the canonical "
        f"{len(error_catalogue)}-parent/{len(error_observations)}-observation "
        "error-block module"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
