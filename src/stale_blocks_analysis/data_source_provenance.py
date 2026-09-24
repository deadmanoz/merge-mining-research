"""Small provenance helpers shared by publication consumers."""

from __future__ import annotations

import subprocess
from pathlib import Path


def read_pinned_ref(manifest_path: Path, key: str) -> str | None:
    """Return a source's declared ref, or None when unavailable/ambiguous."""
    try:
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    refs = [
        fields[2]
        for line in lines
        if line and not line.startswith("#")
        if len(fields := line.split("\t")) == 4 and fields[0] == key
    ]
    return refs[0] if len(refs) == 1 and refs[0] else None


def clone_state(path: Path) -> dict | None:
    """Return commit/dirty metadata; the entire state is None if Git fails.

    Unknown state must never imply a clean checkout. A .git file also supports
    linked worktrees; a directory nested inside another repo is not a clone.
    """
    if not (path / ".git").exists():
        return None
    try:
        commit = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return {"commit": commit, "dirty": bool(status)} if commit else None
