"""Tests for the pinned upstream data-source shell workflow."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PIN_SCRIPT = PROJECT_ROOT / "scripts" / "manage-data-source-pins.sh"


def run(*args: str, cwd: Path, env: dict[str, str] | None = None, check: bool = True):
    return subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=check,
        text=True,
        capture_output=True,
    )


def commit_and_push(seed: Path, message: str, content: str) -> str:
    (seed / "stale-blocks.csv").write_text(content)
    run("git", "add", "stale-blocks.csv", cwd=seed)
    run(
        "git",
        "-c",
        "user.name=Test User",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-m",
        message,
        cwd=seed,
    )
    run("git", "push", "origin", "master", cwd=seed)
    return run("git", "rev-parse", "HEAD", cwd=seed).stdout.strip()


def make_fixture(tmp_path: Path) -> tuple[dict[str, str], Path, Path, str]:
    remote = tmp_path / "remote.git"
    seed = tmp_path / "seed"
    project = tmp_path / "project"
    clone = project / "data" / "stale-blocks"
    manifest = project / "data-sources.tsv"

    run("git", "init", "--bare", str(remote), cwd=tmp_path)
    run("git", "init", "-b", "master", str(seed), cwd=tmp_path)
    run("git", "remote", "add", "origin", str(remote), cwd=seed)
    first = commit_and_push(seed, "initial", "height,hash,header\n")
    run("git", "symbolic-ref", "HEAD", "refs/heads/master", cwd=remote)
    clone.parent.mkdir(parents=True)
    run("git", "clone", str(remote), str(clone), cwd=tmp_path)
    run("git", "checkout", "--detach", first, cwd=clone)

    manifest.write_text(
        f"# test manifest\nstale-blocks\t{remote}\t{first}\tdata/stale-blocks\n"
    )
    env = {
        **os.environ,
        "DATA_SOURCES_ROOT": str(project),
        "DATA_SOURCES_MANIFEST": str(manifest),
    }
    return env, seed, manifest, first


def test_check_reports_stale_pin_and_update_records_exact_commit(tmp_path: Path):
    env, seed, manifest, first = make_fixture(tmp_path)

    current = run("bash", str(PIN_SCRIPT), "check", cwd=PROJECT_ROOT, env=env)
    assert f"up to date at {first}" in current.stdout

    latest = commit_and_push(seed, "new upstream row", "height,hash,header\n1,a,b\n")
    stale = run(
        "bash", str(PIN_SCRIPT), "check", cwd=PROJECT_ROOT, env=env, check=False
    )
    assert stale.returncode == 1
    assert f"pinned {first}" in stale.stdout
    assert f"latest {latest}" in stale.stdout

    updated = run(
        "bash", str(PIN_SCRIPT), "update", "stale-blocks", cwd=PROJECT_ROOT, env=env
    )
    assert f"updated pin {first} -> {latest}" in updated.stdout
    assert f"\t{latest}\tdata/stale-blocks" in manifest.read_text()

    clone = Path(env["DATA_SOURCES_ROOT"]) / "data" / "stale-blocks"
    assert run("git", "rev-parse", "HEAD", cwd=clone).stdout.strip() == latest
    assert (
        run(
            "git", "symbolic-ref", "--quiet", "--short", "HEAD", cwd=clone, check=False
        ).returncode
        == 1
    )


def test_update_refuses_dirty_clone_without_changing_manifest(tmp_path: Path):
    env, seed, manifest, _first = make_fixture(tmp_path)
    commit_and_push(seed, "new upstream row", "height,hash,header\n1,a,b\n")
    before = manifest.read_text()
    clone = Path(env["DATA_SOURCES_ROOT"]) / "data" / "stale-blocks"
    (clone / "local-note").write_text("keep me")

    result = run(
        "bash",
        str(PIN_SCRIPT),
        "update",
        "stale-blocks",
        cwd=PROJECT_ROOT,
        env=env,
        check=False,
    )
    assert result.returncode == 2
    assert "clone has local changes" in result.stderr
    assert manifest.read_text() == before


def test_check_fails_closed_when_origin_cannot_be_refreshed(tmp_path: Path):
    env, _seed, _manifest, _first = make_fixture(tmp_path)
    clone = Path(env["DATA_SOURCES_ROOT"]) / "data" / "stale-blocks"
    run(
        "git",
        "remote",
        "set-url",
        "origin",
        str(tmp_path / "missing-remote.git"),
        cwd=clone,
    )

    result = run(
        "bash", str(PIN_SCRIPT), "check", cwd=PROJECT_ROOT, env=env, check=False
    )
    assert result.returncode == 2
    assert "freshness is unknown" in result.stderr
