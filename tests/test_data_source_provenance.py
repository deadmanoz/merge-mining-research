from stale_blocks_analysis import data_source_provenance as provenance


def test_clone_state_reports_commit_and_dirty(tmp_path):
    import subprocess

    repo = tmp_path / "clone"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "f.txt").write_text("x")
    subprocess.run(["git", "add", "f.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "c"], cwd=repo, check=True)

    state = provenance.clone_state(repo)
    assert state is not None
    assert len(state["commit"]) == 40 and state["dirty"] is False

    (repo / "f.txt").write_text("y")
    assert provenance.clone_state(repo)["dirty"] is True
    assert provenance.clone_state(tmp_path / "missing") is None


def test_pin_reading_is_explicit_and_rejects_ambiguity(tmp_path):
    manifest = tmp_path / "sources.tsv"
    assert provenance.read_pinned_ref(manifest, "source") is None
    manifest.write_text("# comment\nsource\turl\tabc\tdir\nother\turl\tdef\tdir\n")
    assert provenance.read_pinned_ref(manifest, "source") == "abc"
    assert provenance.read_pinned_ref(manifest, "absent") is None
    manifest.write_text(manifest.read_text() + "source\turl\tdef\tdir\n")
    assert provenance.read_pinned_ref(manifest, "source") is None


def test_git_inspection_failure_is_unknown(tmp_path, monkeypatch):
    import subprocess
    from types import SimpleNamespace

    (tmp_path / ".git").mkdir()
    for failing_command in ("rev-parse", "status"):

        def run(args, **kwargs):
            if failing_command in args:
                raise subprocess.CalledProcessError(128, args)
            return SimpleNamespace(stdout="a" * 40)

        monkeypatch.setattr(provenance.subprocess, "run", run)
        assert provenance.clone_state(tmp_path) is None

    def unavailable(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(provenance.subprocess, "run", unavailable)
    assert provenance.clone_state(tmp_path) is None
