from __future__ import annotations

import csv
import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "prep" / "publish_stale_ancestry.py"
ANCESTRY_SCRIPT = REPO / "scripts" / "analysis" / "reconcile_unknown_stale_ancestry.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("publish_stale_ancestry_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_ancestry_module():
    spec = importlib.util.spec_from_file_location(
        "reconcile_unknown_stale_ancestry_test", ANCESTRY_SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("option", sorted(_load_module()._PROTECTED_ANCESTRY_OPTIONS))
@pytest.mark.parametrize("joined", (False, True))
def test_publication_rejects_every_fixed_ancestry_option(
    option: str, joined: bool
) -> None:
    module = _load_module()
    argv = [f"{option}=override"] if joined else [option, "override"]

    with pytest.raises(ValueError, match="fixed by the publication workflow"):
        module._reject_protected_options(argv)


@pytest.mark.parametrize("option", sorted(_load_module()._PROTECTED_ANCESTRY_OPTIONS))
def test_publication_rejects_abbreviated_fixed_ancestry_options(option: str) -> None:
    module = _load_module()

    with pytest.raises(ValueError, match="fixed by the publication workflow"):
        module._reject_protected_options([option[:-1]])


@pytest.mark.parametrize(
    "argv",
    (["--allow-p"], ["--data-d=/tmp/redirected"]),
)
def test_publication_stops_protected_abbreviations_before_any_stage(
    argv: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    commands: list[list[str]] = []
    monkeypatch.setattr(module, "_run", lambda command: commands.append(command))

    assert module.main(argv) == 2
    assert commands == []


@pytest.mark.parametrize("option", sorted(_load_module()._PROTECTED_ANCESTRY_OPTIONS))
def test_ancestry_parser_disables_protected_option_abbreviations(option: str) -> None:
    ancestry = _load_ancestry_module()
    parser = ancestry.build_parser()
    required = [
        "--parent-verdicts-csv",
        "/tmp/parents.csv",
        "--observations-csv",
        "/tmp/observations.csv",
        "--error-candidates-csv",
        "/tmp/error-candidates.csv",
    ]

    with pytest.raises(SystemExit, match="2"):
        parser.parse_args([*required, option[:-1]])


def test_invalid_canonical_error_module_stops_before_ancestry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    commands: list[list[str]] = []

    def fail_validation() -> None:
        raise RuntimeError("invalid canonical module")

    monkeypatch.setattr(
        module.error_block_validation,
        "validate_error_module",
        fail_validation,
    )
    monkeypatch.setattr(module, "_run", lambda command: commands.append(command))

    assert module.main(["--rpc-source-label", "test-node"]) == 1
    assert commands == []


@pytest.mark.parametrize("candidate_count", [0, 1])
def test_publication_installs_only_descendant_interfaces_after_zero_error_candidates(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    candidate_count: int,
) -> None:
    module = _load_module()
    ancestry_calls = 0
    installed: list[dict[Path, Path]] = []

    def run_stage(command: list[str]) -> None:
        nonlocal ancestry_calls
        ancestry_calls += 1
        candidate_path = Path(command[command.index("--error-candidates-csv") + 1])
        candidate_path.parent.mkdir(parents=True, exist_ok=True)
        with candidate_path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["classification"])
            writer.writeheader()
            if candidate_count:
                writer.writerow({"classification": "error_block"})

    monkeypatch.setattr(module, "_run", run_stage)
    monkeypatch.setattr(
        module.error_block_validation,
        "validate_error_module",
        lambda: ([object()] * 39, {index: {} for index in range(86)}),
    )
    monkeypatch.setattr(
        module,
        "load_stale_descendant_parents",
        lambda *_args, **_kwargs: {index: object() for index in range(21)},
    )
    monkeypatch.setattr(
        module,
        "load_stale_descendant_observations",
        lambda *_args, **_kwargs: tuple(range(32)),
    )
    monkeypatch.setattr(
        module,
        "_install_transaction",
        lambda staged: installed.append(staged),
    )

    result = module.main(["--rpc-source-label", "test-node"])
    captured = capsys.readouterr()
    error = captured.err

    assert ancestry_calls == 1
    if candidate_count:
        assert result == 1
        assert installed == []
        assert "blocking consensus-invalid ancestry diagnostic row" in error
        assert "admit only authenticated full-PoW violations" in error
    else:
        assert result == 0
        assert len(installed) == 1
        assert set(installed[0]) == {module.PARENTS_PATH, module.OBSERVATIONS_PATH}
        assert "39-parent/86-observation error-block module" in captured.out


def test_successful_rollback_cleans_backups_and_allows_next_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    first = tmp_path / "stale_descendants.csv"
    second = tmp_path / "stale_descendant_observations.csv"
    staged_first = tmp_path / "staged-parents.csv"
    staged_second = tmp_path / "staged-observations.csv"
    first.write_text("old parents\n")
    second.write_text("old observations\n")
    staged_first.write_text("new parents\n")
    staged_second.write_text("new observations\n")
    real_replace = module.os.replace
    installs = 0

    def fail_second_install(source, destination):
        nonlocal installs
        if ".next-" in Path(source).name:
            installs += 1
            if installs == 2:
                raise OSError("second install failed")
        return real_replace(source, destination)

    monkeypatch.setattr(module.os, "replace", fail_second_install)

    with pytest.raises(OSError, match="second install failed"):
        module._install_transaction({first: staged_first, second: staged_second})

    assert first.read_text() == "old parents\n"
    assert second.read_text() == "old observations\n"
    assert not list(tmp_path.glob(".*.next-*"))
    assert not list(tmp_path.glob(".*.previous-*"))

    module._install_transaction({first: staged_first, second: staged_second})

    assert first.read_text() == "new parents\n"
    assert second.read_text() == "new observations\n"
    assert not list(tmp_path.glob(".*.next-*"))
    assert not list(tmp_path.glob(".*.previous-*"))


@pytest.mark.parametrize("recovery_kind", ("previous", "next"))
def test_different_pid_recovery_file_blocks_install_without_mutating_targets(
    tmp_path: Path, recovery_kind: str
) -> None:
    module = _load_module()
    first = tmp_path / "stale_descendants.csv"
    second = tmp_path / "stale_descendant_observations.csv"
    staged_first = tmp_path / "staged-parents.csv"
    staged_second = tmp_path / "staged-observations.csv"
    first.write_text("old parents\n")
    second.write_text("old observations\n")
    staged_first.write_text("new parents\n")
    staged_second.write_text("new observations\n")
    foreign_pid = module.os.getpid() + 1
    recovery_file = first.with_name(f".{first.name}.{recovery_kind}-{foreign_pid}")
    recovery_file.write_text("operator recovery evidence\n")

    with pytest.raises(
        ValueError, match="stale transaction recovery file blocks publication"
    ):
        module._install_transaction({first: staged_first, second: staged_second})

    assert first.read_text() == "old parents\n"
    assert second.read_text() == "old observations\n"
    assert staged_first.read_text() == "new parents\n"
    assert staged_second.read_text() == "new observations\n"
    assert recovery_file.read_text() == "operator recovery evidence\n"
    assert set(tmp_path.iterdir()) == {
        first,
        second,
        staged_first,
        staged_second,
        recovery_file,
    }


def test_incomplete_rollback_preserves_all_backups_and_blocks_next_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    first = tmp_path / "stale_descendants.csv"
    second = tmp_path / "stale_descendant_observations.csv"
    staged_first = tmp_path / "staged-parents.csv"
    staged_second = tmp_path / "staged-observations.csv"
    first.write_text("old parents\n")
    second.write_text("old observations\n")
    staged_first.write_text("new parents\n")
    staged_second.write_text("new observations\n")
    real_replace = module.os.replace
    replacements = 0

    def fail_second_install_and_rollback(source, destination):
        nonlocal replacements
        if ".next-" in Path(source).name:
            replacements += 1
            if replacements == 2:
                raise OSError("second install failed")
            if replacements == 3:
                raise OSError("rollback failed")
        return real_replace(source, destination)

    monkeypatch.setattr(module.os, "replace", fail_second_install_and_rollback)

    with pytest.raises(OSError, match="second install failed"):
        module._install_transaction({first: staged_first, second: staged_second})

    backups = sorted(tmp_path.glob(".*.previous-*"))
    assert len(backups) == 2
    assert {backup.read_text() for backup in backups} == {
        "old parents\n",
        "old observations\n",
    }
    assert not list(tmp_path.glob(".*.next-*"))

    with pytest.raises(
        ValueError, match="stale transaction recovery file blocks publication"
    ):
        module._install_transaction({first: staged_first, second: staged_second})

    assert sorted(tmp_path.glob(".*.previous-*")) == backups
