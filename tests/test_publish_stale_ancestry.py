from __future__ import annotations

import csv
import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "prep" / "publish_stale_ancestry.py"
ANCESTRY_SCRIPT = REPO / "scripts" / "analysis" / "reconcile_unknown_stale_ancestry.py"


def test_transition_interface_names_are_removed() -> None:
    banned = {
        "promotion" + "_subclass",
        "--promoted" + "-csv",
        "--error-blocks" + "-csv",
        "publish_reconciled" + "_descendants",
        "reconcile-error" + "-blocks",
        "build_error" + "_blocks",
        "derived_error" + "_blocks",
        "child_identity" + "_manifest",
        "reconciled_child" + "_identities",
        "reconciled_error" + "_blocks",
        "stale_descendants" + "_error_blocks",
        "stale_descendant" + "_corrections",
        "classifier-emitted:" + "ancestry-reconciliation",
        "stale-descendant" + "-reconciliation",
        "add-error" + "-observations",
        "reclassified" + "_from_",
    }
    paths = [
        REPO / name for name in ("AGENTS.md", "CHANGELOG.md", "README.md", "justfile")
    ]
    for directory in ("docs", "scripts", "src", "tests"):
        paths.extend(
            path
            for path in (REPO / directory).rglob("*")
            if path.is_file() and path.suffix in {".md", ".py"}
        )
    paths.extend(
        [
            REPO / "data" / "error-blocks" / "error_blocks.csv",
            REPO / "data" / "error-blocks" / "error_block_observations.csv",
            REPO / "data" / "stale_descendants.csv",
            REPO / "data" / "stale_descendant_observations.csv",
        ]
    )
    offenders = {
        str(path.relative_to(REPO)): sorted(token for token in banned if token in text)
        for path in paths
        if path.exists()
        for text in [path.read_text()]
        if any(token in text for token in banned)
    }
    stale_names = [
        str(path.relative_to(REPO))
        for path in (REPO / "data").rglob("*")
        if path.is_file() and any(token in path.name for token in banned)
    ]
    assert offenders == {}
    assert stale_names == []


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

    def fail_validation(command: list[str]) -> None:
        commands.append(command)
        raise RuntimeError("invalid canonical module")

    monkeypatch.setattr(module, "_run", fail_validation)

    assert module.main(["--rpc-source-label", "test-node"]) == 1
    assert commands == [[module.sys.executable, str(module.ERROR_VALIDATION_SCRIPT)]]


@pytest.mark.parametrize("candidate_count", [0, 1])
def test_publication_installs_only_descendant_interfaces_after_zero_error_candidates(
    monkeypatch: pytest.MonkeyPatch,
    candidate_count: int,
) -> None:
    module = _load_module()
    ancestry_calls = 0
    installed: list[dict[Path, Path]] = []

    def run_stage(command: list[str]) -> None:
        nonlocal ancestry_calls
        if Path(command[1]) == module.ERROR_VALIDATION_SCRIPT:
            return
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
        module,
        "validate_error_observation_ledger",
        lambda **_kwargs: ([object()] * 39, {index: {} for index in range(86)}),
    )
    monkeypatch.setattr(
        module,
        "load_stale_descendant_parents",
        lambda _path: {index: object() for index in range(21)},
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

    assert ancestry_calls == 1
    if candidate_count:
        assert result == 1
        assert installed == []
    else:
        assert result == 0
        assert len(installed) == 1
        assert set(installed[0]) == {module.PARENTS_PATH, module.OBSERVATIONS_PATH}


def test_second_descendant_install_failure_restores_first(
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
