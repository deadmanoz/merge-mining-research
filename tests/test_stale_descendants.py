from __future__ import annotations

import csv
import shutil
from pathlib import Path

import pytest

from stale_blocks_analysis.stale_descendants import (
    load_stale_descendant_observations,
    load_stale_descendant_parents,
)

REPO = Path(__file__).resolve().parents[1]
PARENTS = REPO / "data/stale_descendants.csv"
OBSERVATIONS = REPO / "data/stale_descendant_observations.csv"


def _rewrite(path: Path, mutate) -> None:
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or ())
        rows = list(reader)
    mutate(rows)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _copy_module(tmp_path: Path) -> tuple[Path, Path]:
    parents = tmp_path / PARENTS.name
    observations = tmp_path / OBSERVATIONS.name
    shutil.copy2(PARENTS, parents)
    shutil.copy2(OBSERVATIONS, observations)
    return parents, observations


@pytest.mark.dataset
def test_committed_stale_descendant_module_is_exact_and_correction_free() -> None:
    parents = load_stale_descendant_parents()
    observations = load_stale_descendant_observations()

    assert len(parents) == 21
    assert len(observations) == 32
    removed_overlay = "stale_descendant" + "_corrections.csv"
    assert not (REPO / "data" / removed_overlay).exists()
    with PARENTS.open(newline="") as handle:
        fields = csv.DictReader(handle).fieldnames or []
    assert "source_rows" not in fields
    assert "unknown_rows" not in fields


@pytest.mark.parametrize("role", ["candidate", "root"])
def test_active_mainchain_identity_contradiction_is_rejected(
    tmp_path: Path, role: str
) -> None:
    parents, _observations = _copy_module(tmp_path)

    def mutate(rows: list[dict[str, str]]) -> None:
        row = rows[0]
        if role == "candidate":
            row["active_mainchain_hash_at_height"] = row["btc_header_hash"]
        else:
            row["root_active_mainchain_hash_at_height"] = row["root_stale_hash"]

    _rewrite(parents, mutate)
    with pytest.raises(ValueError, match="active-mainchain comparison contradicts"):
        load_stale_descendant_parents(parents)


def test_non_core_active_mainchain_provenance_is_rejected(tmp_path: Path) -> None:
    parents, _observations = _copy_module(tmp_path)
    _rewrite(
        parents,
        lambda rows: rows[0].__setitem__(
            "active_mainchain_verification_source", "migrated-boolean"
        ),
    )
    with pytest.raises(ValueError, match="not authenticated Bitcoin Core RPC"):
        load_stale_descendant_parents(parents)


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("btc_prev_hash", "ff" * 32),
        ("btc_time", "1"),
        ("btc_bits", "1d00ffff"),
    ],
)
def test_parent_verdict_rejects_serialized_header_field_disagreement(
    tmp_path: Path,
    field: str,
    wrong_value: str,
) -> None:
    parents, _observations = _copy_module(tmp_path)
    _rewrite(
        parents,
        lambda rows: rows[0].__setitem__(field, wrong_value),
    )

    with pytest.raises(
        ValueError,
        match=rf"{field} disagrees with serialized Bitcoin parent header",
    ):
        load_stale_descendant_parents(parents)


def test_parent_verdict_derives_nonce_from_serialized_header(tmp_path: Path) -> None:
    parents_path, _observations = _copy_module(tmp_path)

    parents = load_stale_descendant_parents(parents_path)

    assert all(parent.row["btc_nonce"] for parent in parents.values())


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda rows: rows[0].__setitem__("parent_row_number", "999"),
            "parent_row_number",
        ),
        (
            lambda rows: rows.append(dict(rows[0])),
            "duplicate logical observation",
        ),
        (
            lambda rows: rows[1].update(
                {
                    "source_path": rows[0]["source_path"],
                    "source_row_number": rows[0]["source_row_number"],
                    "source_sha256": rows[0]["source_sha256"],
                    "chain": rows[0]["chain"],
                }
            ),
            "duplicate source coordinate",
        ),
    ],
)
def test_observation_ledger_rejects_identity_regressions(
    tmp_path: Path, mutation, message: str
) -> None:
    parents, observations = _copy_module(tmp_path)
    _rewrite(observations, mutation)
    with pytest.raises(ValueError, match=message):
        load_stale_descendant_observations(observations, parents_path=parents)


def test_parent_observation_count_must_match_ledger(tmp_path: Path) -> None:
    parents, observations = _copy_module(tmp_path)
    _rewrite(
        parents,
        lambda rows: rows[0].__setitem__(
            "source_observation_count",
            str(int(rows[0]["source_observation_count"]) + 1),
        ),
    )
    with pytest.raises(ValueError, match="does not match source_observation_count"):
        load_stale_descendant_observations(observations, parents_path=parents)


def test_parent_observed_chains_must_match_ledger(tmp_path: Path) -> None:
    parents, observations = _copy_module(tmp_path)
    _rewrite(
        parents,
        lambda rows: rows[0].__setitem__("observed_chains", "namecoin|xaya"),
    )
    with pytest.raises(ValueError, match="do not match observed_chains"):
        load_stale_descendant_observations(observations, parents_path=parents)


def test_every_parent_requires_a_witness(tmp_path: Path) -> None:
    parents, observations = _copy_module(tmp_path)
    with parents.open(newline="") as handle:
        parent_hash = next(csv.DictReader(handle))["btc_header_hash"]
    _rewrite(
        observations,
        lambda rows: rows.__setitem__(
            slice(None), [row for row in rows if row["btc_header_hash"] != parent_hash]
        ),
    )
    with pytest.raises(ValueError, match="accepted parents have no observations"):
        load_stale_descendant_observations(observations, parents_path=parents)
