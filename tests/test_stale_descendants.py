from __future__ import annotations

import csv
import shutil
from pathlib import Path

import pytest

from stale_blocks_analysis import stale_descendants
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


def test_parent_verdict_rejects_height_depth_disagreement(tmp_path: Path) -> None:
    parents, _observations = _copy_module(tmp_path)

    def mutate(rows: list[dict[str, str]]) -> None:
        row = rows[0]
        row["root_stale_height"] = str(int(row["root_stale_height"]) - 1)

    _rewrite(parents, mutate)

    with pytest.raises(ValueError, match="stale_fork_depth does not match"):
        load_stale_descendant_parents(parents)


def test_parent_verdict_rejects_relation_depth_disagreement(tmp_path: Path) -> None:
    parents, _observations = _copy_module(tmp_path)
    _rewrite(
        parents,
        lambda rows: rows[0].__setitem__("ancestry_relation", "stale_descendant"),
    )

    with pytest.raises(ValueError, match="ancestry_relation does not match"):
        load_stale_descendant_parents(parents)


def test_parent_verdict_rejects_path_length_disagreement(tmp_path: Path) -> None:
    parents, _observations = _copy_module(tmp_path)

    def mutate(rows: list[dict[str, str]]) -> None:
        row = rows[0]
        row["path_hashes"] = f"{row['path_hashes']}>{row['root_stale_hash']}"

    _rewrite(parents, mutate)

    with pytest.raises(ValueError, match="path_hashes length does not match"):
        load_stale_descendant_parents(parents)


@pytest.mark.parametrize("endpoint", ["candidate", "root"])
def test_parent_verdict_rejects_path_endpoint_disagreement(
    tmp_path: Path, endpoint: str
) -> None:
    parents, _observations = _copy_module(tmp_path)

    def mutate(rows: list[dict[str, str]]) -> None:
        row = rows[0]
        path_hashes = row["path_hashes"].split(">")
        index = 0 if endpoint == "candidate" else -1
        path_hashes[index] = "ff" * 32
        row["path_hashes"] = ">".join(path_hashes)

    _rewrite(parents, mutate)

    with pytest.raises(ValueError, match="path_hashes endpoints do not match"):
        load_stale_descendant_parents(parents)


def test_parent_verdict_rejects_path_predecessor_disagreement(
    tmp_path: Path,
) -> None:
    parents, _observations = _copy_module(tmp_path)

    def mutate(rows: list[dict[str, str]]) -> None:
        row = rows[0]
        wrong_root = "ff" * 32
        row["root_stale_hash"] = wrong_root
        path_hashes = row["path_hashes"].split(">")
        path_hashes[-1] = wrong_root
        row["path_hashes"] = ">".join(path_hashes)

    _rewrite(parents, mutate)

    with pytest.raises(ValueError, match="path_hashes predecessor link disagrees"):
        load_stale_descendant_parents(parents)


def test_parent_verdict_requires_every_intermediate_path_node(
    tmp_path: Path,
) -> None:
    parents, _observations = _copy_module(tmp_path)

    def mutate(rows: list[dict[str, str]]) -> None:
        descendant = next(row for row in rows if row["stale_fork_depth"] == "2")
        intermediate_hash = descendant["path_hashes"].split(">")[1]
        intermediate_height = str(int(descendant["btc_height"]) - 1)
        rows[:] = [
            row
            for row in rows
            if not (
                row["btc_header_hash"] == intermediate_hash
                and row["btc_height"] == intermediate_height
            )
        ]

    _rewrite(parents, mutate)

    with pytest.raises(ValueError, match="has no authenticated parent verdict"):
        load_stale_descendant_parents(parents)


def test_parent_verdict_path_must_end_at_a_trusted_stale_root(
    tmp_path: Path,
) -> None:
    parents, _observations = _copy_module(tmp_path)

    def mutate(rows: list[dict[str, str]]) -> None:
        descendant = next(row for row in rows if row["stale_fork_depth"] == "2")
        intermediate_hash = descendant["path_hashes"].split(">")[1]
        descendant["root_stale_hash"] = intermediate_hash
        descendant["root_stale_height"] = str(int(descendant["btc_height"]) - 1)
        descendant["stale_fork_depth"] = "1"
        descendant["ancestry_relation"] = "direct_stale_child"
        descendant["path_hashes"] = (
            f"{descendant['btc_header_hash']}>{intermediate_hash}"
        )

    _rewrite(parents, mutate)

    with pytest.raises(ValueError, match="instead of a trusted stale root"):
        load_stale_descendant_parents(parents)


def test_parent_verdict_terminal_must_exist_in_direct_stale_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parents, _observations = _copy_module(tmp_path)
    with parents.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    trusted_roots = {
        (int(row["root_stale_height"]), row["root_stale_hash"]) for row in rows
    }
    rejected_root = (
        int(rows[0]["root_stale_height"]),
        rows[0]["root_stale_hash"],
    )
    trusted_roots.remove(rejected_root)
    monkeypatch.setattr(
        stale_descendants,
        "_load_trusted_stale_root_keys",
        lambda **_kwargs: trusted_roots,
    )

    with pytest.raises(ValueError, match="canonical accepted direct-stale inputs"):
        load_stale_descendant_parents(parents)


def test_trusted_root_inputs_use_exact_accepted_rows_and_error_exclusion(
    tmp_path: Path,
) -> None:
    validated_dir = tmp_path / "validated-stales"
    validated_dir.mkdir()
    validated_path = validated_dir / "namecoin_validated_stales.csv"
    with validated_path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "btc_height",
                "btc_header_hash",
                "classification",
                "validation_status",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(
            (
                {
                    "btc_height": "1",
                    "btc_header_hash": "11" * 32,
                    "classification": "stale",
                    "validation_status": "VALID",
                },
                {
                    "btc_height": "2",
                    "btc_header_hash": "22" * 32,
                    "classification": "stale",
                    "validation_status": "VALID_BOGUS",
                },
                {
                    "btc_height": "4",
                    "btc_header_hash": "44" * 32,
                    "classification": "stale",
                    "validation_status": "VALID",
                },
            )
        )
    with (validated_dir / "stray_validated_stales.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "btc_height",
                "btc_header_hash",
                "classification",
                "validation_status",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(
            {
                "btc_height": "5",
                "btc_header_hash": "55" * 32,
                "classification": "stale",
                "validation_status": "VALID",
            }
        )
    upstream_path = tmp_path / "stale-blocks.csv"
    with upstream_path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("height", "hash"),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(
            (
                {"height": "3", "hash": "33" * 32},
                {"height": "4", "hash": "44" * 32},
            )
        )
    error_blocks_path = tmp_path / "error_blocks.csv"
    with error_blocks_path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("height", "hash", "classification"),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(
            {
                "height": "4",
                "hash": "44" * 32,
                "classification": "error_block",
            }
        )

    assert stale_descendants._load_trusted_stale_root_keys(
        validated_dir=validated_dir,
        upstream_path=upstream_path,
        error_blocks_path=error_blocks_path,
    ) == {(1, "11" * 32), (3, "33" * 32)}


def test_trusted_root_inputs_reject_legacy_validated_schema(tmp_path: Path) -> None:
    validated_dir = tmp_path / "validated-stales"
    validated_dir.mkdir()
    (validated_dir / "namecoin_validated_stales.csv").write_text(
        "btc_stale_height,btc_hash,classification,validation_status\n"
        f"1,{'11' * 32},stale,VALID\n"
    )
    upstream_path = tmp_path / "stale-blocks.csv"
    upstream_path.write_text(f"height,hash\n2,{'22' * 32}\n")
    error_blocks_path = tmp_path / "error_blocks.csv"
    error_blocks_path.write_text(
        f"height,hash,classification\n3,{'33' * 32},error_block\n"
    )

    with pytest.raises(ValueError, match="btc_header_hash"):
        stale_descendants._load_trusted_stale_root_keys(
            validated_dir=validated_dir,
            upstream_path=upstream_path,
            error_blocks_path=error_blocks_path,
        )


def test_parent_loader_uses_the_selected_data_directory_trust_inputs(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    parents = data_dir / PARENTS.name
    shutil.copy2(PARENTS, parents)
    with parents.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    roots = sorted({(row["root_stale_height"], row["root_stale_hash"]) for row in rows})
    validated_dir = data_dir / "validated-stales"
    validated_dir.mkdir()
    with (validated_dir / "namecoin_validated_stales.csv").open(
        "w", newline=""
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "btc_height",
                "btc_header_hash",
                "classification",
                "validation_status",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(
            {
                "btc_height": height,
                "btc_header_hash": block_hash,
                "classification": "stale",
                "validation_status": "VALID",
            }
            for height, block_hash in roots
        )
    upstream_path = data_dir / "stale-blocks" / "stale-blocks.csv"
    upstream_path.parent.mkdir()
    upstream_path.write_text("height,hash\n")
    rejected_height, rejected_hash = roots[0]
    error_blocks_path = data_dir / "error-blocks" / "error_blocks.csv"
    error_blocks_path.parent.mkdir()
    error_blocks_path.write_text(
        f"height,hash,classification\n{rejected_height},{rejected_hash},error_block\n"
    )

    with pytest.raises(ValueError, match="canonical accepted direct-stale inputs"):
        load_stale_descendant_parents(parents, data_dir=data_dir)


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


def test_observation_ledger_rejects_one_child_event_for_multiple_parents(
    tmp_path: Path,
) -> None:
    parents, observations = _copy_module(tmp_path)

    def mutate(rows: list[dict[str, str]]) -> None:
        first = rows[0]
        second = next(
            row
            for row in rows[1:]
            if row["btc_header_hash"] != first["btc_header_hash"]
        )
        for field in (
            "chain",
            "child_height",
            "child_block_hash",
            "child_block_hash_order",
            "child_header_hex",
            "child_block_time",
            "child_nbits",
        ):
            second[field] = first[field]

    _rewrite(observations, mutate)

    with pytest.raises(ValueError, match="assigned to multiple Bitcoin parents"):
        load_stale_descendant_observations(observations, parents_path=parents)


def test_display_order_child_hash_is_normalized_to_internal_identity(
    tmp_path: Path,
) -> None:
    parents, observations = _copy_module(tmp_path)
    expected: dict[str, str | int] = {}

    def mutate(rows: list[dict[str, str]]) -> None:
        row = next(row for row in rows if row["child_header_hex"])
        internal_hash = row["child_block_hash"]
        row["child_block_hash"] = bytes.fromhex(internal_hash)[::-1].hex()
        row["child_block_hash_order"] = "display"
        expected.update(
            {
                "chain": row["chain"],
                "child_height": int(row["child_height"]),
                "child_hash": internal_hash,
                "parent_hash": row["btc_header_hash"],
            }
        )

    _rewrite(observations, mutate)

    loaded = load_stale_descendant_observations(observations, parents_path=parents)
    observation = next(
        item
        for item in loaded
        if item.chain == expected["chain"]
        and item.child_height == expected["child_height"]
    )

    assert observation.child_hash == expected["child_hash"]
    assert observation.row["child_block_hash"] == expected["child_hash"]
    assert observation.logical_identity == (
        expected["chain"],
        expected["child_height"],
        expected["child_hash"],
        expected["parent_hash"],
    )


def test_display_order_child_hash_must_match_authenticated_header(
    tmp_path: Path,
) -> None:
    parents, observations = _copy_module(tmp_path)

    def mutate(rows: list[dict[str, str]]) -> None:
        row = next(row for row in rows if row["child_header_hex"])
        row["child_block_hash_order"] = "display"

    _rewrite(observations, mutate)

    with pytest.raises(ValueError, match="child_header_hex does not match"):
        load_stale_descendant_observations(observations, parents_path=parents)


def test_rsk_display_order_child_hash_stays_forward(tmp_path: Path) -> None:
    parents, observations = _copy_module(tmp_path)
    expected: dict[str, str | int] = {}

    def mutate(rows: list[dict[str, str]]) -> None:
        row = next(row for row in rows if row["chain"] == "rsk")
        row["child_block_hash_order"] = "display"
        expected.update(
            {
                "child_height": int(row["child_height"]),
                "child_hash": row["child_block_hash"],
                "parent_hash": row["btc_header_hash"],
            }
        )

    _rewrite(observations, mutate)

    loaded = load_stale_descendant_observations(observations, parents_path=parents)
    observation = next(
        item
        for item in loaded
        if item.chain == "rsk" and item.child_height == expected["child_height"]
    )

    assert observation.child_hash == expected["child_hash"]
    assert observation.row["child_block_hash"] == expected["child_hash"]
    assert observation.logical_identity == (
        "rsk",
        expected["child_height"],
        expected["child_hash"],
        expected["parent_hash"],
    )


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
