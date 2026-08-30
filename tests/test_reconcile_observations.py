from __future__ import annotations

import argparse
import csv
from pathlib import Path

import pytest

from stale_blocks_analysis.ancestry_walk import classify_walks, path_for
from stale_blocks_analysis.reconcile_observations import (
    discover_canonical_files,
    fetch_active_hashes_by_height,
    load_observations,
)
from stale_blocks_analysis.reconcile_publication import (
    build_descendant_observation_rows,
    write_csv,
)

REPO = Path(__file__).resolve().parents[1]
ACTIVE_CANONICAL_DESCENDANTS = {
    "000000000000000000023d40bfc33b3ec76af6279145a8027ac06a9fa8aa4c10",
    "00000000000000000000092a45cdefd231baa1d0a5a570c50eebb36e6c0bf805",
    "00000000000000000000e4ea8f1ba1f5f7fca1010240828855e82f85b34f03fd",
    "00000000000000000001d03528155cad45ff1f46611d732b2c62d6cd094e62c4",
}


def _write_inventory(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _load(
    data_dir: Path,
    *,
    chain: str = "test",
    full_files: dict[str, Path] | None = None,
    unknown_files: dict[str, Path] | None = None,
    canonical_files: dict[str, Path] | None = None,
    validated_files: dict[str, Path] | None = None,
    consensus_invalid_keys: set[tuple[int, str]] | None = None,
) -> dict[str, object]:
    return load_observations(
        data_dir=data_dir,
        chain_names={chain},
        full_files=full_files or {},
        unknown_files=unknown_files or {},
        canonical_files=canonical_files or {},
        validated_files=validated_files or {},
        epoch_bits={},
        excluded_keys=set(),
        consensus_invalid_keys=consensus_invalid_keys or set(),
    )


def test_reconciliation_blanks_declared_scan_order_child_height(
    tmp_path: Path,
) -> None:
    block_hash = f"{1:064x}"
    inventory = tmp_path / "namecoin_stale_blocks.csv"
    _write_inventory(
        inventory,
        [
            {
                "btc_header_hash": block_hash,
                "btc_prev_hash": f"{2:064x}",
                "child_height": "817176",
                "classification": "unknown",
            }
        ],
    )

    state = _load(
        tmp_path,
        chain="namecoin",
        full_files={"namecoin": inventory},
    )

    [observation] = state["unknown_observations_by_hash"][block_hash]
    assert observation.child_height == ""


@pytest.mark.parametrize("chain", ("namecoin", "coiledcoin", "i0coin"))
def test_split_unknown_scan_order_height_uses_authenticated_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    chain: str,
) -> None:
    block_hash = f"{1:064x}"
    inventory = tmp_path / f"{chain}_unknown_blocks.csv"
    _write_inventory(
        inventory,
        [
            {
                "btc_height": "100",
                "btc_header_hash": block_hash,
                "btc_prev_hash": f"{2:064x}",
                "child_height": "817176",
                "classification": "unknown",
            }
        ],
    )

    state = _load(
        tmp_path,
        chain=chain,
        unknown_files={chain: inventory},
    )
    [observation] = state["unknown_observations_by_hash"][block_hash]

    assert observation.child_height == ""
    assert observation.source_kind == "full_inventory"
    assert observation.source_path == str(inventory)
    assert len(observation.source_sha256) == 64

    monkeypatch.setattr(
        "stale_blocks_analysis.reconcile_publication.load_child_identity",
        lambda _data_dir: {
            (chain, block_hash): {
                "child_height": "817177",
                "child_block_hash": "aa" * 32,
                "child_block_time": "1700000000",
                "verification": "test-authenticated-identity",
                "child_header_hex": "",
                "child_nbits": "",
            }
        },
    )
    parent = {"btc_height": "100", "btc_header_hash": block_hash}

    rows = build_descendant_observation_rows(
        [parent],
        {block_hash: [observation]},
        data_dir=tmp_path,
        parser=argparse.ArgumentParser(),
    )

    assert rows[0]["child_height"] == "817177"
    assert rows[0]["child_height_provenance"] == (
        "child-identity:test-authenticated-identity"
    )
    assert rows[0]["identity_provenance"] == (
        "child-identity:test-authenticated-identity"
    )
    assert rows[0]["source_kind"] == "full_inventory"


def test_split_unknown_keeps_authenticated_height_for_other_chains(
    tmp_path: Path,
) -> None:
    block_hash = f"{1:064x}"
    inventory = tmp_path / "syscoin_unknown_blocks.csv"
    _write_inventory(
        inventory,
        [
            {
                "btc_header_hash": block_hash,
                "btc_prev_hash": f"{2:064x}",
                "child_height": "817176",
                "classification": "unknown",
            }
        ],
    )

    state = _load(
        tmp_path,
        chain="syscoin",
        unknown_files={"syscoin": inventory},
    )

    [observation] = state["unknown_observations_by_hash"][block_hash]
    assert observation.child_height == "817176"
    assert observation.source_kind == "full_inventory"


def test_reconciliation_writer_uses_lf_line_endings(tmp_path: Path) -> None:
    output = tmp_path / "reconciled.csv"

    write_csv(output, [{"value": "one"}, {"value": "two"}], ["value"])

    assert output.read_bytes() == b"value\none\ntwo\n"


def test_discover_canonical_files_finds_classifier_companions(tmp_path: Path) -> None:
    expected = tmp_path / "test_canonical_blocks.csv"
    expected.write_text("classification\n")
    (tmp_path / "test_unknown_blocks.csv").write_text("classification\n")

    assert discover_canonical_files(tmp_path) == {"test": expected}


def test_active_height_comparison_persists_explicit_rpc_source_label() -> None:
    candidate = "11" * 32
    active = "22" * 32

    class FakeRpc:
        def batch(self, calls: list[dict[str, object]]) -> list[dict[str, str]]:
            assert calls[0]["method"] == "getblockhash"
            assert calls[0]["params"] == [100]
            return [{"result": active}]

    result = fetch_active_hashes_by_height(
        {candidate: 100},
        FakeRpc(),  # type: ignore[arg-type]
        500,
        verification_label="bitcoin-01",
    )

    assert result[candidate] == {
        "exists": False,
        "on_mainchain": False,
        "height": 100,
        "active_hash_at_height": active,
        "verification_source": "bitcoin-core-rpc:bitcoin-01",
    }


@pytest.mark.parametrize("label", ["", "configured node", "node:one", "x" * 65])
def test_active_height_comparison_rejects_unsafe_rpc_source_label(label: str) -> None:
    class NoRpcExpected:
        def batch(self, _calls: object) -> list[dict[str, str]]:
            raise AssertionError("invalid labels must fail before RPC")

    with pytest.raises(ValueError, match="RPC verification label"):
        fetch_active_hashes_by_height(
            {"11" * 32: 100},
            NoRpcExpected(),  # type: ignore[arg-type]
            500,
            verification_label=label,
        )


@pytest.mark.parametrize("classification", ["stale", "orphan", "unknown", "canonical"])
@pytest.mark.parametrize("split_canonical", [False, True])
def test_every_source_bucket_is_candidate_evidence_but_not_a_trusted_root(
    tmp_path: Path,
    classification: str,
    split_canonical: bool,
) -> None:
    if split_canonical and classification != "canonical":
        pytest.skip("only canonical rows belong in a canonical companion")
    block_hash = f"{1:064x}"
    prev_hash = f"{2:064x}"
    inventory = tmp_path / (
        "test_canonical_blocks.csv" if split_canonical else "test_stale_blocks.csv"
    )
    _write_inventory(
        inventory,
        [
            {
                "btc_height": "100",
                "btc_header_hash": block_hash,
                "btc_prev_hash": prev_hash,
                "classification": classification,
                "validation_status": "VALID" if classification == "stale" else "",
            }
        ],
    )

    state = _load(
        tmp_path,
        full_files={} if split_canonical else {"test": inventory},
        canonical_files={"test": inventory} if split_canonical else {},
    )

    assert block_hash not in state["known_stale_hashes"]
    assert state["unknown_prev_by_hash"][block_hash] == prev_hash
    assert state["unknown_row_counts_by_hash"][block_hash] == 1
    assert state["full_classifications_by_hash"][block_hash] == {
        f"test:{classification}"
    }


def test_only_committed_validated_stale_can_anchor_a_root(tmp_path: Path) -> None:
    block_hash = f"{3:064x}"
    prev_hash = f"{4:064x}"
    validated = tmp_path / "test_validated_stales.csv"
    _write_inventory(
        validated,
        [
            {
                "btc_height": "101",
                "btc_header_hash": block_hash,
                "btc_prev_hash": prev_hash,
                "classification": "stale",
                "validation_status": "VALID",
            }
        ],
    )

    state = _load(tmp_path, validated_files={"test": validated})

    assert block_hash in state["known_stale_hashes"]
    assert block_hash not in state["unknown_prev_by_hash"]


@pytest.mark.parametrize(
    "validation_status",
    ("", "REJECTED_bad_nbits", "VALIDATION_FAILED", "VALID_BOGUS"),
)
def test_unvalidated_committed_stale_cannot_anchor_a_root(
    tmp_path: Path,
    validation_status: str,
) -> None:
    block_hash = f"{3:064x}"
    validated = tmp_path / "test_validated_stales.csv"
    _write_inventory(
        validated,
        [
            {
                "btc_height": "101",
                "btc_header_hash": block_hash,
                "btc_prev_hash": f"{4:064x}",
                "classification": "stale",
                "validation_status": validation_status,
            }
        ],
    )

    state = _load(tmp_path, validated_files={"test": validated})

    assert block_hash not in state["known_stale_hashes"]


def test_error_catalogue_hash_precedence_excludes_candidate_but_indexes_terminal(
    tmp_path: Path,
) -> None:
    block_hash = f"{5:064x}"
    prev_hash = f"{6:064x}"
    inventory = tmp_path / "test_stale_blocks.csv"
    _write_inventory(
        inventory,
        [
            {
                "btc_height": "102",
                "btc_header_hash": block_hash,
                "btc_prev_hash": prev_hash,
                "classification": "stale",
                "validation_status": "VALID",
            }
        ],
    )

    state = _load(
        tmp_path,
        full_files={"test": inventory},
        validated_files={"test": inventory},
        consensus_invalid_keys={(102, block_hash)},
    )

    assert block_hash not in state["known_stale_hashes"]
    assert block_hash not in state["unknown_prev_by_hash"]
    assert state["consensus_invalid_hashes"] == {block_hash}
    assert state["consensus_invalid_heights_by_hash"] == {block_hash: 102}


def test_error_catalogue_parent_is_explicit_invalid_ancestry_terminal(
    tmp_path: Path,
) -> None:
    invalid_parent = f"{5:064x}"
    child = f"{6:064x}"
    grandchild = f"{7:064x}"
    inventory = tmp_path / "test_unknown_blocks.csv"
    _write_inventory(
        inventory,
        [
            {
                "btc_height": "102",
                "btc_header_hash": invalid_parent,
                "btc_prev_hash": f"{4:064x}",
                "classification": "stale",
                "validation_status": "VALID",
            },
            {
                "btc_height": "103",
                "btc_header_hash": child,
                "btc_prev_hash": invalid_parent,
                "classification": "unknown",
                "validation_status": "",
            },
            {
                "btc_height": "104",
                "btc_header_hash": grandchild,
                "btc_prev_hash": child,
                "classification": "unknown",
                "validation_status": "",
            },
        ],
    )

    state = _load(
        tmp_path,
        full_files={"test": inventory},
        consensus_invalid_keys={(102, invalid_parent)},
    )
    walks = classify_walks(
        unknown_row_counts_by_hash=state["unknown_row_counts_by_hash"],
        unknown_prev_by_hash=state["unknown_prev_by_hash"],
        conflicting_unknown_prevs=set(),
        unknown_prev_chains=state["unknown_prev_chains"],
        all_hash_chains=state["all_hash_chains"],
        known_stale_hashes=state["known_stale_hashes"],
        consensus_invalid_hashes=state["consensus_invalid_hashes"],
        is_mainchain=lambda _block_hash: False,
        max_depth=100,
    )

    assert invalid_parent not in state["unknown_prev_by_hash"]
    assert walks[child].terminal_kind == "consensus_invalid"
    assert walks[child].category == "consensus_invalid_descendant"
    assert walks[child].terminal_hash == invalid_parent
    assert walks[child].depth == 1
    assert walks[grandchild].terminal_kind == "consensus_invalid"
    assert walks[grandchild].category == "consensus_invalid_descendant"
    assert walks[grandchild].terminal_hash == invalid_parent
    assert walks[grandchild].depth == 2
    assert path_for(
        child,
        unknown_prev_by_hash=state["unknown_prev_by_hash"],
        known_stale_hashes=state["known_stale_hashes"],
        consensus_invalid_hashes=state["consensus_invalid_hashes"],
        is_mainchain=lambda _block_hash: False,
    ) == [child, invalid_parent]
    assert path_for(
        grandchild,
        unknown_prev_by_hash=state["unknown_prev_by_hash"],
        known_stale_hashes=state["known_stale_hashes"],
        consensus_invalid_hashes=state["consensus_invalid_hashes"],
        is_mainchain=lambda _block_hash: False,
    ) == [grandchild, child, invalid_parent]


def test_error_catalogue_rejects_conflicting_heights_for_one_hash(
    tmp_path: Path,
) -> None:
    block_hash = f"{8:064x}"

    with pytest.raises(ValueError, match="assigns conflicting heights"):
        _load(
            tmp_path,
            consensus_invalid_keys={(102, block_hash), (103, block_hash)},
        )


def test_active_893766_through_893769_headers_are_not_published() -> None:
    published: set[str] = set()
    for path, hash_field in (
        (REPO / "data" / "stale_descendants.csv", "btc_header_hash"),
        (REPO / "data" / "error-blocks" / "error_blocks.csv", "hash"),
    ):
        with path.open(newline="") as handle:
            published.update(row[hash_field] for row in csv.DictReader(handle))

    assert ACTIVE_CANONICAL_DESCENDANTS.isdisjoint(published)
