from __future__ import annotations

import csv
from pathlib import Path

import pytest

from stale_blocks_analysis.reconcile_observations import (
    discover_canonical_files,
    load_observations,
)
from stale_blocks_analysis.reconcile_publication import write_csv

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
    full_files: dict[str, Path] | None = None,
    canonical_files: dict[str, Path] | None = None,
    correction_keys: frozenset[tuple[int, str]] = frozenset(),
    corrections: dict[tuple[int, str], str] | None = None,
) -> dict[str, object]:
    return load_observations(
        data_dir=data_dir,
        chain_names={"test"},
        full_files=full_files or {},
        unknown_files={},
        canonical_files=canonical_files or {},
        validated_files={},
        epoch_bits={},
        excluded_keys=set(),
        consensus_invalid_keys=set(),
        stale_descendant_corrections=(
            corrections
            if corrections is not None
            else {key: "reclassified_from_canonical" for key in correction_keys}
        ),
    )


def test_reconciliation_writer_uses_lf_line_endings(tmp_path: Path) -> None:
    output = tmp_path / "reconciled.csv"

    write_csv(output, [{"value": "one"}, {"value": "two"}], ["value"])

    assert output.read_bytes() == b"value\none\ntwo\n"


def test_discover_canonical_files_finds_classifier_companions(tmp_path: Path) -> None:
    expected = tmp_path / "test_canonical_blocks.csv"
    expected.write_text("classification\n")
    (tmp_path / "test_unknown_blocks.csv").write_text("classification\n")

    assert discover_canonical_files(tmp_path) == {"test": expected}


def test_corrected_canonical_bucket_rows_are_candidates_not_stale_roots(
    tmp_path: Path,
) -> None:
    block_hash = f"{1:064x}"
    prev_hash = f"{2:064x}"
    canonical = tmp_path / "test_canonical_blocks.csv"
    _write_inventory(
        canonical,
        [
            {
                "btc_height": "100",
                "btc_header_hash": block_hash,
                "btc_prev_hash": prev_hash,
                "classification": "canonical",
            }
        ],
    )

    state = _load(
        tmp_path,
        canonical_files={"test": canonical},
        correction_keys=frozenset({(100, block_hash)}),
    )

    assert block_hash not in state["known_stale_hashes"]
    assert state["unknown_prev_by_hash"][block_hash] == prev_hash
    assert state["unknown_row_counts_by_hash"][block_hash] == 1
    assert state["full_classifications_by_hash"][block_hash] == {"test:canonical"}


def test_corrected_canonical_bucket_row_must_declare_canonical(
    tmp_path: Path,
) -> None:
    block_hash = f"{8:064x}"
    canonical = tmp_path / "test_canonical_blocks.csv"
    _write_inventory(
        canonical,
        [
            {
                "btc_height": "100",
                "btc_header_hash": block_hash,
                "btc_prev_hash": f"{9:064x}",
                "classification": "unknown",
            }
        ],
    )

    with pytest.raises(ValueError, match="must declare classification=canonical"):
        _load(
            tmp_path,
            canonical_files={"test": canonical},
            correction_keys=frozenset({(100, block_hash)}),
        )


def test_uncorrected_canonical_bucket_row_is_not_an_ancestry_candidate(
    tmp_path: Path,
) -> None:
    block_hash = f"{5:064x}"
    prev_hash = f"{6:064x}"
    stale_root = tmp_path / "test_stale_blocks.csv"
    _write_inventory(
        stale_root,
        [
            {
                "btc_height": "101",
                "btc_header_hash": prev_hash,
                "btc_prev_hash": f"{7:064x}",
                "classification": "stale",
                "validation_status": "VALID",
            }
        ],
    )
    canonical = tmp_path / "test_canonical_blocks.csv"
    _write_inventory(
        canonical,
        [
            {
                "btc_height": "102",
                "btc_header_hash": block_hash,
                "btc_prev_hash": prev_hash,
                "classification": "canonical",
            }
        ],
    )

    state = _load(
        tmp_path,
        full_files={"test": stale_root},
        canonical_files={"test": canonical},
    )

    assert prev_hash in state["known_stale_hashes"]
    assert block_hash not in state["known_stale_hashes"]
    assert block_hash not in state["unknown_prev_by_hash"]
    assert state["unknown_row_counts_by_hash"][block_hash] == 0


def test_corrected_commingled_canonical_row_is_an_ancestry_candidate(
    tmp_path: Path,
) -> None:
    block_hash = f"{10:064x}"
    prev_hash = f"{11:064x}"
    inventory = tmp_path / "test_stale_blocks.csv"
    _write_inventory(
        inventory,
        [
            {
                "btc_height": "103",
                "btc_header_hash": block_hash,
                "btc_prev_hash": prev_hash,
                "classification": "canonical",
            }
        ],
    )

    state = _load(
        tmp_path,
        full_files={"test": inventory},
        correction_keys=frozenset({(103, block_hash)}),
    )

    assert block_hash not in state["known_stale_hashes"]
    assert state["unknown_prev_by_hash"][block_hash] == prev_hash
    assert state["unknown_row_counts_by_hash"][block_hash] == 1
    assert state["full_classifications_by_hash"][block_hash] == {"test:canonical"}
    assert state["seen_correction_keys"] == frozenset({(103, block_hash)})


def test_uncorrected_commingled_canonical_row_is_not_an_ancestry_candidate(
    tmp_path: Path,
) -> None:
    block_hash = f"{12:064x}"
    inventory = tmp_path / "test_stale_blocks.csv"
    _write_inventory(
        inventory,
        [
            {
                "btc_height": "104",
                "btc_header_hash": block_hash,
                "btc_prev_hash": f"{13:064x}",
                "classification": "canonical",
            }
        ],
    )

    state = _load(tmp_path, full_files={"test": inventory})

    assert block_hash not in state["known_stale_hashes"]
    assert block_hash not in state["unknown_prev_by_hash"]
    assert state["unknown_row_counts_by_hash"][block_hash] == 0
    assert state["full_classifications_by_hash"][block_hash] == {"test:canonical"}


def test_commingled_canonical_row_rejects_direct_stale_correction_reason(
    tmp_path: Path,
) -> None:
    block_hash = f"{14:064x}"
    inventory = tmp_path / "test_stale_blocks.csv"
    _write_inventory(
        inventory,
        [
            {
                "btc_height": "105",
                "btc_header_hash": block_hash,
                "btc_prev_hash": f"{15:064x}",
                "classification": "canonical",
            }
        ],
    )

    with pytest.raises(ValueError, match="disagrees with canonical source bucket"):
        _load(
            tmp_path,
            full_files={"test": inventory},
            corrections={(105, block_hash): "reclassified_from_direct_stale"},
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


def test_corrected_stale_row_is_candidate_not_root(tmp_path: Path) -> None:
    block_hash = f"{3:064x}"
    prev_hash = f"{4:064x}"
    inventory = tmp_path / "test_stale_blocks.csv"
    _write_inventory(
        inventory,
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

    state = load_observations(
        data_dir=tmp_path,
        chain_names={"test"},
        full_files={"test": inventory},
        unknown_files={},
        canonical_files={},
        validated_files={},
        epoch_bits={},
        excluded_keys=set(),
        consensus_invalid_keys=set(),
        stale_descendant_corrections={
            (101, block_hash): "reclassified_from_direct_stale"
        },
    )

    assert block_hash not in state["known_stale_hashes"]
    assert state["unknown_prev_by_hash"][block_hash] == prev_hash
    assert state["unknown_row_counts_by_hash"][block_hash] == 1
    assert state["full_classifications_by_hash"][block_hash] == {"test:stale"}
