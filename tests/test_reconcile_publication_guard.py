"""Publication-safety tests for unknown-stale ancestry reconciliation."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import shutil
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from stale_blocks_analysis.ancestry_walk import WalkResult
from stale_blocks_analysis.evidence_hydration import (
    CHILD_IDENTITY_CORE_FIELDS,
    ChildIdentityIndex,
)
from stale_blocks_analysis.reconcile_observations import (
    StaleObservation,
    UnknownObservation,
    hash_meets_bits,
    header_hash,
)
from stale_blocks_analysis.reconcile_publication import (
    CONSENSUS_INVALID_PARENT_RULE,
    DESCENDANT_UNJUDGEABLE_FAILURES,
    OUTPUT_SUMMARY,
    PublicationBaseline,
    build_descendant_observation_rows,
    descendant_consensus_rules,
    descendant_notes,
    partition_ancestry_rows,
    render_and_publish,
    select_parent_evidence,
    validate_publication_discovery,
    validate_publication_rows,
)

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "analysis" / "reconcile_unknown_stale_ancestry.py"
BASELINE_HASH = "11" * 32
# Bitcoin's canonical compact bits for the epoch starting at height 399,168,
# used as the matched header/expected pair the rule derivation requires at the
# height-400,001 candidates below.
BITS = "1806b99f"
EASY_BITS = "207fffff"
IMPOSSIBLE_BITS = "03000001"
PROTECTED_OUTPUT_TARGETS = (
    REPO / "data" / "error-blocks" / "error_blocks.csv",
    REPO / "data" / "error-blocks" / "error_block_observations.csv",
    REPO / "results" / "monitor-evidence" / "monitor-evidence-counts.csv",
    REPO / "results" / "child-header-coverage.csv",
)


def _identity_index(
    rows: dict[tuple[str, str], dict[str, str]],
) -> ChildIdentityIndex:
    identity = ChildIdentityIndex()
    for key, row in rows.items():
        identity.add(key, row)
    return identity


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "reconcile_unknown_stale_ancestry_guard_test", SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _copy_committed_baseline(path: Path) -> str:
    """Copy the canonical parent and witness interfaces beside each other."""
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO / "data/stale_descendants.csv", path)
    shutil.copy2(
        REPO / "data/stale_descendant_observations.csv",
        path.parent / "stale_descendant_observations.csv",
    )
    return path.read_text()


def _publication_baseline(
    *,
    observation_identities: frozenset[tuple[str, int, str, str]] = frozenset(),
    required_inventory_chains: frozenset[str] = frozenset(),
):
    return PublicationBaseline(
        statuses_by_hash={BASELINE_HASH: "VALID_STALE_DESCENDANT"},
        heights_by_hash={BASELINE_HASH: 100},
        root_hashes_by_hash={BASELINE_HASH: "22" * 32},
        mainchain_statuses_by_hash={BASELINE_HASH: "verified_not_active"},
        active_hashes_by_hash={BASELINE_HASH: "33" * 32},
        root_mainchain_statuses_by_hash={BASELINE_HASH: "verified_not_active"},
        root_active_hashes_by_hash={BASELINE_HASH: "44" * 32},
        mainchain_sources_by_hash={BASELINE_HASH: "bitcoin-core-rpc:test"},
        observed_chains_by_hash={BASELINE_HASH: frozenset({"namecoin"})},
        source_observation_counts_by_hash={BASELINE_HASH: {"namecoin": 1}},
        required_inventory_chains=required_inventory_chains,
        observation_identities=observation_identities,
    )


def _set_publication_paths(module, monkeypatch, tmp_path: Path) -> tuple[Path, Path]:
    parent_verdicts = tmp_path / "publication" / "stale_descendants.csv"
    results = tmp_path / "publication-results"
    monkeypatch.setattr(module, "PARENT_VERDICTS_CSV", parent_verdicts)
    monkeypatch.setattr(module, "RESULTS_DIR", results)
    return parent_verdicts, results


def _diagnostic_output_args(tmp_path: Path) -> list[str]:
    return [
        "--parent-verdicts-csv",
        str(tmp_path / "staged" / "stale_descendants.csv"),
        "--observations-csv",
        str(tmp_path / "staged" / "stale_descendant_observations.csv"),
        "--error-candidates-csv",
        str(tmp_path / "staged" / "error_candidates.csv"),
    ]


def _header_with_pow_result(
    prev_hash: str, *, bits: str, should_meet_target: bool
) -> tuple[str, str]:
    prefix = (
        (1).to_bytes(4, "little", signed=True)
        + bytes.fromhex(prev_hash)[::-1]
        + bytes(32)
        + (1_700_000_000).to_bytes(4, "little")
        + bytes.fromhex(bits)[::-1]
    )
    for nonce in range(1_000):
        header_hex = (prefix + nonce.to_bytes(4, "little")).hex()
        block_hash = header_hash(header_hex)
        if hash_meets_bits(block_hash, bits) is should_meet_target:
            return header_hex, block_hash
    raise AssertionError("failed to construct deterministic header with requested PoW")


def _render_single_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    terminal_kind: str,
    terminal_height: int,
    epoch_bits: dict[int, str],
    evidence: str = "valid",
) -> tuple[dict[str, object], Path, Path, str, str]:
    terminal_hash = "22" * 32
    candidate_bits = IMPOSSIBLE_BITS if evidence == "failed_pow" else EASY_BITS
    header_hex, block_hash = _header_with_pow_result(
        terminal_hash,
        bits=candidate_bits,
        should_meet_target=evidence != "failed_pow",
    )
    observation = UnknownObservation(
        chain="namecoin",
        source_path="data/namecoin_stale_blocks.csv",
        row_number=2,
        block_hash=block_hash,
        prev_hash=terminal_hash,
        btc_height=str(terminal_height + 1),
        child_height="",
        btc_time="1700000000",
        bits=candidate_bits,
        scriptsig_hex="",
        outputs="",
        header_hex="" if evidence == "missing_header" else header_hex,
        source_kind="full_inventory",
        source_classification="unknown",
        source_sha256="bb" * 32,
    )
    monkeypatch.setattr(
        "stale_blocks_analysis.reconcile_publication.load_child_identity",
        lambda _data_dir: _identity_index(
            {
                ("namecoin", block_hash): {
                    "child_height": "817177",
                    "child_block_hash": "aa" * 32,
                    "child_block_time": "1774280993",
                    "verification": "test",
                    "child_header_hex": "",
                    "child_nbits": "",
                }
            }
        ),
    )
    parent_verdicts = tmp_path / "staged" / "stale_descendants.csv"
    observations = tmp_path / "staged" / "stale_descendant_observations.csv"
    error_candidates = tmp_path / "staged" / "error_candidates.csv"
    args = SimpleNamespace(
        parent_verdicts_csv=parent_verdicts,
        observations_csv=observations,
        error_candidates_csv=error_candidates,
        check_mainchain=False,
        rpc_url="",
    )
    stale_by_hash = {}
    known_stale_hashes: set[str] = set()
    consensus_invalid_heights: dict[str, int] = {}
    if terminal_kind == "known_stale":
        stale_by_hash[terminal_hash] = [
            StaleObservation(
                chain="upstream",
                source_kind="upstream",
                source_path="data/stale-blocks/stale-blocks.csv",
                row_number=2,
                block_hash=terminal_hash,
                prev_hash="33" * 32,
                btc_height=str(terminal_height),
                child_height="",
                btc_time="",
                bits=EASY_BITS,
            )
        ]
        known_stale_hashes.add(terminal_hash)
    else:
        consensus_invalid_heights[terminal_hash] = terminal_height

    summary = render_and_publish(
        args=args,
        parser=argparse.ArgumentParser(),
        data_dir=tmp_path,
        results_dir=tmp_path / "results",
        cache_dir=tmp_path / "cache",
        publication_baseline=None,
        epoch_bits=epoch_bits,
        stale_by_hash=stale_by_hash,
        known_stale_hashes=known_stale_hashes,
        consensus_invalid_heights_by_hash=consensus_invalid_heights,
        auxpow_stale_hashes=set(),
        upstream_count=len(known_stale_hashes),
        unknown_rows=[observation],
        unknown_row_counts_by_hash=Counter({block_hash: 1}),
        unknown_chains_by_hash={block_hash: {"namecoin"}},
        unknown_example_by_hash={block_hash: observation},
        unknown_observations_by_hash={block_hash: [observation]},
        inventory_rows=[],
        anomalies=[],
        walk_results={block_hash: WalkResult(terminal_kind, terminal_hash, 1)},
        path_for=lambda _block_hash: [block_hash, terminal_hash],
        mainchain_cache={},
        mainchain_cache_dirty=False,
        rel_fn=str,
        descendant_bip34_verdict_fn=lambda *_args: ("not_applicable", None),
    )
    return summary, parent_verdicts, error_candidates, block_hash, terminal_hash


def test_descendant_ledger_uses_identity_height_when_source_height_is_untrusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_hash = "aa" * 32
    monkeypatch.setattr(
        "stale_blocks_analysis.reconcile_publication.load_child_identity",
        lambda _data_dir: _identity_index(
            {
                ("namecoin", BASELINE_HASH): {
                    "child_height": "817177",
                    "child_block_hash": child_hash,
                    "child_block_time": "1774280993",
                    "verification": "child-node-rpc+source-row-auxpow-parent-match",
                    "child_header_hex": "",
                    "child_nbits": "",
                }
            }
        ),
    )
    parent = {"btc_height": "941882", "btc_header_hash": BASELINE_HASH}
    observation = UnknownObservation(
        chain="namecoin",
        source_path="data/namecoin_stale_blocks.csv",
        row_number=464228,
        block_hash=BASELINE_HASH,
        prev_hash="22" * 32,
        btc_height="",
        child_height="",
        btc_time="1774281079",
        bits="17021a91",
        scriptsig_hex="03aabb",
        outputs="",
        header_hex="00" * 80,
        source_kind="full_inventory",
        source_classification="unknown",
        source_sha256="bb" * 32,
    )

    rows = build_descendant_observation_rows(
        [parent],
        {BASELINE_HASH: [observation]},
        data_dir=tmp_path,
        parser=argparse.ArgumentParser(),
    )

    assert rows[0]["child_height"] == "817177"
    assert rows[0]["child_height_provenance"] == (
        "child-identity:child-node-rpc+source-row-auxpow-parent-match"
    )
    assert parent["observed_chains"] == "namecoin"
    assert parent["source_observation_count"] == 1


def test_descendant_ledger_rejects_trusted_source_height_disagreement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "stale_blocks_analysis.reconcile_publication.load_child_identity",
        lambda _data_dir: _identity_index(
            {
                ("namecoin", BASELINE_HASH): {
                    "child_height": "817177",
                    "child_block_hash": "aa" * 32,
                    "child_block_time": "1774280993",
                    "verification": "test",
                    "child_header_hex": "",
                    "child_nbits": "",
                }
            }
        ),
    )
    observation = UnknownObservation(
        chain="namecoin",
        source_path="data/namecoin_validated_stales.csv",
        row_number=2,
        block_hash=BASELINE_HASH,
        prev_hash="22" * 32,
        btc_height="941882",
        child_height="817176",
        btc_time="1774281079",
        bits="17021a91",
        scriptsig_hex="03aabb",
        outputs="",
        header_hex="00" * 80,
        source_kind="validated_stales",
        source_classification="stale",
        source_sha256="bb" * 32,
    )

    with pytest.raises(SystemExit):
        build_descendant_observation_rows(
            [{"btc_height": "941882", "btc_header_hash": BASELINE_HASH}],
            {BASELINE_HASH: [observation]},
            data_dir=tmp_path,
            parser=argparse.ArgumentParser(),
        )


def test_descendant_ledger_collapses_compatible_authenticated_event_copies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_hash = "aa" * 32
    monkeypatch.setattr(
        "stale_blocks_analysis.reconcile_publication.load_child_identity",
        lambda _data_dir: _identity_index(
            {
                ("namecoin", BASELINE_HASH): {
                    "child_height": "817177",
                    "child_block_hash": child_hash,
                    "child_block_time": "1774280993",
                    "verification": "test",
                    "child_header_hex": "",
                    "child_nbits": "",
                }
            }
        ),
    )
    common = {
        "chain": "namecoin",
        "block_hash": BASELINE_HASH,
        "prev_hash": "22" * 32,
        "btc_height": "941882",
        "child_height": "817177",
        "btc_time": "1774281079",
        "bits": "17021a91",
        "scriptsig_hex": "03aabb",
        "outputs": "",
        "header_hex": "00" * 80,
    }
    physical_copies = [
        UnknownObservation(
            **common,
            source_path="data/z_full_inventory.csv",
            row_number=2,
            source_kind="full_inventory",
            source_classification="canonical",
            source_sha256="cc" * 32,
        ),
        UnknownObservation(
            **common,
            source_path="data/a_canonical_blocks.csv",
            row_number=9,
            source_kind="canonical_blocks",
            source_classification="canonical",
            source_sha256="dd" * 32,
        ),
    ]

    def build(observations: list[UnknownObservation]):
        parent = {"btc_height": "941882", "btc_header_hash": BASELINE_HASH}
        rows = build_descendant_observation_rows(
            [parent],
            {BASELINE_HASH: observations},
            data_dir=tmp_path,
            parser=argparse.ArgumentParser(),
        )
        return rows, parent

    rows, parent = build(physical_copies)
    reversed_rows, reversed_parent = build(list(reversed(physical_copies)))

    assert rows == reversed_rows
    assert len(rows) == 1
    assert rows[0]["source_path"] == "data/a_canonical_blocks.csv"
    assert rows[0]["source_row_number"] == "9"
    assert parent["source_observation_count"] == 1
    assert reversed_parent["source_observation_count"] == 1


def test_descendant_ledger_rejects_conflicting_authenticated_event_copies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "stale_blocks_analysis.reconcile_publication.load_child_identity",
        lambda _data_dir: _identity_index(
            {
                ("namecoin", BASELINE_HASH): {
                    "child_height": "817177",
                    "child_block_hash": "aa" * 32,
                    "child_block_time": "1774280993",
                    "verification": "test",
                    "child_header_hex": "",
                    "child_nbits": "",
                }
            }
        ),
    )
    common = {
        "chain": "namecoin",
        "block_hash": BASELINE_HASH,
        "prev_hash": "22" * 32,
        "btc_height": "941882",
        "child_height": "817177",
        "bits": "17021a91",
        "scriptsig_hex": "03aabb",
        "outputs": "",
        "header_hex": "00" * 80,
        "source_kind": "full_inventory",
        "source_classification": "canonical",
    }
    observations = [
        UnknownObservation(
            **common,
            source_path="data/full.csv",
            row_number=2,
            btc_time="1774281079",
            source_sha256="cc" * 32,
        ),
        UnknownObservation(
            **common,
            source_path="data/canonical.csv",
            row_number=2,
            btc_time="1774281080",
            source_sha256="dd" * 32,
        ),
    ]

    with pytest.raises(SystemExit, match="2"):
        build_descendant_observation_rows(
            [{"btc_height": "941882", "btc_header_hash": BASELINE_HASH}],
            {BASELINE_HASH: observations},
            data_dir=tmp_path,
            parser=argparse.ArgumentParser(),
        )

    assert "conflicting evidence for authenticated descendant event" in (
        capsys.readouterr().err
    )


def test_descendant_ledger_keeps_distinct_authenticated_child_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "stale_blocks_analysis.reconcile_publication.load_child_identity",
        lambda _data_dir: _identity_index(
            {
                ("namecoin", BASELINE_HASH): {
                    "child_height": "817177",
                    "child_block_hash": "aa" * 32,
                    "child_block_time": "1774280993",
                    "verification": "test",
                    "child_header_hex": "",
                    "child_nbits": "",
                },
                ("syscoin", BASELINE_HASH): {
                    "child_height": "2272433",
                    "child_block_hash": "bb" * 32,
                    "child_block_time": "1774281093",
                    "verification": "test",
                    "child_header_hex": "",
                    "child_nbits": "",
                },
            }
        ),
    )
    common = {
        "block_hash": BASELINE_HASH,
        "prev_hash": "22" * 32,
        "btc_height": "941882",
        "btc_time": "1774281079",
        "bits": "17021a91",
        "scriptsig_hex": "03aabb",
        "outputs": "",
        "header_hex": "00" * 80,
        "source_kind": "full_inventory",
        "source_classification": "unknown",
    }
    observations = [
        UnknownObservation(
            **common,
            chain="namecoin",
            source_path="data/namecoin.csv",
            row_number=2,
            child_height="817177",
            source_sha256="cc" * 32,
        ),
        UnknownObservation(
            **common,
            chain="syscoin",
            source_path="data/syscoin.csv",
            row_number=2,
            child_height="2272433",
            source_sha256="dd" * 32,
        ),
    ]
    parent = {"btc_height": "941882", "btc_header_hash": BASELINE_HASH}

    rows = build_descendant_observation_rows(
        [parent],
        {BASELINE_HASH: observations},
        data_dir=tmp_path,
        parser=argparse.ArgumentParser(),
    )

    assert [(row["chain"], row["child_block_hash"]) for row in rows] == [
        ("namecoin", "aa" * 32),
        ("syscoin", "bb" * 32),
    ]
    assert parent["observed_chains"] == "namecoin|syscoin"
    assert parent["source_observation_count"] == 2


def test_descendant_ledger_keeps_distinct_same_height_child_events(
    tmp_path: Path,
) -> None:
    identity_path = tmp_path / "child-identity" / "namecoin_child_identity.csv"
    identity_path.parent.mkdir(parents=True)
    with identity_path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=CHILD_IDENTITY_CORE_FIELDS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(
            [
                {
                    "chain": "namecoin",
                    "btc_header_hash": BASELINE_HASH,
                    "child_height": str(child_height),
                    "child_block_hash": child_hash * 64,
                    "child_block_time": str(child_time),
                    "verification": "test",
                    "note": "",
                    "child_header_hex": "",
                    "child_nbits": "",
                }
                for child_height, child_hash, child_time in (
                    (817177, "a", 1774280993),
                    (817177, "b", 1774281093),
                )
            ]
        )
    common = {
        "chain": "namecoin",
        "block_hash": BASELINE_HASH,
        "prev_hash": "22" * 32,
        "btc_height": "941882",
        "btc_time": "1774281079",
        "bits": "17021a91",
        "scriptsig_hex": "03aabb",
        "outputs": "",
        "header_hex": "00" * 80,
        "source_kind": "full_inventory",
        "source_classification": "unknown",
    }
    observations = [
        UnknownObservation(
            **common,
            source_path=f"data/namecoin-{source_hash}.csv",
            row_number=2,
            child_height=str(child_height),
            source_child_hash=child_hash * 64,
            source_sha256=source_hash * 64,
        )
        for child_height, child_hash, source_hash in (
            (817177, "a", "c"),
            (817177, "b", "d"),
        )
    ]
    parent = {"btc_height": "941882", "btc_header_hash": BASELINE_HASH}

    rows = build_descendant_observation_rows(
        [parent],
        {BASELINE_HASH: observations},
        data_dir=tmp_path,
        parser=argparse.ArgumentParser(),
    )

    assert [
        (row["chain"], row["child_height"], row["child_block_hash"]) for row in rows
    ] == [
        ("namecoin", "817177", "a" * 64),
        ("namecoin", "817177", "b" * 64),
    ]
    assert parent["observed_chains"] == "namecoin"
    assert parent["source_observation_count"] == 2


def test_descendant_ledger_rejects_ambiguous_same_height_child_event(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    identity_path = tmp_path / "child-identity" / "namecoin_child_identity.csv"
    identity_path.parent.mkdir(parents=True)
    with identity_path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=CHILD_IDENTITY_CORE_FIELDS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(
            [
                {
                    "chain": "namecoin",
                    "btc_header_hash": BASELINE_HASH,
                    "child_height": str(child_height),
                    "child_block_hash": child_hash * 64,
                    "child_block_time": str(child_time),
                    "verification": "test",
                    "note": "",
                    "child_header_hex": "",
                    "child_nbits": "",
                }
                for child_height, child_hash, child_time in (
                    (817177, "a", 1774280993),
                    (817177, "b", 1774281093),
                )
            ]
        )
    observation = UnknownObservation(
        chain="namecoin",
        source_path="data/namecoin.csv",
        row_number=2,
        block_hash=BASELINE_HASH,
        prev_hash="22" * 32,
        btc_height="941882",
        child_height="817177",
        btc_time="1774281079",
        bits="17021a91",
        scriptsig_hex="03aabb",
        outputs="",
        header_hex="00" * 80,
        source_kind="full_inventory",
        source_classification="unknown",
        source_sha256="cc" * 32,
    )

    with pytest.raises(SystemExit):
        build_descendant_observation_rows(
            [{"btc_height": "941882", "btc_header_hash": BASELINE_HASH}],
            {BASELINE_HASH: [observation]},
            data_dir=tmp_path,
            parser=argparse.ArgumentParser(),
        )

    assert "ambiguous authenticated child identities" in capsys.readouterr().err


def test_descendant_ledger_rejects_source_child_hash_disagreement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "stale_blocks_analysis.reconcile_publication.load_child_identity",
        lambda _data_dir: _identity_index(
            {
                ("namecoin", BASELINE_HASH): {
                    "child_height": "817177",
                    "child_block_hash": "aa" * 32,
                    "child_block_time": "1774280993",
                    "verification": "test",
                    "child_header_hex": "",
                    "child_nbits": "",
                }
            }
        ),
    )
    observation = UnknownObservation(
        chain="namecoin",
        source_path="data/namecoin.csv",
        row_number=2,
        block_hash=BASELINE_HASH,
        prev_hash="22" * 32,
        btc_height="941882",
        child_height="817177",
        btc_time="1774281079",
        bits="17021a91",
        scriptsig_hex="03aabb",
        outputs="",
        header_hex="00" * 80,
        source_kind="full_inventory",
        source_classification="unknown",
        source_sha256="cc" * 32,
        source_child_hash="bb" * 32,
    )

    with pytest.raises(SystemExit):
        build_descendant_observation_rows(
            [{"btc_height": "941882", "btc_header_hash": BASELINE_HASH}],
            {BASELINE_HASH: [observation]},
            data_dir=tmp_path,
            parser=argparse.ArgumentParser(),
        )

    assert "disagrees with source observation" in capsys.readouterr().err


def test_parent_evidence_reconciles_compatible_sources_independent_of_order() -> None:
    payout = "76a914fb37342f6275b13936799def06f2eb4c0f20151588ac"
    op_return = "6a124558534154011508000113021b1a1f120013"
    common = {
        "block_hash": BASELINE_HASH,
        "btc_height": "100",
        "child_height": "200",
        "header_hex": "00" * 80,
        "prev_hash": "22" * 32,
        "btc_time": "1",
        "bits": "1d00ffff",
    }
    observations = [
        UnknownObservation(
            **common,
            chain="syscoin",
            source_path="<archive>/syscoin.csv",
            row_number=2,
            scriptsig_hex="",
            outputs=("SkCJmd2CqThFWqSx6CHjpgxUe2SbHwkdKj:3.13110129|OP_RETURN:0.0"),
        ),
        UnknownObservation(
            **common,
            chain="fractal",
            source_path="<archive>/fractal.csv",
            row_number=3,
            scriptsig_hex="03aabb",
            outputs=f"{payout};{op_return}",
        ),
    ]

    selected = select_parent_evidence(observations)

    assert selected == (
        "00" * 80,
        "22" * 32,
        "1",
        "1d00ffff",
        "03aabb",
        f"{payout}:313110129|{op_return}:0",
    )
    assert select_parent_evidence(list(reversed(observations))) == selected


def test_parent_evidence_rejects_conflicting_scripts() -> None:
    common = {
        "chain": "namecoin",
        "source_path": "<archive>/namecoin.csv",
        "block_hash": BASELINE_HASH,
        "btc_height": "100",
        "child_height": "200",
        "header_hex": "00" * 80,
        "prev_hash": "22" * 32,
        "btc_time": "1",
        "bits": "1d00ffff",
        "scriptsig_hex": "",
    }
    observations = [
        UnknownObservation(**common, row_number=2, outputs="51"),
        UnknownObservation(**common, row_number=3, outputs="52"),
    ]

    with pytest.raises(ValueError, match="conflicting scripts"):
        select_parent_evidence(observations)


def test_parent_evidence_uses_full_coinbase_transaction() -> None:
    full_coinbase = (
        "0100000001"
        + "00" * 32
        + "ffffffff02aabbffffffff01"
        + "0000000000000000"
        + "036a01ff00000000"
    )
    observation = UnknownObservation(
        chain="hathor",
        source_path="<archive>/hathor.csv",
        row_number=2,
        block_hash=BASELINE_HASH,
        btc_height="100",
        child_height="200",
        header_hex="00" * 80,
        prev_hash="22" * 32,
        btc_time="1",
        bits="1d00ffff",
        scriptsig_hex="",
        outputs="OP_RETURN:0.0",
        full_coinbase_hex=full_coinbase,
    )

    assert select_parent_evidence([observation]) == (
        "00" * 80,
        "22" * 32,
        "1",
        "1d00ffff",
        "aabb",
        "6a01ff:0",
    )


def test_descendant_notes_only_report_current_failures() -> None:
    assert descendant_notes([]) == ""
    assert descendant_notes(["pow_target_mismatch"]) == "pow_target_mismatch"


def test_publication_partition_never_emits_rejected_parent() -> None:
    accepted = {
        "classification": "stale_descendant",
        "validation_status": "VALID_STALE_DESCENDANT",
    }
    rejected = {
        "classification": "stale_descendant",
        "validation_status": "REJECTED_missing_header_hex",
    }
    error_candidate = {
        "classification": "error_block",
        "validation_status": "REJECTED_bip34_height_mismatch",
    }
    inherited_unpublishable = {
        "classification": "unpublishable",
        "ancestry_relation": "consensus_invalid_descendant",
        "validation_status": "REJECTED_missing_header_hex",
    }

    assert partition_ancestry_rows(
        [accepted, rejected, error_candidate, inherited_unpublishable]
    ) == (
        [accepted],
        [rejected, inherited_unpublishable],
        [error_candidate, inherited_unpublishable],
    )


def test_publication_mode_rejects_missing_baseline_chain_inventories_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_module()
    parent_verdicts, results = _set_publication_paths(module, monkeypatch, tmp_path)
    baseline = _copy_committed_baseline(parent_verdicts)
    data_dir = tmp_path / "empty-data"
    data_dir.mkdir()

    with pytest.raises(SystemExit, match="2"):
        module.main(
            [
                "--data-dir",
                str(data_dir),
                "--check-mainchain",
                "--rpc-source-label",
                "test-node",
                "--cache-dir",
                str(tmp_path / "cache"),
                "--epoch-reference-dir",
                str(tmp_path / "epochs"),
                *_diagnostic_output_args(tmp_path),
            ]
        )

    assert "missing full, unknown, or canonical inventories" in capsys.readouterr().err
    assert parent_verdicts.read_text() == baseline
    assert not results.exists()


@pytest.mark.parametrize("label", [None, "configured-node", "node:one", "x" * 65])
def test_publication_requires_specific_safe_rpc_source_label(
    label: str | None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_module()
    argv = ["--check-mainchain", *_diagnostic_output_args(Path("/tmp/test"))]
    if label is not None:
        argv.extend(["--rpc-source-label", label])

    with pytest.raises(SystemExit, match="2"):
        module.main(argv)

    error = capsys.readouterr().err
    assert "rpc-source-label" in error


def test_publication_discovery_accepts_canonical_only_baseline_chain(
    tmp_path: Path,
) -> None:
    baseline = _publication_baseline(required_inventory_chains=frozenset({"namecoin"}))
    canonical = tmp_path / "namecoin_canonical_blocks.csv"
    canonical.write_text("classification\n")

    validate_publication_discovery(
        baseline,
        full_files={},
        unknown_files={},
        canonical_files={"namecoin": canonical},
        parser=argparse.ArgumentParser(),
    )


def test_publication_rows_reject_missing_committed_parent_and_witness(
    capsys: pytest.CaptureFixture[str],
) -> None:
    witness = ("namecoin", 200, "55" * 32, BASELINE_HASH)
    baseline = _publication_baseline(observation_identities=frozenset({witness}))

    with pytest.raises(SystemExit, match="2"):
        validate_publication_rows([], [], baseline, argparse.ArgumentParser())

    error = capsys.readouterr().err
    assert "missing 1 committed descendant identities" in error
    assert "missing 1 committed logical witness identities" in error


def test_publication_rows_reject_missing_logical_witness_identity(
    capsys: pytest.CaptureFixture[str],
) -> None:
    witness = ("namecoin", 200, "55" * 32, BASELINE_HASH)
    baseline = _publication_baseline(observation_identities=frozenset({witness}))
    parent_rows = [
        {
            "classification": "stale_descendant",
            "validation_status": "VALID_STALE_DESCENDANT",
            "btc_height": 100,
            "btc_header_hash": BASELINE_HASH,
        }
    ]

    with pytest.raises(SystemExit, match="2"):
        validate_publication_rows(parent_rows, [], baseline, argparse.ArgumentParser())

    assert "missing 1 committed logical witness identities" in capsys.readouterr().err


def test_publication_rows_allow_source_coordinate_changes_for_same_logical_witness() -> (
    None
):
    witness = ("namecoin", 200, "55" * 32, BASELINE_HASH)
    baseline = _publication_baseline(observation_identities=frozenset({witness}))

    validate_publication_rows(
        [
            {
                "classification": "stale_descendant",
                "validation_status": "VALID_STALE_DESCENDANT",
                "btc_height": 100,
                "btc_header_hash": BASELINE_HASH,
            }
        ],
        [
            {
                "chain": "namecoin",
                "child_height": 200,
                "child_block_hash": "55" * 32,
                "btc_header_hash": BASELINE_HASH,
                "source_path": "data/relocated.csv",
                "source_row_number": 999,
            }
        ],
        baseline,
        argparse.ArgumentParser(),
    )


def test_allow_partial_refuses_publication_output_defaults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_module()
    parent_verdicts, results = _set_publication_paths(module, monkeypatch, tmp_path)

    with pytest.raises(SystemExit, match="2"):
        module.main(
            [
                "--allow-partial",
                "--data-dir",
                str(tmp_path / "data"),
                *_diagnostic_output_args(tmp_path),
            ]
        )

    error = capsys.readouterr().err
    assert "--results-dir" in error
    assert not parent_verdicts.exists()
    assert not results.exists()


@pytest.mark.parametrize(
    "target_option",
    (
        "--parent-verdicts-csv",
        "--observations-csv",
        "--error-candidates-csv",
    ),
)
@pytest.mark.parametrize("target_path", PROTECTED_OUTPUT_TARGETS)
@pytest.mark.parametrize("joined", (False, True))
def test_diagnostic_outputs_reject_every_protected_publication_surface_before_write(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    target_option: str,
    target_path: Path,
    joined: bool,
) -> None:
    module = _load_module()
    data_dir = tmp_path / "uncreated-input"
    results_dir = tmp_path / "uncreated-results"
    output_paths = {
        "--parent-verdicts-csv": tmp_path / "scratch" / "parents.csv",
        "--observations-csv": tmp_path / "scratch" / "observations.csv",
        "--error-candidates-csv": tmp_path / "scratch" / "errors.csv",
    }
    output_paths[target_option] = target_path
    before = target_path.read_bytes()
    argv = ["--allow-partial"]
    scalar_options = {
        "--data-dir": data_dir,
        "--results-dir": results_dir,
        **output_paths,
    }
    for option, path in scalar_options.items():
        if joined:
            argv.append(f"{option}={path}")
        else:
            argv.extend((option, str(path)))

    with pytest.raises(SystemExit, match="2"):
        module.main(argv)

    assert "protected publication surface" in capsys.readouterr().err
    assert target_path.read_bytes() == before
    assert not data_dir.exists()
    assert not results_dir.exists()
    for option, path in output_paths.items():
        if option != target_option:
            assert not path.exists()


def test_allow_partial_writes_only_to_explicit_disposable_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    error_dir = data_dir / "error-blocks"
    error_dir.mkdir()
    (error_dir / "error_blocks.csv").write_text(
        f"height,hash,classification\n0,{'00' * 32},error_block\n"
    )
    results = tmp_path / "scratch-results"
    parent_verdicts = tmp_path / "scratch" / "stale_descendants.csv"
    observations = tmp_path / "scratch" / "stale_descendant_observations.csv"
    error_candidates = tmp_path / "scratch" / "error_candidates.csv"

    module.main(
        [
            "--allow-partial",
            "--data-dir",
            str(data_dir),
            "--results-dir",
            str(results),
            "--parent-verdicts-csv",
            str(parent_verdicts),
            "--observations-csv",
            str(observations),
            "--error-candidates-csv",
            str(error_candidates),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--epoch-reference-dir",
            str(tmp_path / "epochs"),
        ]
    )

    captured = capsys.readouterr()
    assert "do not replace publication artifacts" in captured.err
    assert parent_verdicts.is_file()
    assert parent_verdicts.read_text().count("\n") == 1
    assert (results / OUTPUT_SUMMARY).is_file()


def test_candidate_without_canonical_nbits_is_unpublishable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    summary, parent_verdicts, error_candidates, _block_hash, _terminal_hash = (
        _render_single_candidate(
            tmp_path,
            monkeypatch,
            terminal_kind="known_stale",
            terminal_height=100,
            epoch_bits={},
        )
    )

    assert summary["accepted_stale_descendant_hashes"] == 0
    assert summary["unpublishable_candidate_hashes"] == 1
    assert summary["error_candidate_hashes"] == 0
    with parent_verdicts.open(newline="") as handle:
        assert list(csv.DictReader(handle)) == []
    with error_candidates.open(newline="") as handle:
        assert list(csv.DictReader(handle)) == []
    with (tmp_path / "results" / "unknown-stale-anomalies.csv").open(
        newline=""
    ) as handle:
        [anomaly] = list(csv.DictReader(handle))
    assert "missing_expected_nbits" in anomaly["details"]


def test_consensus_invalid_terminal_routes_descendant_to_error_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    summary, parent_verdicts, error_candidates, block_hash, terminal_hash = (
        _render_single_candidate(
            tmp_path,
            monkeypatch,
            terminal_kind="consensus_invalid",
            terminal_height=100,
            epoch_bits={0: EASY_BITS},
        )
    )

    assert summary["accepted_stale_descendant_hashes"] == 0
    assert summary["unpublishable_candidate_hashes"] == 0
    assert summary["error_candidate_hashes"] == 1
    with parent_verdicts.open(newline="") as handle:
        assert list(csv.DictReader(handle)) == []
    with error_candidates.open(newline="") as handle:
        [candidate] = list(csv.DictReader(handle))
    assert candidate["classification"] == "error_block"
    assert candidate["ancestry_relation"] == "consensus_invalid_descendant"
    assert candidate["btc_height"] == "101"
    assert candidate["btc_header_hash"] == block_hash
    assert candidate["root_stale_hash"] == terminal_hash
    assert candidate["root_stale_height"] == "100"
    assert candidate["rules_violated"] == CONSENSUS_INVALID_PARENT_RULE
    assert candidate["validation_status"].startswith(
        f"REJECTED_{CONSENSUS_INVALID_PARENT_RULE}"
    )
    assert candidate["active_mainchain_status"] == "not_checked"
    assert candidate["root_active_mainchain_status"] == "not_checked"
    assert candidate["active_mainchain_verification_source"] == ""


@pytest.mark.parametrize(
    ("evidence", "epoch_bits", "expected_failure"),
    [
        ("valid", {}, "missing_expected_nbits"),
        ("missing_header", {0: EASY_BITS}, "missing_header_hex"),
        ("failed_pow", {0: IMPOSSIBLE_BITS}, "pow_target_mismatch"),
    ],
)
def test_unjudgeable_consensus_invalid_descendant_blocks_without_error_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    evidence: str,
    epoch_bits: dict[int, str],
    expected_failure: str,
) -> None:
    summary, parent_verdicts, error_candidates, _block_hash, _terminal_hash = (
        _render_single_candidate(
            tmp_path,
            monkeypatch,
            terminal_kind="consensus_invalid",
            terminal_height=100,
            epoch_bits=epoch_bits,
            evidence=evidence,
        )
    )

    assert summary["accepted_stale_descendant_hashes"] == 0
    assert summary["unpublishable_candidate_hashes"] == 1
    assert summary["error_candidate_hashes"] == 1
    with parent_verdicts.open(newline="") as handle:
        assert list(csv.DictReader(handle)) == []
    with error_candidates.open(newline="") as handle:
        [candidate] = list(csv.DictReader(handle))
    assert candidate["classification"] == "unpublishable"
    assert candidate["ancestry_relation"] == "consensus_invalid_descendant"
    assert candidate["rules_violated"] == ""
    assert expected_failure in candidate["validation_status"]
    assert candidate["active_mainchain_status"] == "not_checked"
    assert candidate["root_active_mainchain_status"] == "not_checked"


def test_descendant_consensus_rules_needs_judgeable_evidence():
    """A descendant is promoted to error block only on sound evidence.

    The height is the root's confirmed height plus a fork depth, so it is
    trustworthy only when the path was verified, the work meets its target,
    and the bits are Bitcoin's canonical value there. Any of those missing and
    a coinbase-height mismatch is equally consistent with a wrong height, so
    no rule is derived and the candidate stays unpublishable.
    """
    header_hex = "04000000" + "00" * 76
    scriptsig = (b"\x03" + (400000).to_bytes(3, "little") + b"pool").hex()

    assert descendant_consensus_rules(
        header_hex, scriptsig, 400001, [], header_bits=BITS, expected_nbits=BITS
    ) == ["bip34_coinbase_height_mismatch"]
    assert (
        descendant_consensus_rules(
            header_hex, scriptsig, None, [], header_bits=BITS, expected_nbits=BITS
        )
        == []
    )
    for failure in sorted(DESCENDANT_UNJUDGEABLE_FAILURES):
        assert (
            descendant_consensus_rules(
                header_hex,
                scriptsig,
                400001,
                [failure],
                header_bits=BITS,
                expected_nbits=BITS,
            )
            == []
        )


def test_descendant_consensus_rules_needs_a_canonical_difficulty_match():
    """An uncompared difficulty must not read as a canonical-difficulty match.

    ``expected_bits_for_height`` returns ``""`` for a height the committed
    epoch reference does not reach, and the caller then records no
    ``nbits_epoch_mismatch`` -- the comparison simply never happened. Deriving
    rules from that silence would publish a foreign or easy-target header as an
    error block with its canonical difficulty never checked, so the match is
    required outright.
    """
    header_hex = "04000000" + "00" * 76
    scriptsig = (b"\x03" + (400000).to_bytes(3, "little") + b"pool").hex()

    # Control: bits present on both sides and equal.
    assert descendant_consensus_rules(
        header_hex, scriptsig, 400001, [], header_bits=BITS, expected_nbits=BITS
    ) == ["bip34_coinbase_height_mismatch"]

    # The epoch reference does not reach this height, so nothing was compared.
    assert (
        descendant_consensus_rules(
            header_hex, scriptsig, 400001, [], header_bits=BITS, expected_nbits=""
        )
        == []
    )
    # No bits recovered for the candidate at all.
    assert (
        descendant_consensus_rules(
            header_hex, scriptsig, 400001, [], header_bits="", expected_nbits=BITS
        )
        == []
    )
    # Compared, and the header's difficulty is not Bitcoin's at this height.
    assert (
        descendant_consensus_rules(
            header_hex,
            scriptsig,
            400001,
            [],
            header_bits="1d00ffff",
            expected_nbits=BITS,
        )
        == []
    )


def test_descendant_consensus_rules_ignores_unauthenticated_header_bytes():
    """Bytes not proven to be this block's cannot prove anything about it.

    Every rule but the retarget one is read straight out of the supplied header
    and coinbase bytes. When those bytes are absent, or hash to something other
    than the claimed block hash, publishing a violation under that hash would
    attribute another block's evidence -- or nobody's -- to it. Corroborating
    the published hash against the serialized header is the precondition for
    the verdict here, the same as at classification time.
    """
    header_hex = "04000000" + "00" * 76
    scriptsig = (b"\x03" + (400000).to_bytes(3, "little") + b"pool").hex()
    long_scriptsig = "aa" * 101

    # Controls: authenticated, the same evidence does derive each rule.
    assert descendant_consensus_rules(
        header_hex, scriptsig, 400001, [], header_bits=BITS, expected_nbits=BITS
    ) == ["bip34_coinbase_height_mismatch"]
    assert "coinbase_scriptsig_length_above_100" in descendant_consensus_rules(
        header_hex, long_scriptsig, 400001, [], header_bits=BITS, expected_nbits=BITS
    )

    # A header present but not proven to hash to the claimed block hash.
    assert (
        descendant_consensus_rules(
            header_hex,
            scriptsig,
            400001,
            ["header_hash_mismatch"],
            header_bits=BITS,
            expected_nbits=BITS,
        )
        == []
    )
    # No header at all: the coinbase alone must not carry a verdict either.
    assert (
        descendant_consensus_rules(
            "",
            long_scriptsig,
            400001,
            ["missing_header_hex"],
            header_bits=BITS,
            expected_nbits=BITS,
        )
        == []
    )


def test_a_version_rule_alone_cannot_promote_a_descendant():
    """Core counts the version vote over the block's own ancestors.

    A direct stale's are the canonical chain, so the fixed cutover is exact for
    it. A descendant's leave the canonical chain at the fork root, so a fork
    spanning an activation boundary can carry a different verdict, and a
    version rule is not proof there. Rules settled by the bytes alone still are.
    """
    height = 400000
    bits = "1806f0a8"
    common = {
        "header_bits": bits,
        "expected_nbits": bits,
    }

    # Version 1 well past BIP65: the shared derivation names a version rule...
    from stale_blocks_analysis.btc_stale_validation import consensus_violations

    version_only = {
        "btc_header_hex": "01000000" + "00" * 76,
        "coinbase_scriptsig_hex": (
            b"\x03" + height.to_bytes(3, "little") + b"pool"
        ).hex(),
    }
    assert consensus_violations(version_only, height) == ["bip65_block_version_below_4"]
    # ...but it cannot make a descendant an error block.
    assert (
        descendant_consensus_rules(
            version_only["btc_header_hex"],
            version_only["coinbase_scriptsig_hex"],
            height,
            [],
            **common,
        )
        == []
    )

    # A byte-settled rule is unaffected.
    wrong_height = {
        "btc_header_hex": "04000000" + "00" * 76,
        "coinbase_scriptsig_hex": (
            b"\x03" + (height + 1).to_bytes(3, "little") + b"pool"
        ).hex(),
    }
    assert descendant_consensus_rules(
        wrong_height["btc_header_hex"],
        wrong_height["coinbase_scriptsig_hex"],
        height,
        [],
        **common,
    ) == ["bip34_coinbase_height_mismatch"]
