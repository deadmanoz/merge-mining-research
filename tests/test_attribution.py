"""Tests for the attribution assembly: roster, basis passes, RSK join, writer."""

from __future__ import annotations

import csv

from stale_blocks_analysis import attribution, stale_blocks
from stale_blocks_analysis.attribution import (
    ATTRIBUTION_COLUMNS,
    _apply_attribution_basis,
    _apply_rsk_historical_labels,
    _apply_template_producers,
    _auxpow_loader_roster,
    dump_attributions_csv,
)
from stale_blocks_analysis.config import CHAIN_SPECS, CHAINS_BY_AUXPOW_ACTIVATION


def test_roster_follows_activation_order_and_covers_every_chain_spec() -> None:
    roster = _auxpow_loader_roster()
    keys = [key for key, _fn in roster]

    assert keys == [key for key, _date in CHAINS_BY_AUXPOW_ACTIVATION]
    assert set(keys) == set(CHAIN_SPECS)


def test_roster_resolves_the_public_loader_for_each_chain() -> None:
    for key, fn in _auxpow_loader_roster():
        expected = getattr(stale_blocks, f"load_{key.replace('-', '_')}_stales")
        assert fn is expected, key


def test_attribution_basis_marks_only_real_coinbase_labels() -> None:
    records = [
        {"height": 1, "hash": "a", "pool": "P1"},
        {"height": 2, "hash": "b", "pool": "Unknown"},
        {"height": 3, "hash": "c"},
    ]

    _apply_attribution_basis(records)

    assert [r["attribution_basis"] for r in records] == [
        "coinbase",
        "unattributed",
        "unattributed",
    ]


def _write_rsk_csv(path) -> None:
    path.write_text(
        "btc_height,btc_header_hash,classification,validation_status,"
        "rsk_miner,pool_label\n"
        "100,aaa,stale,VALID,32dfc7a8,Braiins Pool\n"
        "200,bbb,stale,REJECTED_NBITS,32dfc7a8,Rejected Pool\n"
        "300,ccc,stale,VALID_STALE,32dfc7a8,F2Pool\n"
        "400,ddd,stale,VALID,32dfc7a8,Unknown\n"
        "500,eee,stale,VALID,32dfc7a8,Braiins Pool\n",
        encoding="utf-8",
    )


def test_rsk_historical_join_applies_only_to_gate_passing_rsk_rows(
    tmp_path, monkeypatch, capsys
) -> None:
    rsk_csv = tmp_path / "rsk_validated_stales.csv"
    _write_rsk_csv(rsk_csv)
    monkeypatch.setattr(attribution, "RSK_CSV", rsk_csv)

    records = [
        {"height": 100, "hash": "aaa", "source": "rsk", "pool": "Unknown"},
        # Same (height, hash) key but a different source: must not be relabelled.
        {"height": 100, "hash": "aaa", "source": "stale-blocks", "pool": "Unknown"},
        # RSK row whose registry entry failed the validation gate.
        {"height": 200, "hash": "bbb", "source": "rsk", "pool": "Unknown"},
        # VALID_-prefixed verdicts pass the public gate.
        {"height": 300, "hash": "ccc", "source": "rsk", "pool": "Unknown"},
        # The registry's literal "Unknown" sentinel is not an attribution.
        {"height": 400, "hash": "ddd", "source": "rsk", "pool": "Unknown"},
        # An RSK row with grafted coinbase evidence keeps its coinbase label.
        {"height": 500, "hash": "eee", "source": "rsk", "pool": "F2Pool"},
    ]
    _apply_attribution_basis(records)

    _apply_rsk_historical_labels(records)

    assert records[0]["pool"] == "Braiins Pool"
    assert records[0]["attribution_basis"] == "rsk_historical"
    assert records[1]["pool"] == "Unknown"
    assert records[1]["attribution_basis"] == "unattributed"
    assert records[2]["pool"] == "Unknown"
    assert records[2]["attribution_basis"] == "unattributed"
    assert records[3]["pool"] == "F2Pool"
    assert records[3]["attribution_basis"] == "rsk_historical"
    assert records[4]["pool"] == "Unknown"
    assert records[4]["attribution_basis"] == "unattributed"
    assert records[5]["pool"] == "F2Pool"
    assert records[5]["attribution_basis"] == "coinbase"

    out = capsys.readouterr().out
    assert "RSK historical miner-registry labels applied to 2 rows" in out


def test_rsk_join_is_a_no_op_when_the_registry_input_is_absent(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(attribution, "RSK_CSV", tmp_path / "missing.csv")
    records = [{"height": 100, "hash": "aaa", "source": "rsk", "pool": "Unknown"}]
    _apply_attribution_basis(records)

    _apply_rsk_historical_labels(records)

    assert records[0]["pool"] == "Unknown"
    assert records[0]["attribution_basis"] == "unattributed"


def test_template_producer_pass_folds_only_coinbase_derived_labels() -> None:
    records = [
        {
            "height": 850_000,
            "hash": "a",
            "pool": "AntPool",
            "attribution_basis": "coinbase",
        },
        # An RSK historical label is not coinbase evidence: carried unfolded.
        {
            "height": 850_000,
            "hash": "b",
            "pool": "AntPool",
            "attribution_basis": "rsk_historical",
        },
        {
            "height": 850_000,
            "hash": "c",
            "pool": None,
            "attribution_basis": "unattributed",
        },
    ]

    _apply_template_producers(records)

    assert records[0]["template_producer"] == "AntPool & friends"
    assert records[1]["template_producer"] == "AntPool"
    assert records[2]["template_producer"] == "Unknown"


def test_writer_projects_stray_working_keys_and_emits_lf_endings(tmp_path) -> None:
    path = tmp_path / "stale-block-attributions.csv"
    records = [
        {
            "height": 500_000,
            "hash": "aaa",
            "source": "stale-blocks",
            "pool": "F2Pool",
            "template_producer": "F2Pool",
            "attribution_basis": "coinbase",
            "has_bin": True,
            # Working keys that survive tagging/merging must not reach DictWriter.
            "_scriptsig_hex": "deadbeef",
            "_outputs_str": "1AbC;3DeF",
        },
        {
            "height": 500_001,
            "hash": "bbb",
            "source": "namecoin",
            "pool": "Unknown",
            "template_producer": "Unknown",
            "attribution_basis": "unattributed",
            "has_bin": False,
        },
    ]

    dump_attributions_csv(records, path)

    raw = path.open(newline="").read()
    assert "\r" not in raw
    assert raw.splitlines()[0] == ",".join(ATTRIBUTION_COLUMNS)

    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert list(rows[0]) == ATTRIBUTION_COLUMNS
    assert rows[0]["hash"] == "aaa"
    assert rows[0]["pool"] == "F2Pool"
    assert rows[1]["attribution_basis"] == "unattributed"


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

    state = attribution._clone_state(repo)
    assert state is not None
    assert len(state["commit"]) == 40 and state["dirty"] is False

    (repo / "f.txt").write_text("y")
    assert attribution._clone_state(repo)["dirty"] is True
    assert attribution._clone_state(tmp_path / "missing") is None


def test_write_attribution_meta_records_provenance(tmp_path, monkeypatch):
    monkeypatch.setattr(
        attribution, "_clone_state", lambda p: {"commit": "a" * 40, "dirty": False}
    )
    monkeypatch.setattr(attribution, "_pinned_ref", lambda key: "a" * 40)
    monkeypatch.setattr(attribution, "pool_dataset_fingerprint", lambda: "fingerprint")
    stale = [
        {"height": 1, "hash": "aa", "attribution_basis": "coinbase"},
        {"height": 2, "hash": "bb", "attribution_basis": "unattributed"},
    ]
    csv_path = tmp_path / "stale-block-attributions.csv"

    meta_path = attribution.write_attribution_meta(stale, csv_path)

    assert meta_path.name == "stale-block-attributions.meta.json"
    import json

    meta = json.loads(meta_path.read_text())
    assert meta["rows"] == 2
    assert meta["attribution_basis_counts"] == {"coinbase": 1, "unattributed": 1}
    assert meta["mining_pools"]["pinned_ref"] == "a" * 40
    assert meta["mining_pools"]["state"]["dirty"] is False
    assert meta["mining_pools"]["dataset_fingerprint"] == "fingerprint"
    assert meta["stale_blocks"]["state"]["commit"] == "a" * 40
