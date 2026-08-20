"""Tests for the attribution assembly: roster, basis passes, RSK join, writer."""

from __future__ import annotations

import csv

from stale_blocks_analysis import attribution, stale_blocks
from stale_blocks_analysis.attribution import (
    ATTRIBUTION_COLUMNS,
    apply_attribution_basis,
    apply_rsk_historical_labels,
    apply_template_producers,
    auxpow_loader_roster,
    dump_attributions_csv,
)
from stale_blocks_analysis.config import CHAIN_SPECS, CHAINS_BY_AUXPOW_ACTIVATION


def test_roster_follows_activation_order_and_covers_every_chain_spec() -> None:
    roster = auxpow_loader_roster()
    keys = [key for key, _fn in roster]

    assert keys == [key for key, _date in CHAINS_BY_AUXPOW_ACTIVATION]
    assert set(keys) == set(CHAIN_SPECS)


def test_roster_resolves_the_public_loader_for_each_chain() -> None:
    for key, fn in auxpow_loader_roster():
        expected = getattr(stale_blocks, f"load_{key.replace('-', '_')}_stales")
        assert fn is expected, key


def test_attribution_basis_marks_only_identified_labels() -> None:
    records = [
        {"height": 1, "hash": "a", "pool": "P1", "_pool_match": "tag"},
        {"height": 2, "hash": "b", "pool": "P2", "_pool_match": "address"},
        {"height": 3, "hash": "c", "pool": "Unknown", "_pool_match": "none"},
        {"height": 4, "hash": "d"},
        # A caller-labelled record keeps the basis the caller supplied.
        {
            "height": 5,
            "hash": "e",
            "pool": "External",
            "attribution_basis": "rsk_historical",
        },
    ]

    apply_attribution_basis(records)

    assert [r["attribution_basis"] for r in records] == [
        "coinbase",
        "coinbase",
        "unattributed",
        "unattributed",
        "rsk_historical",
    ]


def test_caller_labelled_record_without_a_basis_is_an_error() -> None:
    import pytest

    records = [{"height": 9, "hash": "f", "pool": "External"}]

    with pytest.raises(ValueError, match="no attribution_basis"):
        apply_attribution_basis(records)


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
        {
            "height": 500,
            "hash": "eee",
            "source": "rsk",
            "pool": "F2Pool",
            "_pool_match": "tag",
        },
    ]
    apply_attribution_basis(records)

    apply_rsk_historical_labels(records)

    assert records[0]["pool"] == "Braiins Pool"
    assert records[0]["attribution_basis"] == "rsk_historical"
    assert records[1]["pool"] == "Braiins Pool"
    assert records[1]["attribution_basis"] == "rsk_historical"
    assert records[2]["pool"] == "Unknown"
    assert records[2]["attribution_basis"] == "unattributed"
    assert records[3]["pool"] == "F2Pool"
    assert records[3]["attribution_basis"] == "rsk_historical"
    assert records[4]["pool"] == "Unknown"
    assert records[4]["attribution_basis"] == "unattributed"
    assert records[5]["pool"] == "F2Pool"
    assert records[5]["attribution_basis"] == "coinbase"

    out = capsys.readouterr().out
    assert "RSK historical miner-registry labels applied to 3 rows" in out


def test_rsk_join_is_a_no_op_when_the_registry_input_is_absent(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(attribution, "RSK_CSV", tmp_path / "missing.csv")
    records = [{"height": 100, "hash": "aaa", "source": "rsk", "pool": "Unknown"}]
    apply_attribution_basis(records)

    apply_rsk_historical_labels(records)

    assert records[0]["pool"] == "Unknown"
    assert records[0]["attribution_basis"] == "unattributed"


def test_template_producer_pass_folds_only_coinbase_derived_labels() -> None:
    records = [
        {
            "height": 850_000,
            "hash": "a",
            "pool": "AntPool",
            "attribution_basis": "coinbase",
            "_pool_match": "tag",
        },
        # A payout-address-only identification observes no tag: not folded.
        {
            "height": 850_000,
            "hash": "d",
            "pool": "AntPool",
            "attribution_basis": "coinbase",
            "_pool_match": "address",
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

    apply_template_producers(records)

    assert records[0]["template_producer"] == "AntPool & friends"
    assert records[1]["template_producer"] == "AntPool"
    assert records[2]["template_producer"] == "AntPool"
    assert records[3]["template_producer"] == "Unknown"


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
    monkeypatch.setattr(attribution, "_stale_inputs_fingerprint", lambda: "stalefp")
    monkeypatch.setattr(attribution, "_repository_inputs_fingerprint", lambda: "repofp")
    stale = [
        {"height": 1, "hash": "aa", "attribution_basis": "coinbase"},
        {"height": 2, "hash": "bb", "attribution_basis": "unattributed"},
    ]
    csv_path = tmp_path / "stale-block-attributions.csv"

    meta_path = attribution.write_attribution_meta(stale, csv_path, min_height=147_168)

    assert meta_path.name == "stale-block-attributions.meta.json"
    import json

    meta = json.loads(meta_path.read_text())
    assert meta["min_height"] == 147_168
    assert meta["rows"] == 2
    assert meta["attribution_basis_counts"] == {"coinbase": 1, "unattributed": 1}
    assert meta["mining_pools"]["pinned_ref"] == "a" * 40
    assert meta["mining_pools"]["state"]["dirty"] is False
    assert meta["mining_pools"]["dataset_fingerprint"] == "fingerprint"
    assert meta["stale_blocks"]["state"]["commit"] == "a" * 40
    assert meta["stale_blocks"]["input_fingerprint"] == "stalefp"
    assert meta["repository"]["state"] == {"commit": "a" * 40, "dirty": False}
    assert meta["repository"]["input_fingerprint"] == "repofp"


def test_stale_inputs_fingerprint_tracks_content(tmp_path, monkeypatch):
    blocks = tmp_path / "blocks"
    blocks.mkdir()
    (blocks / "1-aa.bin").write_bytes(b"blockbytes")
    monkeypatch.setattr(attribution, "BLOCKS_DIR", blocks)

    first = attribution._stale_inputs_fingerprint()
    assert first == attribution._stale_inputs_fingerprint()

    (blocks / "1-aa.bin").write_bytes(b"editedbytes")
    assert attribution._stale_inputs_fingerprint() != first


def _git_archive(tmp_path, names):
    """A blocks/ archive tracked by a real git checkout."""
    import subprocess

    clone = tmp_path / "stale-blocks"
    blocks = clone / "blocks"
    blocks.mkdir(parents=True)
    for name in names:
        (blocks / name).write_bytes(b"payload")
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "t@t"],
        ["git", "config", "user.name", "t"],
        ["git", "add", "-A"],
        ["git", "commit", "-qm", "archive"],
    ):
        subprocess.run(cmd, cwd=clone, check=True)
    return clone, blocks


def test_require_blocks_archive_rejects_missing_and_empty(tmp_path, monkeypatch):
    import pytest

    monkeypatch.setattr(attribution, "BLOCKS_DIR", tmp_path / "missing")
    monkeypatch.setattr(attribution, "STALE_DIR", tmp_path)
    with pytest.raises(FileNotFoundError, match="No block binaries"):
        attribution.require_blocks_archive()

    empty = tmp_path / "blocks"
    empty.mkdir()
    monkeypatch.setattr(attribution, "BLOCKS_DIR", empty)
    with pytest.raises(FileNotFoundError, match="No block binaries"):
        attribution.require_blocks_archive()


def test_require_blocks_archive_rejects_an_incomplete_checkout(tmp_path, monkeypatch):
    import pytest

    import subprocess

    clone, blocks = _git_archive(tmp_path, ["1-aa.bin", "2-bb.bin", "3-cc.bin"])
    monkeypatch.setattr(attribution, "STALE_DIR", clone)
    monkeypatch.setattr(attribution, "BLOCKS_DIR", blocks)

    # Complete archive: the tracked names and the disk agree.
    attribution.require_blocks_archive()
    expected, present = attribution.archive_inventory()
    assert expected == present == {"1-aa.bin", "2-bb.bin", "3-cc.bin"}

    # An untracked stray must not mask a missing tracked binary: counts
    # would match here, names do not.
    (blocks / "2-bb.bin").unlink()
    (blocks / "99-zz.bin").write_bytes(b"stray")
    with pytest.raises(FileNotFoundError, match="2-bb.bin"):
        attribution.require_blocks_archive()

    # A staged deletion must not shrink the manifest either: it is read
    # from HEAD, not the index.
    subprocess.run(
        ["git", "rm", "-q", "--cached", "blocks/2-bb.bin"], cwd=clone, check=True
    )
    with pytest.raises(FileNotFoundError, match="2-bb.bin"):
        attribution.require_blocks_archive()

    # ...unless the caller opts in explicitly.
    attribution.require_blocks_archive(allow_partial=True)


def test_archive_inventory_without_a_git_checkout(tmp_path, monkeypatch):
    blocks = tmp_path / "blocks"
    blocks.mkdir()
    (blocks / "1-aa.bin").write_bytes(b"payload")
    monkeypatch.setattr(attribution, "STALE_DIR", tmp_path)
    monkeypatch.setattr(attribution, "BLOCKS_DIR", blocks)

    # No manifest to compare against: expected is unknown, presence suffices.
    assert attribution.archive_inventory() == (None, {"1-aa.bin"})
    attribution.require_blocks_archive()


def test_repository_inputs_fingerprint_tracks_content(tmp_path):
    a = tmp_path / "loader.csv"
    b = tmp_path / "module.py"
    a.write_text("height,hash\n1,aa\n")
    b.write_text("VALUE = 1\n")

    first = attribution._repository_inputs_fingerprint([a, b])
    assert first == attribution._repository_inputs_fingerprint([a, b])

    a.write_text("height,hash\n1,bb\n")
    assert attribution._repository_inputs_fingerprint([a, b]) != first


def test_missing_committed_loader_input_stops_the_run(tmp_path, monkeypatch):
    import pytest

    from stale_blocks_analysis.config import CHAINS_BY_AUXPOW_ACTIVATION

    staged = tmp_path / "validated-stales"
    staged.mkdir()
    for key, _date in CHAINS_BY_AUXPOW_ACTIVATION:
        (staged / f"{key}_validated_stales.csv").write_text("btc_height\n")
    descendants = tmp_path / "stale_descendants.csv"
    descendants.write_text("height\n")
    monkeypatch.setattr(attribution, "VALIDATED_STALES_DIR", staged)
    monkeypatch.setattr(attribution, "STALE_DESCENDANTS_CSV", descendants)

    attribution.require_committed_inputs()

    # A deleted loader input is indistinguishable from an empty chain in
    # the export, so its absence stops the run instead.
    first_key = CHAINS_BY_AUXPOW_ACTIVATION[0][0]
    (staged / f"{first_key}_validated_stales.csv").unlink()
    with pytest.raises(FileNotFoundError, match=first_key):
        attribution.require_committed_inputs()


def test_unknown_sentinel_does_not_bypass_identification(monkeypatch):
    from stale_blocks_analysis import stale_merge

    monkeypatch.setattr(
        stale_merge, "identify_pool_detailed", lambda *a, **k: ("FoundPool", "tag")
    )
    rows = [
        {
            "height": 999999999,
            "hash": "ab" * 32,
            "source": "auxpow",
            "pool": "Unknown",
            "_scriptsig_hex": "deadbeef",
            "_outputs_str": "",
        }
    ]

    out = stale_merge.tag_stale_blocks(rows)

    # The sentinel is not a label: the carried coinbase is still read.
    assert out[0]["pool"] == "FoundPool"
    assert out[0]["_pool_match"] == "tag"
