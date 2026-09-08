"""Pin restored Namecoin evidence and its consumer semantics."""

import csv
from dataclasses import replace
from pathlib import Path

import pytest

from stale_blocks_analysis import pool_identification
from stale_blocks_analysis.bitcoin_binary import canonical_output_token
from stale_blocks_analysis.coinbase_output_claims import (
    coinbase_output_claims_refine,
    parse_coinbase_output_claims,
    recipient_hash160_for_script,
    render_coinbase_outputs_column,
)
from stale_blocks_analysis.evidence_normalization import normalize_outputs_cell

P2PK = "21" + "02" + "55" * 32 + "ac"
NULLDATA = "6a084d696e6564206279"


def test_issue_52_parent_by_hash():
    # The issue calls this BTC 153211; the accepted parent height is 183088.
    # Select by hash so historical child metadata cannot misidentify it.
    key = "000000000000001003e4edee91fb4c919489d9941f702366938c16870f1a4ffa"
    scripts = (
        "76a91461e025405ef2b8021baac4611b300405117cac3688ac;"
        "4104549804985236f7f15c6eb52fe5f849cfafcd657bb959c12476c2705054232f8f"
        "c3c459463115334091d1908e559c77d1605099d48e9451b61c2262df3802652dac;"
        "20b5d01e8a9a94acd2fd9d4dd967f81258a7126baf0f4da0686c663418d17c40c3"
    )
    exact = parse_coinbase_output_claims(scripts)
    restored = render_coinbase_outputs_column(exact)
    old = parse_coinbase_output_claims("~N5VtGA8VyfjRWcYaRRNnzfYdorvLDUBPZ8")
    address_subset = tuple(
        replace(c, position=i)
        for i, c in enumerate(
            c
            for c in exact
            if canonical_output_token(bytes.fromhex(c.script_hex)) != c.script_hex
        )
    )
    assert len(address_subset) == len(old)
    assert coinbase_output_claims_refine(
        tuple(replace(c, position_exact=True) for c in old), address_subset
    )
    path = (
        Path(__file__).resolve().parents[1]
        / "data/validated-stales/namecoin_validated_stales.csv"
    )
    with path.open(newline="") as handle:
        row = next(r for r in csv.DictReader(handle) if r["btc_header_hash"] == key)
    assert row["btc_height"] == "183088"
    assert row["coinbase_outputs"] == restored
    assert len(parse_coinbase_output_claims(restored)) == 3


@pytest.mark.parametrize("chain", ["syscoin", "terracoin"])
def test_other_decoded_chains_keep_addressless_slots(chain):
    cell = "134vPp664VcocqouZeuSMZaXfquFyRLfQG:1.0|OP_RETURN:0.0|pubkey:2.0"
    claims = parse_coinbase_output_claims(normalize_outputs_cell(cell, chain=chain))
    assert [c.position for c in claims] == [0, 1, 2]
    assert all(c.position_exact for c in claims)
    assert claims[0].recipient_hash160
    assert claims[1].script_prefix_hex == "6a"
    assert claims[2].value_sats == 200000000
    assert not claims[2].script_hex


def test_recovered_p2pk_and_nulldata_feed_attribution(monkeypatch):
    p2pkh = bytes.fromhex("76a914" + recipient_hash160_for_script(P2PK) + "88ac")
    monkeypatch.setattr(
        pool_identification, "_RUNTIME_POOL_TAGS", [(b"Mined by", "TagPool")]
    )
    monkeypatch.setattr(
        pool_identification, "_RUNTIME_OUTPUT_ADDR_POOLS", {p2pkh: "PayoutPool"}
    )

    def identify(cell):
        return pool_identification.identify_pool_detailed(
            b"", output_claims=parse_coinbase_output_claims(cell)
        )

    assert identify("") == ("Unknown", "none")
    assert identify(P2PK) == ("PayoutPool", "address")
    assert identify(P2PK + ";" + NULLDATA) == (
        "TagPool",
        "op_return",
    )


def test_committed_namecoin_vectors_are_all_exact_and_complete():
    path = (
        Path(__file__).resolve().parents[1]
        / "data/validated-stales/namecoin_validated_stales.csv"
    )
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1649
    assert (
        sum(len(parse_coinbase_output_claims(r["coinbase_outputs"])) for r in rows)
        == 16610
    )
    for row in rows:
        claims = parse_coinbase_output_claims(row["coinbase_outputs"])
        assert claims, row["btc_header_hash"]
        assert all(c.position_exact and c.script_hex for c in claims)
        assert [c.position for c in claims] == list(range(len(claims)))


@pytest.mark.dataset
def test_restored_outputs_refine_every_published_namecoin_stale():
    from stale_blocks_analysis.monitor_publication import (
        _observation_refinement,
        _published_observation,
    )

    root = Path(__file__).resolve().parents[1]
    with (root / "data/validated-stales/namecoin_validated_stales.csv").open(
        newline=""
    ) as handle:
        restored = {
            r["btc_header_hash"]: r["coinbase_outputs"] for r in csv.DictReader(handle)
        }
    path = root / "results/monitor-evidence/namecoin_monitor_evidence.csv"
    seen = set()
    with path.open(newline="") as handle:
        for number, row in enumerate(csv.DictReader(handle), start=2):
            key = row["btc_header_hash"]
            if row["classification"] != "stale" or key not in restored:
                continue
            before = _published_observation(
                row, chain="namecoin", path=path, row_number=number
            )
            after = _published_observation(
                {**row, "coinbase_outputs": restored[key]},
                chain="namecoin",
                path=path,
                row_number=number,
            )
            assert _observation_refinement(before, after) == (True, ""), key
            seen.add(key)
    assert seen == restored.keys()
