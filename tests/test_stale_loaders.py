"""Contract tests for the stale-block loaders in stale_blocks.py.

Each test monkeypatches a module-level <chain>_CSV constant (the
globals()[spec.csv_attr] contract), writes a pinned fixture, and asserts the
gate behaviour and emitted record shape. Covers the default LoaderSpec path
(xaya), the exact-status contract that retains "VALID (post-BCH ...)"
rows (namecoin/i0coin), the addr-output OP_RETURN drop (syscoin/terracoin/
bitcoin-vault), and RSK's bespoke parallel schema.
"""

from __future__ import annotations

import csv

import pytest

from stale_blocks_analysis import stale_blocks
from stale_blocks_analysis.stale_descendants import StaleDescendantParent

EXCLUDED_HASH = "000000000000000010d43fb3f8d02cab156f333f2bfc172de9e6d87359118a1a"

# Modern 12-column validated-stales layout, matching run_classifier output.
_FIELDS = [
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "child_height",
    "classification",
    "validation_status",
    "expected_nbits",
]


def _row(**kw):
    base = {f: "" for f in _FIELDS}
    base.update(kw)
    return base


def _write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=_FIELDS)
        w.writeheader()
        w.writerows(rows)


def test_load_upstream_stales_applies_consensus_exclusion_overlay(
    tmp_path, monkeypatch
):
    csv_path = tmp_path / "stale-blocks.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["height", "hash", "header"])
        writer.writeheader()
        writer.writerow({"height": "331735", "hash": EXCLUDED_HASH, "header": ""})
        writer.writerow({"height": "331736", "hash": "aa", "header": ""})
    monkeypatch.setattr(stale_blocks, "STALE_CSV", csv_path)

    assert stale_blocks.load_stale_csv(min_height=0) == [
        {"height": 331736, "hash": "aa", "source": "stale-blocks"}
    ]


def test_load_xaya_stales_gate_and_shape(tmp_path, monkeypatch):
    csv_path = tmp_path / "xaya_validated_stales.csv"
    _write_csv(
        csv_path,
        [
            # (1) valid stale above the floor -> loaded
            _row(
                btc_height="600000",
                btc_header_hash="aa",
                btc_prev_hash="pp",
                btc_time="1531504550",
                btc_bits="17347a28",
                coinbase_scriptsig_hex="03abc",
                coinbase_outputs="76a914deadbeef88ac",
                btc_header_hex="00" * 80,
                child_height="901",
                classification="stale",
                validation_status="VALID",
                expected_nbits="17347a28",
            ),
            # (2) unknown -> dropped by require_stale
            _row(
                btc_height="600001",
                btc_header_hash="bb",
                btc_prev_hash="qq",
                classification="unknown",
                validation_status="VALID",
            ),
            # (3) stale but REJECTED -> dropped by the exact-status gate
            _row(
                btc_height="600002",
                btc_header_hash="cc",
                btc_prev_hash="rr",
                classification="stale",
                validation_status="REJECTED: nBits mismatch (BCH/BSV)",
            ),
            # (4) valid stale below the floor -> dropped by min_height
            _row(
                btc_height="100000",
                btc_header_hash="dd",
                btc_prev_hash="ss",
                classification="stale",
                validation_status="VALID",
            ),
        ],
    )
    monkeypatch.setattr(stale_blocks, "XAYA_CSV", csv_path)

    recs = stale_blocks.load_xaya_stales(min_height=500000)

    # Only the single VALID stale above the floor survives all gates.
    assert len(recs) == 1
    r = recs[0]
    assert r["height"] == 600000
    assert r["hash"] == "aa"
    assert r["source"] == "xaya"
    # outputs="raw": coinbase_outputs passes through untouched.
    assert r["_scriptsig_hex"] == "03abc"
    assert r["_outputs_str"] == "76a914deadbeef88ac"


def test_loader_drops_blank_validation_status(tmp_path, monkeypatch):
    csv_path = tmp_path / "xaya_validated_stales.csv"
    _write_csv(
        csv_path,
        [
            _row(
                btc_height="600000",
                btc_header_hash="aa",
                classification="stale",
                validation_status="",
            )
        ],
    )
    monkeypatch.setattr(stale_blocks, "XAYA_CSV", csv_path)

    assert stale_blocks.load_xaya_stales(min_height=0) == []


def test_load_xaya_stales_missing_csv_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(stale_blocks, "XAYA_CSV", tmp_path / "does_not_exist.csv")
    assert stale_blocks.load_xaya_stales(min_height=0) == []


@pytest.mark.parametrize(
    ("csv_attr", "loader_name", "source"),
    [
        ("LYNCOIN_CSV", "load_lyncoin_stales", "lyncoin"),
        ("SIXELEVEN_CSV", "load_sixeleven_stales", "sixeleven"),
    ],
)
def test_header_only_chain_loaders_follow_shared_contract(
    tmp_path, monkeypatch, csv_attr, loader_name, source
):
    csv_path = tmp_path / f"{source}_validated_stales.csv"
    _write_csv(csv_path, [])
    monkeypatch.setattr(stale_blocks, csv_attr, csv_path)

    assert getattr(stale_blocks, loader_name)(min_height=0) == []


def test_load_namecoin_stales_exact_validation_keeps_post_bch_rows(
    tmp_path, monkeypatch
):
    # The shared exact-status gate retains the committed
    # "VALID (post-BCH, difficulty matches BTC)" rows. A dispatch refactor
    # that flipped Namecoin to "strict" would silently drop them; this pins
    # the contract without freezing a dataset count in a loader test.
    csv_path = tmp_path / "namecoin_validated_stales.csv"
    _write_csv(
        csv_path,
        [
            _row(
                btc_height="500000",
                btc_header_hash="aa",
                classification="stale",
                validation_status="VALID",
            ),
            _row(
                btc_height="500001",
                btc_header_hash="bb",
                classification="stale",
                validation_status="VALID (post-BCH, difficulty matches BTC)",
            ),
            _row(
                btc_height="500002",
                btc_header_hash="cc",
                classification="stale",
                validation_status="REJECTED: nBits mismatch",
            ),
            _row(
                btc_height="500003",
                btc_header_hash="dd",
                classification="stale",
                validation_status="VALID_BOGUS",
            ),
            _row(
                btc_height="331735",
                btc_header_hash=EXCLUDED_HASH,
                classification="stale",
                validation_status="VALID",
            ),
        ],
    )
    monkeypatch.setattr(stale_blocks, "AUXPOW_CSV", csv_path)

    recs = stale_blocks.load_namecoin_stales(min_height=0)

    assert [r["hash"] for r in recs] == [
        "aa",
        "bb",
    ]  # Rejected and invented-prefix rows are dropped; both exact statuses remain.
    assert all(r["source"] == "namecoin" for r in recs)


def test_parse_addr_outputs_drops_op_return_and_nonstandard():
    from stale_blocks_analysis.stale_blocks import _parse_addr_outputs

    # Pipe-delimited "addr:value" pairs collapse to a ";"-joined address list;
    # OP_RETURN and empty tokens are always dropped. This transform preserves
    # the established loader shape for syscoin/terracoin/bitcoin-vault rows.
    assert _parse_addr_outputs("A:1|B:2|OP_RETURN:0") == "A;B"
    assert _parse_addr_outputs("|A:1||") == "A"
    # drop_nonstandard (addr_nonstandard mode) additionally removes nonstandard* outputs.
    assert (
        _parse_addr_outputs("A:1|nonstandard_x:0|B:2", drop_nonstandard=True) == "A;B"
    )
    assert _parse_addr_outputs("A:1|nonstandard_x:0|B:2") == "A;nonstandard_x;B"


def test_load_rsk_stales_parallel_schema_ignores_historical_pool_labels(
    tmp_path, monkeypatch
):
    # Historical RSK files may contain pool_label, but the recovery loader does
    # not expose it as part of the current public pipeline.
    fields = [
        "btc_height",
        "btc_header_hash",
        "classification",
        "validation_status",
        "pool_label",
    ]
    csv_path = tmp_path / "rsk_validated_stales.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerow(
            {
                "btc_height": "600000",
                "btc_header_hash": "aa",
                "classification": "stale",
                "validation_status": "VALID",
                "pool_label": "Foundry USA",
            }
        )
        w.writerow(
            {
                "btc_height": "600001",
                "btc_header_hash": "bb",
                "classification": "stale",
                "validation_status": "VALID",
                "pool_label": "",
            }
        )
        w.writerow(
            {
                "btc_height": "600002",
                "btc_header_hash": "cc",
                "classification": "unknown",
                "validation_status": "VALID",
                "pool_label": "x",
            }
        )
        w.writerow(
            {
                "btc_height": "331735",
                "btc_header_hash": EXCLUDED_HASH,
                "classification": "stale",
                "validation_status": "VALID",
                "pool_label": "AntPool",
            }
        )
        w.writerow(
            {
                "btc_height": "600003",
                "btc_header_hash": "dd",
                "classification": "stale",
                "validation_status": "",
                "pool_label": "",
            }
        )
    monkeypatch.setattr(stale_blocks, "RSK_CSV", csv_path)

    recs = stale_blocks.load_rsk_stales(min_height=0)

    assert [r["hash"] for r in recs] == ["aa", "bb"]  # unknown dropped
    assert recs == [
        {"height": 600000, "hash": "aa", "source": "rsk"},
        {"height": 600001, "hash": "bb", "source": "rsk"},
    ]
    assert all(r["source"] == "rsk" for r in recs)
    assert all("_scriptsig_hex" not in r for r in recs)  # coinbase fields omitted


def test_load_stale_descendants_uses_canonical_parents_and_invalid_gate(
    monkeypatch,
):
    rows = {
        (331735, EXCLUDED_HASH): StaleDescendantParent(331735, EXCLUDED_HASH, 2, {}),
        (331736, "aa" * 32): StaleDescendantParent(331736, "aa" * 32, 3, {}),
    }
    monkeypatch.setattr(
        stale_blocks,
        "load_stale_descendant_parents",
        lambda _path: rows,
    )

    assert stale_blocks.load_stale_descendants(min_height=0) == [
        {
            "height": 331736,
            "hash": "aa" * 32,
            "source": "stale-descendant",
            "_scriptsig_hex": "",
            "_outputs_str": "",
        }
    ]


def test_stale_descendant_tagging_reads_canonical_script_value_outputs() -> None:
    payout = "76a914fb37342f6275b13936799def06f2eb4c0f20151588ac"
    op_return = "6a01ff"

    assert (
        stale_blocks._outputs_for_tagging(
            f"{payout}:313110129|{op_return}:0|6a*:0|:100"
        )
        == f"{payout};{op_return}"
    )
