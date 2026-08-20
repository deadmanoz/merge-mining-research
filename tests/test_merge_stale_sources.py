"""Unit tests for merge_stale_sources, the (height, hash) dedup primitive.

Per the research semantics in AGENTS.md: dedup is by (height, hash) not height
alone, so competing same-height stale hashes are both preserved; the primary
(bitcoin-data/stale-blocks) record wins on exact duplicates, carrying AuxPoW
coinbase fields as fallback attribution evidence.
"""

from __future__ import annotations

from stale_blocks_analysis.stale_merge import merge_stale_sources


def _rec(height, hash_, **extra):
    r = {"height": height, "hash": hash_, "source": "x"}
    r.update(extra)
    return r


def test_disjoint_records_all_kept_and_sorted_by_height():
    merged = merge_stale_sources([_rec(200, "b")], [_rec(100, "a")])
    assert [(r["height"], r["hash"]) for r in merged] == [(100, "a"), (200, "b")]


def test_exact_duplicate_primary_wins_and_is_enriched():
    primary = [_rec(100, "a", source="stale-blocks")]  # no _scriptsig_hex
    auxpow = [_rec(100, "a", source="auxpow", _scriptsig_hex="dead", _outputs_str="o")]
    merged = merge_stale_sources(primary, auxpow)
    assert len(merged) == 1
    assert merged[0]["source"] == "stale-blocks"  # primary identity preserved
    assert merged[0]["_scriptsig_hex"] == "dead"  # AuxPoW coinbase carried as fallback
    assert merged[0]["_outputs_str"] == "o"


def test_competing_same_height_hashes_are_both_kept():
    merged = merge_stale_sources([_rec(100, "a")], [_rec(100, "b")])
    assert sorted((r["height"], r["hash"]) for r in merged) == [(100, "a"), (100, "b")]


def test_existing_primary_coinbase_is_not_overwritten():
    primary = [_rec(100, "a", _scriptsig_hex="keep")]
    auxpow = [_rec(100, "a", _scriptsig_hex="new", _outputs_str="o")]
    merged = merge_stale_sources(primary, auxpow)
    assert len(merged) == 1
    assert merged[0]["_scriptsig_hex"] == "keep"


def test_new_auxpow_record_is_added_verbatim():
    primary = [_rec(100, "a")]
    auxpow = [_rec(300, "c", source="auxpow", _scriptsig_hex="cc")]
    merged = merge_stale_sources(primary, auxpow)
    added = [r for r in merged if r["hash"] == "c"]
    assert added and added[0]["source"] == "auxpow"
    assert added[0]["_scriptsig_hex"] == "cc"


def test_empty_auxpow_returns_primary_unchanged():
    primary = [_rec(100, "a"), _rec(50, "z")]
    merged = merge_stale_sources(primary, [])
    assert [(r["height"], r["hash"]) for r in merged] == [(50, "z"), (100, "a")]


def test_tag_stale_blocks_preserves_pretagged_rows(monkeypatch):
    from stale_blocks_analysis import stale_merge

    monkeypatch.setattr(
        stale_merge,
        "identify_pool",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not be called")),
    )
    rows = [
        {
            "height": 1,
            "hash": "aa",
            "source": "rsk",
            "pool": "HistoricalPool",
            "_scriptsig_hex": "ff",
            "_outputs_str": "x",
        }
    ]
    out = stale_merge.tag_stale_blocks(rows)
    assert out[0]["pool"] == "HistoricalPool"
    assert out[0]["has_bin"] is False
    assert "_scriptsig_hex" not in out[0] and "_outputs_str" not in out[0]


def test_tag_stale_blocks_auxpow_fallback_passes_coinbase_to_identify(monkeypatch):
    from stale_blocks_analysis import stale_merge

    seen = {}

    def fake_identify(sig, outputs=None):
        seen["sig"] = sig
        seen["outputs"] = outputs
        return "FallbackPool"

    monkeypatch.setattr(stale_merge, "identify_pool", fake_identify)
    # Height/hash chosen so no BLOCKS_DIR .bin file can exist.
    rows = [
        {
            "height": 999999999,
            "hash": "00" * 32,
            "source": "auxpow",
            "_scriptsig_hex": "deadbeef",
            "_outputs_str": "",
        }
    ]
    out = stale_merge.tag_stale_blocks(rows)
    assert out[0]["pool"] == "FallbackPool"
    assert out[0]["has_bin"] is False
    assert seen["sig"] == bytes.fromhex("deadbeef")
    assert seen["outputs"] is None
