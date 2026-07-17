"""Unit tests for compute_views in scripts/compute_chain_novelty.py.

scripts/ is not a package, so the module is loaded by path (mirroring
test_hathor_reconstruction.py / test_classifier_wrappers.py). The novelty logic
is driven with synthetic chains injected via the module-level LOADERS,
load_stale_csv, and CHAINS_BY_AUXPOW_ACTIVATION so the chronological-precedence
rule (earlier-born chain wins) is pinned deterministically, with no dependency
on committed or fetched data.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "compute_chain_novelty.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("compute_chain_novelty", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _rec(height, hash_):
    return {"height": height, "hash": hash_}


def _install_synthetic(mod, monkeypatch):
    # early-born chain claims (100,a) and (200,b); late chain restates (200,b)
    # and adds (300,c),(400,d). Upstream contains only (100,a).
    early = [_rec(100, "a"), _rec(200, "b")]
    late = [_rec(200, "b"), _rec(300, "c"), _rec(400, "d")]
    upstream = [_rec(100, "a")]
    monkeypatch.setattr(
        mod,
        "LOADERS",
        {
            "early": lambda min_height=0: [dict(r) for r in early],
            "late": lambda min_height=0: [dict(r) for r in late],
        },
    )
    monkeypatch.setattr(
        mod, "load_stale_csv", lambda min_height=0: [dict(r) for r in upstream]
    )
    monkeypatch.setattr(
        mod, "CHAINS_BY_AUXPOW_ACTIVATION", [("early", None), ("late", None)]
    )


def test_chronological_precedence_earlier_chain_wins(monkeypatch):
    mod = _load_module()
    _install_synthetic(mod, monkeypatch)
    s = mod.compute_views("late", write_csv=False)

    assert s["total_validated"] == 3  # b, c, d
    # isolated view: none of late's hashes are in upstream (which has only a)
    assert s["isolated"]["also_in_upstream"] == 0
    assert s["isolated"]["novel_vs_upstream"] == 3
    # cumulative view: b was claimed by the earlier-born chain
    assert s["cumulative"]["also_in_earlier_chain"] == 1
    assert s["cumulative"]["novel_at_this_position"] == 2  # c, d
    assert s["cumulative"]["earlier_chain_breakdown"] == {"early": 1}
    assert s["earlier_chains_consulted"] == ["early"]


def test_first_chronological_chain_has_no_earlier_claims(monkeypatch):
    mod = _load_module()
    _install_synthetic(mod, monkeypatch)
    s = mod.compute_views("early", write_csv=False)

    assert s["total_validated"] == 2  # a, b
    assert s["isolated"]["also_in_upstream"] == 1  # a is in upstream
    assert s["cumulative"]["also_in_earlier_chain"] == 0  # position 0, nothing earlier
    assert s["cumulative"]["novel_at_this_position"] == 1  # only b (a is upstream)


def test_unknown_chain_exits(monkeypatch):
    mod = _load_module()
    _install_synthetic(mod, monkeypatch)
    with pytest.raises(SystemExit):
        mod.compute_views("nonexistent", write_csv=False)
