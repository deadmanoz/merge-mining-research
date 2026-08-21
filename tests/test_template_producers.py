"""Tests for the tag-owner-to-template-producer fold."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from stale_blocks_analysis.config import LOCAL_MINING_POOLS_DIR
from stale_blocks_analysis import template_producers
from stale_blocks_analysis.template_producers import (
    TEMPLATE_PRODUCER_MAP,
    fold_template_producer,
)


def test_in_window_fold() -> None:
    assert fold_template_producer("AntPool", 850_000) == "AntPool & friends"


def test_passthrough_outside_window_and_for_unmapped_tags() -> None:
    assert fold_template_producer("AntPool", 500_000) == "AntPool"
    for height in (700_000, 850_000, 900_000):
        assert fold_template_producer("SpiderPool", height) == "SpiderPool"


def test_boundary_semantics_inclusive_from_exclusive_to(monkeypatch) -> None:
    # A synthetic closed-window entry exercises both boundary edges without
    # coupling the test to any committed row's specific window.
    synthetic_map = (
        {
            "tag_label": "TestPool",
            "template_producer": "Folded TestPool",
            "valid_from_height": 100,
            "valid_to_height": 200,
            "evidence": "synthetic entry for boundary testing",
        },
    )
    monkeypatch.setattr(template_producers, "TEMPLATE_PRODUCER_MAP", synthetic_map)

    assert fold_template_producer("TestPool", 100) == "Folded TestPool"
    assert fold_template_producer("TestPool", 199) == "Folded TestPool"
    assert fold_template_producer("TestPool", 200) == "TestPool"
    assert fold_template_producer("TestPool", 99) == "TestPool"


def test_unknown_always_passes_through() -> None:
    for height in (0, 500_000, 850_000, 10_000_000):
        assert fold_template_producer("Unknown", height) == "Unknown"
    # An unmapped name (not "Unknown", not any tag_label) also passes through.
    assert fold_template_producer("SomePoolNotInTheTable", 850_000) == (
        "SomePoolNotInTheTable"
    )


def test_ocean_xyz_registry_name_not_shorthand() -> None:
    # Non-custodial-template pools are deliberately NOT table rows: their
    # tags pass through unchanged at every height (see table note (c)).
    for height in (700_000, 850_000, 950_000):
        assert fold_template_producer("Ocean.xyz", height) == "Ocean.xyz"


def test_table_integrity() -> None:
    windows_by_tag: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for entry in TEMPLATE_PRODUCER_MAP:
        valid_to = entry["valid_to_height"]
        upper = valid_to if valid_to is not None else float("inf")
        assert entry["valid_from_height"] < upper

        evidence = entry["evidence"]
        assert evidence
        assert "0xB10C" in evidence or "obs 12" in evidence or "methodology" in evidence

        windows_by_tag[entry["tag_label"]].append((entry["valid_from_height"], upper))

    for tag_label, windows in windows_by_tag.items():
        for i, (start_a, end_a) in enumerate(windows):
            for start_b, end_b in windows[i + 1 :]:
                overlap = start_a < end_b and start_b < end_a
                assert not overlap, (
                    f"overlapping windows for tag_label={tag_label!r}: "
                    f"{(start_a, end_a)} vs {(start_b, end_b)}"
                )


@pytest.mark.skipif(
    not (LOCAL_MINING_POOLS_DIR / "pools").is_dir(),
    reason="bitcoin-data/mining-pools clone not fetched under data/mining-pools",
)
def test_tag_labels_match_pinned_registry_names() -> None:
    registry_names = {
        json.load(open(p))["name"]
        for p in Path(LOCAL_MINING_POOLS_DIR).glob("pools/*.json")
    }
    for entry in TEMPLATE_PRODUCER_MAP:
        assert entry["tag_label"] in registry_names, (
            f"tag_label {entry['tag_label']!r} not found in pinned "
            "bitcoin-data/mining-pools registry"
        )


def test_cluster_folds_end_when_their_cited_measurements_end() -> None:
    antpool = next(
        e
        for e in template_producers.TEMPLATE_PRODUCER_MAP
        if e["tag_label"] == "AntPool"
    )
    cap = antpool["valid_to_height"]
    assert cap is not None
    assert fold_template_producer("AntPool", cap - 1) == "AntPool & friends"
    assert fold_template_producer("AntPool", cap) == "AntPool"
    # The committed corpus contains an AntPool-tagged stale at 946,470
    # (April 2026), later than any measurement the table cites: left as-is.
    assert fold_template_producer("AntPool", 946_470) == "AntPool"
    # Every row has an end height: no fold extends past its measurements.
    open_rows = [
        e["tag_label"]
        for e in template_producers.TEMPLATE_PRODUCER_MAP
        if e["valid_to_height"] is None
    ]
    assert open_rows == []
