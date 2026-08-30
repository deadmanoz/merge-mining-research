"""Ancestry traversal for stale-ancestry reconciliation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WalkResult:
    """Outcome of walking an unknown header's prev-hash chain to its terminal node.

    `terminal_kind` is the raw walk outcome (`known_stale`, `mainchain`,
    `consensus_invalid`, `cross_seen_root`, `cycle_or_bad_data`, or
    `dangling_unknown`);
    `terminal_hash` is the hash the walk stopped at; `depth` is the number of
    prev-hash hops from the walk's start to that terminal. `category` derives
    the reporting bucket from `terminal_kind` (see its docstring).
    """

    terminal_kind: str
    terminal_hash: str
    depth: int

    @property
    def category(self) -> str:
        """Map `terminal_kind` to the reporting category used in output rows.

        `known_stale` becomes `direct_stale_child` at depth 1 (the unknown
        row's own prev-hash is a known stale) or `stale_descendant` at
        greater depth; `mainchain` becomes `mainchain_descendant`;
        `cross_seen_root` becomes `unknown_root_seen_elsewhere`;
        `consensus_invalid` becomes `consensus_invalid_descendant`;
        `cycle_or_bad_data` passes through unchanged; and anything else is
        `dangling_unknown`.
        """
        if self.terminal_kind == "known_stale":
            return "direct_stale_child" if self.depth == 1 else "stale_descendant"
        if self.terminal_kind == "mainchain":
            return "mainchain_descendant"
        if self.terminal_kind == "consensus_invalid":
            return "consensus_invalid_descendant"
        if self.terminal_kind == "cross_seen_root":
            return "unknown_root_seen_elsewhere"
        if self.terminal_kind == "cycle_or_bad_data":
            return "cycle_or_bad_data"
        return "dangling_unknown"


def is_mainchain(block_hash: str, mainchain_cache: dict[str, dict]) -> bool:
    """Return whether a cached header is on Bitcoin's active chain."""
    value = mainchain_cache.get(block_hash)
    return bool(value and value.get("on_mainchain"))


def classify_walks(
    *,
    unknown_row_counts_by_hash: dict[str, int],
    unknown_prev_by_hash: dict[str, str],
    conflicting_unknown_prevs: set[str],
    unknown_prev_chains: dict[str, set[str]],
    all_hash_chains: dict[str, set[str]],
    known_stale_hashes: set[str],
    consensus_invalid_hashes: set[str],
    is_mainchain: Callable[[str], bool],
    max_depth: int,
) -> dict[str, WalkResult]:
    """Resolve each unknown header to a memoized terminal walk result."""
    memo: dict[str, WalkResult] = {}

    def cross_seen_root(block_hash: str) -> bool:
        if len(unknown_prev_chains.get(block_hash, set())) > 1:
            return True
        header_chains = all_hash_chains.get(block_hash, set())
        return len(header_chains) > 1 and block_hash not in known_stale_hashes

    def resolve(start: str) -> WalkResult:
        if start in memo:
            return memo[start]
        path: list[str] = []
        seen: dict[str, int] = {}
        current = start

        def assign(kind: str, terminal_hash: str, base_depth: int = 0) -> WalkResult:
            for idx, node in enumerate(path):
                memo[node] = WalkResult(
                    kind, terminal_hash, len(path) - idx + base_depth
                )
            return memo[start]

        while True:
            if current in memo:
                base = memo[current]
                return assign(base.terminal_kind, base.terminal_hash, base.depth)
            if current in seen:
                return assign("cycle_or_bad_data", current)
            seen[current] = len(path)
            path.append(current)
            if (
                current in conflicting_unknown_prevs
                or current not in unknown_prev_by_hash
            ):
                return assign("cycle_or_bad_data", current)
            prev_hash = unknown_prev_by_hash[current]
            # Error-catalogue membership has precedence over every source
            # bucket and over stale-root placement. A child of a
            # consensus-invalid block cannot become a valid stale descendant,
            # even when the child header independently passes its own gates.
            if prev_hash in consensus_invalid_hashes:
                return assign("consensus_invalid", prev_hash)
            if prev_hash in known_stale_hashes:
                return assign("known_stale", prev_hash)
            if is_mainchain(prev_hash):
                return assign("mainchain", prev_hash)
            if (
                prev_hash in unknown_prev_by_hash
                or prev_hash in conflicting_unknown_prevs
            ):
                current = prev_hash
                if len(path) >= max_depth:
                    return assign("cycle_or_bad_data", prev_hash)
                continue
            if cross_seen_root(prev_hash):
                return assign("cross_seen_root", prev_hash)
            return assign("dangling_unknown", prev_hash)

    for block_hash in sorted(unknown_row_counts_by_hash):
        resolve(block_hash)
    return memo


def path_for(
    start: str,
    *,
    unknown_prev_by_hash: dict[str, str],
    known_stale_hashes: set[str],
    consensus_invalid_hashes: set[str],
    is_mainchain: Callable[[str], bool],
) -> list[str]:
    """Rebuild one concrete prev-hash path for report rendering."""
    path: list[str] = []
    current = start
    seen: set[str] = set()
    while current and current not in seen and current in unknown_prev_by_hash:
        seen.add(current)
        path.append(current)
        prev_hash = unknown_prev_by_hash[current]
        if (
            prev_hash in consensus_invalid_hashes
            or prev_hash in known_stale_hashes
            or is_mainchain(prev_hash)
        ):
            path.append(prev_hash)
            break
        current = prev_hash
    return path
