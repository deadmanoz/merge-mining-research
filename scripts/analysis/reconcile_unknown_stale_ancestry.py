#!/usr/bin/env python3
"""Reconcile AuxPoW unknown BTC parents against known BTC stale headers."""

from __future__ import annotations

import argparse
import os
import re
import sys
from functools import partial
from pathlib import Path

from stale_blocks_analysis.ancestry_walk import (
    WalkResult,
    classify_walks,
    is_mainchain,
    path_for,
)
from stale_blocks_analysis.btc_rpc import BtcRpc, get_btc_auth
from stale_blocks_analysis.config import BITCOIN_EPOCH_REFERENCE_DIR
from stale_blocks_analysis.error_blocks import (
    load_consensus_invalid_stale_keys,
    load_stale_exclusion_keys,
)
from stale_blocks_analysis.full_evidence import (
    int_or_none,
    is_hash,
    normalize_hash,
)
from stale_blocks_analysis.reconcile_observations import (
    discover_canonical_files,
    discover_chain_names,
    fetch_active_hashes_by_height,
    fetch_mainchain_status,
    load_epoch_bits,
    load_mainchain_cache,
    load_observations,
    rel,
)
from stale_blocks_analysis.reconcile_publication import (
    PARENT_VERDICTS_CSV,
    PublicationBaseline,
    descendant_bip34_verdict,
    load_publication_baseline,
    render_and_publish,
    validate_output_mode,
    validate_publication_discovery,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RESULTS_DIR = PROJECT_ROOT / "results" / "analysis" / "stale-ancestry"
CACHE_DIR = PROJECT_ROOT / "cache"


def build_parser() -> argparse.ArgumentParser:
    """Build the reconciliation CLI parser."""
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    parser.add_argument(
        "--epoch-reference-dir", type=Path, default=BITCOIN_EPOCH_REFERENCE_DIR
    )
    parser.add_argument("--parent-verdicts-csv", type=Path, required=True)
    parser.add_argument("--observations-csv", type=Path, required=True)
    parser.add_argument("--error-candidates-csv", type=Path, required=True)
    parser.add_argument("--max-depth", type=int, default=10_000)
    parser.add_argument("--check-mainchain", action="store_true")
    parser.add_argument(
        "--rpc-url", default=os.environ.get("BTC_RPC_URL", "http://127.0.0.1:8332")
    )
    parser.add_argument("--rpc-user", default=None)
    parser.add_argument("--rpc-pass", default=None)
    parser.add_argument(
        "--rpc-source-label",
        default=os.environ.get("BTC_RPC_SOURCE_LABEL"),
        help="stable non-secret node label persisted with Core RPC verification",
    )
    parser.add_argument("--rpc-batch-size", type=int, default=500)
    parser.add_argument("--max-mainchain-rpc", type=int, default=0)
    parser.add_argument("--allow-partial", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> None:
    """Coordinate observation loading, ancestry traversal, and publication."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.rpc_source_label is None:
        if args.allow_partial:
            args.rpc_source_label = "configured-node"
        else:
            parser.error(
                "publication reconciliation requires --rpc-source-label with "
                "a stable non-secret node identity"
            )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.rpc_source_label):
        parser.error(
            "--rpc-source-label must contain only letters, digits, '.', '_' "
            "or '-' and be at most 64 characters"
        )
    if not args.allow_partial and args.rpc_source_label == "configured-node":
        parser.error(
            "publication reconciliation requires a specific --rpc-source-label; "
            "'configured-node' is diagnostic-only"
        )
    validate_output_mode(
        args,
        parser,
        results_dir_default=RESULTS_DIR,
        parent_verdicts_csv_default=PARENT_VERDICTS_CSV,
    )
    publication_baseline: PublicationBaseline | None = None
    if args.allow_partial:
        print(
            "WARNING: running a partial ancestry reconciliation; do not replace publication artifacts with these outputs",
            file=sys.stderr,
        )
    else:
        if not args.check_mainchain:
            parser.error(
                "publication reconciliation requires --check-mainchain so every "
                "candidate and trusted root is compared with Bitcoin Core's "
                "active hash at its exact height"
            )
        try:
            publication_baseline = load_publication_baseline(PARENT_VERDICTS_CSV)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))

    chain_names, full_files, unknown_files, validated_files = discover_chain_names(
        args.data_dir
    )
    canonical_files = discover_canonical_files(args.data_dir)
    chain_names.update(canonical_files)
    if publication_baseline is not None:
        validate_publication_discovery(
            publication_baseline,
            full_files,
            unknown_files,
            canonical_files,
            parser,
        )
    epoch_bits = load_epoch_bits(args.epoch_reference_dir / "btc_nbits_by_epoch.json")
    try:
        state = load_observations(
            data_dir=args.data_dir,
            chain_names=chain_names,
            full_files=full_files,
            unknown_files=unknown_files,
            canonical_files=canonical_files,
            validated_files=validated_files,
            epoch_bits=epoch_bits,
            excluded_keys=load_stale_exclusion_keys(),
            consensus_invalid_keys=load_consensus_invalid_stale_keys(),
        )
    except ValueError as exc:
        parser.error(str(exc))
    mainchain_cache = load_mainchain_cache(args.cache_dir)

    mainchain_lookup = partial(is_mainchain, mainchain_cache=mainchain_cache)

    conflicting_unknown_prevs = {
        block_hash
        for block_hash, prevs in state["unknown_prevs_by_hash"].items()
        if len(prevs) > 1
    }
    walk_args = {
        "unknown_row_counts_by_hash": state["unknown_row_counts_by_hash"],
        "unknown_prev_by_hash": state["unknown_prev_by_hash"],
        "conflicting_unknown_prevs": conflicting_unknown_prevs,
        "unknown_prev_chains": state["unknown_prev_chains"],
        "all_hash_chains": state["all_hash_chains"],
        "known_stale_hashes": state["known_stale_hashes"],
        "consensus_invalid_hashes": state["consensus_invalid_hashes"],
        "is_mainchain": mainchain_lookup,
        "max_depth": args.max_depth,
    }
    walk_results = classify_walks(**walk_args)
    mainchain_cache_dirty = False
    if args.check_mainchain:
        rpc = BtcRpc(url=args.rpc_url, auth=get_btc_auth(args.rpc_user, args.rpc_pass))
        # Partial diagnostics may resolve dangling terminals to explore the
        # wider candidate population. Publication does not: its classification
        # floor is the trusted-root path, and querying every unrelated unknown
        # hash would turn a 33-height active-chain proof into hundreds of
        # thousands of unnecessary getblockheader calls.
        if publication_baseline is None:
            terminals = {
                result.terminal_hash
                for result in walk_results.values()
                if result.terminal_kind in {"dangling_unknown", "cross_seen_root"}
            }
            terminals = sorted(
                block_hash
                for block_hash in terminals
                if block_hash not in mainchain_cache
            )
            if args.max_mainchain_rpc:
                terminals = terminals[: args.max_mainchain_rpc]
            fetched = fetch_mainchain_status(terminals, rpc, args.rpc_batch_size)
            if fetched:
                mainchain_cache.update(fetched)
                mainchain_cache_dirty = True
                walk_results = classify_walks(**walk_args)
        comparison_heights: dict[str, int] = {}
        for block_hash, result in walk_results.items():
            if result.category not in {"direct_stale_child", "stale_descendant"}:
                continue
            root_heights = {
                int(observation.btc_height)
                for observation in state["stale_by_hash"][result.terminal_hash]
                if int_or_none(observation.btc_height) is not None
            }
            if len(root_heights) != 1:
                parser.error(
                    "cannot authenticate active-chain exclusion with an "
                    f"ambiguous trusted-root height for {result.terminal_hash}"
                )
            root_height = next(iter(root_heights))
            inferred_height = root_height + result.depth
            prior_height = comparison_heights.setdefault(block_hash, inferred_height)
            if prior_height != inferred_height:
                parser.error(f"conflicting inferred heights for {block_hash}")
            comparison_heights.setdefault(result.terminal_hash, root_height)
        compared = fetch_active_hashes_by_height(
            comparison_heights,
            rpc,
            args.rpc_batch_size,
            verification_label=args.rpc_source_label,
        )
        if compared:
            mainchain_cache.update(compared)
            mainchain_cache_dirty = True
            active_hashes = {
                block_hash
                for block_hash, status in compared.items()
                if status.get("on_mainchain")
            }
            # A source incorrectly placed in the validated-stale set cannot
            # remain a trusted root after the exact height comparison proves
            # it active. Rewalk with those roots removed. The generic walker
            # checks predecessors, so mark an active start node explicitly as
            # mainchain too; its descendants are caught naturally when they
            # encounter it as their predecessor.
            state["known_stale_hashes"] = state["known_stale_hashes"] - active_hashes
            state["auxpow_stale_hashes"] = state["auxpow_stale_hashes"] - active_hashes
            walk_args["known_stale_hashes"] = state["known_stale_hashes"]
            walk_results = classify_walks(**walk_args)
            for block_hash in active_hashes & set(walk_results):
                walk_results[block_hash] = WalkResult("mainchain", block_hash, 0)

    if publication_baseline is not None:
        unverified: list[tuple[str, str]] = []
        for block_hash, result in sorted(walk_results.items()):
            if result.category not in {"direct_stale_child", "stale_descendant"}:
                continue
            root_heights = {
                int(observation.btc_height)
                for observation in state["stale_by_hash"][result.terminal_hash]
                if int_or_none(observation.btc_height) is not None
            }
            root_height = next(iter(root_heights)) if len(root_heights) == 1 else -1
            for role, candidate_hash, expected_height in (
                ("candidate", block_hash, root_height + result.depth),
                ("trusted_root", result.terminal_hash, root_height),
            ):
                status = mainchain_cache.get(candidate_hash)
                source = str((status or {}).get("verification_source") or "")
                active_hash = normalize_hash(
                    str((status or {}).get("active_hash_at_height") or "")
                )
                if (
                    not status
                    or source.startswith("bitcoin-core-rpc:") is False
                    or int_or_none(str(status.get("height"))) != expected_height
                    or not is_hash(active_hash)
                    or active_hash == candidate_hash
                ):
                    unverified.append((role, candidate_hash))
        if unverified:
            role, block_hash = unverified[0]
            parser.error(
                "refusing a stale-descendant verdict without exact Bitcoin Core "
                f"off-active-chain evidence ({len(unverified)} missing/active; "
                f"first {role}:{block_hash}); rerun with --check-mainchain and "
                "an authenticated Core RPC"
            )

    def report_path(block_hash: str) -> list[str]:
        return path_for(
            block_hash,
            unknown_prev_by_hash=state["unknown_prev_by_hash"],
            known_stale_hashes=state["known_stale_hashes"],
            consensus_invalid_hashes=state["consensus_invalid_hashes"],
            is_mainchain=mainchain_lookup,
        )

    summary = render_and_publish(
        args=args,
        parser=parser,
        data_dir=args.data_dir,
        results_dir=args.results_dir,
        cache_dir=args.cache_dir,
        publication_baseline=publication_baseline,
        epoch_bits=epoch_bits,
        stale_by_hash=state["stale_by_hash"],
        known_stale_hashes=state["known_stale_hashes"],
        consensus_invalid_heights_by_hash=state["consensus_invalid_heights_by_hash"],
        auxpow_stale_hashes=state["auxpow_stale_hashes"],
        upstream_count=state["upstream_count"],
        unknown_rows=state["unknown_rows"],
        unknown_row_counts_by_hash=state["unknown_row_counts_by_hash"],
        unknown_chains_by_hash=state["unknown_chains_by_hash"],
        unknown_example_by_hash=state["unknown_example_by_hash"],
        unknown_observations_by_hash=state["unknown_observations_by_hash"],
        inventory_rows=state["inventory_rows"],
        anomalies=state["anomalies"],
        walk_results=walk_results,
        path_for=report_path,
        mainchain_cache=mainchain_cache,
        mainchain_cache_dirty=mainchain_cache_dirty,
        rel_fn=rel,
        descendant_bip34_verdict_fn=descendant_bip34_verdict,
    )
    print(__import__("json").dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
