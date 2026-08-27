#!/usr/bin/env python3
"""Reconcile AuxPoW unknown BTC parents against known BTC stale headers."""

from __future__ import annotations

import argparse
import os
import sys
from functools import partial
from pathlib import Path

from stale_blocks_analysis.ancestry_walk import (
    WalkResult,
    classify_walks,
    is_mainchain,
    path_for,
)  # noqa: F401
from stale_blocks_analysis.btc_rpc import BtcRpc, get_btc_auth
from stale_blocks_analysis.config import BITCOIN_EPOCH_REFERENCE_DIR
from stale_blocks_analysis.error_blocks import (
    load_consensus_invalid_stale_keys,
    load_stale_exclusion_keys,
)
from stale_blocks_analysis.full_evidence import (  # noqa: F401
    first_present,
    get_value,
    int_or_none,
    is_hash,
    load_namecoin_header_hexes,
    normalize_hash,
)
from stale_blocks_analysis.reconcile_observations import (  # noqa: F401
    BITS_COLUMNS,
    BTC_HEIGHT_COLUMNS,
    HASH_COLUMNS,
    HEADER_HEX_COLUMNS,
    NON_CHILD_HEIGHT_COLUMNS,
    PREV_COLUMNS,
    StaleObservation,
    UnknownObservation,
    accepted_stale_root,
    compact_target,
    discover_chain_names,
    expected_bits_for_height,
    fetch_mainchain_status,
    get_child_height,
    get_hash,
    get_prev,
    hash_meets_bits,
    header_hash,
    join_sorted,
    load_epoch_bits,
    load_mainchain_cache,
    load_observations,
    parse_header_fields,
    rel,
    save_mainchain_cache,
    scan_upstream_stales,
    stale_identity_key,
    stale_sources,
)
from stale_blocks_analysis.reconcile_publication import (  # noqa: F401
    DESCENDANT_UNJUDGEABLE_FAILURES,
    OUTPUT_ANOMALIES,
    OUTPUT_DIRECT,
    OUTPUT_INVENTORY,
    OUTPUT_PATHS,
    OUTPUT_ROOTS,
    OUTPUT_SUMMARY,
    PROMOTED_ERROR_BLOCK_FIELDS,
    PROMOTED_FIELDS,
    PublicationBaseline,
    descendant_bip34_verdict,
    descendant_consensus_rules,
    descendant_notes,
    error_blocks_csv_for,
    load_publication_baseline,
    render_and_publish,
    select_promoted_evidence,
    source_observation_counts,
    validate_output_mode,
    validate_publication_discovery,
    validate_publication_rows,
    write_csv,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RESULTS_DIR = PROJECT_ROOT / "results" / "analysis" / "stale-ancestry"
CACHE_DIR = PROJECT_ROOT / "cache"
PROMOTED_CSV = DATA_DIR / "stale_descendants.csv"

# Kept explicit for path-loaded callers that used the former script's result type.
__all__ = ("WalkResult",)


def build_parser() -> argparse.ArgumentParser:
    """Build the reconciliation CLI parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    parser.add_argument(
        "--epoch-reference-dir", type=Path, default=BITCOIN_EPOCH_REFERENCE_DIR
    )
    parser.add_argument("--promoted-csv", type=Path, default=PROMOTED_CSV)
    parser.add_argument("--error-blocks-csv", type=Path, default=None)
    parser.add_argument("--max-depth", type=int, default=10_000)
    parser.add_argument("--check-mainchain", action="store_true")
    parser.add_argument(
        "--rpc-url", default=os.environ.get("BTC_RPC_URL", "http://127.0.0.1:8332")
    )
    parser.add_argument("--rpc-user", default=None)
    parser.add_argument("--rpc-pass", default=None)
    parser.add_argument("--rpc-batch-size", type=int, default=500)
    parser.add_argument("--max-mainchain-rpc", type=int, default=0)
    parser.add_argument("--allow-partial", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> None:
    """Coordinate observation loading, ancestry traversal, and publication."""
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_output_mode(
        args,
        parser,
        results_dir_default=RESULTS_DIR,
        promoted_csv_default=PROMOTED_CSV,
    )
    publication_baseline: PublicationBaseline | None = None
    if args.allow_partial:
        print(
            "WARNING: running a partial ancestry reconciliation; do not replace publication artifacts with these outputs",
            file=sys.stderr,
        )
    else:
        try:
            publication_baseline = load_publication_baseline(PROMOTED_CSV)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))

    chain_names, full_files, unknown_files, validated_files = discover_chain_names(
        args.data_dir
    )
    if publication_baseline is not None:
        validate_publication_discovery(
            publication_baseline, full_files, unknown_files, parser
        )
    epoch_bits = load_epoch_bits(args.epoch_reference_dir / "btc_nbits_by_epoch.json")
    state = load_observations(
        data_dir=args.data_dir,
        chain_names=chain_names,
        full_files=full_files,
        unknown_files=unknown_files,
        validated_files=validated_files,
        epoch_bits=epoch_bits,
        excluded_keys=load_stale_exclusion_keys(),
        consensus_invalid_keys=load_consensus_invalid_stale_keys(),
    )
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
        "is_mainchain": mainchain_lookup,
        "max_depth": args.max_depth,
    }
    walk_results = classify_walks(**walk_args)
    mainchain_cache_dirty = False
    if args.check_mainchain:
        terminals = sorted(
            {
                result.terminal_hash
                for result in walk_results.values()
                if result.terminal_kind in {"dangling_unknown", "cross_seen_root"}
                and result.terminal_hash not in mainchain_cache
            }
        )
        if args.max_mainchain_rpc:
            terminals = terminals[: args.max_mainchain_rpc]
        rpc = BtcRpc(url=args.rpc_url, auth=get_btc_auth(args.rpc_user, args.rpc_pass))
        fetched = fetch_mainchain_status(terminals, rpc, args.rpc_batch_size)
        if fetched:
            mainchain_cache.update(fetched)
            mainchain_cache_dirty = True
            walk_results = classify_walks(**walk_args)

    def report_path(block_hash: str) -> list[str]:
        return path_for(
            block_hash,
            unknown_prev_by_hash=state["unknown_prev_by_hash"],
            known_stale_hashes=state["known_stale_hashes"],
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
