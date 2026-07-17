#!/usr/bin/env python3
"""Characterize every Doichain AuxPoW parent, including non-winning shares.

Use the generic blkdat extractor with ``--all-headers`` first. This report
separates exponent-``0x17`` parent headers from the other compact-target
exponents, then checks parent tips against Bitcoin Core. The exponent alone
does not establish that the full ``nBits`` value equals Bitcoin's expected
target at the time.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from stale_blocks_analysis.btc_classify import _meets_btc_difficulty
from stale_blocks_analysis.classifier_cli import add_rpc_args, rpc_from_args

BATCH_SIZE = 200


def _canonical_status(rpc, hashes: list[str]) -> tuple[int, set[str]]:
    """Return the number known and the subset on Bitcoin's active chain."""
    known = 0
    canonical: set[str] = set()
    for start in range(0, len(hashes), BATCH_SIZE):
        chunk = hashes[start : start + BATCH_SIZE]
        calls = [
            {"jsonrpc": "1.0", "id": i, "method": "getblockheader", "params": [h]}
            for i, h in enumerate(chunk)
        ]
        for response in rpc.batch(calls):
            result = response.get("result")
            if result is None:
                continue
            known += 1
            if result.get("confirmations", -1) >= 0:
                canonical.add(chunk[int(response["id"])])
    return known, canonical


def characterize_rows(rows: list[dict[str, str]]) -> dict[str, object]:
    """Partition raw rows without RPC and return intermediate populations."""
    histogram: Counter[str] = Counter()
    winners: set[str] = set()
    share_prevs: list[str] = []
    fillers: set[str] = set()
    for row in rows:
        block_hash = row.get("btc_header_hash") or row.get("btc_hash", "")
        bits = (row.get("btc_bits") or row.get("btc_bits_hex", "")).lower()
        exponent = bits[:2] if len(bits) >= 2 else "??"
        histogram[exponent] += 1
        self_pow = _meets_btc_difficulty(row.get("btc_header_hex", ""))
        if exponent == "17":
            if self_pow:
                winners.add(block_hash)
            else:
                share_prevs.append(row.get("btc_prev_hash", ""))
        elif self_pow:
            fillers.add(block_hash)
    return {
        "total_commitments": len(rows),
        "nbits_exponent_histogram": dict(histogram.most_common()),
        "winner_hashes": winners,
        "share_prevs": share_prevs,
        "filler_hashes": fillers,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    add_rpc_args(parser)
    args = parser.parse_args()

    with args.input.open(newline="") as f:
        populations = characterize_rows(list(csv.DictReader(f)))

    rpc = rpc_from_args(args)
    winners = sorted(populations.pop("winner_hashes"))
    share_prevs = list(populations.pop("share_prevs"))
    fillers = sorted(populations.pop("filler_hashes"))
    winner_known, winner_canonical = _canonical_status(rpc, winners)
    unique_prevs = sorted(set(share_prevs))
    prev_known, canonical_prevs = _canonical_status(rpc, unique_prevs)
    filler_known, filler_canonical = _canonical_status(rpc, fillers)

    # These legacy output keys are retained for compatibility. Their grouping
    # is exponent-based; it is not an expected-Bitcoin-nBits comparison.
    summary = {
        **populations,
        "real_difficulty_winners": {
            "unique_self_pow_headers": len(winners),
            "known_to_node": winner_known,
            "canonical_btc_blocks": len(winner_canonical),
            "stale_btc_blocks": winner_known - len(winner_canonical),
        },
        "real_difficulty_shares": {
            "share_rows": len(share_prevs),
            "unique_prev_tips": len(unique_prevs),
            "prev_tips_known_to_node": prev_known,
            "prev_tips_canonical": len(canonical_prevs),
            "share_rows_building_on_canonical_btc_tip": sum(
                prev in canonical_prevs for prev in share_prevs
            ),
        },
        "low_difficulty_fillers": {
            "unique_self_pow_headers": len(fillers),
            "known_to_node": filler_known,
            "canonical_btc_blocks": len(filler_canonical),
        },
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
