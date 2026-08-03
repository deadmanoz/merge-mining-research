#!/usr/bin/env python3
"""Audit rejected stale_descendant candidates with BIP34 height mismatches."""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import defaultdict
from pathlib import Path

import reconcile_unknown_stale_ancestry as rec
from stale_blocks_analysis.btc_rpc import BtcRpc, get_btc_auth


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RESULTS_DIR = PROJECT_ROOT / "results" / "analysis" / "stale-ancestry"
CACHE_DIR = PROJECT_ROOT / "cache"
PROMOTED_CSV = DATA_DIR / "stale_descendants.csv"
OUTPUT_CSV = "unknown-stale-bip34-rejection-audit.csv"
OUTPUT_JSON = "unknown-stale-bip34-rejection-audit-summary.json"


def parse_bip34_height(scriptsig_hex: str) -> int | None:
    """Decode a BIP34 coinbase-height push from a scriptSig hex string.

    Returns the little-endian height encoded in the leading push, or None if
    the hex is empty/invalid or the leading push length is not in 1..5 bytes.
    """
    try:
        raw = bytes.fromhex(scriptsig_hex or "")
    except ValueError:
        return None
    if not raw:
        return None
    push_len = raw[0]
    if push_len == 0 or push_len > 5 or len(raw) < 1 + push_len:
        return None
    return int.from_bytes(raw[1 : 1 + push_len], "little")


def load_stale_header_index(data_dir: Path) -> dict[str, list[dict[str, str]]]:
    """Index known BTC stale headers by hash across upstream and per-chain sources.

    Scans the upstream stale-blocks CSV and every discovered per-chain
    full-inventory/validated-stales CSV (only rows with
    ``classification == "stale"``), building ``hash -> [observation, ...]``
    where each observation carries the source path/kind/row number plus
    prev_hash/bits/time/header_hex. A hash can map to more than one observation
    when several sources report the same stale header.
    """
    out: dict[str, list[dict[str, str]]] = defaultdict(list)

    def add(
        block_hash: str,
        *,
        source_path: Path,
        source_kind: str,
        row_number: int,
        height: str,
        prev_hash: str,
        bits: str,
        time: str,
        header_hex: str,
    ) -> None:
        """Normalize `block_hash` and append one observation to `out`.

        Fields parsed from `header_hex` take precedence over the
        caller-supplied prev_hash/bits/time when the header decodes cleanly.
        Rows whose hash does not normalize to a valid 32-byte hex hash are
        dropped silently.
        """
        block_hash = rec.normalize_hash(block_hash)
        if not rec.is_hash(block_hash):
            return
        parsed = rec.parse_header_fields(header_hex)
        out[block_hash].append(
            {
                "source_path": rec.rel(source_path),
                "source_kind": source_kind,
                "row_number": str(row_number),
                "height": height,
                "prev_hash": parsed.get("prev_hash") or rec.normalize_hash(prev_hash),
                "bits": parsed.get("bits") or bits,
                "time": parsed.get("time") or time,
                "header_hex": header_hex,
            }
        )

    path = data_dir / "stale-blocks" / "stale-blocks.csv"
    if path.exists():
        with path.open(newline="") as f:
            for row_number, row in enumerate(csv.DictReader(f), start=2):
                add(
                    row.get("hash", ""),
                    source_path=path,
                    source_kind="upstream",
                    row_number=row_number,
                    height=row.get("height", ""),
                    prev_hash="",
                    bits="",
                    time="",
                    header_hex=row.get("header", ""),
                )

    _chain_names, full_files, validated_files = rec.discover_chain_names(data_dir)
    for source_kind, paths in [
        ("full_inventory", full_files),
        ("validated_stales", validated_files),
    ]:
        for _chain, path in sorted(paths.items()):
            with path.open(newline="") as f:
                reader = csv.DictReader(f)
                fields = reader.fieldnames or []
                hash_col = rec.first_present(fields, rec.HASH_COLUMNS)
                prev_col = rec.first_present(fields, rec.PREV_COLUMNS)
                bits_col = rec.first_present(fields, rec.BITS_COLUMNS)
                header_col = rec.first_present(fields, rec.HEADER_HEX_COLUMNS)
                height_col = rec.first_present(fields, rec.BTC_HEIGHT_COLUMNS)
                for row_number, row in enumerate(reader, start=2):
                    classification = (
                        row.get("classification", "stale").strip().lower() or "stale"
                    )
                    if classification != "stale":
                        continue
                    add(
                        rec.get_hash(row, hash_col),
                        source_path=path,
                        source_kind=source_kind,
                        row_number=row_number,
                        height=row.get(height_col, "").strip() if height_col else "",
                        prev_hash=row.get(prev_col, "").strip() if prev_col else "",
                        bits=row.get(bits_col, "").strip().lower() if bits_col else "",
                        time=row.get("btc_time", "").strip(),
                        header_hex=row.get(header_col, "").strip()
                        if header_col
                        else "",
                    )
    return out


def main() -> None:
    """Audit rejected stale_descendant rows for BIP34-height-only mismatches.

    Reads the rejected (``validation_status != "VALID_STALE_DESCENDANT"``)
    rows from ``data/stale_descendants.csv``, cross-checks each row's header
    hash, its stale root, and the root's parent against Bitcoin Core (unless
    ``--skip-rpc``), and writes a per-row audit CSV plus a JSON summary
    distinguishing rejections confirmed as a pure BIP34-height mismatch for
    the row's stale-fork position from rows that still need manual review.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    parser.add_argument("--promoted-csv", type=Path, default=PROMOTED_CSV)
    parser.add_argument(
        "--rpc-url",
        default=os.environ.get("BTC_RPC_URL", "http://127.0.0.1:8332"),
        help="Bitcoin Core JSON-RPC URL; forward a remote node with ssh -L 8332:localhost:8332 <host>.",
    )
    parser.add_argument("--rpc-user", default=None)
    parser.add_argument("--rpc-pass", default=None)
    parser.add_argument("--skip-rpc", action="store_true")
    args = parser.parse_args()
    args.results_dir.mkdir(parents=True, exist_ok=True)

    epoch_bits = rec.load_epoch_bits(args.cache_dir / "btc_nbits_by_epoch.json")
    stale_index = load_stale_header_index(args.data_dir)

    with args.promoted_csv.open(newline="") as f:
        rejected = [
            row
            for row in csv.DictReader(f)
            if row.get("validation_status") != "VALID_STALE_DESCENDANT"
        ]

    hashes_to_query = set()
    root_prev_by_row: dict[str, str] = {}
    for row in rejected:
        root_obs = stale_index.get(row["root_stale_hash"], [])
        root_prev = root_obs[0]["prev_hash"] if root_obs else ""
        root_prev_by_row[row["btc_header_hash"]] = root_prev
        hashes_to_query.update(
            h
            for h in [row["btc_header_hash"], row["root_stale_hash"], root_prev]
            if rec.is_hash(h)
        )

    mainchain_status = {}
    if not args.skip_rpc and hashes_to_query:
        rpc = BtcRpc(url=args.rpc_url, auth=get_btc_auth(args.rpc_user, args.rpc_pass))
        mainchain_status = rec.fetch_mainchain_status(hashes_to_query, rpc, 500)

    rows = []
    for row in rejected:
        candidate_hash = row["btc_header_hash"]
        root_hash = row["root_stale_hash"]
        root_height = rec.int_or_none(row["root_stale_height"])
        inferred_height = rec.int_or_none(row["btc_height"])
        observed_heights = [
            h for h in row.get("observed_btc_heights", "").split("|") if h
        ]
        parsed_bip34_height = parse_bip34_height(row.get("coinbase_scriptsig_hex", ""))
        root_obs = stale_index.get(root_hash, [])
        root_prev = root_prev_by_row.get(candidate_hash, "")
        root_prev_status = mainchain_status.get(root_prev, {})
        root_status = mainchain_status.get(root_hash, {})
        candidate_status = mainchain_status.get(candidate_hash, {})
        root_height_from_core = ""
        if (
            root_prev_status.get("on_mainchain")
            and root_prev_status.get("height") is not None
        ):
            root_height_from_core = int(root_prev_status["height"]) + 1

        parsed_header = rec.parse_header_fields(row.get("btc_header_hex", ""))
        expected_nbits = rec.expected_bits_for_height(row["btc_height"], epoch_bits)
        observed_height = (
            int(observed_heights[0]) if len(observed_heights) == 1 else None
        )
        bip34_minus_inferred = (
            parsed_bip34_height - inferred_height
            if parsed_bip34_height is not None and inferred_height is not None
            else ""
        )
        root_height_consistent = (
            root_height_from_core == root_height
            if isinstance(root_height_from_core, int) and root_height is not None
            else ""
        )
        rejection_confirmed = (
            row.get("header_hash_match") == "true"
            and row.get("pow_valid") == "true"
            and parsed_header.get("prev_hash") == row.get("btc_prev_hash")
            and parsed_bip34_height == observed_height
            and inferred_height is not None
            and parsed_bip34_height != inferred_height
            and (root_height_consistent is True or root_height_consistent == "")
        )

        rows.append(
            {
                "btc_header_hash": candidate_hash,
                "promotion_subclass": row["promotion_subclass"],
                "validation_status": row["validation_status"],
                "root_stale_hash": root_hash,
                "root_stale_height": row["root_stale_height"],
                "stale_fork_depth": row["stale_fork_depth"],
                "inferred_btc_height": row["btc_height"],
                "observed_btc_heights": row["observed_btc_heights"],
                "parsed_bip34_height": ""
                if parsed_bip34_height is None
                else parsed_bip34_height,
                "bip34_minus_inferred": bip34_minus_inferred,
                "btc_prev_hash": row["btc_prev_hash"],
                "header_prev_hash": parsed_header.get("prev_hash", ""),
                "prev_hash_matches_path": parsed_header.get("prev_hash", "")
                == row["btc_prev_hash"],
                "root_prev_hash": root_prev,
                "root_prev_mainchain_height": root_prev_status.get("height", ""),
                "root_height_from_core_parent": root_height_from_core,
                "root_height_consistent": root_height_consistent,
                "candidate_mainchain_hit": candidate_status.get("on_mainchain", False),
                "root_stale_mainchain_hit": root_status.get("on_mainchain", False),
                "btc_bits": row["btc_bits"],
                "expected_nbits": expected_nbits,
                "nbits_match": row["btc_bits"] == expected_nbits,
                "pow_valid": row["pow_valid"],
                "header_hash_match": row["header_hash_match"],
                "observed_chains": row["observed_chains"],
                "source_rows": row["source_rows"],
                "verdict": (
                    "confirmed_invalid_bip34_height_for_stale_fork_position"
                    if rejection_confirmed
                    else "needs_manual_review"
                ),
            }
        )

    fieldnames = [
        "btc_header_hash",
        "promotion_subclass",
        "validation_status",
        "root_stale_hash",
        "root_stale_height",
        "stale_fork_depth",
        "inferred_btc_height",
        "observed_btc_heights",
        "parsed_bip34_height",
        "bip34_minus_inferred",
        "btc_prev_hash",
        "header_prev_hash",
        "prev_hash_matches_path",
        "root_prev_hash",
        "root_prev_mainchain_height",
        "root_height_from_core_parent",
        "root_height_consistent",
        "candidate_mainchain_hit",
        "root_stale_mainchain_hit",
        "btc_bits",
        "expected_nbits",
        "nbits_match",
        "pow_valid",
        "header_hash_match",
        "observed_chains",
        "source_rows",
        "verdict",
    ]
    rec.write_csv(args.results_dir / OUTPUT_CSV, rows, fieldnames)

    summary = {
        "rejected_rows": len(rows),
        "confirmed_invalid_bip34_height_for_stale_fork_position": sum(
            1
            for row in rows
            if row["verdict"]
            == "confirmed_invalid_bip34_height_for_stale_fork_position"
        ),
        "needs_manual_review": sum(
            1 for row in rows if row["verdict"] == "needs_manual_review"
        ),
        "all_bip34_minus_inferred": sorted(
            {row["bip34_minus_inferred"] for row in rows}
        ),
        "queried_bitcoin_core": not args.skip_rpc,
        "rpc_url": "" if args.skip_rpc else args.rpc_url,
    }
    (args.results_dir / OUTPUT_JSON).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
