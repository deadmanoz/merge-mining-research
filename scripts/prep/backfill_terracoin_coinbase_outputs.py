#!/usr/bin/env python3
"""Backfill coinbase_outputs with decoded addresses for Terracoin stales.

Re-fetches the 35 validated-stale TRC blocks from a running terracoind and
rewrites their `coinbase_outputs` in the shared canonical rendering (see
docs/data-reference.md), sourced from `scriptPubKey.hex`. terracoind
(Dash-Core-0.12.x-derived) decodes addresses through Dash's base58, so its
`scriptPubKey.address`/`addresses` fields are never used. The columns
rewritten are:
  - data/validated-stales/terracoin_validated_stales.csv (committed; load_terracoin_stales input)
  - data/terracoin_stale_blocks.csv (intermediate; stale rows only)

Unknown rows in the intermediate are left untouched — they pass through
output_scripts() in scripts/analysis/analyze_*_unknown_origin.py with a graceful
fallback to scriptsig-based pool ID for any unresolvable label, and the
~523k re-fetches are not worth the cost.

Connectivity: talks to a terracoind JSON-RPC endpoint over HTTP
(TERRACOIN_RPC_URL, default http://127.0.0.1:13332, with
TERRACOIN_RPC_USER / TERRACOIN_RPC_PASS). When the node is on another host,
forward its RPC port with `ssh -L 13332:localhost:13332 <host>`.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path

from stale_blocks_analysis.bitcoin_binary import format_outputs_canonical
from stale_blocks_analysis.child_rpc import RpcClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
VALIDATED_CSV = (
    PROJECT_ROOT / "data" / "validated-stales" / "terracoin_validated_stales.csv"
)
INTERMEDIATE_CSV = PROJECT_ROOT / "data" / "terracoin_stale_blocks.csv"

RPC_URL = os.environ.get("TERRACOIN_RPC_URL", "http://127.0.0.1:13332")


def fetch_block(rpc: RpcClient, trc_hash: str) -> dict:
    """Fetch a verbose ``getblock`` result for ``trc_hash`` over JSON-RPC."""
    return rpc.call("getblock", [trc_hash, True])


def get_trc_hash(rpc: RpcClient, trc_height: int) -> str:
    """Resolve a Terracoin block hash for ``trc_height`` over JSON-RPC."""
    return rpc.call("getblockhash", [trc_height])


def main() -> int:
    """Re-fetch each validated Terracoin stale's parent coinbase and rewrite
    ``coinbase_outputs`` in the validated CSV and, for stale rows, the
    intermediate stale-blocks CSV.

    Raises ``RuntimeError`` if a re-fetched auxpow carries no vout, or if its
    parent header does not match the header already recorded in the CSV.
    """
    user = os.environ.get("TERRACOIN_RPC_USER", "")
    password = os.environ.get("TERRACOIN_RPC_PASS", "")
    if not (user and password):
        raise SystemExit(
            "Set TERRACOIN_RPC_USER/TERRACOIN_RPC_PASS (and optionally TERRACOIN_RPC_URL); "
            "forward a remote node with ssh -L 13332:localhost:13332 <host>"
        )
    rpc = RpcClient(RPC_URL, jsonrpc="1.0", user=user, password=password, timeout=60)
    with VALIDATED_CSV.open(newline="") as f:
        rows = list(csv.DictReader(f))
    fieldnames = list(rows[0].keys())

    by_btc_hash: dict[str, str] = {}
    for i, row in enumerate(rows, 1):
        trc_height = int(row["trc_height"])
        btc_hash = row["btc_header_hash"]
        print(f"[{i}/{len(rows)}] TRC {trc_height} BTC {btc_hash[:16]}…", flush=True)
        trc_hash = get_trc_hash(rpc, trc_height)
        block = fetch_block(rpc, trc_hash)
        auxpow = block.get("auxpow") or {}
        vout = (auxpow.get("tx") or {}).get("vout") or []
        if not vout:
            raise RuntimeError(f"no vout in auxpow for TRC {trc_height}")
        outputs = format_outputs_canonical(vout)
        # Sanity: parent header in JSON must match what we already recorded.
        parent_hex = auxpow.get("parentblock", "")
        if parent_hex.lower() != row["btc_header_hex"].lower():
            raise RuntimeError(
                f"parent header mismatch for TRC {trc_height}: "
                f"node={parent_hex[:32]}… csv={row['btc_header_hex'][:32]}…"
            )
        row["coinbase_outputs"] = outputs
        by_btc_hash[btc_hash] = outputs
        print(f"    -> {outputs}", flush=True)

    with VALIDATED_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows to {VALIDATED_CSV}")

    if INTERMEDIATE_CSV.exists():
        updated = 0
        with INTERMEDIATE_CSV.open(newline="") as f:
            inter_rows = list(csv.DictReader(f))
        inter_fields = list(inter_rows[0].keys()) if inter_rows else []
        for row in inter_rows:
            if row.get("classification") != "stale":
                continue
            h = row.get("btc_header_hash")
            if h in by_btc_hash:
                row["coinbase_outputs"] = by_btc_hash[h]
                updated += 1
        with INTERMEDIATE_CSV.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=inter_fields)
            writer.writeheader()
            writer.writerows(inter_rows)
        print(f"updated {updated} stale rows in {INTERMEDIATE_CSV}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
