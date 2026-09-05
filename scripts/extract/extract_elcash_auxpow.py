#!/usr/bin/env python3
"""Extract Bitcoin parent headers from Electric Cash (ELCASH) AuxPoW blocks.

ELCASH is a Bitcoin Core 0.20 fork that merge-mines Bitcoin from a fresh
December 2020 genesis with the standard Namecoin-style CAuxPow encoding
(chain ID 0x2137, strict). getblock does not expose a decoded ``auxpow``
JSON field, so we fetch raw block hex (``getblock <hash> false``) and
parse the CAuxPow binary directly — the same approach as Crown / Devcoin
/ Myriadcoin / Argentum.

The version gate keeps only blocks with the AuxPoW flag AND chain ID
0x2137 in the nVersion high bits, which doubles as a census: the stage
counts report the merge-mined vs direct-mined split and the chain-id
distribution actually observed. Run against the node-infra/elcash node;
RPC uses cookie auth (``.cookie`` in the datadir) or explicit
user/password via the environment.

Output CSV schema matches the other chain extractors for pipeline
compatibility; classify with ``scripts/classify/classify_elcash_stales.py``
(a thin ``run_classifier`` wrapper that reproduces the committed
``data/validated-stales/elcash_validated_stales.csv`` schema).
"""

import argparse
import csv
import os
import struct
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from stale_blocks_analysis.child_rpc import RpcClient  # noqa: E402
from stale_blocks_analysis.auxpow_parse import (  # noqa: E402
    parse_child_header,
    parse_coinbase_height,
    parse_parent_header,
    read_auxpow,
    standard_auxpow_extraction_columns,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_canonical  # noqa: E402

RPC_URL = os.environ.get("ELCASH_RPC_URL", "http://127.0.0.1:18432")

VERSION_AUXPOW = 1 << 8
ELCASH_CHAIN_ID = 0x2137
BATCH_SIZE = 200
PROGRESS_INTERVAL = 10_000

CSV_COLUMNS = standard_auxpow_extraction_columns("elc_height")


def _rpc_auth() -> tuple[str, str]:
    """Resolve RPC auth as (user, password): explicit env, else the datadir cookie."""
    user = os.environ.get("ELCASH_RPC_USER")
    password = os.environ.get("ELCASH_RPC_PASS")
    if user and password:
        return user, password
    cookie_path = os.environ.get("ELCASH_RPC_COOKIE")
    if not cookie_path:
        raise SystemExit(
            "Set ELCASH_RPC_USER/ELCASH_RPC_PASS or ELCASH_RPC_COOKIE "
            "(path to the datadir's .cookie file)"
        )
    token = Path(cookie_path).read_text().strip()
    if ":" not in token:
        raise SystemExit("ELCASH_RPC_COOKIE must contain user:password")
    cookie_user, cookie_password = token.split(":", 1)
    return cookie_user, cookie_password


_rpc = None


def rpc() -> RpcClient:
    """The ELCASH RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        user, password = _rpc_auth()
        _rpc = RpcClient(RPC_URL, user=user, password=password, timeout=120)
    return _rpc


def get_chain_tip() -> int:
    """Return the current ELCASH chain tip height via ``getblockcount``."""
    call = [{"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}]
    return rpc().batch(call)[0]["result"]


def extract_range(start: int, end: int, writer: csv.DictWriter, stats: dict) -> None:
    """Extract AuxPoW data for ELCASH heights ``[start, end)`` into CSV rows.

    Batches ``getblockhash`` then ``getblock <hash> 0`` (raw hex) RPC
    calls. For each block, tallies whether the AuxPoW nVersion flag is
    clear (``direct_mined``), and for AuxPoW blocks records the observed
    chain ID in ``stats["chain_ids"]`` before filtering out any chain ID
    other than ELCASH's own (``skipped_foreign_chain_id``). Blocks that
    pass both gates are parsed as a Namecoin-style CAuxPow tail and
    written as a row; malformed CAuxPow payloads are skipped rather than
    raising.
    """
    hash_calls = [
        {"jsonrpc": "1.0", "id": i, "method": "getblockhash", "params": [h]}
        for i, h in enumerate(range(start, end))
    ]
    hash_results = sorted(rpc().batch(hash_calls), key=lambda x: x["id"])
    hashes = [r["result"] for r in hash_results]

    block_calls = [
        {"jsonrpc": "1.0", "id": i, "method": "getblock", "params": [h, 0]}
        for i, h in enumerate(hashes)
    ]
    block_results = sorted(rpc().batch(block_calls), key=lambda x: x["id"])
    hex_blocks = [r["result"] for r in block_results]

    for i, hx in enumerate(hex_blocks):
        height = start + i
        if not hx:
            stats["skipped_empty"] += 1
            continue
        raw = bytes.fromhex(hx)
        if len(raw) < 80:
            stats["skipped_short"] += 1
            continue
        version = struct.unpack_from("<i", raw, 0)[0]
        if not (version & VERSION_AUXPOW):
            stats["direct_mined"] += 1
            continue
        chain_id = (version >> 16) & 0xFFFF
        stats["chain_ids"][chain_id] = stats["chain_ids"].get(chain_id, 0) + 1
        if chain_id != ELCASH_CHAIN_ID:
            stats["skipped_foreign_chain_id"] += 1
            continue
        try:
            auxpow, _ = read_auxpow(raw, 80)
        except (IndexError, struct.error, ValueError):
            stats["skipped_parse_error"] += 1
            continue

        child_fields = parse_child_header(raw[:80], expected_hash_display=hashes[i])

        parent = parse_parent_header(auxpow["parent_header_raw"])
        tx = auxpow["coinbase_tx"]
        scriptsig = tx["vin"][0]["scriptsig"] if tx["vin"] else b""
        btc_height = parse_coinbase_height(scriptsig)

        stats["auxpow_blocks"] += 1
        writer.writerow(
            {
                "elc_height": height,
                **child_fields,
                "btc_header_hash": parent["hash"],
                "btc_prev_hash": parent["prev_hash"],
                "btc_time": parent["time"],
                "btc_bits": parent["bits_hex"],
                "btc_height": btc_height if btc_height is not None else "",
                "coinbase_scriptsig_hex": scriptsig.hex(),
                "coinbase_outputs": format_outputs_canonical(tx["vout"]),
                "btc_header_hex": parent["header_hex"],
            }
        )


def main() -> None:
    """Parse CLI args, extract ELCASH's AuxPoW range in one pass, and write
    the output CSV.

    Resolves ``--end`` to the current chain tip when omitted. Unlike the
    other RPC-based extractors, batches are processed straight through
    (no per-batch retry-by-block); prints periodic progress and a final
    per-``stats``-key summary, including the observed ``chain_ids`` census.
    """
    ap = argparse.ArgumentParser(
        description="Extract BTC AuxPoW parent headers from ELCASH"
    )
    ap.add_argument(
        "--start",
        type=int,
        default=0,
        help="First ELCASH height (merge-mined from launch)",
    )
    ap.add_argument(
        "--end",
        type=int,
        default=None,
        help="Exclusive end height (default: chain tip + 1)",
    )
    ap.add_argument("--output", default="data/elcash_auxpow_raw.csv")
    args = ap.parse_args()

    end = args.end if args.end is not None else get_chain_tip() + 1
    stats = {
        "auxpow_blocks": 0,
        "direct_mined": 0,
        "skipped_foreign_chain_id": 0,
        "skipped_parse_error": 0,
        "skipped_empty": 0,
        "skipped_short": 0,
        "chain_ids": {},
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for lo in range(args.start, end, BATCH_SIZE):
            hi = min(lo + BATCH_SIZE, end)
            extract_range(lo, hi, writer, stats)
            if lo % PROGRESS_INTERVAL < BATCH_SIZE:
                print(
                    f"  {hi}/{end} auxpow={stats['auxpow_blocks']} "
                    f"direct={stats['direct_mined']}",
                    file=sys.stderr,
                )

    print("=== ELCASH extraction ===")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print(f"  wrote {out_path}")


if __name__ == "__main__":
    main()
