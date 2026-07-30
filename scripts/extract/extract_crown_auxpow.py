#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from the Crown blockchain via RPC.

Crown (CRW) is a 2014 Bitcoin/Dash-derived chain with SHA-256d AuxPoW
(standard Namecoin / Daniel Kraft lineage, chain ID 20, fStrictChainId
true). AuxPoW activates at Crown height 453,273. Crown went PoS-hybrid
at height 2,330,000 — PoS blocks carry no AuxPoW. In the PoS era the
chain-ID field in nVersion also rotated from 20 (0x14) to 22 (0x16),
but that is irrelevant here: PoS blocks never have the AuxPoW flag set.

Crown is single-algo (SHA-256d) so there is no per-algo filter — unlike
Myriadcoin/Argentum. The only gate is the AuxPoW flag.

nVersion layout (Namecoin-style):
    bits 0-7   : base version
    bit  8     : VERSION_AUXPOW (1 << 8) — AuxPoW present
    bits 16+   : chain ID (20 for Crown's PoW era; 22 in the PoS era)

Observed in practice (probed 2026-05-20):
    h 453,273          version 0x00140002  PoW  auxbit 0  (activation block, pre-merge)
    h 460,000-2,330,000 version 0x00140102 PoW  auxbit 1  (merge-mined — in scope)
    h 2,330,001+       version 0x0016xxxx  PoS  auxbit 0  (PoS-hybrid era)

The extractor iterates 453,273 -> tip, skips any block whose AuxPoW flag
is clear (covers both the pre-merge-mining PoW blocks and the entire
PoS era), and parses the Namecoin-style CAuxPow tail for the rest.

getblock does NOT expose a decoded `auxpow` JSON field on Crown's RPC,
so we fetch raw block hex (`getblock <hash> false`) and parse the
CAuxPow binary directly — same approach as Devcoin / Myriadcoin /
Argentum.

Output CSV schema matches the other chain extractors for pipeline
compatibility.
"""

import argparse
import os
import sys
from pathlib import Path


# Shared modules: CAuxPow deserialisation, parent-header parsing, BIP-34 height
# decode, and the raw-hex coinbase-output formatter. Crown uses the standard
# Namecoin-lineage CAuxPow tail (chain ID 20), so the parser is identical to
# the consolidated implementation. Chain-specific logic (AuxPoW activation
# height, the nVersion AuxPoW flag gate) stays in this script.
from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.auxpow_parse import (
    CHILD_HEADER_FIELDS,
    parse_coinbase_height,
    parse_parent_header,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_pkhex

# --- Configuration ---
RPC_URL = os.environ.get("CRW_RPC_URL", "http://127.0.0.1:9341")
RPC_USER = os.environ.get("CRW_RPC_USER", "crw")
RPC_PASS = os.environ.get("CRW_RPC_PASS", "")

FIRST_AUXPOW_HEIGHT = 453_273
VERSION_AUXPOW = 1 << 8
BATCH_SIZE = 100
PROGRESS_INTERVAL = 10_000

CSV_COLUMNS = [
    "crown_height",
    *CHILD_HEADER_FIELDS,
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_height",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
]


# ---------------------------------------------------------------------------
# RPC
# ---------------------------------------------------------------------------

_rpc = None


def rpc() -> RpcClient:
    """The Crown RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        _rpc = RpcClient(RPC_URL, user=RPC_USER, password=RPC_PASS, timeout=120)
    return _rpc


def get_chain_tip() -> int:
    """Return the current Crown chain tip height via ``getblockcount``."""
    return extract_driver.get_chain_tip(rpc())


# ---------------------------------------------------------------------------
# Extraction hooks (the gate and the block-to-row parse are the only parts
# that differ from the shared ``extract_driver.run_extraction`` loop; see
# that module for the batched getblockhash/getblock, retry, resume, and
# progress/summary logic this used to duplicate).
# ---------------------------------------------------------------------------


def _gate(version: int, stats: dict) -> bool:
    """Keep only AuxPoW-flagged blocks (skips pre-merge PoW and the PoS era)."""
    if not (version & VERSION_AUXPOW):
        stats["skipped_no_auxpow_flag"] += 1
        return False
    return True


def _parse_row(height: int, auxpow: dict, child_fields: dict) -> dict:
    """Build one CSV row from a parsed CAuxPow structure."""
    parent = parse_parent_header(auxpow["parent_header_raw"])
    tx = auxpow["coinbase_tx"]
    scriptsig = tx["vin"][0]["scriptsig"] if tx["vin"] else b""
    btc_height = parse_coinbase_height(scriptsig)
    return {
        "crown_height": height,
        **child_fields,
        "btc_header_hash": parent["hash"],
        "btc_prev_hash": parent["prev_hash"],
        "btc_time": parent["time"],
        "btc_bits": parent["bits_hex"],
        "btc_height": btc_height if btc_height is not None else "",
        "coinbase_scriptsig_hex": scriptsig.hex(),
        "coinbase_outputs": format_outputs_pkhex(tx["vout"]),
        "btc_header_hex": parent["header_hex"],
    }


def main():
    """Parse CLI args, extract Crown's AuxPoW range in batches, and write
    the output CSV.

    Resolves ``--end`` to the current chain tip when omitted, resumes from
    the last recorded height in an existing output file when ``--resume``
    is set, retries a failed batch one block at a time before giving up on
    it, and prints periodic progress/ETA plus a final per-``stats``-key
    summary. Exits with status 2 if the RPC password env var is unset.
    """
    ap = argparse.ArgumentParser(description="Extract BTC AuxPoW from Crown")
    ap.add_argument("--start", type=int, default=FIRST_AUXPOW_HEIGHT)
    ap.add_argument("--end", type=int, default=None, help="Exclusive")
    ap.add_argument("--output", default="data/crown_auxpow_raw.csv")
    ap.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    if not RPC_PASS:
        print("CRW_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)

    if args.end is None:
        args.end = get_chain_tip() + 1
        print(f"Chain tip: {args.end - 1}")

    start = args.start
    out_path = Path(args.output)
    if args.resume and out_path.exists():
        resumed = extract_driver.resume_start(out_path, "crown_height", args.start)
        if resumed > args.start:
            start = resumed
            print(f"Resuming from height {start}")

    total = args.end - start
    print(f"Extracting AuxPoW: {start:,} → {args.end - 1:,} ({total:,} blocks)")

    stats = {
        "auxpow_blocks": 0,
        "skipped_empty": 0,
        "skipped_short": 0,
        "skipped_no_auxpow_flag": 0,
        "skipped_parse_error": 0,
    }
    append = args.resume and out_path.exists() and start > args.start

    extract_driver.run_extraction(
        rpc=rpc(),
        start=start,
        end=args.end,
        batch_size=args.batch_size,
        output_path=out_path,
        csv_columns=CSV_COLUMNS,
        gate=_gate,
        parse_row=_parse_row,
        stats=stats,
        append=append,
        progress_extra=("no-flag", "skipped_no_auxpow_flag"),
        progress_interval=PROGRESS_INTERVAL,
    )


if __name__ == "__main__":
    main()
