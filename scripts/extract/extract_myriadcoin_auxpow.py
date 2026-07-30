#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from the Myriadcoin blockchain via RPC.

Myriadcoin is a multi-algo PoW chain (SHA-256d / Scrypt / Groestl /
Yescrypt / Argon2d, with Skein and Qubit deprecated in the ~2019 hard
fork). Only the SHA-256d branch is Bitcoin-parent merge-mined; the other
four algos either merge with non-Bitcoin parents (Scrypt → Litecoin/
Dogecoin) or are native PoW.

The algorithm is encoded in nVersion bits 9-11 (BLOCK_VERSION_ALGO =
7 << 9). SHA-256d is encoded as 0 (no bits set). The AuxPoW flag is
nVersion bit 8 (VERSION_AUXPOW = 1 << 8). We filter on both bit fields
before attempting Namecoin-style CAuxPow deserialisation.

AuxPoW activates at Myriadcoin height 1,402,000 (consensus.nStartAuxPow
in src/chainparams.cpp). The extractor iterates 1,402,000 → tip, skipping
blocks whose algo bits indicate a non-SHA-256d branch OR whose AuxPoW
flag is not set.

fStrictChainId is false on Myriadcoin — the SHA-256d branch will accept
AuxPoW from any SHA-256d parent. In practice Bitcoin is the only parent
miners use, but we leave the downstream classify_auxpow_candidates.py
step to enforce parent-against-BTC-mainchain matching.

Output CSV schema matches the other chain extractors for pipeline
compatibility.
"""

import argparse
import os
import sys
from pathlib import Path


from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.auxpow_parse import (
    CHILD_HEADER_FIELDS,
    parse_coinbase_height,
    parse_parent_header,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_pkhex

# --- Configuration ---
RPC_URL = os.environ.get("XMY_RPC_URL", "http://127.0.0.1:10889")
RPC_USER = os.environ.get("XMY_RPC_USER", "myriadcoin")
RPC_PASS = os.environ.get("XMY_RPC_PASS", "")

FIRST_AUXPOW_HEIGHT = 1_402_000
VERSION_AUXPOW = 1 << 8
BLOCK_VERSION_ALGO = 7 << 9  # 3-bit algo field at nVersion[9:12]
ALGO_SHA256D = 0
BATCH_SIZE = 100
PROGRESS_INTERVAL = 10_000

CSV_COLUMNS = [
    "xmy_height",
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
# Bitcoin serialisation primitives
# ---------------------------------------------------------------------------
#
# The CAuxPow deserialiser (read_transaction / read_merkle_branch /
# read_auxpow), the 80-byte parent-header parser (parse_parent_header), and the
# ';'-joined pkscript output formatter now come from the shared modules
# stale_blocks_analysis.auxpow_parse and .bitcoin_binary. The Myriadcoin tail is
# the standard Namecoin-lineage CAuxPow (identical to ixcoin/devcoin/unobtanium/
# terracoin), so it maps onto the shared parsers directly, including the BIP34
# parent-coinbase height decode (parse_coinbase_height). The emitted btc_height
# is informational: the classifier re-derives it authoritatively as
# prev_height + 1 for confirmed stales.


# ---------------------------------------------------------------------------
# RPC
# ---------------------------------------------------------------------------

_rpc = None


def rpc() -> RpcClient:
    """The Myriadcoin RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        _rpc = RpcClient(RPC_URL, user=RPC_USER, password=RPC_PASS, timeout=120)
    return _rpc


def get_chain_tip() -> int:
    """Return the current Myriadcoin chain tip height via ``getblockcount``."""
    return extract_driver.get_chain_tip(rpc())


# ---------------------------------------------------------------------------
# Extraction hooks (the gate and the block-to-row parse are the only parts
# that differ from the shared ``extract_driver.run_extraction`` loop; see
# that module for the batched getblockhash/getblock, retry, resume, and
# progress/summary logic this used to duplicate).
# ---------------------------------------------------------------------------


def _gate(version: int, stats: dict) -> bool:
    """Keep only SHA-256d AuxPoW blocks; tally the two skip reasons."""
    algo = (version & BLOCK_VERSION_ALGO) >> 9
    if algo != ALGO_SHA256D:
        stats["skipped_non_sha256d"] += 1
        return False
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
        "xmy_height": height,
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
    """Parse CLI args, extract Myriadcoin's AuxPoW range in batches, and
    write the output CSV.

    Resolves ``--end`` to the current chain tip when omitted, resumes from
    the last recorded height in an existing output file when ``--resume``
    is set, retries a failed batch one block at a time before giving up on
    it, and prints periodic progress/ETA plus a final per-``stats``-key
    summary. Exits with status 2 if the RPC password env var is unset.
    """
    ap = argparse.ArgumentParser(
        description="Extract BTC AuxPoW from Myriadcoin (SHA-256d branch)"
    )
    ap.add_argument("--start", type=int, default=FIRST_AUXPOW_HEIGHT)
    ap.add_argument("--end", type=int, default=None, help="Exclusive")
    ap.add_argument("--output", default="data/myriadcoin_auxpow_raw.csv")
    ap.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    if not RPC_PASS:
        print("XMY_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)

    if args.end is None:
        args.end = get_chain_tip() + 1
        print(f"Chain tip: {args.end - 1}")

    start = args.start
    out_path = Path(args.output)
    if args.resume and out_path.exists():
        resumed = extract_driver.resume_start(out_path, "xmy_height", args.start)
        if resumed > args.start:
            start = resumed
            print(f"Resuming from height {start}")

    total = args.end - start
    print(
        f"Extracting AuxPoW (SHA-256d only): {start:,} → {args.end - 1:,} ({total:,} blocks)"
    )

    stats = {
        "auxpow_blocks": 0,
        "skipped_empty": 0,
        "skipped_short": 0,
        "skipped_non_sha256d": 0,
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
        progress_extra=("non-sha256d", "skipped_non_sha256d"),
        progress_interval=PROGRESS_INTERVAL,
    )


if __name__ == "__main__":
    main()
