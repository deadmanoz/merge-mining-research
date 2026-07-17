#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from the Bitmark blockchain via RPC.

Bitmark is a hybrid 8-algo PoW chain (SHA-256d / Scrypt / Yescrypt /
Argon2d / X17 / LYRA2REv2 / Equihash / CryptoNight, all merge-mineable
since the 2018-06-07 Fork 1 activation). Only the SHA-256d branch is
considered for Bitcoin-parent recovery; the other seven branches either merge with
non-Bitcoin parents (Scrypt -> Litecoin/Dogecoin, Equihash -> Zcash,
CryptoNight -> Monero family) or are out of project scope.

Algorithm is encoded in nVersion bits 9-11 (BLOCK_VERSION_ALGO = 7 << 9):
ALGO_SCRYPT=0, ALGO_SHA256D=1, ALGO_YESCRYPT=2, ALGO_ARGON2=3, ALGO_X17=4,
ALGO_LYRA2REv2=5, ALGO_EQUIHASH=6, ALGO_CRYPTONIGHT=7 (per src/pureheader.h).
Note the SHA-256d encoding differs from Myriadcoin (where SHA-256d=0); the
ALGO_SHA256D constant below is 1 for Bitmark. The AuxPoW flag is nVersion
bit 8 (VERSION_AUXPOW = 1 << 8). We filter on both bit fields before
attempting Namecoin-style CAuxPow deserialisation.

Fork 1 activation is empirically pinned at Bitmark height 450,947
(2018-06-07 04:18:55 UTC) via boundary walk on the synced node -- the
first block where the algo bits flip from SCRYPT v4 to LYRA2REv2.
Pre-fork blocks are Scrypt-only with no AuxPoW; the extractor iterates
450,947 -> tip, skipping blocks whose algo bits indicate a non-SHA-256d
branch OR whose AuxPoW flag is not set.

fStrictChainId is true on Bitmark (chain ID 0x005B = 91) -- tighter than
Myriadcoin's permissive mode. The classifier's self-target PoW filter is only
an internal header-PoW check; downstream RPC classification establishes
Bitcoin linkage.

CPureBlockHeader serialisation is conditional on algo: Equihash blocks
have extra fields (hashReserved, nNonce256, nSolution vector) per the
Zcash layout, but SHA-256d blocks use the standard 80-byte Bitcoin
layout. Our algo filter guarantees we only parse 80-byte headers.

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
    parse_coinbase_height,
    parse_parent_header,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_pkhex

# --- Configuration ---
RPC_URL = os.environ.get("BTMK_RPC_URL", "http://127.0.0.1:9266")
RPC_USER = os.environ.get("BTMK_RPC_USER", "bitmark")
RPC_PASS = os.environ.get("BTMK_RPC_PASS", "")

FIRST_AUXPOW_HEIGHT = 450_947
VERSION_AUXPOW = 1 << 8
BLOCK_VERSION_ALGO = 7 << 9  # 3-bit algo field at nVersion[9:12]
ALGO_SHA256D = 1  # Bitmark's enum (Myriadcoin uses 0 -- these are NOT compatible)
BATCH_SIZE = 100
PROGRESS_INTERVAL = 10_000

CSV_COLUMNS = [
    "btmk_height",
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
    """The Bitmark RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        _rpc = RpcClient(RPC_URL, user=RPC_USER, password=RPC_PASS, timeout=120)
    return _rpc


def get_chain_tip() -> int:
    """Return the current Bitmark chain tip height via ``getblockcount``."""
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


def _parse_row(height: int, auxpow: dict) -> dict:
    """Build one CSV row from a parsed CAuxPow structure."""
    parent = parse_parent_header(auxpow["parent_header_raw"])
    tx = auxpow["coinbase_tx"]
    scriptsig = tx["vin"][0]["scriptsig"] if tx["vin"] else b""
    btc_height = parse_coinbase_height(scriptsig)
    return {
        "btmk_height": height,
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
    """Parse CLI args, extract Bitmark's AuxPoW range in batches, and write
    the output CSV.

    Resolves ``--end`` to the current chain tip when omitted, resumes from
    the last recorded height in an existing output file when ``--resume``
    is set, retries a failed batch one block at a time before giving up on
    it, and prints periodic progress/ETA plus a final per-``stats``-key
    summary. Exits with status 2 if the RPC password env var is unset.
    """
    ap = argparse.ArgumentParser(
        description="Extract BTC AuxPoW from Bitmark (SHA-256d branch)"
    )
    ap.add_argument("--start", type=int, default=FIRST_AUXPOW_HEIGHT)
    ap.add_argument("--end", type=int, default=None, help="Exclusive")
    ap.add_argument("--output", default="data/bitmark_auxpow_raw.csv")
    ap.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    if not RPC_PASS:
        print("BTMK_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)

    if args.end is None:
        args.end = get_chain_tip() + 1
        print(f"Chain tip: {args.end - 1}")

    start = args.start
    out_path = Path(args.output)
    if args.resume and out_path.exists():
        resumed = extract_driver.resume_start(out_path, "btmk_height", args.start)
        if resumed > args.start:
            start = resumed
            print(f"Resuming from height {start}")

    total = args.end - start
    print(
        f"Extracting AuxPoW (SHA-256d only): {start:,} -> {args.end - 1:,} ({total:,} blocks)"
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
