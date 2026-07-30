#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from the Argentum blockchain via RPC.

Argentum is a multi-algo PoW chain:
  - pre-2018-03 fork: Scrypt + SHA-256d only
  - post-fork (height >= 2,977,000): Scrypt + SHA-256d + Lyra2REv2 +
    Myriad-Groestl + Argon2d + Yescrypt

Only the SHA-256d branch is Bitcoin-parent merge-mined; Scrypt
merge-mines with Litecoin/Dogecoin (out of scope; only Bitcoin-parent
AuxPoW is in scope here) and the four post-fork native algos have no
AuxPoW.

Algorithm encoding (src/primitives/pureheader.h, dbkeys/argentum):

    BLOCK_VERSION_ALGO     = (7 << 9)   == 0x0E00
    BLOCK_VERSION_SHA256D  = (1 << 9)   == 0x0200    <- in-scope filter
    BLOCK_VERSION_LYRA2RE2 = (2 << 9)   == 0x0400
    BLOCK_VERSION_GROESTL  = (3 << 9)   == 0x0600
    BLOCK_VERSION_ARGON2D  = (4 << 9)   == 0x0800
    BLOCK_VERSION_YESCRYPT = (5 << 9)   == 0x0A00
    # ALGO_SCRYPT == 0 (no bits set; default case in GetAlgo())

  NOTE: this differs from Myriadcoin, where SHA-256d is the *default*
  (algo == 0). In Argentum SHA-256d is explicit (1<<9) and Scrypt is
  the default. The Argentum filter is therefore
      (nVersion & BLOCK_VERSION_ALGO) == BLOCK_VERSION_SHA256D
  NOT the Myriadcoin-style `algo == 0`.

AuxPoW flag (`VERSION_AUXPOW = 1 << 8`, bit 8 of nVersion) must also
be set. We filter on both fields before attempting Namecoin-style
CAuxPow deserialisation.

AuxPoW activates at Argentum height 1,825,000
(consensus.nStartAuxPow in src/chainparams.cpp; exact wall-clock date
derivable from the block-1825000 timestamp). The extractor iterates
1,825,000 -> tip, skipping blocks whose algo bits indicate a
non-SHA-256d branch OR whose AuxPoW flag is not set.

fStrictChainId is false on Argentum (identical to Myriadcoin) — the
SHA-256d branch will accept AuxPoW from any SHA-256d parent. In
practice Bitcoin is the only economically rational parent (the live
SHA-256d difficulty is ~4.3e10, requiring real BTC-scale hashrate),
but the downstream classify_*_candidates.py step is what enforces
parent-against-BTC-mainchain matching.

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
RPC_URL = os.environ.get("ARG_RPC_URL", "http://127.0.0.1:13581")
RPC_USER = os.environ.get("ARG_RPC_USER", "argentum")
RPC_PASS = os.environ.get("ARG_RPC_PASS", "")

FIRST_AUXPOW_HEIGHT = 1_825_000
VERSION_AUXPOW = 1 << 8
BLOCK_VERSION_ALGO = 7 << 9  # 3-bit algo field at nVersion[9:12]
BLOCK_VERSION_SHA256D = 1 << 9  # ARG: SHA-256d == 0x0200 (NOT the default)
BATCH_SIZE = 100
PROGRESS_INTERVAL = 10_000

CSV_COLUMNS = [
    "arg_height",
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
#
# The CAuxPow tail deserialiser (read_transaction / read_auxpow /
# read_merkle_branch) and the parent-header parser (parse_parent_header) are
# the standard Namecoin-family format and now come from
# ``stale_blocks_analysis.auxpow_parse`` (imported above). format_outputs is
# the shared ';'-joined raw-pkscript helper, and the BIP34 parent-coinbase
# height decode comes from ``parse_coinbase_height``.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# RPC
# ---------------------------------------------------------------------------

_rpc = None


def rpc() -> RpcClient:
    """The Argentum RPC client, built lazily so importing this module needs no creds."""
    global _rpc
    if _rpc is None:
        _rpc = RpcClient(RPC_URL, user=RPC_USER, password=RPC_PASS, timeout=120)
    return _rpc


def get_chain_tip() -> int:
    """Return the current Argentum chain tip height via ``getblockcount``."""
    return extract_driver.get_chain_tip(rpc())


# ---------------------------------------------------------------------------
# Extraction hooks (the gate and the block-to-row parse are the only parts
# that differ from the shared ``extract_driver.run_extraction`` loop; see
# that module for the batched getblockhash/getblock, retry, resume, and
# progress/summary logic this used to duplicate).
# ---------------------------------------------------------------------------


def _gate(version: int, stats: dict) -> bool:
    """Keep only SHA-256d AuxPoW blocks; tally the two skip reasons."""
    if (version & BLOCK_VERSION_ALGO) != BLOCK_VERSION_SHA256D:
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
        "arg_height": height,
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
    """Parse CLI args, extract Argentum's AuxPoW range in batches, and
    write the output CSV.

    Resolves ``--end`` to the current chain tip when omitted, resumes from
    the last recorded height in an existing output file when ``--resume``
    is set, retries a failed batch one block at a time before giving up on
    it, and prints periodic progress/ETA plus a final per-``stats``-key
    summary. Exits with status 2 if the RPC password env var is unset.
    """
    ap = argparse.ArgumentParser(
        description="Extract BTC AuxPoW from Argentum (SHA-256d branch)"
    )
    ap.add_argument("--start", type=int, default=FIRST_AUXPOW_HEIGHT)
    ap.add_argument("--end", type=int, default=None, help="Exclusive")
    ap.add_argument("--output", default="data/argentum_auxpow_raw.csv")
    ap.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    if not RPC_PASS:
        print("ARG_RPC_PASS env var not set", file=sys.stderr)
        sys.exit(2)

    if args.end is None:
        args.end = get_chain_tip() + 1
        print(f"Chain tip: {args.end - 1}")

    start = args.start
    out_path = Path(args.output)
    if args.resume and out_path.exists():
        resumed = extract_driver.resume_start(out_path, "arg_height", args.start)
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
