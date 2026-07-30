#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW headers from the Emercoin (EMC) blockchain via RPC.

Emercoin is a hybrid PoW/PoS chain in the Peercoin lineage. Only PoW
blocks carry the Namecoin-style AuxPoW commitment after the merged-
mining activation height (MMHeight = 219,809). The PoS branch is
filtered out via the RPC `flags` field — `"proof-of-work"` vs
`"proof-of-stake"` — which mirrors the on-chain `nFlags & BLOCK_PROOF_OF_STAKE`
predicate (`src/primitives/block.h:36`, `src/chain.h:206-213`).

Unlike the Namecoin/ixcoin/devcoin/myriadcoin extractors, Emercoin RPC
exposes the full `auxpow` object as structured JSON (parent header
fields + decoded coinbase tx), so no binary CAuxPow deserialisation is
required. The Bitcoin parent's 80-byte header is reconstructed from the
JSON fields so the output schema matches the rest of the pipeline.

Output CSV schema matches the other chain extractors for pipeline
compatibility (only the first column name differs: `emc_height`).
"""

import argparse
import csv
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# Repo `src/` is on sys.path when installed via `pip install -e .`; these
# shared modules are pure-stdlib and safe to import on the archival host.
from stale_blocks_analysis.auxpow_chainid import (
    hash_from_display_hex,
    hash_from_header_bytes,
    hash_to_display_hex,
)
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.auxpow_parse import (
    CHILD_HEADER_FIELDS,
    ChildHeaderValidationError,
    parse_child_header,
    parse_coinbase_height,
    serialize_block_header,
)

FIRST_AUXPOW_HEIGHT = 219_809  # MMHeight from src/chainparams.cpp:158
PROGRESS_INTERVAL = 10_000
FLUSH_INTERVAL = 10_000

CSV_COLUMNS = [
    "emc_height",
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


def reconstruct_btc_header(parent: dict) -> bytes:
    """Rebuild the 80-byte BTC parent header from `auxpow.parent_block`.

    RPC presents hash fields as big-endian hex (display order); the
    on-wire header serialises them little-endian. nBits is a hex string
    of the 32-bit compact target shown big-endian; on-wire it's a u32
    LE. version/time/nonce are integers — pack LE.
    """
    version = struct.pack("<i", parent["version"])
    prev_hash = hash_from_display_hex(parent["previousblockhash"])
    merkle_root = hash_from_display_hex(parent["merkleroot"])
    time_ = struct.pack("<I", parent["time"])
    bits = struct.pack("<I", int(parent["bits"], 16))
    nonce = struct.pack("<I", parent["nonce"])
    return version + prev_hash + merkle_root + time_ + bits + nonce


def get_chain_tip(rpc: RpcClient) -> int:
    """Return the current Emercoin chain tip height via ``getblockcount``."""
    return int(rpc.call("getblockcount", []))


def extract_one(rpc: RpcClient, height: int) -> tuple[int, dict | None, str | None]:
    """Fetch+parse one EMC height. Returns (height, row_or_None, error_or_None).

    Returns row=None for PoS blocks (the mandatory filter), missing
    `auxpow`, or malformed coinbase tx — all silent skips. Errors are
    only for RPC failures or unexpected exceptions.
    """
    try:
        block_hash = rpc.call("getblockhash", [height])
        block = rpc.call("getblock", [block_hash])
    except Exception as e:
        return height, None, f"fetch: {e}"

    if block.get("flags") != "proof-of-work":
        return height, None, None  # PoS — skip silently

    ap = block.get("auxpow")
    if not ap:
        return height, None, None  # PoW block without AuxPoW commitment

    try:
        child_raw = serialize_block_header(
            version=block["version"],
            previous_block_hash=block["previousblockhash"],
            merkle_root=block["merkleroot"],
            timestamp=block["time"],
            bits=block["bits"],
            nonce=block["nonce"],
        )
        child_fields = parse_child_header(child_raw, expected_hash_display=block_hash)
        parent = ap["parent_block"]
        coinbase_tx = ap["coinbasetx"]
        vin = coinbase_tx.get("vin", [])
        vout = coinbase_tx.get("vout", [])
        if not vin or not vout:
            return height, None, None

        scriptsig_hex = vin[0].get("coinbase", "")
        scriptsig = bytes.fromhex(scriptsig_hex)
        btc_height = parse_coinbase_height(scriptsig)

        outputs = ";".join(v["scriptPubKey"]["hex"] for v in vout)

        header_raw = reconstruct_btc_header(parent)
        # Sanity check: the BTC header hash from the reconstructed bytes
        # must match what the RPC reports under parent_block.hash.
        computed_hash = hash_to_display_hex(hash_from_header_bytes(header_raw))
        if computed_hash != parent["hash"]:
            return (
                height,
                None,
                (
                    f"parent header reconstruction mismatch: "
                    f"computed={computed_hash} rpc={parent['hash']}"
                ),
            )

        row = {
            "emc_height": height,
            **child_fields,
            "btc_header_hash": parent["hash"],
            "btc_prev_hash": parent["previousblockhash"],
            "btc_time": parent["time"],
            "btc_bits": parent["bits"],
            "btc_height": btc_height if btc_height is not None else "",
            "coinbase_scriptsig_hex": scriptsig_hex,
            "coinbase_outputs": outputs,
            "btc_header_hex": header_raw.hex(),
        }
        return height, row, None
    except ChildHeaderValidationError:
        raise
    except Exception as e:
        return height, None, f"parse: {e}"


def resume_start(output: Path, default_start: int) -> int:
    """Return one past the highest ``emc_height`` already in ``output``,
    or ``default_start`` if the file doesn't exist or has no data rows.
    """
    if not output.exists():
        return default_start
    last_height = None
    with open(output) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("emc_height"):
                continue
            try:
                last_height = int(line.split(",", 1)[0])
            except ValueError:
                continue
    if last_height is None:
        return default_start
    return last_height + 1


def main():
    """Parse CLI args, extract Emercoin's AuxPoW range concurrently, and
    write the output CSV.

    Requires an RPC password via ``--rpc-pass`` or ``EMC_RPC_PASS`` (exits
    with status 2 if neither is set). Resolves ``--end`` to the current
    chain tip when omitted, resumes from the last recorded height in
    ``--output`` when ``--resume`` is set, and dispatches ``extract_one``
    across a thread pool sized by ``--rpc-concurrency``, draining in
    ``--batch-size``-height windows so a worker exception only loses that
    window's progress. Rows are written in ascending height order within
    each window; prints periodic progress/ETA and flushes the output file
    every ``FLUSH_INTERVAL`` heights.
    """
    parser = argparse.ArgumentParser(
        description="Extract Bitcoin AuxPoW from Emercoin (PoW blocks only)"
    )
    parser.add_argument(
        "--rpc-url",
        required=True,
        help="JSON-RPC endpoint (e.g. http://127.0.0.1:6662)",
    )
    parser.add_argument("--rpc-user", default="emercoin")
    parser.add_argument(
        "--rpc-pass", default="", help="RPC password (or set EMC_RPC_PASS)"
    )
    parser.add_argument(
        "--start",
        type=int,
        default=FIRST_AUXPOW_HEIGHT,
        help="Start EMC height (inclusive)",
    )
    parser.add_argument(
        "--end",
        type=int,
        default=None,
        help="End EMC height (exclusive). Defaults to chain tip + 1",
    )
    parser.add_argument("--output", type=str, default="data/emercoin_auxpow_raw.csv")
    parser.add_argument(
        "--rpc-concurrency", type=int, default=16, help="Concurrent in-flight RPC calls"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Heights scheduled per pool drain (bounds memory)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from the last emc_height in --output",
    )
    args = parser.parse_args()

    import os

    rpc_pass = args.rpc_pass or os.environ.get("EMC_RPC_PASS", "")
    if not rpc_pass:
        print(
            "RPC password required (--rpc-pass or EMC_RPC_PASS env var)",
            file=sys.stderr,
        )
        sys.exit(2)

    rpc = RpcClient(args.rpc_url, jsonrpc="1.0", user=args.rpc_user, password=rpc_pass)
    if args.end is None:
        tip = get_chain_tip(rpc)
        args.end = tip + 1
        print(f"Chain tip: {tip}")

    output_path = Path(args.output)
    start = args.start
    if args.resume:
        resumed = resume_start(output_path, args.start)
        if resumed > args.start:
            start = resumed
            print(f"Resuming from EMC height {start}")

    if start >= args.end:
        print(f"Nothing to do: start={start}, end={args.end}")
        return

    total = args.end - start
    print(
        f"Extracting EMC AuxPoW (PoW only): heights {start:,}..{args.end - 1:,} "
        f"({total:,} blocks) via {args.rpc_url} (concurrency={args.rpc_concurrency})"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    is_append = args.resume and output_path.exists() and output_path.stat().st_size > 0
    mode = "a" if is_append else "w"

    stats = {"written": 0, "skipped": 0, "errors": 0}
    t_start = time.time()

    with open(output_path, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        if not is_append:
            writer.writeheader()

        with ThreadPoolExecutor(max_workers=args.rpc_concurrency) as pool:
            for window_start in range(start, args.end, args.batch_size):
                window_end = min(window_start + args.batch_size, args.end)
                futures = {
                    pool.submit(extract_one, rpc, h): h
                    for h in range(window_start, window_end)
                }
                results: dict[int, dict | None] = {}
                for fut in as_completed(futures):
                    h = futures[fut]
                    try:
                        height, row, err = fut.result()
                    except ChildHeaderValidationError:
                        raise
                    except Exception as e:
                        print(f"  height {h} worker exception: {e}", flush=True)
                        stats["errors"] += 1
                        continue
                    if err:
                        print(f"  height {height}: {err}", flush=True)
                        stats["errors"] += 1
                        continue
                    results[height] = row

                for h in sorted(results.keys()):
                    row = results[h]
                    if row is None:
                        stats["skipped"] += 1
                        continue
                    writer.writerow(row)
                    stats["written"] += 1

                processed = window_end - start
                if processed % PROGRESS_INTERVAL < args.batch_size:
                    elapsed = time.time() - t_start
                    rate = processed / elapsed if elapsed > 0 else 0
                    eta = (total - processed) / rate if rate > 0 else 0
                    pct = processed / total * 100
                    print(
                        f"  {processed:>10,}/{total:,} ({pct:5.1f}%) | "
                        f"{rate:5.1f} blk/s | "
                        f"written: {stats['written']:,} | "
                        f"skipped: {stats['skipped']:,} | "
                        f"errors: {stats['errors']:,} | "
                        f"ETA: {eta / 60:.0f}m",
                        flush=True,
                    )
                if processed % FLUSH_INTERVAL < args.batch_size:
                    f.flush()

    elapsed = time.time() - t_start
    print(f"\nDone in {elapsed / 60:.1f} minutes")
    print(f"  Written:  {stats['written']:,}")
    print(f"  Skipped:  {stats['skipped']:,}  (PoS / no auxpow / malformed coinbase)")
    print(f"  Errors:   {stats['errors']:,}")
    print(f"  Output:   {args.output}")


if __name__ == "__main__":
    main()
