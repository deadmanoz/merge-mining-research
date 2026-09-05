#!/usr/bin/env python3
"""
Extract Bitcoin AuxPoW headers from the Terracoin blockchain.

Iterates all Terracoin blocks from the first AuxPoW block (height 833,000)
to the chain tip, extracting the embedded Bitcoin parent block header and
coinbase transaction data from each merge-mined block.

Shape matches scripts/extract/extract_syscoin_auxpow.py. Terracoin runs Dash Core
0.12.2.x which only supports boolean verbose on getblock — verbosity 1 (true)
already exposes the fully-decoded `auxpow` object.
"""

import argparse
import csv
import re
import time
from pathlib import Path


# Repo `src/` is on sys.path when installed via `pip install -e .`; these
# shared modules are pure-stdlib and safe to import on the archival host.
from stale_blocks_analysis.auxpow_parse import (
    ChildHeaderValidationError,
    parse_child_header,
    parse_parent_header,
    serialize_block_header,
    standard_auxpow_extraction_columns,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_canonical
from stale_blocks_analysis.coinbase_markers import parse_bip34_height
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.extract_driver import validate_append_schema

RPC_URL = "http://127.0.0.1:13332"
DEFAULT_CONF = Path.home() / "terracoin-docker" / "data" / "terracoin.conf"

FIRST_AUXPOW_HEIGHT = 833_000
BATCH_SIZE = 100
PROGRESS_INTERVAL = 10_000

CSV_COLUMNS = standard_auxpow_extraction_columns("trc_height")


def load_rpc_auth(conf_path: Path) -> tuple[str, str]:
    """Parse rpcuser and rpcpassword from a bitcoind-style config file."""
    text = conf_path.read_text()
    user = re.search(r"^rpcuser=(.+)$", text, re.MULTILINE)
    pw = re.search(r"^rpcpassword=(.+)$", text, re.MULTILINE)
    if not user or not pw:
        raise SystemExit(f"rpcuser/rpcpassword missing from {conf_path}")
    return user.group(1).strip(), pw.group(1).strip()


def get_chain_tip(rpc: RpcClient) -> int:
    """Return the current Terracoin chain tip height via ``getblockcount``."""
    call = [{"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}]
    return rpc.batch(call)[0]["result"]


def parse_header(hex_str: str) -> dict:
    """Parse the 80-byte BTC parent header from RPC-provided hex.

    Delegates to the shared parser, then maps its field names back to
    the local CSV vocabulary (``timestamp`` and the 8-char hex ``bits``) so
    the writerow call site and CSV encoding are byte-identical.
    """
    raw = bytes.fromhex(hex_str)
    assert len(raw) == 80, f"Header is {len(raw)} bytes, expected 80"
    parsed = parse_parent_header(raw)
    return {
        "hash": parsed["hash"],
        "prev_hash": parsed["prev_hash"],
        "timestamp": parsed["time"],
        "bits": parsed["bits_hex"],
        "version": parsed["version"],
        "nonce": parsed["nonce"],
    }


def extract_range(
    start: int, end: int, writer: csv.DictWriter, stats: dict, rpc: RpcClient
):
    """Extract AuxPoW data for Terracoin heights ``[start, end)`` into CSV rows.

    Batches ``getblockhash`` then ``getblock <hash> true`` (decoded JSON,
    verbose) RPC calls. Blocks with no ``auxpow`` object, or whose
    ``parentblock`` hex is not the expected 160 hex chars (80 bytes), are
    skipped and tallied into ``stats``; the rest are written as rows using
    the RPC-decoded parent header and coinbase.
    """
    hash_calls = [
        {"jsonrpc": "1.0", "id": i, "method": "getblockhash", "params": [h]}
        for i, h in enumerate(range(start, end))
    ]
    hash_results = rpc.batch(hash_calls)
    hash_results.sort(key=lambda x: x["id"])
    hashes = [r["result"] for r in hash_results]

    block_calls = [
        {"jsonrpc": "1.0", "id": i, "method": "getblock", "params": [h, True]}
        for i, h in enumerate(hashes)
    ]
    block_results = rpc.batch(block_calls)
    block_results.sort(key=lambda x: x["id"])

    for i, br in enumerate(block_results):
        height = start + i
        block = br["result"]
        auxpow = block.get("auxpow")
        if not auxpow or not isinstance(auxpow, dict):
            stats["skipped_no_auxpow"] += 1
            continue
        stats["auxpow_blocks"] += 1

        parent_hex = auxpow.get("parentblock", "")
        if not parent_hex or len(parent_hex) != 160:
            stats["skipped_bad_header"] += 1
            continue

        header = parse_header(parent_hex)
        try:
            child_raw = serialize_block_header(
                version=block["version"],
                previous_block_hash=block["previousblockhash"],
                merkle_root=block["merkleroot"],
                timestamp=block["time"],
                bits=block["bits"],
                nonce=block["nonce"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ChildHeaderValidationError(
                f"Terracoin h={height}: malformed RPC child-header fields"
            ) from exc
        child_fields = parse_child_header(child_raw, expected_hash_display=hashes[i])
        tx = auxpow.get("tx", {})
        vin = tx.get("vin", [])
        vout = tx.get("vout", [])

        scriptsig = vin[0].get("coinbase", "") if vin else ""
        try:
            btc_height = (
                parse_bip34_height(bytes.fromhex(scriptsig)) if scriptsig else None
            )
        except ValueError:
            btc_height = None
        outputs = format_outputs_canonical(vout)

        writer.writerow(
            {
                "trc_height": height,
                **child_fields,
                "btc_header_hash": header["hash"],
                "btc_prev_hash": header["prev_hash"],
                "btc_time": header["timestamp"],
                "btc_bits": header["bits"],
                "btc_height": btc_height if btc_height is not None else "",
                "coinbase_scriptsig_hex": scriptsig,
                "coinbase_outputs": outputs,
                "btc_header_hex": parent_hex,
            }
        )


def main():
    """Parse CLI args, extract Terracoin's AuxPoW range in batches, and
    write the output CSV.

    Loads RPC credentials from ``--conf`` (a bitcoind-style config file),
    resolves ``--end`` to the current chain tip when omitted, resumes from
    the last recorded height in an existing output file when ``--resume``
    is set, retries a failed batch one block at a time before giving up on
    it, and prints periodic progress/ETA plus a final summary.
    """
    parser = argparse.ArgumentParser(
        description="Extract Bitcoin AuxPoW from Terracoin"
    )
    parser.add_argument("--start", type=int, default=FIRST_AUXPOW_HEIGHT)
    parser.add_argument("--end", type=int, default=None, help="End height (exclusive)")
    parser.add_argument("--output", type=str, default="data/terracoin_auxpow_raw.csv")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--conf", type=Path, default=DEFAULT_CONF)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    auth = load_rpc_auth(args.conf)
    rpc = RpcClient(RPC_URL, user=auth[0], password=auth[1], timeout=60)

    if args.end is None:
        args.end = get_chain_tip(rpc) + 1
        print(f"Chain tip: {args.end - 1}")

    start = args.start
    if args.resume and Path(args.output).exists():
        with open(args.output) as f:
            last_line = None
            for line in f:
                last_line = line
            if last_line and not last_line.startswith("trc_height"):
                last_height = int(last_line.split(",")[0])
                start = last_height + 1
                print(f"Resuming from height {start}")

    total = args.end - start
    print(f"Extracting AuxPoW: heights {start} to {args.end - 1} ({total:,} blocks)")

    stats = {"auxpow_blocks": 0, "skipped_no_auxpow": 0, "skipped_bad_header": 0}
    mode = (
        "a"
        if args.resume and Path(args.output).exists() and start > args.start
        else "w"
    )
    if mode == "a":
        validate_append_schema(Path(args.output), CSV_COLUMNS)

    with open(args.output, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        if mode == "w":
            writer.writeheader()

        t_start = time.time()
        processed = 0

        for batch_start in range(start, args.end, args.batch_size):
            batch_end = min(batch_start + args.batch_size, args.end)
            try:
                extract_range(batch_start, batch_end, writer, stats, rpc)
            except ChildHeaderValidationError:
                raise
            except Exception as e:
                print(f"\nError at heights {batch_start}-{batch_end}: {e}")
                print("Retrying individually...")
                for h in range(batch_start, batch_end):
                    try:
                        extract_range(h, h + 1, writer, stats, rpc)
                    except ChildHeaderValidationError:
                        raise
                    except Exception as e2:
                        print(f"  Failed height {h}: {e2}")
                        stats["skipped_bad_header"] += 1

            processed += batch_end - batch_start

            if processed % PROGRESS_INTERVAL < args.batch_size:
                elapsed = time.time() - t_start
                rate = processed / elapsed if elapsed > 0 else 0
                eta = (total - processed) / rate if rate > 0 else 0
                pct = processed / total * 100
                print(
                    f"  {processed:>10,}/{total:,} ({pct:5.1f}%) | "
                    f"{rate:,.0f} blocks/s | "
                    f"AuxPoW: {stats['auxpow_blocks']:,} | "
                    f"ETA: {eta / 60:.0f}m",
                    flush=True,
                )
                f.flush()

    elapsed = time.time() - t_start
    print(f"\nDone in {elapsed / 60:.1f} minutes")
    print(f"  AuxPoW blocks extracted: {stats['auxpow_blocks']:,}")
    print(f"  Skipped (no AuxPoW):     {stats['skipped_no_auxpow']:,}")
    print(f"  Skipped (bad header):    {stats['skipped_bad_header']:,}")
    print(f"  Output: {args.output}")


if __name__ == "__main__":
    main()
