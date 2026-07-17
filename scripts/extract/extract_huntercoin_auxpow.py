#!/usr/bin/env python3
"""
Extract Bitcoin AuxPoW parent headers from Huntercoin blocks preserved on
Arweave by domob1812/arblockstore.

Huntercoin is a dual-algo merge-mined chain: blocks tag themselves with
chain_id=6 (SHA-256, merge-mined with Bitcoin) or chain_id=2 (Scrypt,
merge-mined with Litecoin). Only chain_id=6 + auxpow-bit blocks commit
to BTC parent headers, so we filter to those.

The AuxPoW binary layout is the standard Vince Durham / Daniel Kraft
format used across Namecoin-family chains — identical to ixcoin, i0coin,
Devcoin. This script is adapted from extract_devcoin_auxpow.py but reads
from the pre-downloaded block binaries at
    data/prototype/huntercoin/arweave-blocks/block-<height>.bin
rather than a running node.

Output CSV columns: huc_height, huc_block_hash, btc_header_hash,
btc_prev_hash, btc_merkle_root, btc_time, btc_bits, btc_nonce,
btc_version, btc_header_hex, coinbase_scriptsig_hex, coinbase_outputs,
chain_id, pow_valid.
"""

from __future__ import annotations

import argparse
import csv
import struct
import sys
import time
from pathlib import Path

from stale_blocks_analysis.auxpow_chainid import (
    hash_from_header_bytes,
    hash_to_display_hex,
)
from stale_blocks_analysis.auxpow_parse import (
    hash_meets_btc_difficulty,
    parse_parent_header,
    read_auxpow,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_pkhex

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_BLOCKS_DIR = REPO_ROOT / "data" / "prototype" / "huntercoin" / "arweave-blocks"
DEFAULT_INDEX_CSV = (
    REPO_ROOT / "data" / "prototype" / "huntercoin" / "arweave-index.csv"
)
DEFAULT_OUTPUT = REPO_ROOT / "data" / "huntercoin_auxpow_raw.csv"

# Huntercoin version-field layout (same idea as Namecoin's upper-16-chain-id
# scheme, but with two chain IDs — SHA-256 and Scrypt — sharing the namespace).
# SHA-256 branch = chain_id=0x0006 (merge-mined with Bitcoin), Scrypt branch =
# chain_id=0x0002 (merge-mined with Litecoin).
VERSION_AUXPOW = 1 << 8  # 0x0100
HUC_CHAIN_ID_SHA256 = 6  # BTC-merge-mined branch (the ones we want)
HUC_CHAIN_ID_SCRYPT = 2  # LTC-merge-mined branch (skipped)

CSV_COLUMNS = [
    "huc_height",
    "huc_block_hash",
    "chain_id",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_merkle_root",
    "btc_time",
    "btc_bits",
    "btc_nonce",
    "btc_version",
    "pow_valid",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
]


# ── PoW validation (HUC child-chain target) ───────────────────────────────


def parent_hash_meets_huc_target(parent_header_raw: bytes, huc_bits: int) -> bool:
    """True iff sha256d(parent_header) <= target implied by the *HUC*
    block's nBits (the child-chain target).

    This is the actual AuxPoW validity rule: the parent header serves as
    the child chain's PoW, so the parent's sha256d must beat HUC's
    difficulty target — not BTC's. BTC-canonical / stale classification
    is a separate, stricter filter applied downstream by the classifier.
    Failures here indicate archive corruption.

    The numeric comparison is identical to ``hash_meets_btc_difficulty``
    (internal-order hash bytes compared as a little-endian integer), the
    only difference being that the target derives from HUC's nBits rather
    than BTC's. We therefore reuse the shared helper, passing the
    internal-order parent header hash from ``hash_from_header_bytes``.
    """
    return hash_meets_btc_difficulty(
        hash_from_header_bytes(parent_header_raw), huc_bits
    )


# ── block-level parsing ──────────────────────────────────────────────────


def parse_huc_block(huc_height: int, data: bytes) -> dict | None:
    """Parse a single HUC block binary. Returns a CSV row dict, or None if
    the block does not carry a BTC-chain (chain_id=6) AuxPoW header.
    """
    if len(data) < 80:
        return None
    child_version = struct.unpack_from("<i", data, 0)[0]
    huc_bits = struct.unpack_from("<I", data, 72)[0]
    child_hash = hash_to_display_hex(hash_from_header_bytes(data[:80]))
    chain_id = (child_version >> 16) & 0xFFFF
    has_auxpow = bool(child_version & VERSION_AUXPOW)

    if not has_auxpow or chain_id != HUC_CHAIN_ID_SHA256:
        return None

    try:
        auxpow, _ = read_auxpow(data, 80)
    except (IndexError, struct.error, ValueError):
        return None

    parent = parse_parent_header(auxpow["parent_header_raw"])
    pow_ok = parent_hash_meets_huc_target(auxpow["parent_header_raw"], huc_bits)
    tx = auxpow["coinbase_tx"]
    scriptsig = tx["vin"][0]["scriptsig"] if tx["vin"] else b""
    return {
        "huc_height": huc_height,
        "huc_block_hash": child_hash,
        "chain_id": chain_id,
        "btc_header_hash": parent["hash"],
        "btc_prev_hash": parent["prev_hash"],
        "btc_merkle_root": parent["merkle_root"],
        "btc_time": parent["time"],
        "btc_bits": parent["bits_hex"],
        "btc_nonce": parent["nonce"],
        "btc_version": parent["version"],
        "pow_valid": "1" if pow_ok else "0",
        "coinbase_scriptsig_hex": scriptsig.hex(),
        "coinbase_outputs": format_outputs_pkhex(tx["vout"]),
        "btc_header_hex": parent["header_hex"],
    }


# ── main ─────────────────────────────────────────────────────────────────


def main() -> int:
    """Scan the pre-downloaded Huntercoin block binaries, extract the
    BTC-merge-mined (chain_id=6) AuxPoW rows, and write the output CSV.

    Reads ``--blocks-dir`` for ``block-<height>.bin`` files in filename
    order, buckets each by AuxPoW presence and chain ID before attempting
    a full parse, cross-checks the computed block hash against
    ``--index`` when available (mismatches are logged, not fatal), and
    warns (first 10 occurrences only) when a parsed parent header fails
    the HUC-target PoW check, which would indicate archive corruption.
    Prints periodic progress/ETA plus a final per-``stats``-key summary.
    Returns 1 if ``--blocks-dir`` is not a directory, 0 otherwise.
    """
    parser = argparse.ArgumentParser(
        description="Extract Bitcoin AuxPoW parent headers from Huntercoin blocks"
    )
    parser.add_argument(
        "--blocks-dir",
        type=Path,
        default=DEFAULT_BLOCKS_DIR,
        help="Directory of block-<height>.bin files (default: arweave-blocks)",
    )
    parser.add_argument(
        "--index",
        type=Path,
        default=DEFAULT_INDEX_CSV,
        help="arweave-index.csv for hash cross-check (default: arweave-index.csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output CSV path (default: data/huntercoin_auxpow_raw.csv)",
    )
    parser.add_argument(
        "--progress-interval",
        type=int,
        default=10_000,
        help="Print a progress line every N HUC blocks",
    )
    args = parser.parse_args()

    if not args.blocks_dir.is_dir():
        print(f"ERROR: {args.blocks_dir} is not a directory", file=sys.stderr)
        return 1

    # Load the index to cross-check recorded HUC block hashes against what we
    # compute from the binary. Mismatches are a red flag but don't prevent
    # extraction — we still emit the row with a warning.
    index_by_height: dict[int, str] = {}
    if args.index.exists():
        with args.index.open() as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    index_by_height[int(row["height"])] = row["block_hash"]
                except (KeyError, ValueError):
                    continue

    bins = sorted(args.blocks_dir.glob("block-*.bin"))
    total_files = len(bins)
    print(f"Scanning {total_files:,} HUC block binaries from {args.blocks_dir}")

    stats = {
        "files_scanned": 0,
        "short_files": 0,
        "parse_errors": 0,
        "non_auxpow": 0,
        "scrypt_auxpow": 0,  # chain_id=6 (Litecoin merge-mine)
        "sha256_auxpow": 0,  # chain_id=2 (BTC merge-mine)
        "pow_fail": 0,
        "hash_mismatch": 0,
    }

    t0 = time.time()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as out_fh:
        writer = csv.DictWriter(out_fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for path in bins:
            try:
                huc_height = int(path.stem.split("-")[1])
            except (IndexError, ValueError):
                stats["parse_errors"] += 1
                continue

            stats["files_scanned"] += 1
            try:
                data = path.read_bytes()
            except OSError as exc:
                print(f"  WARN: cannot read {path.name}: {exc}", file=sys.stderr)
                stats["parse_errors"] += 1
                continue

            if len(data) < 80:
                stats["short_files"] += 1
                continue

            # Quick peek at version + chain to bucket stats before full parse.
            child_version = struct.unpack_from("<i", data, 0)[0]
            chain_id = (child_version >> 16) & 0xFFFF
            has_auxpow = bool(child_version & VERSION_AUXPOW)
            if not has_auxpow:
                stats["non_auxpow"] += 1
                continue
            if chain_id == HUC_CHAIN_ID_SCRYPT:
                stats["scrypt_auxpow"] += 1
                continue
            if chain_id != HUC_CHAIN_ID_SHA256:
                # Unexpected chain id — skip but note.
                stats["non_auxpow"] += 1
                continue

            row = parse_huc_block(huc_height, data)
            if row is None:
                stats["parse_errors"] += 1
                continue

            stats["sha256_auxpow"] += 1

            if row["pow_valid"] == "0":
                stats["pow_fail"] += 1
                if stats["pow_fail"] <= 10:
                    print(
                        f"  WARN h={huc_height}: sha256d(parent) does not meet "
                        f"HUC target (parent={row['btc_header_hash'][:20]}...) "
                        f"— archive corruption?",
                        file=sys.stderr,
                    )

            expected = index_by_height.get(huc_height)
            if expected and expected != row["huc_block_hash"]:
                stats["hash_mismatch"] += 1
                if stats["hash_mismatch"] <= 10:
                    print(
                        f"  WARN h={huc_height}: HUC hash mismatch "
                        f"(index={expected[:20]}, computed={row['huc_block_hash'][:20]})",
                        file=sys.stderr,
                    )

            writer.writerow(row)

            if stats["files_scanned"] % args.progress_interval == 0:
                elapsed = time.time() - t0
                rate = stats["files_scanned"] / elapsed if elapsed > 0 else 0
                eta = (total_files - stats["files_scanned"]) / rate if rate > 0 else 0
                print(
                    f"  {stats['files_scanned']:>7,}/{total_files:,} "
                    f"({100 * stats['files_scanned'] / total_files:5.1f}%) | "
                    f"{rate:,.0f} files/s | "
                    f"sha256-auxpow: {stats['sha256_auxpow']:,} | "
                    f"scrypt-auxpow: {stats['scrypt_auxpow']:,} | "
                    f"ETA: {eta / 60:.1f}m",
                    flush=True,
                )

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.1f}s")
    print(f"  Files scanned:        {stats['files_scanned']:>10,}")
    print(f"  Short files (<80B):   {stats['short_files']:>10,}")
    print(f"  Non-AuxPoW blocks:    {stats['non_auxpow']:>10,}")
    print(f"  Scrypt AuxPoW (id=2):  {stats['scrypt_auxpow']:>10,}")
    print(f"  SHA-256 AuxPoW (id=6): {stats['sha256_auxpow']:>10,}")
    print(
        f"  PoW validation fails:  {stats['pow_fail']:>10,}  "
        f"(sha256d(parent) vs HUC target; non-zero = archive corruption)"
    )
    print(f"  HUC hash mismatches:  {stats['hash_mismatch']:>10,}")
    print(f"  Parse errors:         {stats['parse_errors']:>10,}")
    print(f"  Output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
