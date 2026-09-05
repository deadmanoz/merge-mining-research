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

Output CSV columns: huc_height, child_block_hash, child_header_hex,
child_block_time, child_nbits, huc_block_hash, chain_id, btc_header_hash,
btc_prev_hash, btc_merkle_root, btc_time, btc_bits, btc_nonce, btc_version,
pow_valid, coinbase_scriptsig_hex, coinbase_outputs, btc_header_hex.
"""

from __future__ import annotations

import argparse
import csv
import os
import struct
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from stale_blocks_analysis.auxpow_chainid import (
    hash_from_header_bytes,
    hash_to_display_hex,
)
from stale_blocks_analysis.auxpow_parse import (
    CHILD_HEADER_FIELDS,
    ChildHeaderValidationError,
    hash_meets_btc_difficulty,
    parse_child_header,
    parse_parent_header,
    read_auxpow,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_canonical

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_BLOCKS_DIR = REPO_ROOT / "data" / "prototype" / "huntercoin" / "arweave-blocks"
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
    *CHILD_HEADER_FIELDS,
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


def _fsync_directory(path: Path) -> None:
    """Persist a completed same-directory rename."""
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@contextmanager
def _atomic_csv_output(destination: Path):
    """Yield a staged CSV handle and publish it only after a clean close."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, staged_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    staged = Path(staged_name)
    try:
        with os.fdopen(fd, "w", newline="") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged, destination)
        _fsync_directory(destination.parent)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        staged.unlink(missing_ok=True)
        raise


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


def parse_huc_block(
    huc_height: int,
    data: bytes,
    expected_child_hash: str | None = None,
    verified_child_fields: dict[str, str] | None = None,
) -> dict | None:
    """Parse a single HUC block binary. Returns a CSV row dict, or None if
    the block does not carry a BTC-chain (chain_id=6) AuxPoW header.
    """
    if len(data) < 80:
        return None
    child_version = struct.unpack_from("<i", data, 0)[0]
    huc_bits = struct.unpack_from("<I", data, 72)[0]
    chain_id = (child_version >> 16) & 0xFFFF
    has_auxpow = bool(child_version & VERSION_AUXPOW)

    if not has_auxpow or chain_id != HUC_CHAIN_ID_SHA256:
        return None

    child_fields = verified_child_fields or parse_child_header(
        data[:80], expected_hash_display=expected_child_hash
    )
    child_hash = hash_to_display_hex(bytes.fromhex(child_fields["child_block_hash"]))

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
        **child_fields,
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
        "coinbase_outputs": format_outputs_canonical(tx["vout"]),
        "btc_header_hex": parent["header_hex"],
    }


def load_source_index(path: Path) -> tuple[dict[int, str], dict[int, str]]:
    """Load and authenticate the Arweave height, block-hash, and txid index."""
    index_by_height: dict[int, str] = {}
    txid_by_height: dict[int, str] = {}
    with path.open() as handle:
        reader = csv.DictReader(handle)
        missing_fields = {"height", "block_hash"} - set(reader.fieldnames or [])
        if missing_fields:
            raise ChildHeaderValidationError(
                "Huntercoin source index is missing required columns: "
                + ", ".join(sorted(missing_fields))
            )
        for row_number, row in enumerate(reader, start=2):
            height_text = (row.get("height") or "").strip()
            block_hash = (row.get("block_hash") or "").strip().lower()
            try:
                height = int(height_text)
            except ValueError as exc:
                raise ChildHeaderValidationError(
                    f"Huntercoin source index row {row_number} has invalid height"
                ) from exc
            if height < 0:
                raise ChildHeaderValidationError(
                    f"Huntercoin source index row {row_number} has invalid height"
                )
            try:
                block_hash_bytes = bytes.fromhex(block_hash)
            except ValueError as exc:
                raise ChildHeaderValidationError(
                    f"Huntercoin source index row {row_number} has invalid block_hash"
                ) from exc
            if len(block_hash_bytes) != 32:
                raise ChildHeaderValidationError(
                    f"Huntercoin source index row {row_number} has invalid block_hash"
                )
            existing = index_by_height.get(height)
            if existing is not None and existing != block_hash:
                raise ChildHeaderValidationError(
                    f"Huntercoin source index row {row_number} contradicts "
                    f"the earlier hash for height {height}"
                )
            index_by_height[height] = block_hash

            txid = (row.get("txid") or "").strip()
            if not txid:
                continue
            existing_txid = txid_by_height.get(height)
            if existing_txid is not None and existing_txid != txid:
                raise ChildHeaderValidationError(
                    f"Huntercoin source index row {row_number} contradicts "
                    f"the earlier transaction ID for height {height}"
                )
            txid_by_height[height] = txid
    return index_by_height, txid_by_height


def load_failure_manifest(path: Path) -> dict[int, str]:
    """Load the authenticated Arweave acquisition failures by height."""
    failures: dict[int, str] = {}
    with path.open() as handle:
        reader = csv.DictReader(handle)
        missing_fields = {"height", "txid"} - set(reader.fieldnames or [])
        if missing_fields:
            raise ChildHeaderValidationError(
                "Huntercoin failure manifest is missing required columns: "
                + ", ".join(sorted(missing_fields))
            )
        for row_number, row in enumerate(reader, start=2):
            height_text = (row.get("height") or "").strip()
            txid = (row.get("txid") or "").strip()
            try:
                height = int(height_text)
            except ValueError as exc:
                raise ChildHeaderValidationError(
                    f"Huntercoin failure manifest row {row_number} has invalid height"
                ) from exc
            if height < 0 or not txid:
                raise ChildHeaderValidationError(
                    f"Huntercoin failure manifest row {row_number} is incomplete"
                )
            existing_txid = failures.get(height)
            if existing_txid is not None and existing_txid != txid:
                raise ChildHeaderValidationError(
                    f"Huntercoin failure manifest row {row_number} contradicts "
                    f"the earlier transaction ID for height {height}"
                )
            failures[height] = txid
    return failures


def validate_acquisition_coverage(
    index_by_height: dict[int, str],
    index_txid_by_height: dict[int, str],
    block_paths: list[Path],
    documented_failures: dict[int, str] | None,
) -> list[int]:
    """Require every indexed height to have a block or authenticated failure."""
    bin_heights: set[int] = set()
    for path in block_paths:
        try:
            bin_heights.add(int(path.stem.split("-")[1]))
        except (IndexError, ValueError):
            continue
    missing_binaries = sorted(set(index_by_height) - bin_heights)
    if missing_binaries and documented_failures is None:
        preview = ", ".join(map(str, missing_binaries[:5]))
        raise ChildHeaderValidationError(
            "Huntercoin source index contains "
            f"{len(missing_binaries)} heights without block binaries"
            + (f" (first: {preview})" if preview else "")
            + "; pass --failures with the authenticated acquisition manifest"
        )

    failures = documented_failures or {}
    if set(missing_binaries) != set(failures):
        preview = ", ".join(map(str, missing_binaries[:5]))
        unexpected = sorted(set(failures) - set(missing_binaries))
        unexpected_preview = ", ".join(map(str, unexpected[:5]))
        raise ChildHeaderValidationError(
            "Huntercoin source index and failure manifest disagree: "
            f"{len(missing_binaries)} missing block binaries"
            + (f" (first: {preview})" if preview else "")
            + f", {len(unexpected)} documented failures have binaries"
            + (f" (first: {unexpected_preview})" if unexpected_preview else "")
        )
    for height in missing_binaries:
        index_txid = index_txid_by_height.get(height)
        if index_txid is None:
            raise ChildHeaderValidationError(
                "Huntercoin source index must include txid when --failures is used"
            )
        if failures[height] != index_txid:
            raise ChildHeaderValidationError(
                "Huntercoin failure manifest transaction ID contradicts the source "
                f"index at height {height}"
            )
    return missing_binaries


def extract_blocks(
    block_paths: list[Path],
    index_by_height: dict[int, str],
    output: Path,
    progress_interval: int,
) -> tuple[dict[str, int], float]:
    """Extract authenticated BTC AuxPoW rows and return scan statistics."""
    stats = {
        "files_scanned": 0,
        "parse_errors": 0,
        "non_auxpow": 0,
        "scrypt_auxpow": 0,
        "sha256_auxpow": 0,
        "pow_fail": 0,
    }
    total_files = len(block_paths)
    started = time.time()
    with _atomic_csv_output(output) as out_fh:
        writer = csv.DictWriter(out_fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for path in block_paths:
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

            expected = index_by_height.get(huc_height)
            if expected is None:
                raise ChildHeaderValidationError(
                    f"Huntercoin h={huc_height} ({path.name}): "
                    "source index has no block hash for this height"
                )
            if len(data) < 80:
                raise ChildHeaderValidationError(
                    f"Huntercoin h={huc_height} ({path.name}): "
                    "source block is shorter than its 80-byte header"
                )
            try:
                child_fields = parse_child_header(
                    data[:80], expected_hash_display=expected
                )
            except ChildHeaderValidationError as exc:
                raise ChildHeaderValidationError(
                    f"Huntercoin h={huc_height} ({path.name}): {exc}"
                ) from exc

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
                stats["non_auxpow"] += 1
                continue

            try:
                row = parse_huc_block(
                    huc_height,
                    data,
                    expected,
                    verified_child_fields=child_fields,
                )
            except ChildHeaderValidationError as exc:
                raise ChildHeaderValidationError(
                    f"Huntercoin h={huc_height} ({path.name}): {exc}"
                ) from exc
            if row is None:
                stats["parse_errors"] += 1
                continue

            stats["sha256_auxpow"] += 1
            if row["pow_valid"] == "0":
                stats["pow_fail"] += 1
                if stats["pow_fail"] <= 10:
                    print(
                        f"  WARN h={huc_height}: sha256d(parent) does not meet "
                        f"HUC target (parent={row['btc_header_hash'][:20]}...), "
                        "possible archive corruption",
                        file=sys.stderr,
                    )

            writer.writerow(row)
            if stats["files_scanned"] % progress_interval == 0:
                elapsed = time.time() - started
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

    return stats, time.time() - started


# ── main ─────────────────────────────────────────────────────────────────


def main() -> int:
    """Scan the pre-downloaded Huntercoin block binaries, extract the
    BTC-merge-mined (chain_id=6) AuxPoW rows, and write the output CSV.

    Reads ``--blocks-dir`` for ``block-<height>.bin`` files in filename
    order, buckets each by AuxPoW presence and chain ID before attempting
    a full parse, requires ``--index`` to cross-check the computed block hash
    for every source height (a missing entry or mismatch aborts extraction), and
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
        required=True,
        help="Required arweave-index.csv for height-to-hash authentication",
    )
    parser.add_argument(
        "--failures",
        type=Path,
        help=(
            "Optional arweave-failures.csv. When the source index includes "
            "payloads that could not be acquired, this manifest must account "
            "for exactly every missing block binary with the same transaction ID"
        ),
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
    if not args.index.is_file():
        print(f"ERROR: Huntercoin index is not a file: {args.index}", file=sys.stderr)
        return 1

    index_by_height, index_txid_by_height = load_source_index(args.index)
    bins = sorted(args.blocks_dir.glob("block-*.bin"))
    documented_failures = None
    if args.failures is not None:
        if not args.failures.is_file():
            print(
                f"ERROR: Huntercoin failure manifest is not a file: {args.failures}",
                file=sys.stderr,
            )
            return 1
        documented_failures = load_failure_manifest(args.failures)
    missing_binaries = validate_acquisition_coverage(
        index_by_height,
        index_txid_by_height,
        bins,
        documented_failures,
    )
    if missing_binaries:
        print(
            f"Authenticated {len(missing_binaries):,} documented Arweave "
            "acquisition gaps against the source index"
        )
    total_files = len(bins)
    print(f"Scanning {total_files:,} HUC block binaries from {args.blocks_dir}")
    stats, elapsed = extract_blocks(
        bins,
        index_by_height,
        args.output,
        args.progress_interval,
    )
    print(f"\nDone in {elapsed:.1f}s")
    print(f"  Files scanned:        {stats['files_scanned']:>10,}")
    print(f"  Acquisition gaps:     {len(missing_binaries):>10,}")
    print(f"  Non-AuxPoW blocks:    {stats['non_auxpow']:>10,}")
    print(f"  Scrypt AuxPoW (id=2):  {stats['scrypt_auxpow']:>10,}")
    print(f"  SHA-256 AuxPoW (id=6): {stats['sha256_auxpow']:>10,}")
    print(
        f"  PoW validation fails:  {stats['pow_fail']:>10,}  "
        f"(sha256d(parent) vs HUC target; non-zero = archive corruption)"
    )
    print(f"  Parse errors:         {stats['parse_errors']:>10,}")
    print(f"  Output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
