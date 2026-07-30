#!/usr/bin/env python3
"""Extract Bitcoin parent headers + coinbases from AuxPoW blk*.dat files.

Directly parses raw block files from Namecoin-family AuxPoW chains
(i0coin, ixcoin, Lyncoin, SixEleven, etc.) without requiring a running node.
Outputs a CSV of all blocks where the embedded Bitcoin header meets
the target encoded in that header's own ``nBits`` field.

The AuxPoW binary format is identical across the supported pre-Flex
Namecoin-family chains (Vince Durham / Daniel Kraft specification). Network
magic, chain-ID enforcement, and AuxPoW activation boundaries differ.

Usage:
    python3 extract_auxpow_from_blkdat.py \
        --blocks-dir ~/i0coin-snapshot/chain-data/blocks \
        --chain i0coin \
        --output ~/i0coin-snapshot/i0coin_auxpow_candidates.csv

Requires: Python 3.10+ (no external dependencies)
"""

import argparse
import csv
import os
import struct
import sys
import tempfile
import time
from collections.abc import Generator
from functools import lru_cache
from pathlib import Path

# The CAuxPow deserialiser, parent-header parsing, nBits/difficulty maths, and
# coinbase-output formatting used to be inlined here. They are byte-for-byte the
# standard Namecoin-family format, so they now come from the shared modules. Only
# the chain-specific config (magic / auxpow_start / chain_id), the blk*.dat XOR
# de-obfuscation and file iteration, the AuxPoW-present decision, and this
# chain's stricter BIP34-height gate stay local.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from stale_blocks_analysis.auxpow_chainid import (  # noqa: E402
    hash_from_header_bytes,
    hash_to_display_hex,
)
from stale_blocks_analysis.auxpow_parse import (  # noqa: E402
    VERSION_AUXPOW,
    hash_meets_btc_difficulty,
    parse_child_header,
    parse_coinbase_height,
    parse_parent_header,
    read_auxpow,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_pkhex  # noqa: E402


# ---------------------------------------------------------------------------
# Chain configurations
# ---------------------------------------------------------------------------

CHAINS = {
    "i0coin": {
        "magic": bytes([0xF1, 0xB2, 0xB3, 0xD4]),
        "auxpow_start": 160_000,
        "chain_id": 2,
        "name": "i0coin",
    },
    "ixcoin": {
        "magic": bytes([0xF1, 0xBA, 0xB6, 0xDB]),
        "auxpow_start": 45_001,
        "chain_id": 3,
        "name": "ixcoin",
    },
    "devcoin": {
        "magic": bytes([0xC0, 0xDB, 0xF1, 0xFD]),  # placeholder — verify before use
        "auxpow_start": 25_000,
        "chain_id": 4,
        "name": "Devcoin",
    },
    "namecoin": {
        "magic": bytes([0xF9, 0xBE, 0xB4, 0xFE]),
        "auxpow_start": 19_200,
        "chain_id": 1,
        "name": "Namecoin",
        "enforce_chain_id": True,
    },
    "coiledcoin": {
        "magic": bytes(
            [0x92, 0xD5, 0xA8, 0x8C]
        ),  # verified against blk0001.dat 2026-04-24
        "auxpow_start": 0,  # GetAuxPowStartBlock returns 0 — AuxPoW accepted from genesis+1
        "chain_id": 16,  # collides with Syscoin's chain ID but independent at runtime
        "name": "CoiledCoin",
    },
    "lyncoin": {
        "magic": bytes.fromhex("52030e2f"),
        "auxpow_start": 0,
        "auxpow_end": 260_499,
        "chain_id": 0x0B0D,
        "name": "Lyncoin",
        "enforce_chain_id": True,
        # Height 260,500 switches to the incompatible Flex encoding. The
        # child-header version flag lets us reject those blocks without a
        # consensus-height lookup.
        "excluded_version_mask": 0x8000,
    },
    "sixeleven": {
        "magic": bytes.fromhex("f9beb611"),
        "auxpow_start": 19_200,
        "chain_id": 1,
        "name": "SixEleven",
        "enforce_chain_id": True,
    },
    "doichain": {
        "magic": bytes.fromhex("f8b2b2ff"),
        "auxpow_start": 1,
        "chain_id": 2,
        "name": "Doichain",
    },
    "blast": {
        "magic": bytes.fromhex("b3c4fda2"),
        "auxpow_start": 1,
        # BLAST consensus accepts either value at every height. Height 796,000
        # controls only which value the bundled miner stamps into new blocks.
        "chain_ids": (0x1940, 0x00A4),
        "name": "BLAST",
        "enforce_chain_id": True,
    },
}


# ---------------------------------------------------------------------------
# Coinbase BIP34 height (kept local: stricter gate than the shared helper)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# blk*.dat file iteration
# ---------------------------------------------------------------------------


def block_data_files(blocks_dir: Path) -> list[Path]:
    """Return numbered blkNNNN.dat files, excluding legacy blkindex.dat."""
    return sorted(
        path for path in blocks_dir.glob("blk*.dat") if path.name[3:-4].isdigit()
    )


@lru_cache(maxsize=256)
def _xor_translate_table(key_byte: int) -> bytes:
    """Return the 256-byte XOR-with-``key_byte`` lookup table for ``bytes.translate``, cached per key byte."""
    return bytes(b ^ key_byte for b in range(256))


def _deobfuscate(data: bytes, xor_key: bytes) -> bytes:
    """XOR-deobfuscate blk*.dat contents (Bitcoin Core >=28 / Namecoin Core 28).

    The key (typically 8 bytes, read from blocks/xor.dat) is applied cyclically
    starting at file offset 0. For empty keys this is a no-op.
    """
    if not xor_key:
        return data
    klen = len(xor_key)
    out = bytearray(data)
    for offset, key_byte in enumerate(xor_key):
        out[offset::klen] = out[offset::klen].translate(_xor_translate_table(key_byte))
    return bytes(out)


def iter_blocks_from_file(
    filepath: Path,
    magic: bytes,
    xor_key: bytes = b"",
) -> "Generator[tuple[int, bytes], None, None]":
    """Yield (block_offset, block_data) from a blk*.dat file."""
    data = filepath.read_bytes()
    if xor_key:
        data = _deobfuscate(data, xor_key)
    pos = 0
    size = len(data)

    while pos < size - 8:
        # Find the next magic bytes
        m = data[pos : pos + 4]
        if m != magic:
            # Scan forward for magic (handles padding / corruption)
            next_pos = data.find(magic, pos)
            if next_pos == -1:
                break
            pos = next_pos
            m = data[pos : pos + 4]

        block_size = struct.unpack_from("<I", data, pos + 4)[0]
        if block_size == 0 or pos + 8 + block_size > size:
            raise ValueError(
                f"{filepath}: invalid block size {block_size} at offset {pos} "
                f"for {size}-byte file"
            )

        block_data = data[pos + 8 : pos + 8 + block_size]
        yield pos, block_data
        pos += 8 + block_size


def child_chain_id(version: int) -> int:
    """Return the 16-bit AuxPoW chain ID encoded in a block version."""
    return (version >> 16) & 0xFFFF


def chain_scope_rejection(child_version: int, chain_config: dict) -> str | None:
    """Return why a version is outside this extractor's chain scope."""
    if chain_config.get("enforce_chain_id"):
        allowed_chain_ids = chain_config.get("chain_ids")
        if allowed_chain_ids is None:
            allowed_chain_ids = (chain_config["chain_id"],)
        if child_chain_id(child_version) not in allowed_chain_ids:
            return "chain_id_mismatch"

    excluded_mask = chain_config.get("excluded_version_mask", 0)
    if excluded_mask and child_version & excluded_mask:
        return "excluded_version"

    return None


def parse_block(block_data: bytes) -> dict | None:
    """Parse a block from raw bytes, extracting AuxPoW if present.

    Returns a dict with child_header info and optionally auxpow data,
    or None if parsing fails. Height gating against the chain's AuxPoW
    activation happens in the caller; this parser only reads bytes.
    """
    if len(block_data) < 80:
        return None

    # Parse the child chain's 80-byte block header
    child_header = block_data[:80]
    child_version = struct.unpack_from("<i", child_header, 0)[0]
    child_hash_internal = hash_from_header_bytes(child_header)
    child_fields = parse_child_header(child_header)

    result = {
        # MMM's normalized importer expects child_block_hash in internal
        # rust-bitcoin to_byte_array() order. Keep child_hash as conventional
        # display hex for diagnostics and make the distinction explicit.
        "child_block_hash": child_hash_internal.hex(),
        "child_hash": hash_to_display_hex(child_hash_internal),
        "child_header_hex": child_fields["child_header_hex"],
        "child_version": child_version,
        "child_chain_id": child_chain_id(child_version),
        "child_block_time": child_fields["child_block_time"],
        "child_nbits": child_fields["child_nbits"],
        "has_auxpow": False,
        "auxpow": None,
    }

    # Check if this block has AuxPoW data
    if child_version & VERSION_AUXPOW:
        try:
            auxpow, _pos = read_auxpow(block_data, 80)
            result["has_auxpow"] = True
            result["auxpow"] = auxpow
        except (IndexError, struct.error, ValueError):
            # Malformed AuxPoW — skip
            pass

    return result


def provisional_child_fields(parsed: dict) -> dict:
    """Return child fields with an explicitly unavailable consensus height."""
    return {
        "child_height": "",
        "child_block_hash": parsed["child_block_hash"],
        "child_block_hash_display": parsed["child_hash"],
        "child_header_hex": parsed["child_header_hex"],
        "child_version": parsed["child_version"],
        "child_chain_id": parsed["child_chain_id"],
        "child_block_time": parsed["child_block_time"],
        "child_nbits": parsed["child_nbits"],
    }


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------


def process_chain(
    blocks_dir: Path,
    chain_config: dict,
    output_path: Path,
    btc_difficulty_only: bool = True,
    progress_interval: int = 50_000,
    xor_key: bytes = b"",
):
    """Scan every ``blk*.dat`` file in ``blocks_dir`` for ``chain_config`` and
    write recovered Bitcoin parent headers to ``output_path``.

    Auto-detects an ``xor.dat`` deobfuscation key when ``xor_key`` is not
    given. For each block, parses the child header, keeps only blocks with
    the AuxPoW nVersion flag set, applies ``chain_scope_rejection`` (chain-ID
    and excluded-version-mask gating), then parses the CAuxPow parent
    header and drops dummy headers (``bits`` of 0 or ``0x7FFFFFFF``). When
    ``btc_difficulty_only`` is true (the default), rows are further
    filtered to parents whose hash meets the target encoded in that parent's
    own ``nBits`` field. Skip reasons are tallied into a local ``stats`` dict and
    printed as a summary. The raw output leaves child height blank because
    ``blk*.dat`` order is not consensus order. A later RPC-backed pass may fill
    the exact height by child hash. Writes to a temp file in ``output_path``'s
    directory and atomically renames it into place on completion, fsyncing both
    the file and its directory entry.
    """
    magic = chain_config["magic"]
    chain_name = chain_config["name"]

    # Auto-detect XOR obfuscation key (Bitcoin Core >=28 style).
    if not xor_key:
        xor_path = blocks_dir / "xor.dat"
        if xor_path.is_file():
            xor_key = xor_path.read_bytes()
            print(f"Detected XOR key: {xor_key.hex()} (from {xor_path})")

    # Discover blk*.dat files in order
    blk_files = block_data_files(blocks_dir)
    if not blk_files:
        print(f"ERROR: no blk*.dat files found in {blocks_dir}")
        sys.exit(1)
    print(f"Found {len(blk_files)} blk*.dat files in {blocks_dir}")

    fieldnames = [
        "child_height",
        "child_block_hash",
        "child_block_hash_display",
        "child_header_hex",
        "child_version",
        "child_chain_id",
        "child_block_time",
        "child_nbits",
        "btc_hash",
        "btc_prev_hash",
        "btc_time",
        "btc_bits_hex",
        "btc_bip34_height",
        "btc_nonce",
        "coinbase_scriptsig_hex",
        "coinbase_outputs",
        "btc_header_hex",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_fd, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    temporary_path = Path(temporary_name)
    outfile = os.fdopen(output_fd, "w", newline="")
    writer = csv.DictWriter(outfile, fieldnames=fieldnames)
    writer.writeheader()

    stats = {
        "blocks_scanned": 0,
        "auxpow_blocks": 0,
        "btc_difficulty_met": 0,
        "non_auxpow": 0,
        "parse_errors": 0,
        "chain_id_mismatch": 0,
        "excluded_version": 0,
    }
    t0 = time.time()

    for blk_file in blk_files:
        blk_path = Path(blk_file)
        file_blocks = 0

        for _offset, block_data in iter_blocks_from_file(blk_path, magic, xor_key):
            stats["blocks_scanned"] += 1

            parsed = parse_block(block_data)
            if parsed is None:
                stats["parse_errors"] += 1
                continue

            if not parsed["has_auxpow"]:
                stats["non_auxpow"] += 1
                continue

            scope_rejection = chain_scope_rejection(
                parsed["child_version"], chain_config
            )
            if scope_rejection is not None:
                stats[scope_rejection] += 1
                continue

            stats["auxpow_blocks"] += 1
            auxpow = parsed["auxpow"]

            # Parse the Bitcoin parent header
            parent_header_raw = auxpow["parent_header_raw"]
            parent = parse_parent_header(parent_header_raw)

            # Skip dummy/invalid headers (bits=0 or 0x7FFFFFFF)
            if parent["bits"] == 0 or parent["bits"] == 0x7FFFFFFF:
                continue

            # Check if the parent header meets its own encoded target. The
            # shared helper takes the internal-order (sha256d) header-hash
            # bytes, not a display-hex string; the numeric comparison is
            # identical.
            if btc_difficulty_only:
                parent_hash_internal = hash_from_header_bytes(parent_header_raw)
                if not hash_meets_btc_difficulty(parent_hash_internal, parent["bits"]):
                    continue

            stats["btc_difficulty_met"] += 1

            # Extract coinbase info
            coinbase_tx = auxpow["coinbase_tx"]
            scriptsig = b""
            if coinbase_tx["vin"]:
                scriptsig = coinbase_tx["vin"][0]["scriptsig"]

            bip34_height = parse_coinbase_height(scriptsig)
            outputs = format_outputs_pkhex(coinbase_tx["vout"])

            row = {
                **provisional_child_fields(parsed),
                "btc_hash": parent["hash"],
                "btc_prev_hash": parent["prev_hash"],
                "btc_time": parent["time"],
                "btc_bits_hex": parent["bits_hex"],
                "btc_bip34_height": bip34_height if bip34_height is not None else "",
                "btc_nonce": parent["nonce"],
                "coinbase_scriptsig_hex": scriptsig.hex(),
                "coinbase_outputs": outputs,
                "btc_header_hex": parent["header_hex"],
            }
            writer.writerow(row)
            file_blocks += 1

            # Progress
            if (
                stats["btc_difficulty_met"] % 1000 == 0
                and stats["btc_difficulty_met"] > 0
            ):
                elapsed = time.time() - t0
                rate = stats["blocks_scanned"] / elapsed if elapsed > 0 else 0
                print(
                    f"  {stats['blocks_scanned']:>9,} scanned | "
                    f"{stats['auxpow_blocks']:>8,} auxpow | "
                    f"{stats['btc_difficulty_met']:>7,} self-target-valid | "
                    f"{rate:,.0f} blk/s | "
                    f"file: {blk_path.name}"
                )

        if stats["blocks_scanned"] % progress_interval < 1000 or file_blocks > 0:
            elapsed = time.time() - t0
            rate = stats["blocks_scanned"] / elapsed if elapsed > 0 else 0
            print(
                f"  Completed {blk_path.name}: "
                f"{stats['blocks_scanned']:,} total | "
                f"{stats['btc_difficulty_met']:,} self-target-valid | "
                f"{rate:,.0f} blk/s"
            )

    outfile.flush()
    os.fsync(outfile.fileno())
    outfile.close()
    os.replace(temporary_path, output_path)
    try:
        directory_fd = os.open(output_path.parent, os.O_RDONLY)
    except OSError:
        directory_fd = None
    if directory_fd is not None:
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    elapsed = time.time() - t0

    print(f"\n{'=' * 60}")
    print(f"{chain_name} AuxPoW extraction complete in {elapsed:.1f}s")
    print(f"  Blocks scanned:     {stats['blocks_scanned']:>10,}")
    print(f"  Non-AuxPoW (skip):  {stats['non_auxpow']:>10,}")
    print(f"  AuxPoW blocks:      {stats['auxpow_blocks']:>10,}")
    print(f"  Chain-ID mismatch:  {stats['chain_id_mismatch']:>10,}")
    print(f"  Excluded version:   {stats['excluded_version']:>10,}")
    print(f"  Self-target PoW met: {stats['btc_difficulty_met']:>10,}")
    print(f"  Parse errors:       {stats['parse_errors']:>10,}")
    print(f"  Output: {output_path}")


def main():
    """Parse CLI args, print the resolved chain configuration, and run
    ``process_chain`` over ``--blocks-dir`` for the selected ``--chain``.

    Exits with status 1 if ``--blocks-dir`` is not a directory.
    """
    parser = argparse.ArgumentParser(
        description="Extract Bitcoin parent headers from AuxPoW blk*.dat files"
    )
    parser.add_argument(
        "--blocks-dir",
        required=True,
        help="Path to the blocks/ directory containing blk*.dat files",
    )
    parser.add_argument(
        "--chain",
        required=True,
        choices=list(CHAINS.keys()),
        help="Chain to parse (determines magic bytes, auxpow start height, chain ID)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output CSV path",
    )
    parser.add_argument(
        "--all-headers",
        action="store_true",
        help="Output ALL AuxPoW parent headers, not just those meeting their encoded target",
    )
    args = parser.parse_args()

    chain_config = CHAINS[args.chain]
    blocks_dir = Path(args.blocks_dir)
    output_path = Path(args.output)

    if not blocks_dir.is_dir():
        print(f"ERROR: {blocks_dir} is not a directory")
        sys.exit(1)

    print(f"Chain: {chain_config['name']}")
    print(f"Magic: {chain_config['magic'].hex()}")
    print(f"Reference AuxPoW transition: block {chain_config['auxpow_start']:,}")
    if "auxpow_end" in chain_config:
        print(f"AuxPoW end: block {chain_config['auxpow_end']:,}")
    if chain_config.get("enforce_chain_id"):
        chain_ids = chain_config.get("chain_ids", (chain_config.get("chain_id"),))
        print(f"Enforced chain ID(s): {', '.join(str(value) for value in chain_ids)}")
    print(f"Self-target PoW filter: {'OFF' if args.all_headers else 'ON'}")
    print()

    process_chain(
        blocks_dir=blocks_dir,
        chain_config=chain_config,
        output_path=output_path,
        btc_difficulty_only=not args.all_headers,
    )


if __name__ == "__main__":
    main()
