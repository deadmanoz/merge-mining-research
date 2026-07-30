#!/usr/bin/env python3
"""Extract Bitcoin parent headers from Xaya (CHI) blk*.dat AuxPoW commitments.

Xaya does NOT use the Namecoin-family version-bit AuxPoW layout that
extract_auxpow_from_blkdat.py handles. A Xaya block on disk is:

    [80-byte CPureBlockHeader][PowData][varint tx count][txs...]

where PowData (src/powdata.h) serialises as:

    algo   : uint8   (PowAlgo; high bit 0x80 = FLAG_MERGE_MINED)
    nBits  : uint32  (the PoW target for the chosen algo)
    payload: CAuxPow            if (algo & 0x80)   merge-mined
             CPureBlockHeader   otherwise          standalone "fake header"

In Xaya, SHA256D blocks MUST be merge-mined and NEOSCRYPT blocks must not
(src/powdata.cpp), so every merge-mined block carries a CAuxPow whose
parentBlock is a Bitcoin header. We therefore key purely on the merge-mined
flag and validate each parent against Bitcoin difficulty downstream, which is
robust regardless of the exact PowAlgo integer values.

The CAuxPow tail at offset 85 is the standard Namecoin CAuxPow, so the shared
``read_auxpow`` / ``parse_parent_header`` / ``hash_meets_btc_difficulty``
parser is reused unchanged.

The output CSV uses the canonical ``run_classifier`` input schema
(``btc_header_hash`` / ``btc_bits`` plus exact ``child_height``). Xaya enforces
BIP34 from child height 1, so the extractor reads the consensus height from the
child coinbase after the ``PowData`` wrapper.

Requires: Python 3.10+ and the installed stale_blocks_analysis package.
"""

from __future__ import annotations

import argparse
import csv
import glob
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from stale_blocks_analysis.auxpow_chainid import hash_from_header_bytes  # noqa: E402
from stale_blocks_analysis.auxpow_parse import (  # noqa: E402
    CHILD_HEADER_FIELDS,
    ChildHeaderValidationError,
    _varint,
    hash_meets_btc_difficulty,
    parse_child_header,
    parse_coinbase_height,
    parse_parent_header,
    read_auxpow,
    read_transaction,
    validate_child_header_fields,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_pkhex  # noqa: E402

# Xaya mainnet message-start bytes (src/kernel/chainparams.cpp). Verify against
# the first 4 bytes of blk00000.dat before trusting a zero-block run.
XAYA_MAGIC = bytes.fromhex("cc be b4 fe".replace(" ", ""))
FLAG_MERGE_MINED = 0x80
POW_OFFSET = 80  # PowData starts right after the 80-byte pure header
AUXPOW_OFFSET = 85  # 80 (header) + 1 (algo) + 4 (nBits)


def _deobfuscate(data: bytes, key: bytes) -> bytes:
    """XOR-decode ``data`` against a repeating ``xor.dat`` key. No-op if ``key`` is empty."""
    if not key:
        return data
    k = bytearray(key)
    out = bytearray(data)
    for i in range(len(out)):
        out[i] ^= k[i % len(k)]
    return bytes(out)


def iter_blocks_from_file(filepath: Path, magic: bytes, xor_key: bytes = b""):
    """Yield raw block bytes from a blk*.dat file (magic + 4-byte LE size framing)."""
    data = filepath.read_bytes()
    if xor_key:
        data = _deobfuscate(data, xor_key)
    pos, size = 0, len(data)
    while pos < size - 8:
        if data[pos : pos + 4] != magic:
            nxt = data.find(magic, pos)
            if nxt == -1:
                break
            pos = nxt
        block_size = struct.unpack_from("<I", data, pos + 4)[0]
        if block_size == 0 or pos + 8 + block_size > size:
            break
        yield data[pos + 8 : pos + 8 + block_size]
        pos += 8 + block_size


def _child_height_from_coinbase(block_data: bytes, offset: int) -> int:
    """Return Xaya's consensus-enforced BIP34 height from the first child tx."""
    try:
        tx_count, offset = _varint(block_data, offset)
        if tx_count < 1:
            raise ValueError("block has no child transactions")
        coinbase, _ = read_transaction(block_data, offset)
    except (IndexError, struct.error, ValueError) as exc:
        raise ChildHeaderValidationError(
            "cannot decode Xaya child coinbase after PowData"
        ) from exc
    vins = coinbase["vin"]
    if (
        len(vins) != 1
        or vins[0]["prev_hash"] != b"\x00" * 32
        or vins[0]["prev_idx"] != 0xFFFFFFFF
    ):
        raise ChildHeaderValidationError(
            "Xaya child transaction vector does not begin with a coinbase"
        )
    height = parse_coinbase_height(vins[0]["scriptsig"])
    if height is None or height < 1:
        raise ChildHeaderValidationError(
            "Xaya child coinbase lacks its consensus BIP34 height"
        )
    return height


def parse_xaya_block(block_data: bytes) -> dict | None:
    """Return Xaya header/PowData/AuxPoW fields, or ``None`` when too short."""
    if len(block_data) < AUXPOW_OFFSET:
        return None
    algo = block_data[POW_OFFSET]
    if not (algo & FLAG_MERGE_MINED):
        return {
            "merge_mined": False,
            "auxpow": None,
            "child_fields": None,
            "child_height": None,
        }
    child_nbits = struct.unpack_from("<I", block_data, POW_OFFSET + 1)[0]
    child_fields = parse_child_header(block_data[:80], nbits=child_nbits)
    validate_child_header_fields(child_fields, nbits_from_header=False)
    try:
        auxpow, offset = read_auxpow(block_data, AUXPOW_OFFSET)
    except (IndexError, struct.error, ValueError):
        return {
            "merge_mined": True,
            "auxpow": None,
            "child_fields": child_fields,
            "child_height": None,
        }
    return {
        "merge_mined": True,
        "auxpow": auxpow,
        "child_fields": child_fields,
        "child_height": _child_height_from_coinbase(block_data, offset),
    }


def main() -> None:
    """Scan a directory of Xaya ``blk*.dat`` files and write recovered BTC
    parent headers to the output CSV.

    Auto-detects an ``xor.dat`` deobfuscation key in ``--blocks-dir``,
    iterates every ``blk*.dat`` file in sorted order, and for each
    merge-mined block parses the CAuxPow tail and BTC parent header. Rows
    with an all-zero or all-ones ``bits`` field are dropped as
    unparseable; by default (``--all-headers`` unset) rows are further
    filtered to those whose parent hash meets the target encoded in its header. The
    emitted ``child_height`` is the exact consensus height encoded by the
    BIP34 child coinbase. Prints periodic progress and a final scan summary.
    """
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--blocks-dir", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument(
        "--all-headers",
        action="store_true",
        help="emit every merge-mined parent, not only self-target-PoW-passing ones",
    )
    args = ap.parse_args()

    btc_difficulty_only = not args.all_headers
    xor_key = b""
    xor_path = args.blocks_dir / "xor.dat"
    if xor_path.is_file():
        xor_key = xor_path.read_bytes()
        print(f"Detected XOR key {xor_key.hex()} from {xor_path}")

    blk_files = sorted(glob.glob(str(args.blocks_dir / "blk*.dat")))
    if not blk_files:
        sys.exit(f"ERROR: no blk*.dat in {args.blocks_dir}")
    print(f"Found {len(blk_files)} blk*.dat files; magic={XAYA_MAGIC.hex()}")

    fields = [
        "child_height",
        *CHILD_HEADER_FIELDS,
        "btc_header_hash",
        "btc_prev_hash",
        "btc_time",
        "btc_bits",
        "btc_bip34_height",
        "btc_nonce",
        "coinbase_scriptsig_hex",
        "coinbase_outputs",
        "btc_header_hex",
    ]
    out = open(args.output, "w", newline="")
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()

    st = {"scanned": 0, "merge_mined": 0, "auxpow_ok": 0, "btc_valid": 0, "errors": 0}
    t0 = time.time()
    for blk_file in blk_files:
        p = Path(blk_file)
        for block_data in iter_blocks_from_file(p, XAYA_MAGIC, xor_key):
            st["scanned"] += 1
            parsed = parse_xaya_block(block_data)
            if parsed is None:
                st["errors"] += 1
                continue
            if not parsed["merge_mined"]:
                continue
            st["merge_mined"] += 1
            auxpow = parsed["auxpow"]
            if auxpow is None:
                st["errors"] += 1
                continue
            st["auxpow_ok"] += 1
            raw80 = auxpow["parent_header_raw"]
            if len(raw80) != 80:
                continue
            parent = parse_parent_header(raw80)
            if parent["bits"] in (0, 0x7FFFFFFF):
                continue
            if btc_difficulty_only and not hash_meets_btc_difficulty(
                hash_from_header_bytes(raw80), parent["bits"]
            ):
                continue
            st["btc_valid"] += 1
            cb = auxpow["coinbase_tx"]
            scriptsig = cb["vin"][0]["scriptsig"] if cb["vin"] else b""
            bip34 = parse_coinbase_height(scriptsig)
            writer.writerow(
                {
                    "child_height": parsed["child_height"],
                    **parsed["child_fields"],
                    "btc_header_hash": parent["hash"],
                    "btc_prev_hash": parent["prev_hash"],
                    "btc_time": parent["time"],
                    "btc_bits": parent["bits_hex"],
                    "btc_bip34_height": bip34 if bip34 is not None else "",
                    "btc_nonce": parent["nonce"],
                    "coinbase_scriptsig_hex": scriptsig.hex(),
                    "coinbase_outputs": format_outputs_pkhex(cb["vout"]),
                    "btc_header_hex": parent["header_hex"],
                }
            )
            if st["btc_valid"] % 1000 == 0:
                print(
                    f"  {st['scanned']:>10,} scanned | {st['merge_mined']:>9,} merge-mined | "
                    f"{st['btc_valid']:>7,} self-target-valid | {p.name}"
                )
        print(
            f"  done {p.name}: scanned={st['scanned']:,} merge-mined={st['merge_mined']:,} "
            f"self-target-valid={st['btc_valid']:,}"
        )
    out.close()
    dt = time.time() - t0
    print("\n=== Xaya AuxPoW extraction summary ===")
    print(f"  blocks scanned:        {st['scanned']:,}")
    print(f"  merge-mined (SHA256D): {st['merge_mined']:,}")
    print(f"  CAuxPow parsed ok:     {st['auxpow_ok']:,}")
    print(f"  Self-target PoW valid: {st['btc_valid']:,}   (candidate parent headers)")
    print(f"  parse errors:          {st['errors']:,}")
    print(f"  elapsed: {dt:,.0f}s -> {args.output}")


if __name__ == "__main__":
    main()
