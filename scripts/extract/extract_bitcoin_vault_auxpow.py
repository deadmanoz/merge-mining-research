#!/usr/bin/env python3
"""
Extract Bitcoin AuxPoW headers from Bitcoin Vault (BTCV).

BTCV is dormant (last block 2024-03-10) and no public node is reliably reachable,
but btcvexplorer.com (Trezor Blockbook backend) exposes /api/rawblock/<hash>
which returns full serialised block hex including the AuxPoW tail. This
extractor walks BTCV heights via REST, parses the Namecoin-byte-identical
AuxPoW serialisation in src/primitives/block.h::CAuxBlockHeader, and emits
the BTC parent header + coinbase data in the schema used by the rest of
the pipeline.

Designed to run on 4 hosts in parallel (one egress IP each) covering disjoint
height ranges. Per-host CSVs are concatenated locally after all four complete.

Phase 1 confirmed the wire format end-to-end
across 8 sampled blocks (h=58420, 80k, 100k, 120k, 150k, 180k, 200k, 225k,
228360) — every parent_block_header.hash matches the AuxPoW commitment.

Usage:
  python3 extract_bitcoin_vault_auxpow.py --start 58420 --end 100001 \\
      --output data/bitcoin-vault_auxpow_raw.local.csv --rate 1.0 --resume
"""

import argparse
import csv
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

# Shared modules: segwit-aware CAuxPow deserialisation, parent-header parsing,
# BIP-34 height decode, and the addr:value coinbase-output formatter. BTCV uses
# the Namecoin-byte-identical CAuxPow tail (chain ID 0x0666), so the parser is
# the consolidated implementation. Chain-specific logic (AuxPoW activation
# height, the nVersion AuxPoW flag gate, and the FAKE_AUXPOW_PREFORK_BLOCKS
# skip-set) stays in this script.
from stale_blocks_analysis.auxpow_parse import (
    CHILD_HEADER_FIELDS,
    ChildHeaderValidationError,
    parse_child_header,
    parse_coinbase_height,
    parse_parent_header,
    read_auxpow,
)
from stale_blocks_analysis.bitcoin_binary import format_outputs_addr

# --- Configuration ---
BLOCKBOOK_BASE = "https://btcvexplorer.com"
FIRST_AUXPOW_HEIGHT = 58420  # consensus.nAuxpowStartHeight per chainparams.cpp L101
CHAIN_TIP_HEIGHT = (
    228360  # explorer-reported tip as of 2026-05-16; chain dormant since 2024-03-10
)
USER_AGENT = "merge-mining-research/bitcoin-vault-extractor"

CSV_COLUMNS = [
    "btcv_height",
    *CHILD_HEADER_FIELDS,
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_height",  # BIP34 height parsed from parent coinbase scriptSig
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
]

# Pre-fork blocks with auxpow version flag but no AuxPoW header
# (per src/policy/auxpow.h FAKE_AUXPOW_PREFORK_BLOCKS).
# All four are pre-h=58420 so we never hit them in the post-activation extract range,
# but list them defensively in case the script is run with --start below 58420.
FAKE_AUXPOW_PREFORK_BLOCKS = {
    "00000000000000002027ff541d87aa8c8f86b6c9a0d382e64317fd0759a3e059",
    "00000000000000001f681336cb01354a5f61116fd7441822b4dfa43ee000ecc2",
    "0000000000000000297cdc35b437991e391665d027bde8e3e67bfa3cb4364911",
    "00000000000000000491ee8ac245c4cc31e64ee1e5d00ae9b0d258c17dd97ad1",
}


# ============================================================================
# Block-hex parsing (verified end-to-end in Phase 1 across 8 sample blocks)
#
# The CAuxPow tail is the standard Namecoin/Daniel-Kraft serialisation, so the
# deserialiser, parent-header parser, BIP-34 height decode, and address/output
# formatting all come from the shared modules. BTCV-specific gating (the nVersion
# AuxPoW flag and the FAKE_AUXPOW_PREFORK_BLOCKS skip-set) stays here.
# ============================================================================


def parse_btcv_block(hex_str: str, expected_child_hash: str | None = None) -> dict:
    """Returns the BTCV header + AuxPoW parent header + parent coinbase tx.

    The BTCV block is an 80-byte CPureBlockHeader followed, when the nVersion
    AuxPoW flag (bit 8) is set and the block isn't a fake-prefork block, by the
    Namecoin-byte-identical CAuxPow tail.
    """
    data = bytes.fromhex(hex_str)
    header = parse_parent_header(data[:80])
    out = {
        "btcv_header": header,
        "child_fields": parse_child_header(
            data[:80], expected_hash_display=expected_child_hash
        ),
    }
    auxpow_flag = bool(header["version"] & 0x100)
    if auxpow_flag and header["hash"] not in FAKE_AUXPOW_PREFORK_BLOCKS:
        auxpow, _ = read_auxpow(data, 80)
        out["auxpow"] = {
            "parent_coinbase_tx": auxpow["coinbase_tx"],
            "parent_block_header": parse_parent_header(auxpow["parent_header_raw"]),
        }
    return out


# ============================================================================
# HTTP layer
# ============================================================================


class BlockbookClient:
    """Throttled HTTP client using stdlib only — no third-party dependencies.

    NixOS hosts in this fleet don't have `requests` installed and root partitions
    are tight, so we avoid the venv-on-each-host overhead by sticking to urllib.
    Connection reuse is the only feature we give up vs `requests.Session`;
    at 1 req/s that's negligible (~10ms per call) compared to the network RTT.
    """

    def __init__(self, base: str, rate: float):
        """Store the Blockbook base URL and minimum seconds between requests."""
        self.base = base.rstrip("/")
        self.rate = rate
        self._last_req = 0.0

    def _throttle(self):
        """Sleep, if needed, so successive requests are at least ``self.rate`` seconds apart."""
        now = time.time()
        wait = self.rate - (now - self._last_req)
        if wait > 0:
            time.sleep(wait)
        self._last_req = time.time()

    def get_json(self, path: str, retries: int = 5):
        """GET with exponential backoff on 429/5xx and connection errors."""
        delay = 5
        last_err = None
        for attempt in range(retries):
            self._throttle()
            req = urllib.request.Request(
                self.base + path, headers={"User-Agent": USER_AGENT}
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504):
                    last_err = f"HTTP {e.code}"
                else:
                    raise RuntimeError(f"HTTP {e.code} for {path}: {e.read()[:200]!r}")
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_err = str(e)
            print(
                f"  [warn] {path}: {last_err} — backing off {delay}s (attempt {attempt + 1}/{retries})",
                flush=True,
            )
            time.sleep(delay)
            delay = min(delay * 3, 300)
        raise RuntimeError(f"giving up on {path} after {retries} attempts: {last_err}")

    def get_hash_for_height(self, height: int) -> str:
        """Resolve a BTCV block hash for ``height`` via the Blockbook v2 API."""
        d = self.get_json(f"/api/v2/block/{height}?page=1&pageSize=1")
        return d["hash"]

    def get_raw_block(self, blockhash: str) -> str:
        """Fetch the full serialised block hex for ``blockhash`` via ``/api/rawblock``."""
        d = self.get_json(f"/api/rawblock/{blockhash}")
        return d["hex"]


# ============================================================================
# Extractor
# ============================================================================


def extract_one(
    client: BlockbookClient, height: int, writer: csv.DictWriter, stats: dict
):
    """Fetch and parse one BTCV height, writing a CSV row if it carries AuxPoW.

    Resolves the block hash then its raw hex via ``client``, and skips
    (counting into ``stats["skipped_no_auxpow"]``) blocks with no AuxPoW
    tail, i.e. pre-activation or fake-prefork blocks. On success increments
    ``stats["auxpow_blocks"]``.
    """
    h = client.get_hash_for_height(height)
    hexblob = client.get_raw_block(h)
    parsed = parse_btcv_block(hexblob, h)

    if "auxpow" not in parsed:
        # Block lacks AuxPoW tail (only happens for pre-h=58420 or fake-prefork).
        stats["skipped_no_auxpow"] += 1
        return

    aux = parsed["auxpow"]
    parent_hdr = aux["parent_block_header"]
    parent_cb = aux["parent_coinbase_tx"]
    scriptsig = parent_cb["vin"][0]["scriptsig"]
    btc_height = parse_coinbase_height(scriptsig)

    writer.writerow(
        {
            "btcv_height": height,
            **parsed["child_fields"],
            "btc_header_hash": parent_hdr["hash"],
            "btc_prev_hash": parent_hdr["prev_hash"],
            "btc_time": parent_hdr["time"],
            "btc_bits": parent_hdr["bits"],
            "btc_height": btc_height if btc_height is not None else "",
            "coinbase_scriptsig_hex": scriptsig.hex(),
            "coinbase_outputs": format_outputs_addr(parent_cb["vout"]),
            "btc_header_hex": parent_hdr["header_hex"],
        }
    )
    stats["auxpow_blocks"] += 1


def resume_from(out_path: Path, default_start: int) -> int:
    """Return one past the highest btcv_height already in out_path,
    or default_start if the file doesn't exist or is empty."""
    if not out_path.exists() or out_path.stat().st_size == 0:
        return default_start
    last = None
    with open(out_path) as f:
        for line in f:
            if not line.strip():
                continue
            if line.startswith("btcv_height"):
                continue
            last = line
    if last is None:
        return default_start
    return int(last.split(",", 1)[0]) + 1


def main():
    """Parse CLI args, extract BTCV's AuxPoW range height-by-height via
    Blockbook, and write the output CSV.

    Resolves the effective start height from ``--resume`` (one past the
    last recorded height, floored at ``--start``) when set, throttling
    requests to one every ``--rate`` seconds. A per-height exception is
    caught, logged, and counted into ``stats["errors"]`` rather than
    aborting the run; flushes the output file and prints progress/ETA
    every ``--progress-every`` blocks.
    """
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--start",
        type=int,
        default=FIRST_AUXPOW_HEIGHT,
        help="Start BTCV height (inclusive). Default: %(default)s",
    )
    ap.add_argument(
        "--end",
        type=int,
        default=CHAIN_TIP_HEIGHT,
        help="End BTCV height (inclusive). Default: %(default)s",
    )
    ap.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output CSV path (will append on --resume)",
    )
    ap.add_argument(
        "--rate",
        type=float,
        default=1.0,
        help="Seconds between successive HTTP requests (default: 1.0)",
    )
    ap.add_argument(
        "--resume",
        action="store_true",
        help="Append to existing output, starting from last height + 1",
    )
    ap.add_argument(
        "--progress-every",
        type=int,
        default=1000,
        help="Log progress every N blocks (default: %(default)s)",
    )
    args = ap.parse_args()

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    effective_start = args.start
    if args.resume:
        effective_start = max(args.start, resume_from(out_path, args.start))
        if effective_start > args.end:
            print(
                f"Resume start {effective_start} is past --end {args.end}; nothing to do."
            )
            return

    new_file = not out_path.exists() or out_path.stat().st_size == 0
    mode = "a" if (args.resume and not new_file) else "w"

    client = BlockbookClient(BLOCKBOOK_BASE, args.rate)
    stats = {"auxpow_blocks": 0, "skipped_no_auxpow": 0, "errors": 0}
    total = args.end - effective_start + 1
    t0 = time.time()

    print(
        f"BTCV AuxPoW extract: heights {effective_start} → {args.end} "
        f"({total:,} blocks) at {args.rate}s/req → output {out_path}",
        flush=True,
    )

    with open(out_path, mode, newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        if mode == "w" or out_path.stat().st_size == 0:
            w.writeheader()

        for i, h in enumerate(range(effective_start, args.end + 1)):
            try:
                extract_one(client, h, w, stats)
            except ChildHeaderValidationError:
                raise
            except Exception as e:
                stats["errors"] += 1
                print(f"  [error] height {h}: {e}", flush=True)
                # Skip and keep going — one bad block shouldn't kill a 170k run

            if (i + 1) % args.progress_every == 0:
                f.flush()
                dt = time.time() - t0
                rate = (i + 1) / dt if dt > 0 else 0
                remaining = total - (i + 1)
                eta_h = (remaining / rate / 3600) if rate > 0 else float("inf")
                print(
                    f"  {i + 1:>7,}/{total:,} ({(i + 1) / total * 100:5.1f}%) | "
                    f"{rate:5.2f} blocks/s | "
                    f"aux={stats['auxpow_blocks']:,} skip={stats['skipped_no_auxpow']} err={stats['errors']} | "
                    f"eta={eta_h:4.1f}h",
                    flush=True,
                )

    dt = time.time() - t0
    print(
        f"\nDone in {dt / 60:.1f}m. AuxPoW={stats['auxpow_blocks']:,} "
        f"skipped={stats['skipped_no_auxpow']} errors={stats['errors']}"
    )


if __name__ == "__main__":
    main()
