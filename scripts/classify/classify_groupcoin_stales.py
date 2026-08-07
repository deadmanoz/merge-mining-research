#!/usr/bin/env python3
"""Classify Groupcoin AuxPoW parent headers against Bitcoin Core.

Streams the archival `getblock`-JSON dump shared by Nicholas Stifter
(`data/prototype/groupcoin/groupcoin_getblocks_0to235751_auxheight.json.gz`,
1.8 GB gzipped, ~235k blocks total, 218k AuxPoW-bearing), filters records to
those whose parent header meets its own encoded target, dedups by parent
header hash, then classifies each unique parent against Bitcoin Core:

  1. ``getblockheader <parent_hash>`` hit → ``canonical``.
  2. miss → ``getblockheader <prev_hash>`` hit → ``stale``; height is
     ``prev.height + 1``.
  3. both miss → ``unknown``; ``btc_height`` is left blank.

Quirk: ``coinbasetx.vout[*].scriptPubKey.addresses`` in the dump are
Groupcoin-base58 encoded (e.g. ``2h…``), not BTC mainnet. The classifier
emits raw ``scriptPubKey.hex`` semicolon-joined in ``coinbase_outputs``
(Unobtanium / Huntercoin pattern), so downstream pool ID re-decodes the
pkscripts correctly.

Outputs:

* ``data/groupcoin_canonical_blocks.csv``: canonical rows.
* ``data/groupcoin_stale_blocks.csv``: stale rows.
* ``data/groupcoin_unknown_blocks.csv``: unknown rows.
* ``data/groupcoin_error_blocks.csv``: rows proven to break a consensus rule.
* ``data/validated-stales/groupcoin_validated_stales.csv``: loader input;
  ``classification == "stale"`` rows only.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import struct
import sys
import time
from pathlib import Path

from stale_blocks_analysis.auxpow_chainid import hash_from_header_bytes
from stale_blocks_analysis.auxpow_parse import hash_meets_btc_difficulty
from stale_blocks_analysis.auxpow_parse import (
    ChildHeaderValidationError,
    parse_child_header,
    serialize_block_header,
)
from stale_blocks_analysis.btc_classify import (
    classify_candidates,
    derive_split_paths,
    output_columns,
    route_rejected_stale_rows,
    write_classifier_outputs,
)
from stale_blocks_analysis.btc_stale_validation import validate_stale_header_context
from stale_blocks_analysis.btc_rpc import BtcRpc
from stale_blocks_analysis.classifier_cli import add_rpc_args, rpc_from_args
from stale_blocks_analysis.config import CHAIN_SPECS

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SPEC = CHAIN_SPECS["groupcoin"]

# The input is the chain-specific getblock-JSON archival dump, not the shared
# raw-extract CSV, so it stays a local constant rather than reading spec.input_csv.
DEFAULT_INPUT = (
    REPO_ROOT
    / "data"
    / "prototype"
    / "groupcoin"
    / "groupcoin_getblocks_0to235751_auxheight.json.gz"
)
# Output/validated defaults and the child-height column come from CHAIN_SPECS.
DEFAULT_OUTPUT = _SPEC.output_csv
DEFAULT_VALIDATED_OUTPUT = _SPEC.validated_csv

# Bitcoin Core RPC
BATCH_SIZE = 200

OUTPUT_COLUMNS = output_columns(_SPEC.height_column)

# ── PoW + nBits helpers ──────────────────────────────────────────────────


def hash_meets_target(header_hex: str) -> bool:
    """Phase 1 PoW predicate: does this 80-byte parent header meet its own BTC nBits?

    Routes through the mandated byte-order helper
    (``auxpow_chainid.hash_from_header_bytes`` returns the internal-order 32-byte
    SHA256d) and the shared ``auxpow_parse.hash_meets_btc_difficulty`` rather than
    ad hoc ``[::-1]`` slicing or ``int(display_hex, 16)``.
    """
    try:
        raw = bytes.fromhex(header_hex)
    except (ValueError, TypeError):
        return False
    if len(raw) != 80:
        return False
    bits = int.from_bytes(raw[72:76], "little")
    return hash_meets_btc_difficulty(hash_from_header_bytes(raw), bits)


def header_bytes(parent: dict) -> bytes:
    """Serialize a parent_block dict into the 80-byte BTC header layout."""
    version = int(parent["version"])
    prev = bytes.fromhex(parent["previousblockhash"])[::-1]
    mr = bytes.fromhex(parent["merkleroot"])[::-1]
    t = int(parent["time"])
    bits = int(parent["bits"], 16)
    nonce = int(parent["nonce"])
    return (
        struct.pack("<I", version)
        + prev
        + mr
        + struct.pack("<I", t)
        + struct.pack("<I", bits)
        + struct.pack("<I", nonce)
    )


# ── Bitcoin Core batched RPC ───────────────────────────────────────────


def btc_rpc_batch(rpc: BtcRpc, calls: list[dict]) -> list:
    """Send a JSON-RPC batch via the shared ``BtcRpc`` client (sorted by id)."""
    return rpc.batch(calls)


# ── Extraction (streaming JSONL → PoW-valid, deduped candidate dict) ─────


def extract_candidates(
    dump_path: Path,
    progress_every: int = 25_000,
) -> tuple[dict[str, dict], dict]:
    """Stream the gzipped JSONL dump and return:
    * candidates: {btc_header_hash: row}, PoW-valid and deduped
    * stats: counters for the run summary
    """
    candidates: dict[str, dict] = {}
    stats = {
        "total_records": 0,
        "auxpow_records": 0,
        "dropped_pow": 0,
        "duplicates": 0,
    }
    t0 = time.time()
    with gzip.open(dump_path, "rt") as fh:
        for line in fh:
            stats["total_records"] += 1
            rec = json.loads(line)
            ap = rec.get("auxpow")
            if not ap:
                continue
            stats["auxpow_records"] += 1

            parent = ap["parent_block"]
            header_hex = header_bytes(parent).hex()

            # Self-target PoW filter using the parent header's own nBits.
            if not hash_meets_target(header_hex):
                stats["dropped_pow"] += 1
                continue

            btc_hash = parent["hash"]
            if btc_hash in candidates:
                stats["duplicates"] += 1
                continue

            try:
                child_raw = serialize_block_header(
                    version=rec["version"],
                    previous_block_hash=rec["previousblockhash"],
                    merkle_root=rec["merkleroot"],
                    timestamp=rec["time"],
                    bits=rec["bits"],
                    nonce=rec["nonce"],
                )
                child_fields = parse_child_header(
                    child_raw, expected_hash_display=rec["hash"]
                )
            except ChildHeaderValidationError:
                raise
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"record {stats['total_records']}: invalid child header: {exc}"
                ) from exc

            cb = ap.get("coinbasetx") or {}
            scriptsig = ""
            try:
                scriptsig = cb["vin"][0].get("coinbase", "") or cb["vin"][0].get(
                    "coin_base", {}
                ).get("hex", "")
            except (KeyError, IndexError):
                scriptsig = ""

            # Raw scriptPubKey hex semicolon-joined; addresses field is
            # Groupcoin-base58 and must not be used.
            outputs_hex: list[str] = []
            for vo in cb.get("vout", []) or []:
                spk = (vo.get("scriptPubKey") or {}).get("hex", "")
                if spk:
                    outputs_hex.append(spk)

            candidates[btc_hash] = {
                **child_fields,
                "btc_height": "",
                "btc_header_hash": btc_hash,
                "btc_prev_hash": parent.get("previousblockhash", ""),
                "btc_time": str(parent.get("time", "")),
                "btc_bits": parent.get("bits", ""),
                "coinbase_scriptsig_hex": scriptsig,
                "coinbase_outputs": ";".join(outputs_hex),
                "btc_header_hex": header_hex,
                "groupcoin_height": str(rec.get("height", "")),
                "classification": "",
            }

            if stats["auxpow_records"] % progress_every == 0:
                print(
                    f"  scanned {stats['total_records']:>7,} records "
                    f"| auxpow {stats['auxpow_records']:>7,} "
                    f"| pow-valid unique {len(candidates):>6,} "
                    f"| dropped-pow {stats['dropped_pow']:>6,} "
                    f"| dupes {stats['duplicates']:>6,} "
                    f"| {time.time() - t0:5.1f}s",
                    flush=True,
                )

    stats["elapsed_s"] = round(time.time() - t0, 1)
    return candidates, stats


# ── main ────────────────────────────────────────────────────────────────


def main() -> int:
    """Run this chain's classification pipeline end to end."""
    parser = argparse.ArgumentParser(
        description="Classify Groupcoin AuxPoW parent headers as stale / unknown"
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--validated-output", type=Path, default=DEFAULT_VALIDATED_OUTPUT
    )
    add_rpc_args(parser)
    args = parser.parse_args()

    rpc = rpc_from_args(args)

    try:
        probe = btc_rpc_batch(
            rpc,
            [{"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}],
        )
        btc_tip = probe[0].get("result")
        if btc_tip is None:
            raise RuntimeError("RPC probe returned no result")
        print(f"Bitcoin Core tip via {args.rpc_url}: {btc_tip:,}")
    except Exception as exc:
        print(f"ERROR: cannot reach Bitcoin Core: {exc}", file=sys.stderr)
        return 1

    # Phase 1: stream + PoW filter + dedup
    print(f"\n=== Phase 1: stream dump + self-target PoW filter ===")
    print(f"Reading {args.input}…")
    if not args.input.exists():
        print(f"ERROR: input not found: {args.input}", file=sys.stderr)
        return 1

    candidates, stats = extract_candidates(args.input)

    print(f"\n  Total records scanned:      {stats['total_records']:,}")
    print(f"  AuxPoW-bearing records:     {stats['auxpow_records']:,}")
    print(f"  Below BTC full difficulty:  {stats['dropped_pow']:,}")
    print(f"  Duplicate parent hashes:    {stats['duplicates']:,}")
    print(f"  Unique PoW-valid parents:   {len(candidates):,}")
    print(f"  Phase 1 elapsed:            {stats['elapsed_s']}s")

    if not candidates:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", newline="") as fh:
            writer = csv.DictWriter(
                fh, fieldnames=OUTPUT_COLUMNS, extrasaction="ignore"
            )
            writer.writeheader()
        with args.validated_output.open("w", newline="") as fh:
            writer = csv.DictWriter(
                fh, fieldnames=OUTPUT_COLUMNS, extrasaction="ignore"
            )
            writer.writeheader()
        print("\nNo PoW-valid AuxPoW parents — empty outputs written.")
        return 0

    # Phase 2: classify via RPC
    print(f"\n=== Phase 2: Bitcoin Core classification ===")
    cand_list = list(candidates.values())
    all_results: list[dict] = []
    t1 = time.time()
    for start in range(0, len(cand_list), BATCH_SIZE):
        batch = cand_list[start : start + BATCH_SIZE]
        try:
            all_results.extend(classify_candidates(batch, rpc))
        except Exception as exc:
            # A deterministic API/signature error (not a transient RPC failure) means
            # a bug, not a bad batch; re-raise so it fails loud instead of silently
            # retrying into an empty result set that overwrites committed CSVs.
            if isinstance(exc, (TypeError, AttributeError, NameError)):
                raise
            print(f"  Error at batch {start}: {exc}", file=sys.stderr)
            for c in batch:
                try:
                    all_results.extend(classify_candidates([c], rpc))
                except Exception as inner:
                    raise RuntimeError(
                        f"individual classification failed for {c['btc_header_hash']}"
                    ) from inner
        done = start + len(batch)
        if done % 10_000 < BATCH_SIZE:
            rate = done / max(time.time() - t1, 1e-6)
            eta = (len(cand_list) - done) / rate if rate > 0 else 0
            print(
                f"  {done:>7,}/{len(cand_list):,} | {rate:,.0f} headers/s "
                f"| ETA: {eta / 60:.1f}m",
                flush=True,
            )

    if len(all_results) != len(cand_list):
        raise RuntimeError(
            "classification produced a partial result set "
            f"({len(all_results)} of {len(cand_list)} headers)"
        )

    stales = [r for r in all_results if r["classification"] == "stale"]
    validate_stale_header_context(
        stales,
        rpc.batch,
    )
    # Sort the rejected rows by what the rejection means: a proven consensus
    # violation is an error block, an unplaceable or non-Bitcoin-difficulty
    # header is an unknown. The verdict tallies below still count every
    # rejection, whichever bucket the row ends up in.
    route_rejected_stale_rows(stales)
    rejected = [
        r for r in stales if r.get("validation_status", "").startswith("REJECTED")
    ]
    unknown = [
        r for r in stales if r.get("validation_status", "").startswith("UNKNOWN")
    ]
    validated = [r for r in stales if r.get("validation_status") == "VALID"]
    stales = [r for r in stales if r["classification"] == "stale"]
    unknown_rows = [r for r in all_results if r["classification"] == "unknown"]

    # Write the five bucket-split outputs via the shared writer.
    canonical_path, unknown_path, error_block_path = derive_split_paths(
        str(args.output)
    )
    counts = write_classifier_outputs(
        all_results,
        columns=OUTPUT_COLUMNS,
        canonical_path=canonical_path,
        stale_path=str(args.output),
        unknown_path=unknown_path,
        validated_path=str(args.validated_output),
        error_block_path=error_block_path,
    )

    heights = [int(r["btc_height"]) for r in all_results if r.get("btc_height")]

    print(f"\n=== Summary ===")
    print(f"  AuxPoW-bearing records:    {stats['auxpow_records']:,}")
    print(f"  Unique PoW-valid parents:  {len(candidates):,}")
    print(f"  Canonical:                 {len(candidates) - len(all_results):,}")
    print(f"  Stale candidates:          {len(stales):,}")
    print(f"  Valid stales:              {len(validated):,}")
    print(f"  Rejected nBits:            {len(rejected):,}")
    print(f"  Unknown nBits:             {len(unknown):,}")
    print(f"  Unknown:                   {len(unknown_rows):,}")
    print(f"  Error block:               {counts['error_block']:,}")
    if heights:
        print(f"  BTC height range:          {min(heights):,} – {max(heights):,}")
    print(f"  Output: {args.output}")
    print(f"  Validated stales: {args.validated_output}")

    if stales:
        print(f"\n=== Stale blocks ===")
        for r in sorted(stales, key=lambda x: int(x.get("btc_height") or 0)):
            print(
                f"  BTC height {r.get('btc_height', '?'):>7} | "
                f"hash {r['btc_header_hash']} | "
                f"GPC h={r['groupcoin_height']} | time {r['btc_time']}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
