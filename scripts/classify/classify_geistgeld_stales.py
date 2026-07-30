#!/usr/bin/env python3
"""Classify Geistgeld AuxPoW parent headers against Bitcoin Core.

Geistgeld is a dead 2011-era merge-mined chain with no surviving public
infrastructure. The input is a complete `getblock`-JSON dump shared by
Nicholas Stifter; one JSONL record per Geistgeld block,
~7.3M total, ~2.49M AuxPoW-bearing. Records carry a fully-decoded
``auxpow`` object with ``coinbasetx`` (scriptsig only — no ``vout``) and
``parent_block`` (BTC header fields plus a pre-computed ``hash``).

There is no separate ``extract_*`` step: the dump itself is the
extraction output. This script merges what extract+classify do for the
other chains:

  1. Stream the gzipped JSONL and select AuxPoW-bearing records.
  2. Reconstruct the 80-byte BTC header from ``parent_block`` fields and
     check ``SHA256d(header)`` against the header's own ``nBits`` at full
     Bitcoin difficulty. Discard headers that meet only Geistgeld's
     lower target.
  3. Deduplicate by BTC parent header hash (many GG blocks can embed the
     same parent during a BTC interval).
  4. Classify non-canonical headers against Bitcoin Core via
     ``getblockheader``: prev_hash on mainchain → ``stale``, otherwise
     ``unknown``. ``btc_height = prev.height + 1`` for stales.

Outputs are written in the shared classifier schema (matches
``classify_huntercoin_stales.py``):

  - ``data/geistgeld_canonical_blocks.csv`` — canonical rows.
  - ``data/geistgeld_stale_blocks.csv`` — stale rows.
  - ``data/geistgeld_unknown_blocks.csv`` — unknown rows.
  - ``data/validated-stales/geistgeld_validated_stales.csv`` — stale-only subset, the
    loader's input.

``coinbase_outputs`` is always empty for Geistgeld: ``auxpow.coinbasetx``
in the dump carries no ``vout`` field. The scriptSig is preserved as the only
available evidence for a later attribution phase.
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


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

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
    normalize_bits_hex,
    output_columns,
    write_classifier_outputs,
)
from stale_blocks_analysis.btc_stale_validation import validate_stale_header_context
from stale_blocks_analysis.classifier_cli import add_rpc_args, rpc_from_args
from stale_blocks_analysis.config import CHAIN_SPECS

_SPEC = CHAIN_SPECS["geistgeld"]

# The input is the chain-specific getblock-JSON archival dump, not the shared
# raw-extract CSV, so it stays a local constant rather than reading spec.input_csv.
DEFAULT_INPUT = (
    REPO_ROOT
    / "data"
    / "prototype"
    / "geistgeld"
    / "geistgeld_getblock_0to7309971_nbits_fixedlabels_auxheight.json.gz"
)
# Output/validated defaults and the child-height column come from CHAIN_SPECS.
DEFAULT_OUTPUT = _SPEC.output_csv
DEFAULT_VALIDATED_OUTPUT = _SPEC.validated_csv

# Bitcoin Core RPC

BATCH_SIZE = 200

OUTPUT_COLUMNS = output_columns(_SPEC.height_column)

# ── PoW + nBits helpers ──────────────────────────────────────────────────


def hash_meets_target(header_hex: str) -> bool:
    """Phase 1 PoW predicate: does the 80-byte parent header meet its own BTC nBits?

    Routes the header hash through the mandated byte-order helper
    (``hash_from_header_bytes`` -> internal 32 bytes) and the shared
    ``hash_meets_btc_difficulty`` rather than ad hoc ``[::-1]`` / int(display).
    """
    try:
        raw = bytes.fromhex(header_hex)
    except (ValueError, TypeError):
        return False
    if len(raw) != 80:
        return False
    bits = int.from_bytes(raw[72:76], "little")
    header_hash_internal = hash_from_header_bytes(raw)
    return hash_meets_btc_difficulty(header_hash_internal, bits)


def reconstruct_header_hex(pb: dict) -> str:
    """80-byte BTC header hex from a decoded `parent_block` dict.

    Layout (each field little-endian):
      version (4) | prev hash (32) | merkle root (32) | time (4) |
      bits (4) | nonce (4)

    The hex strings in the JSON are big-endian display form, so they're
    byte-reversed before concatenation.
    """
    version = struct.pack("<I", pb["version"])
    prev = bytes.fromhex(pb["previousblockhash"])[::-1]
    merkle = bytes.fromhex(pb["merkleroot"])[::-1]
    t = struct.pack("<I", pb["time"])
    bits = bytes.fromhex(pb["bits"])[::-1]
    nonce = struct.pack("<I", pb["nonce"])
    return (version + prev + merkle + t + bits + nonce).hex()


# ── Phase 1: stream + PoW filter + dedup ─────────────────────────────────


def stream_candidates(input_path: Path) -> tuple[dict[str, dict], dict[str, int]]:
    """Walk the gzipped JSONL once. Returns (unique_candidates, stats).

    The unique-candidate map keys on BTC parent header hash (Stifter's
    pre-computed value, sample-verified to match SHA256d(header) — see
    the verification report in the brief). The first AuxPoW record
    embedding a given parent wins; later duplicates are skipped, so
    ``geistgeld_height`` is the minimum GG height that witnessed that
    parent.

    Stats include total records, AuxPoW count, self-target-PoW-pass count
    (pre-dedup), and the final unique-parent count.
    """
    candidates: dict[str, dict] = {}
    stats = {
        "total": 0,
        "auxpow": 0,
        "pow_pass": 0,
        "missing_fields": 0,
    }
    t0 = time.time()

    with gzip.open(input_path, "rt") as fh:
        for line in fh:
            stats["total"] += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ap = rec.get("auxpow")
            if not ap:
                continue
            stats["auxpow"] += 1

            pb = ap.get("parent_block")
            if not pb:
                stats["missing_fields"] += 1
                continue

            try:
                header_hex = reconstruct_header_hex(pb)
            except (KeyError, ValueError):
                stats["missing_fields"] += 1
                continue

            if not hash_meets_target(header_hex):
                continue
            stats["pow_pass"] += 1

            parent_hash = pb.get("hash") or ""
            if not parent_hash or parent_hash in candidates:
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
                    f"record {stats['total']}: invalid child header: {exc}"
                ) from exc

            cb_vin = ap.get("coinbasetx", {}).get("vin", [{}])
            scriptsig_hex = cb_vin[0].get("coinbase", "") if cb_vin else ""

            candidates[parent_hash] = {
                **child_fields,
                "btc_header_hash": parent_hash,
                "btc_prev_hash": pb.get("previousblockhash", ""),
                "btc_time": str(pb.get("time", "")),
                "btc_bits": pb.get("bits", ""),
                "coinbase_scriptsig_hex": scriptsig_hex,
                "coinbase_outputs": "",  # absent from the dump; see module doc
                "btc_header_hex": header_hex,
                "geistgeld_height": str(rec.get("height", "")),
                "btc_height": "",  # filled in by classify
                "classification": "",
            }

            if stats["total"] % 500_000 == 0:
                elapsed = time.time() - t0
                rate = stats["total"] / elapsed if elapsed else 0
                print(
                    f"  scanned {stats['total']:>10,} | auxpow {stats['auxpow']:,} | "
                    f"self-target-pass unique {len(candidates):,} | "
                    f"{rate:,.0f} rec/s",
                    flush=True,
                )

    return candidates, stats


# ── orchestration ────────────────────────────────────────────────────────


def main() -> int:
    """Run the classifier CLI over the extracted candidate CSV."""
    parser = argparse.ArgumentParser(
        description="Classify Geistgeld AuxPoW parent headers as stale / unknown"
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--validated-output", type=Path, default=DEFAULT_VALIDATED_OUTPUT
    )
    add_rpc_args(parser)
    args = parser.parse_args()

    if not args.input.exists():
        print(f"ERROR: input not found at {args.input}", file=sys.stderr)
        return 1

    rpc = rpc_from_args(args)

    try:
        probe = rpc.batch(
            [{"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}]
        )
        btc_tip = probe[0].get("result")
        if btc_tip is None:
            raise RuntimeError("RPC probe returned no result")
        print(f"Bitcoin Core tip via {args.rpc_url}: {btc_tip}")
    except Exception as exc:
        print(
            f"ERROR: cannot reach Bitcoin Core at {args.rpc_url}: {exc}",
            file=sys.stderr,
        )
        return 1

    print(f"\n=== Phase 1: stream + PoW filter + dedup ===")
    print(f"Reading {args.input}…")
    t0 = time.time()
    candidates, stats = stream_candidates(args.input)
    t1 = time.time()
    print(f"  Total records:           {stats['total']:,}")
    print(f"  AuxPoW-bearing:          {stats['auxpow']:,}")
    print(f"  Missing parent_block:    {stats['missing_fields']:,}")
    print(f"  Self-target PoW passes:  {stats['pow_pass']:,} (pre-dedup)")
    print(f"  Unique parent hashes:    {len(candidates):,}")
    print(f"  Phase 1 elapsed:         {t1 - t0:.1f}s")

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
        print("\nNo self-target-PoW-valid parent headers found. Empty outputs written.")
        return 0

    print(f"\n=== Phase 2: Bitcoin Core classification ===")
    cand_list = list(candidates.values())
    all_results: list[dict] = []
    t2 = time.time()
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
            rate = done / max(time.time() - t2, 1e-6)
            eta = (len(cand_list) - done) / rate if rate > 0 else 0
            stales = sum(1 for r in all_results if r["classification"] == "stale")
            unknowns = sum(1 for r in all_results if r["classification"] == "unknown")
            print(
                f"  {done:>7,}/{len(cand_list):,} | "
                f"{rate:,.0f} headers/s | "
                f"stale {stales} | unknown {unknowns} | "
                f"ETA {eta / 60:.1f}m",
                flush=True,
            )

    if len(all_results) != len(cand_list):
        raise RuntimeError(
            "classification produced a partial result set "
            f"({len(all_results)} of {len(cand_list)} headers)"
        )

    # nBits gate (canonical schema): normalize btc_bits to lowercase 8-char hex
    # (geistgeld parent_block bits is hex) and mark each stale VALID / REJECTED /
    # UNKNOWN against the canonical Bitcoin nBits before writing.
    pre_stales = [r for r in all_results if r["classification"] == "stale"]
    for r in pre_stales:
        if r.get("btc_bits"):
            r["btc_bits"] = normalize_bits_hex(r["btc_bits"], source_is_decimal=False)
    validate_stale_header_context(
        pre_stales,
        rpc.batch,
        height_key="btc_height",
        bits_key="btc_bits",
        status_key="validation_status",
        expected_key="expected_nbits",
    )

    # Write the four bucket-split outputs via the shared writer.
    canonical_path, unknown_path = derive_split_paths(str(args.output))
    write_classifier_outputs(
        all_results,
        columns=OUTPUT_COLUMNS,
        canonical_path=canonical_path,
        stale_path=str(args.output),
        unknown_path=unknown_path,
        validated_path=str(args.validated_output),
    )
    stales = [r for r in all_results if r["classification"] == "stale"]
    unknown_rows = [r for r in all_results if r["classification"] == "unknown"]
    valid_stales = [s for s in stales if s.get("validation_status") == "VALID"]

    heights = [int(r["btc_height"]) for r in all_results if r.get("btc_height")]

    print(f"\n=== Summary ===")
    print(f"  Total records scanned:   {stats['total']:,}")
    print(f"  AuxPoW-bearing:          {stats['auxpow']:,}")
    print(f"  Unique parent hashes:    {len(candidates):,}")
    print(f"  Stale:                   {len(stales):,}")
    print(f"  Unknown:                 {len(unknown_rows):,}")
    if heights:
        print(f"  BTC height range:        {min(heights):,} – {max(heights):,}")
    print(f"  Output: {args.output}")
    print(f"  Validated stales: {args.validated_output}")

    if stales:
        print(f"\n=== Stale blocks ===")
        for r in stales:
            print(
                f"  BTC height {r.get('btc_height', '?'):>7} | "
                f"hash {r['btc_header_hash']} | "
                f"GG h={r['geistgeld_height']} | time {r['btc_time']}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
