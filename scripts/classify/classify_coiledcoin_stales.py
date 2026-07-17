#!/usr/bin/env python3
"""
Classify CoiledCoin AuxPoW candidates as canonical, stale, or unknown.

Input: output of extract_auxpow_from_blkdat.py --chain coiledcoin
       (fields: child_height, btc_hash, btc_prev_hash, btc_time, btc_bits_hex,
                btc_bip34_height, btc_nonce, coinbase_scriptsig_hex,
                coinbase_outputs, btc_header_hex)

Phases:
  1. Deduplicate by btc_hash (multiple CLC blocks can embed the same BTC header)
  2. Batch-query local Bitcoin Core:
       - getblockheader <hash>       → canonical? skip.
       - getblockheader <prev_hash>  → prev exists? STALE; else UNKNOWN.
  3. Flag the Eligius attack window (BTC ~160,000-163,000, Jan 2012).

Candidate range (Dec 2011 to May 2016) is all pre-BCH, so no BCH/BSV nBits
cross-check is applied here (in contrast to elastos/ixcoin classifiers).
"""

import argparse
import csv
import sys
import time


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

BATCH_SIZE = 200

_SPEC = CHAIN_SPECS["coiledcoin"]

# Eligius attack window: BTC heights ~160,000 to ~163,000 (Jan 5-10, 2012)
# Timestamp bounds: 1325721600 (Jan 5 2012) to 1326585600 (Jan 15 2012)
ELIGIUS_WINDOW_START = 1325721600
ELIGIUS_WINDOW_END = 1326585600

# Shared split schema (child-height column from CHAIN_SPECS) plus the
# CoiledCoin-specific eligius_attack_window flag column.
OUTPUT_COLUMNS = output_columns(_SPEC.height_column) + ["eligius_attack_window"]


def remap_candidate(row):
    """Rename extractor's fields to classifier's expected names (in place)."""
    return {
        "btc_header_hash": row["btc_hash"],
        "btc_prev_hash": row["btc_prev_hash"],
        "btc_time": row["btc_time"],
        "btc_bits": row["btc_bits_hex"],
        "coinbase_scriptsig_hex": row["coinbase_scriptsig_hex"],
        "coinbase_outputs": row["coinbase_outputs"],
        "btc_header_hex": row["btc_header_hex"],
        "clc_height": row["child_height"],
        "btc_height": row.get("btc_bip34_height") or "",
    }


def main():
    """Run this chain's classification pipeline end to end."""
    p = argparse.ArgumentParser()
    p.add_argument(
        "--input",
        required=True,
        help="Candidate CSV from extract_auxpow_from_blkdat.py",
    )
    p.add_argument("--output", required=True, help="Output CSV of stale/unknown blocks")
    p.add_argument(
        "--validated-output",
        default=str(_SPEC.validated_csv),
        help="VALID-only stale loader input (the committed canonical artifact)",
    )
    add_rpc_args(p)
    args = p.parse_args()

    rpc = rpc_from_args(args)

    # Sanity-check Bitcoin Core connectivity
    try:
        test = rpc.batch(
            [{"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}]
        )
        tip = test[0]["result"]
        print(f"Bitcoin Core tip: {tip:,}")
    except Exception as e:
        print(f"ERROR: Bitcoin Core unreachable: {e}", file=sys.stderr)
        sys.exit(1)

    # Load + dedupe candidates
    print(f"Loading {args.input}...")
    t0 = time.time()
    seen = set()
    candidates = []
    total_rows = 0
    with open(args.input) as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_rows += 1
            h = row["btc_hash"]
            if h in seen:
                continue
            seen.add(h)
            candidates.append(remap_candidate(row))
    print(f"  Total rows:         {total_rows:,}")
    print(f"  Unique BTC hashes:  {len(candidates):,}")
    print(f"  Load time:          {time.time() - t0:.1f}s")

    # Classify
    print(f"\nClassifying via Bitcoin Core RPC...")
    t1 = time.time()
    stale_unknown = []
    for start in range(0, len(candidates), BATCH_SIZE):
        batch = candidates[start : start + BATCH_SIZE]
        try:
            stale_unknown.extend(classify_candidates(batch, rpc))
        except Exception as e:
            # A deterministic API/signature error (not a transient RPC failure) means
            # a bug, not a bad batch; re-raise so it fails loud instead of silently
            # retrying into an empty result set that overwrites committed CSVs.
            if isinstance(e, (TypeError, AttributeError, NameError)):
                raise
            print(
                f"  Batch {start} failed ({e}); retrying individually", file=sys.stderr
            )
            for c in batch:
                try:
                    stale_unknown.extend(classify_candidates([c], rpc))
                except Exception as e2:
                    raise RuntimeError(
                        f"individual classification failed for {c['btc_header_hash']}"
                    ) from e2
        processed = min(start + BATCH_SIZE, len(candidates))
        if processed % 2000 < BATCH_SIZE:
            elapsed = time.time() - t1
            rate = processed / elapsed if elapsed > 0 else 0
            stales = sum(1 for r in stale_unknown if r["classification"] == "stale")
            unknowns_n = sum(
                1 for r in stale_unknown if r["classification"] == "unknown"
            )
            print(
                f"  {processed:>6,}/{len(candidates):,} | "
                f"{rate:,.0f} hdr/s | stale: {stales} | unknown: {unknowns_n}"
            )

    if len(stale_unknown) != len(candidates):
        raise RuntimeError(
            "classification produced a partial result set "
            f"({len(stale_unknown)} of {len(candidates)} headers)"
        )

    print(f"\nClassification complete in {time.time() - t1:.1f}s")
    stales = [r for r in stale_unknown if r["classification"] == "stale"]
    unknowns = [r for r in stale_unknown if r["classification"] == "unknown"]
    print(f"  STALE:   {len(stales)}")
    print(f"  UNKNOWN: {len(unknowns)}")

    # Flag the Eligius attack window
    for r in stale_unknown:
        ts = int(r.get("btc_time") or 0)
        r["eligius_attack_window"] = (
            "true" if ELIGIUS_WINDOW_START <= ts <= ELIGIUS_WINDOW_END else ""
        )
    eligius_stales = [r for r in stales if r["eligius_attack_window"] == "true"]
    eligius_unknowns = [r for r in unknowns if r["eligius_attack_window"] == "true"]
    print(
        f"  In Eligius attack window: "
        f"{len(eligius_stales)} stale, {len(eligius_unknowns)} unknown"
    )

    # nBits gate (canonical schema): normalize btc_bits to lowercase 8-char hex
    # (coiledcoin's candidate btc_bits_hex is already hex) then mark each stale
    # VALID / REJECTED / UNKNOWN against the canonical Bitcoin nBits.
    for r in stales:
        if r.get("btc_bits"):
            r["btc_bits"] = normalize_bits_hex(r["btc_bits"], source_is_decimal=False)
    validate_stale_header_context(
        stales,
        rpc.batch,
        height_key="btc_height",
        bits_key="btc_bits",
        status_key="validation_status",
        expected_key="expected_nbits",
    )
    valid_stales = [r for r in stales if r.get("validation_status") == "VALID"]
    print(
        f"  nBits gate: {len(valid_stales)} VALID / "
        f"{len(stales) - len(valid_stales)} REJECTED|UNKNOWN"
    )

    # Write the four bucket-split outputs via the shared writer.
    canonical_path, unknown_path = derive_split_paths(args.output)
    counts = write_classifier_outputs(
        stale_unknown,
        columns=OUTPUT_COLUMNS,
        canonical_path=canonical_path,
        stale_path=args.output,
        unknown_path=unknown_path,
        validated_path=args.validated_output,
    )
    print(
        f"\nWrote {counts['stale']} stale / {counts['unknown']} unknown / "
        f"{counts['canonical']} canonical; {counts['valid']} VALID → {args.validated_output}"
    )

    if stales:
        print(f"\n=== Stale summary (sorted by BTC height) ===")
        for s in sorted(stales, key=lambda x: int(x.get("btc_height") or 0)):
            flag = " [ELIGIUS]" if s["eligius_attack_window"] == "true" else ""
            print(
                f"  BTC {s['btc_height']:>7} | {s['btc_header_hash'][:16]}... | "
                f"CLC {s['clc_height']} | time {s['btc_time']}{flag}"
            )


if __name__ == "__main__":
    main()
