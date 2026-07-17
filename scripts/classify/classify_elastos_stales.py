#!/usr/bin/env python3
"""
Phase 3: Classify Elastos AuxPoW extracts as canonical, stale, or unknown.

The archived scan starts at ELA height 177,000 and first retains a non-dummy
parent proof at ELA 177,153 (August 2018), mapping to BTC height 538,457. Every
extracted row is therefore post-BCH. Expected-nBits validation against the
canonical Bitcoin chain is one part of the shared direct-stale publication
gate and rejects Bitcoin-family headers whose difficulty context is not BTC's.

Pipeline:
  Step 1: PoW filter (pure Python, no RPC):
    SHA256d(header) ≤ target(nBits). Retains only headers meeting
    their own encoded target. Deduplicate by btc_header_hash to minimise
    RPC volume because multiple ELA blocks often share the same parent.

  Step 2: Bitcoin Core classification (batch RPC):
    getblockheader(hash) with positive confirmations: canonical.
    Otherwise, getblockheader(prev) with positive confirmations: STALE;
    the remainder are UNKNOWN.

  Step 3: direct-stale context validation:
    Apply active-parent placement, median-time-past, historical block-version,
    coinbase scriptSig, BIP34 height, and canonical-at-height nBits checks.
    A candidate is accepted only when every available-evidence gate passes.

Output: bucket-split canonical, stale, and unknown CSVs, the committed
validated-stales CSV, and a rejected direct-stale audit CSV.
"""

import argparse
import csv
import os
import sys
import time

# Shared helpers (src/stale_blocks_analysis/). These replace the
# inline copies of the PoW filter, RPC auth/batch, and stale/unknown classifier
# that previously lived in this script.
sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src")
)
from stale_blocks_analysis.auxpow_chainid import hash_from_header_bytes
from stale_blocks_analysis.auxpow_parse import hash_meets_btc_difficulty
from stale_blocks_analysis.btc_classify import (
    classify_candidates as _classify_candidates,
    derive_split_paths,
    write_classifier_outputs,
)
from stale_blocks_analysis.btc_stale_validation import validate_stale_header_context
from stale_blocks_analysis.btc_rpc import BtcRpc
from stale_blocks_analysis.classifier_cli import add_rpc_args, rpc_from_args

# --- Bitcoin Core RPC config ---
BATCH_SIZE = 200

# BCH/BSV fork boundaries. All ELA real-parent evidence is post-BCH, and most
# is post-BSV.
BCH_FORK_HEIGHT = 478_559

# Output CSV columns. This matches the syscoin/ixcoin schema so the downstream
# load_elastos_stales() loader can mirror load_syscoin_stales().
OUTPUT_COLUMNS = [
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "ela_height",
    "classification",  # "stale" | "unknown"
    "validation_status",  # "VALID" | "REJECTED: ..." | "UNKNOWN"
    "expected_nbits",  # canonical nBits at that height, when known
    "post_bch_fork",  # "true" / "false"
]


def hash_meets_target(header_hex: str) -> bool:
    """SHA256d(header) ≤ target(nBits).

    Routes the Phase 1 PoW filter through the shared helpers: the header
    hash is computed in internal (little-endian) order via
    ``hash_from_header_bytes`` and compared against its own encoded nBits target
    by ``hash_meets_btc_difficulty``. The bits are read with the same little-
    endian slice the shared helpers use, never an ad hoc ``[::-1]``.
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


def classify_candidates(candidates: list[dict], rpc: BtcRpc) -> list[dict]:
    """Batch-classify self-target-PoW-valid headers as stale or unknown.

    Delegates the canonical/prev getblockheader linkage and the authoritative
    prev-height+1 override to the shared ``btc_classify.classify_candidates``
    (keyed on the Elastos child-height column), then re-applies the Elastos-
    specific annotations the inline copy carried: a tentative
    ``NEEDS_CONTEXT_VALIDATION`` status for stales (replaced later by
    ``validate_stale_header_context``), an ``UNKNOWN`` status for unknowns,
    the ``post_bch_fork`` flag derived from the corrected height, and an
    ``expected_nbits`` default.
    """
    results = _classify_candidates(candidates, rpc)
    for c in results:
        if c["classification"] == "stale":
            c["validation_status"] = "NEEDS_CONTEXT_VALIDATION"
            c["post_bch_fork"] = str(int(c["btc_height"]) >= BCH_FORK_HEIGHT).lower()
        else:
            c["validation_status"] = "UNKNOWN"
            c["post_bch_fork"] = ""
        c.setdefault("expected_nbits", "")
    return results


def main():
    """Run this chain's classification pipeline end to end."""
    p = argparse.ArgumentParser(description="Classify Elastos AuxPoW as stale/unknown")
    p.add_argument("--input", default="data/elastos_auxpow_raw.csv")
    p.add_argument("--output", default="data/elastos_stale_blocks.csv")
    p.add_argument("--rejected", default="data/elastos_rejected.csv")
    p.add_argument(
        "--validated-output",
        default="data/validated-stales/elastos_validated_stales.csv",
    )
    p.add_argument(
        "--all-valid",
        default="data/elastos_btc_valid.csv",
        help="Intermediate: unique headers passing PoW filter",
    )
    add_rpc_args(p)
    args = p.parse_args()

    rpc = rpc_from_args(args)

    try:
        tip_resp = rpc.batch(
            [{"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}],
        )
        print(f"Bitcoin Core tip: {tip_resp[0]['result']:,}")
    except Exception as e:
        print(f"ERROR: Cannot connect to Bitcoin Core: {e}")
        sys.exit(1)

    # --- Phase 1: PoW filter ---
    print(f"\n=== Phase 1: PoW filter ===")
    print(f"Reading {args.input}...")
    t0 = time.time()
    seen = set()
    valid = []
    total = 0
    with open(args.input) as f:
        for row in csv.DictReader(f):
            total += 1
            if hash_meets_target(row["btc_header_hex"]):
                h = row["btc_header_hash"]
                if h not in seen:
                    seen.add(h)
                    valid.append(row)
            if total % 500_000 == 0:
                elapsed = time.time() - t0
                print(
                    f"  {total:>10,} scanned | {len(valid):,} self-target-valid unique | "
                    f"{total / elapsed:,.0f} rows/s"
                )
    print(f"\nPoW filter done in {time.time() - t0:.1f}s")
    print(f"  Scanned:            {total:,}")
    print(f"  Self-target valid:  {len(valid):,}")
    print(f"  Filtered out:       {total - len(valid):,}")

    if valid:
        os.makedirs(os.path.dirname(args.all_valid) or ".", exist_ok=True)
        with open(args.all_valid, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(valid[0].keys()))
            w.writeheader()
            w.writerows(valid)
        print(f"  Intermediate:       {args.all_valid}")

    # --- Phase 2: classification ---
    print(f"\n=== Phase 2: Bitcoin Core classification ===")
    t2 = time.time()
    all_results = []
    for batch_start in range(0, len(valid), BATCH_SIZE):
        batch = valid[batch_start : batch_start + BATCH_SIZE]
        try:
            all_results.extend(classify_candidates(batch, rpc))
        except Exception as e:
            # A deterministic API/signature error (not a transient RPC failure) means
            # a bug, not a bad batch; re-raise so it fails loud instead of silently
            # retrying into an empty result set that overwrites committed CSVs.
            if isinstance(e, (TypeError, AttributeError, NameError)):
                raise
            print(f"  batch {batch_start} error: {e}; retrying individually")
            for c in batch:
                try:
                    all_results.extend(classify_candidates([c], rpc))
                except Exception as e2:
                    raise RuntimeError(
                        f"individual classification failed for {c['btc_header_hash']}"
                    ) from e2

        done = batch_start + len(batch)
        if done % 10_000 < BATCH_SIZE:
            elapsed = time.time() - t2
            rate = done / elapsed if elapsed else 0
            eta = (len(valid) - done) / rate if rate else 0
            stales = sum(1 for r in all_results if r["classification"] == "stale")
            unknown_rows = sum(
                1 for r in all_results if r["classification"] == "unknown"
            )
            print(
                f"  {done:>8,}/{len(valid):,} | {rate:,.0f} hdr/s | "
                f"stale: {stales} | unknown: {unknown_rows} | ETA: {eta / 60:.1f}m",
                flush=True,
            )
    if len(all_results) != len(valid):
        raise RuntimeError(
            "classification produced a partial result set "
            f"({len(all_results)} of {len(valid)} headers)"
        )
    print(f"\nClassification done in {time.time() - t2:.1f}s")

    stales = [r for r in all_results if r["classification"] == "stale"]
    unknown_rows = [r for r in all_results if r["classification"] == "unknown"]
    print(f"  Stale candidates: {len(stales)}")
    print(f"  Unknowns:         {len(unknown_rows)}")

    # --- Phase 3: shared available-evidence validation on direct stales ---
    print(f"\n=== Phase 3: direct-stale context validation ===")
    t3 = time.time()
    for batch_start in range(0, len(stales), BATCH_SIZE):
        batch = stales[batch_start : batch_start + BATCH_SIZE]
        try:
            validate_stale_header_context(batch, rpc.batch)
        except Exception as e:
            print(f"  validation batch {batch_start} error: {e}; retrying individually")
            for s in batch:
                try:
                    validate_stale_header_context([s], rpc.batch)
                except Exception as e2:
                    s["validation_status"] = f"UNKNOWN: {e2}"
    print(f"Context validation done in {time.time() - t3:.1f}s")

    validated = [s for s in stales if s["validation_status"] == "VALID"]
    rejected = [s for s in stales if s["validation_status"].startswith("REJECTED")]
    unknown = [
        s
        for s in stales
        if not (
            s["validation_status"] == "VALID"
            or s["validation_status"].startswith("REJECTED")
        )
    ]
    print(f"  VALID:    {len(validated)}")
    print(f"  REJECTED: {len(rejected)}")
    print(f"  UNKNOWN:  {len(unknown)}")

    # --- Phase 4: output (four bucket-split files + the rejected audit file) ---
    print(f"\n=== Output ===")
    canonical_path, unknown_path = derive_split_paths(args.output)
    counts = write_classifier_outputs(
        all_results,
        columns=OUTPUT_COLUMNS,
        canonical_path=canonical_path,
        stale_path=args.output,
        unknown_path=unknown_path,
        validated_path=args.validated_output,
    )
    print(
        f"  {args.output} → {counts['stale']} stale "
        f"({counts['valid']} VALID, {counts['rejected']} REJECTED)"
    )
    print(f"  {unknown_path} → {counts['unknown']} unknown")
    print(f"  {canonical_path} → {counts['canonical']} canonical")
    print(f"  {args.validated_output} → {counts['valid']} VALID stale")

    # Rejected stales are also kept as a separate audit artifact.
    os.makedirs(os.path.dirname(args.rejected) or ".", exist_ok=True)
    with open(args.rejected, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(sorted(rejected, key=lambda x: int(x.get("btc_height") or 0)))
    print(f"  {args.rejected} → {len(rejected)} rows")

    if validated:
        print(f"\n=== Validated stale summary ===")
        for s in sorted(validated, key=lambda x: int(x["btc_height"])):
            print(
                f"  BTC {int(s['btc_height']):,} | "
                f"{s['btc_header_hash'][:16]}... | "
                f"ELA {s['ela_height']} | "
                f"{s['btc_time']}"
            )


if __name__ == "__main__":
    main()
