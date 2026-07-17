#!/usr/bin/env python3
"""Classify the RSK merge-mining CSV into stale + unknown BTC parent headers.

Run near a local Bitcoin Core RPC endpoint against the raw CSV produced by
scripts/extract/extract_rsk_auxpow.py. Four passes:

  1. Stream the raw CSV, corroborate each serialized parent header, and keep
     rows whose computed hash meets the target encoded in that header. This is
     not yet a comparison with Bitcoin's contemporaneous target.
  2. Canonical check: for each self-target-PoW-valid row, ask Bitcoin Core if the header is
     on the active chain. Discard those because they are not stales.
  3. Parent check: for the non-canonical candidates, look up btc_prev_hash.
     If found, the row is a `stale` (canonical-parent → known stale height).
     If not, the row is an `unknown` (no canonical ancestor in our Core).
  4. Available-evidence validation: require the candidate time to exceed its
     active parent's median-time-past, require btc_bits to match the canonical
     block at the inferred height, and enforce Bitcoin's historical minimum
     header version. RSK's compressed proof does not expose the coinbase fields
     needed for the scriptSig-length or BIP34-prefix checks.

The full parallel-schema `rsk_stale_blocks.csv` preserves every stale row,
including rejected candidates, plus the unknown inventory. The normalized
VALID-only `rsk_validated_stales.csv` applies the exact-key exclusion overlay.
RSK loses the coinbase scriptSig and outputs to its midstate-compressed proof,
so the standard Namecoin-family evidence schema is necessarily sparse. The
classifier retains `rsk_miner` and joins labels only from the committed
historical registry snapshot.
"""

import argparse
import csv
import sys
import time
from pathlib import Path

from stale_blocks_analysis.auxpow_chainid import hash_from_header_bytes
from stale_blocks_analysis.auxpow_parse import (
    hash_meets_btc_difficulty,
    parse_parent_header,
)
from stale_blocks_analysis.btc_classify import (
    _header_result,
    _is_active_chain_header,
    _ordered_batch_responses,
    normalize_bits_hex,
)
from stale_blocks_analysis.btc_stale_validation import (
    block_version_error,
    median_time_past_error,
)
from stale_blocks_analysis.classifier_cli import add_rpc_args, rpc_from_args
from stale_blocks_analysis.stale_exclusions import load_stale_exclusion_keys

BATCH = 100

DEFAULT_INPUT = "data/rsk/rsk_auxpow_raw.csv"
DEFAULT_STALES_OUT = "data/rsk_stale_blocks.csv"
DEFAULT_VALIDATED_OUT = "data/validated-stales/rsk_validated_stales.csv"
DEFAULT_SUMMARY_OUT = "results/rsk_classification_summary.txt"
DEFAULT_POOL_REGISTRY = "results/rsk_pool_registry.csv"

# Full classified-output columns. Uncle fields pass through from the raw
# extractor's uncle traversal and remain empty in canonical-only extracts.
OUT_COLS = [
    "btc_stale_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "rsk_height",
    "rsk_timestamp",
    "rsk_miner",
    "merge_mining_hash",
    "btc_header_hex",
    "coinbase_op_return",
    "coinbase_ascii_strings",
    "is_uncle",
    "uncle_index",
    "uncle_parent_height",
    "classification",
    "validation_status",
    "expected_nbits",
]

VALIDATED_COLS = [
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "rsk_height",
    "classification",
    "validation_status",
    "expected_nbits",
    "rsk_timestamp",
    "rsk_miner",
    "pool_label",
    "merge_mining_hash",
    "coinbase_op_return",
    "coinbase_ascii_strings",
    "is_uncle",
    "uncle_index",
    "uncle_parent_height",
]


def parse_args(argv: list[str] | None = None):
    """Parse CLI flags for input/output paths."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", default=DEFAULT_INPUT, help="raw RSK merge-mining CSV"
    )
    parser.add_argument(
        "--stales-out",
        default=DEFAULT_STALES_OUT,
        help="classified stale/unknown output CSV",
    )
    parser.add_argument(
        "--validated-out",
        default=DEFAULT_VALIDATED_OUT,
        help="normalized VALID-only direct-stale loader input",
    )
    parser.add_argument(
        "--pool-registry",
        default=DEFAULT_POOL_REGISTRY,
        help="committed historical RSK miner-label snapshot",
    )
    parser.add_argument(
        "--summary-out",
        default=DEFAULT_SUMMARY_OUT,
        help="classification summary text output",
    )
    add_rpc_args(parser)
    return parser.parse_args(argv)


def ensure_parent(path: str) -> None:
    """Create the parent directory of ``path`` if it does not already exist."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def bits_to_target(bits_hex: str) -> int:
    """Expand a compact ``nBits`` hex string into the full target integer."""
    n = int(bits_hex, 16)
    e, m = n >> 24, n & 0xFFFFFF
    return m >> (8 * (3 - e)) if e <= 3 else m << (8 * (e - 3))


def meets_pow(h, b):
    """Return True if header hash ``h`` satisfies target ``b`` (compact hex).

    ``h`` is display-order (RPC-order) hex. Parsing it directly with
    ``int(h, 16)`` yields the same magnitude as the internal little-endian
    interpretation, so no byte-order conversion is needed here.
    """
    return int(h, 16) <= bits_to_target(b)


def validate_candidate_header(row: dict[str, str], row_number: int) -> dict:
    """Corroborate RSK metadata against the serialized Bitcoin header."""
    header_hex = (row.get("btc_header_hex") or "").strip()
    if len(header_hex) != 160:
        raise ValueError(f"RSK row {row_number}: btc_header_hex is not 80 bytes")
    try:
        raw = bytes.fromhex(header_hex)
    except ValueError as exc:
        raise ValueError(f"RSK row {row_number}: btc_header_hex is malformed") from exc
    parsed = parse_parent_header(raw)
    expected = {
        "btc_header_hash": parsed["hash"],
        "btc_prev_hash": parsed["prev_hash"],
        "btc_time": str(parsed["time"]),
        "btc_bits": parsed["bits_hex"],
    }
    for field, value in expected.items():
        stated = (row.get(field) or "").strip().lower()
        if field == "btc_bits":
            try:
                stated = normalize_bits_hex(stated)
            except ValueError as exc:
                raise ValueError(f"RSK row {row_number}: malformed btc_bits") from exc
        if stated != value:
            raise ValueError(
                f"RSK row {row_number}: {field} does not match btc_header_hex"
            )
    if not hash_meets_btc_difficulty(hash_from_header_bytes(raw), parsed["bits"]):
        return {**parsed, "meets_pow": False}
    row["btc_bits"] = parsed["bits_hex"]
    return {**parsed, "meets_pow": True}


def load_pool_labels(path: str) -> dict[str, str]:
    """Load the committed historical miner-address label snapshot."""
    labels: dict[str, str] = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            miner = (row.get("rsk_miner") or "").strip().lower()
            if miner:
                labels[miner] = (row.get("pool_label") or "").strip()
    return labels


def row_to_out(
    row,
    classification,
    btc_stale_height="",
    *,
    validation_status="",
    expected_nbits="",
):
    """Map a raw RSK proof row plus its classification to an OUT_COLS row dict."""
    return {
        "btc_stale_height": btc_stale_height,
        "btc_header_hash": row["btc_header_hash"],
        "btc_prev_hash": row["btc_prev_hash"],
        "btc_time": row["btc_time"],
        "btc_bits": row["btc_bits"],
        "rsk_height": row["rsk_height"],
        "rsk_timestamp": row["rsk_timestamp"],
        "rsk_miner": row["rsk_miner"],
        "merge_mining_hash": row["merge_mining_hash"],
        "btc_header_hex": row["btc_header_hex"],
        "coinbase_op_return": row["coinbase_op_return"],
        "coinbase_ascii_strings": row["coinbase_ascii_strings"],
        "is_uncle": row.get("is_uncle", ""),
        "uncle_index": row.get("uncle_index", ""),
        "uncle_parent_height": row.get("uncle_parent_height", ""),
        "classification": classification,
        "validation_status": validation_status,
        "expected_nbits": expected_nbits,
    }


def validated_row(row: dict[str, str], height: int, pool_labels: dict[str, str]):
    """Normalize one accepted RSK row to the committed public schema."""
    miner = (row.get("rsk_miner") or "").strip().lower()
    return {
        "btc_height": str(height),
        "btc_header_hash": row["btc_header_hash"],
        "btc_prev_hash": row["btc_prev_hash"],
        "btc_time": row["btc_time"],
        "btc_bits": row["btc_bits"],
        "coinbase_scriptsig_hex": "",
        "coinbase_outputs": "",
        "btc_header_hex": row["btc_header_hex"],
        "rsk_height": row["rsk_height"],
        "classification": "stale",
        "validation_status": "VALID",
        "expected_nbits": row["expected_nbits"],
        "rsk_timestamp": row["rsk_timestamp"],
        "rsk_miner": row["rsk_miner"],
        "pool_label": pool_labels.get(miner, ""),
        "merge_mining_hash": row["merge_mining_hash"],
        "coinbase_op_return": row["coinbase_op_return"],
        "coinbase_ascii_strings": row["coinbase_ascii_strings"],
        "is_uncle": row.get("is_uncle", ""),
        "uncle_index": row.get("uncle_index", ""),
        "uncle_parent_height": row.get("uncle_parent_height", ""),
    }


def build_validated_rows(
    verified: list[tuple[int, dict[str, str]]],
    pool_labels: dict[str, str],
    excluded: set[tuple[int, str]],
) -> list[dict[str, str]]:
    """Build deterministic public rows after the exact-key exclusion overlay."""
    rows = [
        validated_row(row, height, pool_labels)
        for height, row in verified
        if (height, row["btc_header_hash"].lower()) not in excluded
    ]
    rows.sort(key=lambda row: (int(row["btc_height"]), row["btc_header_hash"]))
    return rows


def active_header(response: object, block_hash: str, *, require_height: bool = False):
    """Return a validated active-chain header, or ``None`` for absent/side-chain."""
    result = _header_result(response, block_hash=block_hash)
    if not _is_active_chain_header(result, block_hash=block_hash):
        return None
    if require_height:
        height = result.get("height")
        if not isinstance(height, int) or isinstance(height, bool) or height < 0:
            raise ValueError(
                f"active-chain getblockheader result lacks a valid height for {block_hash}"
            )
    return result


def canonical_hash(response: object, height: int) -> str:
    """Validate one getblockhash response for an active-chain height."""
    if not isinstance(response, dict):
        raise ValueError(f"getblockhash response for height {height} is not an object")
    if response.get("error") is not None:
        raise RuntimeError(
            f"getblockhash failed for active-chain height {height}: "
            f"{response['error']!r}"
        )
    block_hash = response.get("result")
    if not isinstance(block_hash, str) or len(block_hash) != 64:
        raise ValueError(f"getblockhash returned malformed hash at height {height}")
    try:
        bytes.fromhex(block_hash)
    except ValueError as exc:
        raise ValueError(
            f"getblockhash returned malformed hash at height {height}"
        ) from exc
    return block_hash.lower()


def stale_validation_error(
    row: dict[str, str],
    height: int,
    expected_nbits: str,
    parent_median_time_past: int,
) -> str | None:
    """Return an MTP, version, or nBits rejection reason."""
    mtp_error = median_time_past_error(row, parent_median_time_past)
    if mtp_error is not None:
        return mtp_error
    version_error = block_version_error(row, height)
    if version_error is not None:
        return version_error
    ours = row["btc_bits"].lower()
    expected = expected_nbits.lower()
    if not expected or expected != ours:
        return (
            f"REJECTED: nBits mismatch (got {ours}, expected {expected or 'unknown'})"
        )
    return None


def main():
    """Run the four-pass RSK classifier and write CSV and summary outputs."""
    args = parse_args()
    bitcoin_rpc = rpc_from_args(args)
    real_pow_rows = []
    total = 0
    t0 = time.time()

    print("=== Pass 1: scanning all rows ===", file=sys.stderr, flush=True)
    with open(args.input) as f:
        reader = csv.DictReader(f)
        for row_number, row in enumerate(reader, start=2):
            total += 1
            parsed = validate_candidate_header(row, row_number)
            if parsed["meets_pow"]:
                real_pow_rows.append(row)
            if total % 1_000_000 == 0:
                rate = total / (time.time() - t0)
                print(
                    f"  {total:,} rows scanned ({rate:,.0f}/s) | "
                    f"{len(real_pow_rows):,} self-target-PoW-valid so far",
                    file=sys.stderr,
                    flush=True,
                )
    pass1_time = time.time() - t0
    print(f"\nPass 1 done in {pass1_time:.0f}s", file=sys.stderr)
    print(f"  Total rows: {total:,}", file=sys.stderr)
    print(
        f"  Self-target PoW valid: {len(real_pow_rows):,} "
        f"({100 * len(real_pow_rows) / total:.3f}%)",
        file=sys.stderr,
    )

    # Pass 2: canonical check
    print("\n=== Pass 2: canonical check ===", file=sys.stderr, flush=True)
    candidates = []
    canonical_count = 0
    t0 = time.time()
    for i in range(0, len(real_pow_rows), BATCH):
        batch = real_pow_rows[i : i + BATCH]
        calls = [
            {
                "jsonrpc": "1.0",
                "id": j,
                "method": "getblockheader",
                "params": [r["btc_header_hash"]],
            }
            for j, r in enumerate(batch)
        ]
        res = _ordered_batch_responses(
            bitcoin_rpc.batch(calls),
            expected_count=len(calls),
            method="RSK canonical check",
        )
        for j, rr in enumerate(res):
            block_hash = batch[j]["btc_header_hash"]
            if active_header(rr, block_hash) is not None:
                canonical_count += 1
            else:
                candidates.append(batch[j])
        if (i // BATCH) % 100 == 0:
            done = i + BATCH
            rate = done / (time.time() - t0 + 0.001)
            print(
                f"  {done:,}/{len(real_pow_rows):,} ({rate:.0f}/s) | "
                f"canonical={canonical_count:,}, candidates={len(candidates):,}",
                file=sys.stderr,
                flush=True,
            )
    print(f"  canonical: {canonical_count:,}", file=sys.stderr)
    print(f"  candidates (non-canonical): {len(candidates):,}", file=sys.stderr)

    # Pass 3: parent check
    print("\n=== Pass 3: parent check ===", file=sys.stderr, flush=True)
    stales_with_height = []
    unknowns = []
    parent_results = [None] * len(candidates)
    for i in range(0, len(candidates), BATCH):
        batch_idx = list(range(i, min(i + BATCH, len(candidates))))
        calls = [
            {
                "jsonrpc": "1.0",
                "id": k,
                "method": "getblockheader",
                "params": [candidates[idx]["btc_prev_hash"]],
            }
            for k, idx in enumerate(batch_idx)
        ]
        res = _ordered_batch_responses(
            bitcoin_rpc.batch(calls),
            expected_count=len(calls),
            method="RSK parent check",
        )
        for k, rr in enumerate(res):
            candidate_idx = batch_idx[k]
            parent_hash = candidates[candidate_idx]["btc_prev_hash"]
            parent_results[candidate_idx] = active_header(
                rr, parent_hash, require_height=True
            )
    for idx, parent in enumerate(parent_results):
        if parent:
            mediantime = parent.get("mediantime")
            if (
                not isinstance(mediantime, int)
                or isinstance(mediantime, bool)
                or mediantime < 0
                or mediantime > 0xFFFFFFFF
            ):
                raise ValueError(
                    f"canonical parent {parent['hash']} lacks valid mediantime"
                )
            stales_with_height.append(
                (parent["height"] + 1, candidates[idx], mediantime)
            )
        else:
            unknowns.append(candidates[idx])
    print(
        f"  stale candidates (parent canonical): {len(stales_with_height):,}",
        file=sys.stderr,
    )
    print(f"  unknowns (parent unknown): {len(unknowns):,}", file=sys.stderr)

    # Pass 4: nBits and block-version validation, only for the stale path.
    # Unknowns have no canonical parent so no height to validate against.
    print("\n=== Pass 4: header-context validation ===", file=sys.stderr, flush=True)
    unique_heights = sorted(set(h for h, _, _ in stales_with_height))
    canon_bits_at = {}
    for i in range(0, len(unique_heights), BATCH):
        sub = unique_heights[i : i + BATCH]
        calls = [
            {"jsonrpc": "1.0", "id": j, "method": "getblockhash", "params": [h]}
            for j, h in enumerate(sub)
        ]
        res = _ordered_batch_responses(
            bitcoin_rpc.batch(calls),
            expected_count=len(calls),
            method="RSK getblockhash",
        )
        sub_hashes = [(sub[j], canonical_hash(r, sub[j])) for j, r in enumerate(res)]
        calls2 = [
            {"jsonrpc": "1.0", "id": j, "method": "getblockheader", "params": [h]}
            for j, (_, h) in enumerate(sub_hashes)
        ]
        res2 = _ordered_batch_responses(
            bitcoin_rpc.batch(calls2),
            expected_count=len(calls2),
            method="RSK canonical header",
        )
        for j, rr in enumerate(res2):
            canonical_block_hash = sub_hashes[j][1]
            header = active_header(rr, canonical_block_hash, require_height=True)
            if header is None:
                raise ValueError(
                    f"getblockhash returned non-active header {canonical_block_hash}"
                )
            if header["height"] != sub_hashes[j][0]:
                raise ValueError(
                    f"canonical header height mismatch for {canonical_block_hash}: "
                    f"expected {sub_hashes[j][0]}, got {header['height']}"
                )
            try:
                canon_bits_at[sub_hashes[j][0]] = normalize_bits_hex(
                    header.get("bits", "")
                )
            except ValueError as exc:
                raise ValueError(
                    f"canonical header {canonical_block_hash} lacks valid bits"
                ) from exc

    verified = []
    rejected = []
    for height, row, parent_median_time_past in stales_with_height:
        expected = canon_bits_at.get(height, "").lower()
        row["expected_nbits"] = expected
        error = stale_validation_error(
            row,
            height,
            expected,
            parent_median_time_past,
        )
        if error is None:
            row["validation_status"] = "VALID"
            verified.append((height, row))
        else:
            row["validation_status"] = error
            rejected.append((height, row, error))
    print(f"  publication-gate accepted stales: {len(verified):,}", file=sys.stderr)
    print(
        f"  rejected (MTP/nBits/version): {len(rejected):,}",
        file=sys.stderr,
    )

    # Resolve every committed dependency before opening either output, so a
    # missing exclusion overlay or historical registry cannot leave a newly
    # written full inventory beside a stale validated artifact.
    excluded = load_stale_exclusion_keys()
    pool_labels = load_pool_labels(args.pool_registry)
    public_rows = build_validated_rows(verified, pool_labels, excluded)

    # Full classified output retains every stale-labelled row, including gate
    # rejections, plus the unknown inventory. The normalized public loader input
    # contains only VALID direct stales after the exact-key exclusion overlay.
    print("\n=== Writing outputs ===", file=sys.stderr)
    ensure_parent(args.stales_out)
    with open(args.stales_out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=OUT_COLS)
        w.writeheader()
        classified_stales = [(h, row) for h, row in verified] + [
            (h, row) for h, row, _ in rejected
        ]
        for h, row in sorted(classified_stales, key=lambda x: x[0]):
            w.writerow(
                row_to_out(
                    row,
                    "stale",
                    btc_stale_height=h,
                    validation_status=row["validation_status"],
                    expected_nbits=row["expected_nbits"],
                )
            )
        for row in sorted(unknowns, key=lambda r: int(r["rsk_height"])):
            w.writerow(row_to_out(row, "unknown"))

    ensure_parent(args.validated_out)
    with open(args.validated_out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=VALIDATED_COLS)
        writer.writeheader()
        writer.writerows(public_rows)

    ensure_parent(args.summary_out)
    with open(args.summary_out, "w") as f:
        f.write("RSK merge-mining classification summary\n")
        f.write("=" * 60 + "\n")
        f.write(f"Total RSK merge-mining rows:     {total:>12,}\n")
        f.write(
            f"Self-target-PoW-valid headers:   {len(real_pow_rows):>12,}  "
            f"({100 * len(real_pow_rows) / total:.3f}%)\n"
        )
        f.write(f"  Canonical (in BTC chain):      {canonical_count:>12,}\n")
        f.write(f"  Stale candidates:              {len(candidates):>12,}\n")
        f.write(f"    With canonical parent:       {len(stales_with_height):>12,}\n")
        f.write(f"      Gate-accepted candidates:  {len(verified):>12,}\n")
        f.write(f"      Rejected (MTP/nBits/version): {len(rejected):>9,}\n")
        f.write(f"    Unknowns (no canonical parent): {len(unknowns):>10,}\n")
        f.write(
            f"\nOutput rows in rsk_stale_blocks.csv: "
            f"{len(stales_with_height) + len(unknowns):,} "
            f"({len(stales_with_height):,} stale + {len(unknowns):,} unknown)\n"
        )
        f.write(
            f"VALID direct-stale rows after exclusion overlay: {len(public_rows):,}\n"
        )
    print(f"\n✓ Outputs:", file=sys.stderr)
    print(
        f"  {args.stales_out}  ({len(stales_with_height) + len(unknowns):,} rows: "
        f"{len(stales_with_height):,} stale + {len(unknowns):,} unknown)",
        file=sys.stderr,
    )
    print(
        f"  {args.validated_out}  ({len(public_rows):,} VALID direct stales)",
        file=sys.stderr,
    )
    print(f"  {args.summary_out}", file=sys.stderr)


if __name__ == "__main__":
    main()
