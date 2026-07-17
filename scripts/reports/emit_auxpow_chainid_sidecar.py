#!/usr/bin/env python3
"""Emit child-side AuxPoW chain-ID inference sidecars.

This is the first Namecoin-family sidecar emitter. It reads raw blk*.dat files,
parses the child-side CAuxPow proof, and uses the embedded parent coinbase by
default. A caller may supply a precomputed coinbase marker census to join
canonical BTC parents by internal-order parent-header hash; the embedded
coinbase remains the fallback when the parent hash is absent from that input.

Example:
    python scripts/reports/emit_auxpow_chainid_sidecar.py \\
        --chain namecoin \\
        --blocks-dir ~/.namecoin/blocks \\
        --output data/namecoin_auxpow_chainid_sidecar.csv
"""

from __future__ import annotations

import argparse
import csv
import glob
import sqlite3
import struct
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "extract"))

from extract_auxpow_from_blkdat import (  # noqa: E402
    CHAINS,
    VERSION_AUXPOW,
    hash_meets_btc_difficulty,
    iter_blocks_from_file,
    parse_parent_header,
    read_auxpow,
)
from stale_blocks_analysis.auxpow_chainid import (  # noqa: E402
    ParentCommitment,
    auxpow_lcg_index,
    candidate_chains_for_residue,
    commitment_size_status,
    fold_merkle_branch,
    hash_from_display_bytes,
    hash_from_header_bytes,
    hash_to_display_hex,
    lcg_chain_id_residue,
    parent_commitment_for_proof,
    size_status_allows_inference,
)
from stale_blocks_analysis.auxpow_registry import get_chain  # noqa: E402

DEFAULT_OUTPUT = REPO_ROOT / "data" / "namecoin_auxpow_chainid_sidecar.csv"
CAUXPOW_PARSE_ERRORS = (IndexError, struct.error, ValueError)

FIELDNAMES = [
    "chain_slug",
    "child_sequence",
    "child_hash_internal_hex",
    "child_hash_display_hex",
    "child_version",
    "parent_header_hash_internal_hex",
    "parent_header_hash_display_hex",
    "parent_header_hex",
    "parent_prev_hash_display_hex",
    "parent_time",
    "parent_bits_hex",
    "parent_coinbase_scriptsig_hex",
    "parent_coinbase_outputs_hex",
    "vChainMerkleBranch_len",
    "vChainMerkleBranch_internal_hex",
    "nChainIndex",
    "computed_chain_merkle_root_internal_hex",
    "commitment_source",
    "commitment_root_internal_hex",
    "commitment_merkle_size",
    "commitment_merkle_nonce",
    "commitment_auxpow_offset",
    "commitment_census_height",
    "commitment_census_block_time",
    "commitment_tuple",
    "commitment_size_status",
    "chain_merkle_root_ok",
    "lcg_residue",
    "lcg_modulus",
    "candidate_chain_slugs",
    "candidate_chain_ids",
    "expected_index",
    "expected_index_ok",
    "expected_index_enforced",
    "inference_status",
]


def connect_census(path: Path | None) -> dict[bytes, ParentCommitment] | None:
    """Load the ``coinbase_mergemining_v1`` census DB into an in-memory commitment map.

    Returns ``None`` when ``path`` is ``None`` (census join disabled). Keys
    are internal-order parent header hash bytes. Raises ``FileNotFoundError``
    if ``path`` does not exist.
    """
    if path is None:
        return None
    if not path.exists():
        raise FileNotFoundError(f"census DB not found: {path}")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            """
            SELECT block_hash, block_height, block_time, auxpow_present,
                   auxpow_merkle_root, auxpow_merkle_size,
                   auxpow_merkle_nonce, auxpow_offset
            FROM coinbase_mergemining_v1
            """
        )
        census: dict[bytes, ParentCommitment] = {}
        for (
            block_hash,
            height,
            block_time,
            present,
            root,
            size,
            nonce,
            offset,
        ) in rows:
            if present:
                commitment = ParentCommitment(
                    merkle_root=(
                        hash_from_display_bytes(bytes(root))
                        if root is not None
                        else None
                    ),
                    merkle_size=size,
                    merkle_nonce=nonce,
                    source="census",
                    auxpow_offset=offset,
                    census_height=height,
                    census_block_time=block_time,
                )
            else:
                commitment = ParentCommitment(
                    merkle_root=None,
                    merkle_size=None,
                    merkle_nonce=None,
                    source="census_no_auxpow",
                    census_height=height,
                    census_block_time=block_time,
                )
            census[bytes(block_hash)] = commitment
        return census
    finally:
        conn.close()


def read_block_files(blocks_dir: Path) -> list[Path]:
    """Return every ``blk*.dat`` file under ``blocks_dir``, sorted by name."""
    return [Path(p) for p in sorted(glob.glob(str(blocks_dir / "blk*.dat")))]


def detect_xor_key(blocks_dir: Path, cli_key_hex: str | None) -> bytes:
    """Resolve the blk*.dat XOR obfuscation key.

    Prefers ``cli_key_hex`` (decoded from hex) when given, then
    ``blocks_dir/xor.dat``, else an empty key (no obfuscation).
    """
    if cli_key_hex:
        return bytes.fromhex(cli_key_hex)
    xor_path = blocks_dir / "xor.dat"
    if xor_path.is_file():
        return xor_path.read_bytes()
    return b""


def parse_auxpow_tail_for_sidecar(block_data: bytes) -> tuple[dict, int]:
    """Parse the AuxPoW tail while retaining chain-merkle branch fields."""
    return read_auxpow(block_data, 80)


def parent_coinbase_scriptsig(auxpow: dict) -> bytes:
    """Return the AuxPoW parent coinbase's first-input scriptSig, or ``b""`` if it has no inputs."""
    coinbase_tx = auxpow["coinbase_tx"]
    if not coinbase_tx["vin"]:
        return b""
    return coinbase_tx["vin"][0]["scriptsig"]


def parent_coinbase_outputs_hex(auxpow: dict) -> str:
    """Return the AuxPoW parent coinbase's output scripts as ``;``-joined hex."""
    return ";".join(
        txout["pkscript"].hex() for txout in auxpow["coinbase_tx"].get("vout", [])
    )


def infer_row(
    *,
    chain_slug: str,
    child_sequence: int,
    child_header_raw: bytes,
    child_version: int,
    auxpow: dict,
    census_conn: dict[bytes, ParentCommitment] | None,
) -> dict[str, object]:
    """Build one FIELDNAMES-shaped sidecar row for a single AuxPoW-bearing child block.

    Resolves the parent's commitment (census first, embedded-scriptSig
    fallback), recomputes the child-side chain-merkle root and compares it
    against the commitment root, classifies the commitment's declared merkle
    size against the proof's branch length, and — only when the root matches
    and the size status permits inference — recovers ``chain_id mod
    2**branch_len`` via the LCG and lists every registered chain consistent
    with that residue. ``inference_status`` records why inference was skipped
    (``skip:<reason>``) or ``"inferred"`` on success. All hash-hex fields are
    internal-order unless the field name says ``_display_hex``.
    """
    child_hash_internal = hash_from_header_bytes(child_header_raw)
    parent_header_raw = auxpow["parent_header_raw"]
    parent_hash_internal = hash_from_header_bytes(parent_header_raw)
    parent = parse_parent_header(parent_header_raw)
    scriptsig = parent_coinbase_scriptsig(auxpow)
    chain_branch = auxpow["chain_merkle_branch"]
    chain_index = auxpow["chain_index"]
    branch_len = len(chain_branch)
    computed_root = fold_merkle_branch(child_hash_internal, chain_branch, chain_index)

    commitment = parent_commitment_for_proof(
        census_conn, parent_hash_internal, scriptsig
    )
    size_status = commitment_size_status(commitment.merkle_size, branch_len)
    root_ok: bool | str = ""
    if commitment.merkle_root is not None:
        root_ok = computed_root == commitment.merkle_root

    residue = ""
    modulus = ""
    candidate_slugs = ""
    candidate_ids = ""
    expected_index = ""
    expected_index_ok = ""
    expected_index_enforced = ""
    inference_status = ""

    source_chain = get_chain(chain_slug)
    if source_chain is not None and commitment.merkle_nonce is not None:
        expected = auxpow_lcg_index(
            commitment.merkle_nonce,
            source_chain.chain_id,
            branch_len,
        )
        expected_index = expected
        expected_index_ok = expected == chain_index
        expected_index_enforced = source_chain.slot_enforcement == "consensus"

    if commitment.merkle_root is None:
        inference_status = f"skip:{commitment.source}"
    elif not root_ok:
        inference_status = "skip:chain_merkle_root_mismatch"
    elif not size_status_allows_inference(size_status):
        inference_status = f"skip:{size_status}"
    elif commitment.merkle_nonce is None:
        inference_status = "skip:missing_merkle_nonce"
    else:
        try:
            residue = lcg_chain_id_residue(
                commitment.merkle_nonce,
                chain_index,
                branch_len,
            )
            modulus = 1 << branch_len
            candidates = candidate_chains_for_residue(residue, branch_len)
            candidate_slugs = ";".join(chain.slug for chain in candidates)
            candidate_ids = ";".join(str(chain.chain_id) for chain in candidates)
            inference_status = "inferred"
        except ValueError as exc:
            inference_status = f"skip:{exc}"

    commitment_tuple = ""
    if (
        commitment.merkle_root is not None
        and commitment.merkle_size is not None
        and commitment.merkle_nonce is not None
    ):
        commitment_tuple = (
            f"{parent_hash_internal.hex()}:"
            f"{commitment.merkle_root.hex()}:"
            f"{commitment.merkle_size}:"
            f"{commitment.merkle_nonce}"
        )

    return {
        "chain_slug": chain_slug,
        "child_sequence": child_sequence,
        "child_hash_internal_hex": child_hash_internal.hex(),
        "child_hash_display_hex": hash_to_display_hex(child_hash_internal),
        "child_version": child_version,
        "parent_header_hash_internal_hex": parent_hash_internal.hex(),
        "parent_header_hash_display_hex": hash_to_display_hex(parent_hash_internal),
        "parent_header_hex": parent_header_raw.hex(),
        "parent_prev_hash_display_hex": parent["prev_hash"],
        "parent_time": parent["time"],
        "parent_bits_hex": parent["bits_hex"],
        "parent_coinbase_scriptsig_hex": scriptsig.hex(),
        "parent_coinbase_outputs_hex": parent_coinbase_outputs_hex(auxpow),
        "vChainMerkleBranch_len": branch_len,
        "vChainMerkleBranch_internal_hex": ";".join(h.hex() for h in chain_branch),
        "nChainIndex": chain_index,
        "computed_chain_merkle_root_internal_hex": computed_root.hex(),
        "commitment_source": commitment.source,
        "commitment_root_internal_hex": (
            commitment.merkle_root.hex() if commitment.merkle_root is not None else ""
        ),
        "commitment_merkle_size": (
            commitment.merkle_size if commitment.merkle_size is not None else ""
        ),
        "commitment_merkle_nonce": (
            commitment.merkle_nonce if commitment.merkle_nonce is not None else ""
        ),
        "commitment_auxpow_offset": (
            commitment.auxpow_offset if commitment.auxpow_offset is not None else ""
        ),
        "commitment_census_height": (
            commitment.census_height if commitment.census_height is not None else ""
        ),
        "commitment_census_block_time": commitment.census_block_time or "",
        "commitment_tuple": commitment_tuple,
        "commitment_size_status": size_status,
        "chain_merkle_root_ok": root_ok,
        "lcg_residue": residue,
        "lcg_modulus": modulus,
        "candidate_chain_slugs": candidate_slugs,
        "candidate_chain_ids": candidate_ids,
        "expected_index": expected_index,
        "expected_index_ok": expected_index_ok,
        "expected_index_enforced": expected_index_enforced,
        "inference_status": inference_status,
    }


def emit_sidecar(args: argparse.Namespace) -> int:
    """Scan ``args.blocks_dir``'s blk*.dat files and write the chain-ID inference sidecar CSV.

    For each AuxPoW-bearing child block (``nVersion`` carries
    ``VERSION_AUXPOW``), parses the AuxPoW tail and (optionally, when
    ``args.btc_difficulty_only``) skips parents that do not meet real BTC
    difficulty, then emits an ``infer_row`` row. Always returns 0; raises
    ``SystemExit`` if no blk*.dat files are found.
    """
    chain_config = CHAINS[args.chain]
    blocks_dir = Path(args.blocks_dir).expanduser()
    output_path = Path(args.output).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    census_path = (
        None
        if args.no_census or args.census_db is None
        else args.census_db.expanduser()
    )
    census_conn = connect_census(census_path)
    xor_key = detect_xor_key(blocks_dir, args.xor_key_hex)

    blk_files = read_block_files(blocks_dir)
    if not blk_files:
        raise SystemExit(f"no blk*.dat files found in {blocks_dir}")

    stats = {
        "blocks": 0,
        "auxpow": 0,
        "written": 0,
        "skipped_non_btc_difficulty": 0,
        "parse_errors": 0,
    }
    t0 = time.time()

    try:
        with output_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
            child_sequence = 0
            for blk_path in blk_files:
                for _offset, block_data in iter_blocks_from_file(
                    blk_path, chain_config["magic"], xor_key
                ):
                    child_sequence += 1
                    stats["blocks"] += 1
                    if len(block_data) < 80:
                        stats["parse_errors"] += 1
                        continue
                    child_header_raw = block_data[:80]
                    child_version = int.from_bytes(
                        child_header_raw[:4], "little", signed=True
                    )
                    if not child_version & VERSION_AUXPOW:
                        continue
                    stats["auxpow"] += 1
                    try:
                        auxpow, _ = parse_auxpow_tail_for_sidecar(block_data)
                        parent = parse_parent_header(auxpow["parent_header_raw"])
                    except CAUXPOW_PARSE_ERRORS:
                        stats["parse_errors"] += 1
                        continue
                    if args.btc_difficulty_only and not hash_meets_btc_difficulty(
                        parent["hash"], parent["bits"]
                    ):
                        stats["skipped_non_btc_difficulty"] += 1
                        continue
                    row = infer_row(
                        chain_slug=args.chain,
                        child_sequence=child_sequence,
                        child_header_raw=child_header_raw,
                        child_version=child_version,
                        auxpow=auxpow,
                        census_conn=census_conn,
                    )
                    writer.writerow(row)
                    stats["written"] += 1
                    if args.max_rows and stats["written"] >= args.max_rows:
                        break
                    if stats["written"] % args.progress_interval == 0:
                        elapsed = time.time() - t0
                        rate = stats["blocks"] / elapsed if elapsed else 0.0
                        print(
                            f"written={stats['written']:,} "
                            f"auxpow={stats['auxpow']:,} "
                            f"scanned={stats['blocks']:,} "
                            f"rate={rate:,.0f} blk/s "
                            f"file={blk_path.name}",
                            file=sys.stderr,
                        )
                if args.max_rows and stats["written"] >= args.max_rows:
                    break
    finally:
        if isinstance(census_conn, sqlite3.Connection):
            census_conn.close()

    elapsed = time.time() - t0
    print(f"Wrote {stats['written']:,} rows to {output_path}", file=sys.stderr)
    print(
        "Scanned "
        f"{stats['blocks']:,} blocks, {stats['auxpow']:,} AuxPoW, "
        f"{stats['parse_errors']:,} parse errors in {elapsed:.1f}s",
        file=sys.stderr,
    )
    if args.btc_difficulty_only:
        print(
            f"Skipped {stats['skipped_non_btc_difficulty']:,} "
            "parents that fail their encoded self-target",
            file=sys.stderr,
        )
    return 0


def main() -> int:
    """Parse CLI args and run ``emit_sidecar``."""
    parser = argparse.ArgumentParser(
        description="Emit Namecoin-family AuxPoW chain-ID inference sidecar CSV"
    )
    parser.add_argument(
        "--chain",
        default="namecoin",
        choices=sorted(CHAINS.keys()),
        help="Namecoin-family chain config from extract_auxpow_from_blkdat.py",
    )
    parser.add_argument(
        "--blocks-dir",
        required=True,
        help="Directory containing blk*.dat files",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Sidecar CSV path",
    )
    census_group = parser.add_mutually_exclusive_group()
    census_group.add_argument(
        "--census-db",
        type=Path,
        default=None,
        help=(
            "optional precomputed coinbase_mergemining_v1.db path; when omitted, "
            "parse the embedded parent coinbase"
        ),
    )
    census_group.add_argument(
        "--no-census",
        action="store_true",
        help=(
            "explicitly skip the optional census join (retained for compatibility; "
            "this is the default)"
        ),
    )
    parser.add_argument(
        "--self-target-pow-only",
        "--btc-difficulty-only",
        dest="btc_difficulty_only",
        action="store_true",
        help=(
            "Emit only parent headers whose hash meets their encoded nBits "
            "target; --btc-difficulty-only is retained as a legacy alias"
        ),
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="Stop after writing this many rows (0 = no limit)",
    )
    parser.add_argument(
        "--progress-interval",
        type=int,
        default=50_000,
        help="Rows between progress messages",
    )
    parser.add_argument(
        "--xor-key-hex",
        default=None,
        help="Explicit blk*.dat XOR key hex; defaults to blocks/xor.dat if present",
    )
    args = parser.parse_args()
    return emit_sidecar(args)


if __name__ == "__main__":
    raise SystemExit(main())
