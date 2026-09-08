#!/usr/bin/env python3
"""Classify the RSK merge-mining CSV into stale + unknown BTC parent headers.

Run near a local Bitcoin Core RPC endpoint against the raw CSV produced by
scripts/extract/extract_rsk_auxpow.py. Four passes:

  1. Stream the raw CSV, corroborate each serialized parent header, and keep
     rows whose computed hash meets the target encoded in that header. This is
     not yet a comparison with Bitcoin's contemporaneous target.
  2. Canonical check: for each self-target-PoW-valid row, ask Bitcoin Core if the header is
     on the active chain. Preserve those in the private
     ``rsk_canonical_blocks.csv`` companion consumed by evidence publication.
  3. Parent check: for the non-canonical candidates, look up btc_prev_hash.
     If found, the row is a `stale` (canonical-parent → known stale height).
     If not, the row is an `unknown` (no canonical ancestor in our Core).
  4. Available-evidence validation: require the candidate time to exceed its
     active parent's median-time-past, require btc_bits to match the canonical
     block at the inferred height, and enforce Bitcoin's historical minimum
     header version. RSK's compressed proof does not expose the coinbase fields
     needed for the scriptSig-length or BIP34-prefix checks. Rejected rows are
     then handed to the shared `route_rejected_stale_rows`, which re-derives
     the broken rules from each row's own bytes: a proven consensus violation
     becomes an `error_block`, and a contamination (nBits) rejection becomes an
     `unknown`.

The full parallel-schema `rsk_stale_blocks.csv` preserves every row that is
still a stale, including gate rejections whose evidence proves nothing, plus
the unknown inventory (Phase 3 unknowns and rows the routing moved there).
Consensus-invalid full-proof-of-work headers go to the sibling
`rsk_error_blocks.csv` instead, so they are neither published as stales nor
counted as stales in the summary. The normalized VALID-only
`rsk_validated_stales.csv` applies the exact-key error-block exclusion gate.
RSK loses the coinbase scriptSig and outputs to its midstate-compressed proof,
so the standard Namecoin-family evidence schema is necessarily sparse. The
classifier retains `rsk_miner` and joins labels only from the committed
historical registry snapshot.
"""

import argparse
import csv
import subprocess
import sys
import time
from pathlib import Path

from stale_blocks_analysis.auxpow_chainid import hash_from_header_bytes
from stale_blocks_analysis.auxpow_parse import (
    CHILD_HEADER_FIELDS,
    hash_meets_btc_difficulty,
    parse_parent_header,
)
from stale_blocks_analysis.btc_classify import (
    _header_result,
    _is_active_chain_header,
    _ordered_batch_responses,
    RULES_VIOLATED_COLUMN,
    derive_split_paths,
    normalize_bits_hex,
    route_rejected_stale_rows,
)
from stale_blocks_analysis.btc_nbits_validation import NBITS_MISMATCH_PREFIX
from stale_blocks_analysis.btc_stale_validation import (
    block_version_error,
    median_time_past_error,
)
from stale_blocks_analysis.classifier_cli import add_rpc_args, rpc_from_args
from stale_blocks_analysis.config import ERROR_BLOCKS_CSV, PROJECT_ROOT
from stale_blocks_analysis.error_blocks import load_error_block_keys
from stale_blocks_analysis.rsk_classifier_artifacts import (
    default_manifest_path,
    publish_output_family,
    validate_manifest_output_path,
)
from stale_blocks_analysis.rsk_extraction import (
    checkpoint_artifact_path,
    default_checkpoint_path,
    is_lower_hex,
    load_complete_extraction,
    sha256_file,
)
from stale_blocks_analysis.rsk_sidecar import validate_rsk_sidecar_cells

BATCH = 100

DEFAULT_INPUT = "data/rsk/rsk_auxpow_raw.csv"
DEFAULT_STALES_OUT = "data/rsk_stale_blocks.csv"
DEFAULT_VALIDATED_OUT = "data/validated-stales/rsk_validated_stales.csv"
DEFAULT_SUMMARY_OUT = "results/rsk_classification_summary.txt"
DEFAULT_POOL_REGISTRY = "results/rsk_pool_registry.csv"
CLASSIFIER_PATH = Path(__file__).resolve()

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
    "rsk_block_hash",
    "child_block_time",
    "rsk_miner",
    "merge_mining_hash",
    "rsk_merkle_proof",
    "rsk_coinbase_tail",
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

# The error-block sibling carries the standard row plus the pipe-joined rule
# set the routing derived, matching the shared writer and Hathor classifier. It is
# the evidence for the error-block claim, and ``validation_status`` alone does
# not carry it: RSK's rejections are worded for the gate that fired, not for
# the rule that decided the routing.
ERROR_BLOCK_COLS = [*OUT_COLS, RULES_VIOLATED_COLUMN]

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
    # RSK's child block is Ethereum-native, so these stay explicitly blank here
    # and are hydrated separately into data/child-identity/. They must still be
    # emitted: every chain's loader input carries the same child-identity
    # contract, and omitting them silently narrows a committed schema.
    *CHILD_HEADER_FIELDS,
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
        "--checkpoint",
        default=None,
        help="completed extractor checkpoint (default: <input>.checkpoint.json)",
    )
    parser.add_argument(
        "--stales-out",
        default=DEFAULT_STALES_OUT,
        help="classified stale/unknown output CSV",
    )
    parser.add_argument(
        "--canonical-out",
        default=None,
        help=(
            "classified canonical output CSV "
            "(default: the _canonical_blocks sibling of --stales-out)"
        ),
    )
    parser.add_argument(
        "--validated-out",
        default=DEFAULT_VALIDATED_OUT,
        help="normalized VALID-only direct-stale loader input",
    )
    parser.add_argument(
        "--error-blocks-out",
        default=None,
        help=(
            "consensus-invalid full-proof-of-work output CSV "
            "(default: the _error_blocks sibling of --stales-out)"
        ),
    )
    parser.add_argument(
        "--pool-registry",
        default=DEFAULT_POOL_REGISTRY,
        help="committed historical RSK miner-label snapshot",
    )
    parser.add_argument(
        "--error-blocks",
        default=str(ERROR_BLOCKS_CSV),
        help="committed exact-key consensus-invalid exclusion dataset",
    )
    parser.add_argument(
        "--summary-out",
        default=DEFAULT_SUMMARY_OUT,
        help="classification summary text output",
    )
    parser.add_argument(
        "--manifest-out",
        default=None,
        help=(
            "hash manifest for the staged output family "
            "(default: the _classification_manifest sibling of --stales-out)"
        ),
    )
    add_rpc_args(parser)
    return parser.parse_args(argv)


def validate_distinct_paths(
    args,
    canonical_out: str,
    error_blocks_out: str,
    manifest_out: str,
    checkpoint_path: Path,
    *,
    skip_ledger_path: Path | None = None,
) -> None:
    """Refuse to run when any two input/output paths resolve to the same file.

    The staged family still promotes each final path in sequence, so an aliased
    pair would silently replace an earlier member during promotion. Pointing
    ``--error-blocks-out`` at ``--stales-out`` would leave only the error
    blocks; pointing it at ``--validated-out`` would erase that member.

    This mirrors ``_validate_distinct_paths`` in
    ``classify_auxpow_candidates.py``. That one is not reused: its parameters
    are positional over that script's own artifact set and it derives that
    script's publication split, neither of which describes RSK's outputs.
    """
    labelled = {
        "input": Path(args.input).resolve(),
        "input checkpoint": checkpoint_path.resolve(),
        "pool registry": Path(args.pool_registry).resolve(),
        "error-block exclusion input": Path(args.error_blocks).resolve(),
        "canonical inventory output": Path(canonical_out).resolve(),
        "stale/unknown inventory output": Path(args.stales_out).resolve(),
        "validated-stale output": Path(args.validated_out).resolve(),
        "error-block output": Path(error_blocks_out).resolve(),
        "summary output": Path(args.summary_out).resolve(),
        "classification manifest": Path(manifest_out).resolve(),
        "classifier script": CLASSIFIER_PATH,
    }
    if skip_ledger_path is not None:
        labelled["input skip ledger"] = skip_ledger_path.resolve()
    seen: dict[Path, str] = {}
    for label, path in labelled.items():
        previous = seen.get(path)
        if previous is not None:
            raise ValueError(f"{label} aliases {previous}: {path}")
        seen[path] = label


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


def validate_source_bundle(row: dict[str, str], row_number: int) -> None:
    """Validate the complete RSK child identity and publication-sidecar bundle."""
    for field in ("rsk_height", "rsk_timestamp"):
        value = row.get(field, "")
        if not value.isascii() or not value.isdigit() or int(value) < 0:
            raise ValueError(f"RSK row {row_number}: {field} is malformed")
    if int(row["rsk_timestamp"]) <= 0:
        raise ValueError(f"RSK row {row_number}: rsk_timestamp must be positive")
    if not is_lower_hex(row.get("rsk_hash")):
        raise ValueError(f"RSK row {row_number}: rsk_hash is not canonical hex")
    validate_rsk_sidecar_cells(
        {
            "rsk_miner": row.get("rsk_miner", ""),
            "merge_mining_hash": row.get("merge_mining_hash", ""),
            "is_uncle": row.get("is_uncle", ""),
            "uncle_index": row.get("uncle_index", ""),
            "uncle_parent_height": row.get("uncle_parent_height", ""),
            "rsk_merkle_proof": row.get("merge_mining_merkle_proof", ""),
            "rsk_coinbase_tail": row.get("coinbase_tail_hex", ""),
        },
        row_id=f"RSK row {row_number}",
    )


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
        "rsk_block_hash": row.get("rsk_hash", "") or row.get("rsk_block_hash", ""),
        "child_block_time": row.get("rsk_timestamp", "")
        or row.get("child_block_time", ""),
        "rsk_miner": row["rsk_miner"],
        "merge_mining_hash": row["merge_mining_hash"],
        "rsk_merkle_proof": row.get("merge_mining_merkle_proof", "")
        or row.get("rsk_merkle_proof", ""),
        "rsk_coinbase_tail": row.get("coinbase_tail_hex", "")
        or row.get("rsk_coinbase_tail", ""),
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
        **{field: "" for field in CHILD_HEADER_FIELDS},
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
    """Build deterministic public rows after the exact-key error-block gate."""
    rows = [
        validated_row(row, height, pool_labels)
        for height, row in verified
        if (height, row["btc_header_hash"].lower()) not in excluded
    ]
    # The compact artifact contains parent verdicts. Choose the earliest
    # child witness deterministically; the full inventory keeps every witness.
    rows.sort(
        key=lambda row: (
            int(row["btc_height"]),
            row["btc_header_hash"].lower(),
            int(row["rsk_height"]),
            int(row.get("is_uncle") or 0),
            tuple(str(row.get(field, "")) for field in VALIDATED_COLS),
        )
    )
    parents: dict[tuple[int, str], dict[str, str]] = {}
    for row in rows:
        parents.setdefault(
            (int(row["btc_height"]), row["btc_header_hash"].lower()), row
        )
    return list(parents.values())


def build_canonical_output_rows(
    canonical_rows: list[tuple[int, dict[str, str]]],
) -> list[dict[str, object]]:
    """Map active-chain observations to the deterministic private companion."""
    return [
        row_to_out(row, "canonical", btc_stale_height=height)
        for height, row in sorted(
            canonical_rows,
            key=lambda item: (
                item[0],
                int(item[1]["rsk_height"]),
                int(item[1].get("is_uncle") or 0),
                int(item[1].get("uncle_index") or 0),
                item[1]["btc_header_hash"],
            ),
        )
    ]


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


def _rpc_result(response: object, *, method: str) -> dict:
    if not isinstance(response, dict) or response.get("error") is not None:
        raise RuntimeError(f"{method} failed: {response!r}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise ValueError(f"{method} returned a non-object result")
    return result


def bitcoin_core_tip_context(bitcoin_rpc, *, label: str) -> dict[str, object]:
    """Capture one synchronized Bitcoin mainnet tip and node-version identity."""
    responses = _ordered_batch_responses(
        bitcoin_rpc.batch(
            [
                {
                    "jsonrpc": "1.0",
                    "id": 0,
                    "method": "getblockchaininfo",
                    "params": [],
                },
                {
                    "jsonrpc": "1.0",
                    "id": 1,
                    "method": "getnetworkinfo",
                    "params": [],
                },
            ]
        ),
        expected_count=2,
        method=f"RSK {label} Core context",
    )
    chain = _rpc_result(responses[0], method="getblockchaininfo")
    network = _rpc_result(responses[1], method="getnetworkinfo")
    height = chain.get("blocks")
    headers = chain.get("headers")
    best_hash = chain.get("bestblockhash")
    version = network.get("version")
    if (
        chain.get("chain") != "main"
        or type(height) is not int
        or height < 0
        or type(headers) is not int
        or headers < height
        or chain.get("initialblockdownload") is not False
        or type(version) is not int
        or version < 0
        or not isinstance(best_hash, str)
        or best_hash != best_hash.lower()
        or len(best_hash) != 64
    ):
        raise ValueError(f"Bitcoin Core {label} context is malformed or unsynced")
    try:
        bytes.fromhex(best_hash)
    except ValueError as exc:
        raise ValueError(f"Bitcoin Core {label} best hash is malformed") from exc
    return {
        "chain": "main",
        "height": height,
        "headers": headers,
        "hash": best_hash,
        "initial_block_download": False,
        "version": version,
    }


def verify_bitcoin_core_context(bitcoin_rpc, start: dict) -> dict[str, dict]:
    """Allow normal tip growth while rejecting a reorg through the start tip."""
    end = bitcoin_core_tip_context(bitcoin_rpc, label="end")
    height = int(start["height"])
    responses = _ordered_batch_responses(
        bitcoin_rpc.batch(
            [
                {
                    "jsonrpc": "1.0",
                    "id": 0,
                    "method": "getblockhash",
                    "params": [height],
                }
            ]
        ),
        expected_count=1,
        method="RSK Core start-tip continuity",
    )
    still_active = canonical_hash(responses[0], height)
    if end["height"] < height or still_active != start["hash"]:
        raise ValueError(
            "Bitcoin Core active chain changed through the pinned start tip"
        )
    return {"start": start, "end": end}


def repository_code_context() -> dict[str, object]:
    """Record the repository revision and whether classification code is dirty."""

    def git(*args: str) -> str:
        completed = subprocess.run(
            ["git", *args],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    return {
        "git_commit": git("rev-parse", "HEAD").lower(),
        "dirty": bool(git("status", "--porcelain", "--untracked-files=all")),
    }


def dependency_fingerprints(paths: dict[str, Path]) -> dict[str, tuple[int, str]]:
    """Snapshot byte lengths and digests for every classification dependency."""
    fingerprints: dict[str, tuple[int, str]] = {}
    for label, path in paths.items():
        if not path.is_file():
            raise ValueError(f"RSK classifier dependency is missing: {path}")
        fingerprints[label] = (path.stat().st_size, sha256_file(path))
    return fingerprints


def stale_validation_error(
    row: dict[str, str],
    height: int,
    expected_nbits: str,
    parent_median_time_past: int,
) -> str | None:
    """Return an MTP, version, or nBits rejection reason.

    The three verdict strings are the shared vocabulary the rest of the
    pipeline routes on: the MTP and version reasons come straight from the
    shared gate functions, and the nBits reason carries the shared
    ``NBITS_MISMATCH_PREFIX`` so ``route_rejected_stale_rows`` recognises it as
    the contamination verdict rather than a judgement on the block.
    """
    mtp_error = median_time_past_error(row, parent_median_time_past)
    if mtp_error is not None:
        return mtp_error
    version_error = block_version_error(row, height)
    if version_error is not None:
        return version_error
    ours = row["btc_bits"].lower()
    expected = expected_nbits.lower()
    if not expected or expected != ours:
        return f"{NBITS_MISMATCH_PREFIX} (got {ours}, expected {expected or 'unknown'})"
    return None


GatedRows = tuple[
    list[tuple[int, dict[str, str]]],
    list[tuple[int, dict[str, str]]],
    list[tuple[int, dict[str, str]]],
    list[tuple[int, dict[str, str]]],
]


def gate_and_route(
    stales_with_height: list[tuple[int, dict[str, str], int]],
    canon_bits_at: dict[int, str],
) -> GatedRows:
    """Apply the publication gate, then route the rejections by what they mean.

    Returns ``(verified, stale_rows, error_blocks, rerouted_unknowns)``, where
    ``verified`` is the VALID subset of ``stale_rows``. Rows are mutated in
    place, gaining ``classification``, ``validation_status``, and
    ``expected_nbits``.

    The router re-derives the broken consensus rules from each row's own bytes
    rather than reading the verdict string, so a rejection whose evidence was
    merely unusable produces no rules and the row stays a stale. For RSK only
    the median-time-past, block-version, and epoch-retarget rules can ever
    fire: the midstate-compressed proof carries no parent coinbase, so the
    coinbase scriptSig-length and BIP34-height rules have nothing to evaluate
    and never contribute a violation.
    """
    gated: list[tuple[int, dict[str, str]]] = []
    for height, row, parent_median_time_past in stales_with_height:
        expected = canon_bits_at.get(height, "").lower()
        row["expected_nbits"] = expected
        row["classification"] = "stale"
        # Internal keys the shared router needs and this pass already holds:
        # the authoritative prev+1 height and the canonical parent's
        # median-time-past. row_to_out/validated_row build their output dicts
        # field by field, so neither key can leak into a CSV.
        row["btc_height"] = str(height)
        row["_parent_median_time_past"] = parent_median_time_past
        error = stale_validation_error(
            row,
            height,
            expected,
            parent_median_time_past,
        )
        row["validation_status"] = "VALID" if error is None else error
        gated.append((height, row))

    route_rejected_stale_rows([row for _, row in gated])

    def bucket(name: str) -> list[tuple[int, dict[str, str]]]:
        return [(height, row) for height, row in gated if row["classification"] == name]

    stale_rows = bucket("stale")
    verified = [
        (height, row)
        for height, row in stale_rows
        if row["validation_status"] == "VALID"
    ]
    return verified, stale_rows, bucket("error_block"), bucket("unknown")


def main():
    """Run the four-pass RSK classifier and write CSV and summary outputs."""
    args = parse_args()
    # Resolve the derived error-block path and check every path for aliasing
    # before any RPC work happens or any output is opened.
    derived_canonical, _, derived_error_blocks = derive_split_paths(args.stales_out)
    canonical_out = args.canonical_out or derived_canonical
    error_blocks_out = args.error_blocks_out or derived_error_blocks
    manifest_out = args.manifest_out or default_manifest_path(args.stales_out)
    validate_manifest_output_path(args.stales_out, manifest_out)
    input_path = Path(args.input)
    checkpoint_path = (
        Path(args.checkpoint)
        if args.checkpoint is not None
        else default_checkpoint_path(input_path)
    )
    validate_distinct_paths(
        args, canonical_out, error_blocks_out, manifest_out, checkpoint_path
    )
    extraction = load_complete_extraction(input_path, checkpoint_path)
    validate_distinct_paths(
        args,
        canonical_out,
        error_blocks_out,
        manifest_out,
        checkpoint_path,
        skip_ledger_path=checkpoint_artifact_path(
            checkpoint_path, extraction["skip_ledger_path"]
        ),
    )
    dependency_paths = {
        "classifier_script": CLASSIFIER_PATH,
        "error_blocks": Path(args.error_blocks),
        "pool_registry": Path(args.pool_registry),
    }
    initial_dependencies = dependency_fingerprints(dependency_paths)
    code_context = repository_code_context()
    if code_context["dirty"]:
        raise ValueError("RSK classifier requires a clean repository worktree")
    bitcoin_rpc = rpc_from_args(args)
    real_pow_rows = []
    total = 0
    t0 = time.time()

    print("=== Pass 1: scanning all rows ===", file=sys.stderr, flush=True)
    with input_path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row_number, row in enumerate(reader, start=2):
            total += 1
            validate_source_bundle(row, row_number)
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
    if total != extraction["output_rows"]:
        raise ValueError(
            f"RSK classifier read {total} raw rows, checkpoint declares "
            f"{extraction['output_rows']}"
        )
    pass1_time = time.time() - t0
    pow_percent = 100 * len(real_pow_rows) / total if total else 0.0
    print(f"\nPass 1 done in {pass1_time:.0f}s", file=sys.stderr)
    print(f"  Total rows: {total:,}", file=sys.stderr)
    print(
        f"  Self-target PoW valid: {len(real_pow_rows):,} ({pow_percent:.3f}%)",
        file=sys.stderr,
    )
    core_start = bitcoin_core_tip_context(bitcoin_rpc, label="start")

    # Pass 2: canonical check
    print("\n=== Pass 2: canonical check ===", file=sys.stderr, flush=True)
    candidates = []
    canonical_rows: list[tuple[int, dict[str, str]]] = []
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
            canonical = active_header(rr, block_hash, require_height=True)
            if canonical is not None:
                canonical_rows.append((canonical["height"], batch[j]))
            else:
                candidates.append(batch[j])
        if (i // BATCH) % 100 == 0:
            done = i + BATCH
            rate = done / (time.time() - t0 + 0.001)
            print(
                f"  {done:,}/{len(real_pow_rows):,} ({rate:.0f}/s) | "
                f"canonical={len(canonical_rows):,}, candidates={len(candidates):,}",
                file=sys.stderr,
                flush=True,
            )
    canonical_count = len(canonical_rows)
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

    verified, stale_rows, error_blocks, rerouted_unknowns = gate_and_route(
        stales_with_height, canon_bits_at
    )
    rejected_stales = len(stale_rows) - len(verified)
    print(f"  publication-gate accepted stales: {len(verified):,}", file=sys.stderr)
    print(
        f"  rejected, still stale (unusable evidence): {rejected_stales:,}",
        file=sys.stderr,
    )
    print(
        f"  error blocks (proven consensus violation): {len(error_blocks):,}",
        file=sys.stderr,
    )
    print(
        f"  re-routed to unknown (contamination/placement): {len(rerouted_unknowns):,}",
        file=sys.stderr,
    )
    core_context = verify_bitcoin_core_context(bitcoin_rpc, core_start)

    # Resolve every committed dependency before opening any output, so a
    # missing exclusion overlay or historical registry cannot leave a newly
    # written full inventory beside a stale validated artifact.
    excluded = load_error_block_keys(Path(args.error_blocks))
    pool_labels = load_pool_labels(args.pool_registry)
    public_rows = build_validated_rows(verified, pool_labels, excluded)

    if len(real_pow_rows) != canonical_count + len(candidates):
        raise ValueError("RSK canonical/candidate classification partition mismatch")
    if len(candidates) != len(stales_with_height) + len(unknowns):
        raise ValueError("RSK parent classification partition mismatch")
    if len(stales_with_height) != (
        len(stale_rows) + len(error_blocks) + len(rerouted_unknowns)
    ):
        raise ValueError("RSK publication-gate routing partition mismatch")

    # The canonical companion retains active-chain observations. The full
    # classified output retains every row that is still a stale, including
    # gate rejections whose evidence proved nothing, plus the unknown inventory
    # (Phase 3 unknowns and rows the routing moved there). Error blocks go to
    # their own sibling file. The normalized public loader input contains only
    # VALID direct stales after the exact-key exclusion overlay.
    print("\n=== Staging output family ===", file=sys.stderr)
    canonical_output_rows = build_canonical_output_rows(canonical_rows)
    stale_output_rows = [
        row_to_out(
            row,
            "stale",
            btc_stale_height=height,
            validation_status=row["validation_status"],
            expected_nbits=row["expected_nbits"],
        )
        for height, row in sorted(
            stale_rows,
            key=lambda item: (
                item[0],
                int(item[1]["rsk_height"]),
                item[1]["btc_header_hash"],
            ),
        )
    ]
    unknown_out: list[tuple[dict[str, str], int | str]] = [
        (row, "") for row in unknowns
    ] + [(row, height) for height, row in rerouted_unknowns]
    unknown_output_rows = [
        row_to_out(row, "unknown", btc_stale_height=height)
        for row, height in sorted(
            unknown_out,
            key=lambda item: (
                int(item[0]["rsk_height"]),
                int(item[0].get("is_uncle") or 0),
                int(item[0].get("uncle_index") or 0),
                item[0]["btc_header_hash"],
            ),
        )
    ]
    stale_unknown_output_rows = [*stale_output_rows, *unknown_output_rows]
    error_output_rows = [
        {
            **row_to_out(
                row,
                "error_block",
                btc_stale_height=height,
                validation_status=row["validation_status"],
                expected_nbits=row["expected_nbits"],
            ),
            RULES_VIOLATED_COLUMN: row[RULES_VIOLATED_COLUMN],
        }
        for height, row in sorted(
            error_blocks,
            key=lambda item: (
                item[0],
                int(item[1]["rsk_height"]),
                item[1]["btc_header_hash"],
            ),
        )
    ]
    total_unknown_rows = len(unknowns) + len(rerouted_unknowns)
    summary_text = (
        "RSK merge-mining classification summary\n"
        + "=" * 60
        + "\n"
        + f"Input checkpoint SHA-256:       {sha256_file(checkpoint_path)}\n"
        + f"Input range:                    [{extraction['start_height']}, {extraction['end_height']})\n"
        + f"Input content SHA-256:          {extraction['content_sha256']}\n"
        + f"Bitcoin Core start tip:         {core_context['start']['height']} {core_context['start']['hash']}\n"
        + f"Bitcoin Core end tip:           {core_context['end']['height']} {core_context['end']['hash']}\n"
        + f"Pool registry SHA-256:          {initial_dependencies['pool_registry'][1]}\n"
        + f"Error-block overlay SHA-256:    {initial_dependencies['error_blocks'][1]}\n"
        + f"Classifier git revision:        {code_context['git_commit']} dirty={str(code_context['dirty']).lower()}\n"
        + f"Total RSK merge-mining rows:     {total:>12,}\n"
        + f"Self-target-PoW-valid headers:   {len(real_pow_rows):>12,}  ({pow_percent:.3f}%)\n"
        + f"  Canonical (in BTC chain):      {canonical_count:>12,}\n"
        + f"  Stale candidates:              {len(candidates):>12,}\n"
        + f"    With canonical parent:       {len(stales_with_height):>12,}\n"
        + f"      Gate-accepted candidates:  {len(verified):>12,}\n"
        + f"      Rejected, still stale:     {rejected_stales:>12,}\n"
        + f"      Error blocks:              {len(error_blocks):>12,}\n"
        + f"      Re-routed to unknown:      {len(rerouted_unknowns):>12,}\n"
        + f"    Unknowns (no canonical parent): {len(unknowns):>10,}\n"
        + f"\nOutput rows in rsk_stale_blocks.csv: {len(stale_rows) + total_unknown_rows:,} "
        + f"({len(stale_rows):,} stale + {total_unknown_rows:,} unknown)\n"
        + f"Canonical rows in rsk_canonical_blocks.csv: {canonical_count:,}\n"
        + f"Error-block rows in rsk_error_blocks.csv: {len(error_blocks):,}\n"
        + f"VALID direct-stale rows after exclusion overlay: {len(public_rows):,}\n"
    )
    if dependency_fingerprints(dependency_paths) != initial_dependencies:
        raise ValueError("RSK classification dependency changed during the run")
    if repository_code_context() != code_context:
        raise ValueError("RSK classifier repository state changed during the run")
    publish_output_family(
        csv_artifacts=[
            ("canonical", Path(canonical_out), OUT_COLS, canonical_output_rows),
            (
                "stale_unknown",
                Path(args.stales_out),
                OUT_COLS,
                stale_unknown_output_rows,
            ),
            (
                "error_blocks",
                Path(error_blocks_out),
                ERROR_BLOCK_COLS,
                error_output_rows,
            ),
            ("validated_stales", Path(args.validated_out), VALIDATED_COLS, public_rows),
        ],
        summary_path=Path(args.summary_out),
        summary_text=summary_text,
        manifest_path=Path(manifest_out),
        checkpoint_path=checkpoint_path,
        checkpoint_state=extraction,
        dependency_paths=dependency_paths,
        expected_dependency_fingerprints=initial_dependencies,
        classification_context={
            "bitcoin_core": core_context,
            "code": code_context,
        },
    )
    print("\n✓ Outputs:", file=sys.stderr)
    print(
        f"  {canonical_out}  ({canonical_count:,} canonical)",
        file=sys.stderr,
    )
    print(
        f"  {args.stales_out}  ({len(stale_rows) + total_unknown_rows:,} rows: "
        f"{len(stale_rows):,} stale + {total_unknown_rows:,} unknown)",
        file=sys.stderr,
    )
    print(
        f"  {error_blocks_out}  ({len(error_blocks):,} error blocks)",
        file=sys.stderr,
    )
    print(
        f"  {args.validated_out}  ({len(public_rows):,} VALID direct stales)",
        file=sys.stderr,
    )
    print(f"  {args.summary_out}", file=sys.stderr)
    print(
        f"  {manifest_out}  (published last; binds the output family)", file=sys.stderr
    )


if __name__ == "__main__":
    main()
