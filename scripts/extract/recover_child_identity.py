#!/usr/bin/env python3
"""Recover child-chain block identity for the six live-lifecycle chains.

The monitor-evidence exports for namecoin, rsk, syscoin, hathor, elastos and
fractal carry recovered Bitcoin parent evidence but no child block identity:
the recovery pipeline recorded each proof's child HEIGHT, never the child
block HASH or timestamp. merge-mining-monitor keys `merge_mining_event` rows
by (source, child_height, child_block_hash), so imported rows need the exact
child identity or they can never deduplicate against live-captured rows.

All six chains still have reachable nodes (a public API for Hathor), so the
identity is recoverable by height -> hash -> block RPC. Every recovered row is
verified by re-deriving the Bitcoin parent linkage FROM the fetched child
block and requiring it to match the row's own `btc_header_hash`:

  namecoin  getblock().auxpow.parentblock (node-decoded CAuxPow parent)
  syscoin   same call; parentblock arrives as header hex, hash recomputed
  elastos   read_auxpow(getblock().auxpow) -> parent header (serialized form)
  fractal   getblockheader(hash, false, true): 80-byte FB header + CAuxPow;
            parent header parsed from the proof, FB hash/time from the header
  rsk       sha256d(bitcoinMergedMiningHeader[:80]); uncle rows resolved via
            eth_getUncleByBlockNumberAndIndex(uncle_parent_height, uncle_index)
  hathor    block_at_height().tx_id equals btc_header_hash and not is_voided
            (a merge-mined Hathor block's hash IS its BTC parent header hash)

A mismatch means today's canonical child chain does not contain the child
block that carried the recovered proof (child-side reorg, or a re-mined
slot). Such rows are written with an empty child identity and a reason so the
exports leave them blank and the monitor importer skips them instead of
synthesizing an identity.

RSK rows additionally carry the fields merge-mining-monitor's
`rsk_merge_mining_evidence` sidecar requires (miner, hashForMergedMining,
uncle placement, merkle proof, coinbase tail). Miner, merge-mining hash and
timestamp are cross-checked against the classified recovery metadata; any
disagreement is recorded in `note` without blocking the row.

`btc_header_hash` stays in display (RPC) order like every other pipeline
artifact. `child_block_hash` follows the pipeline's established column
contract of INTERNAL (wire) byte order for the Bitcoin-family chains and
Hathor (the reverse of the node's display hex; see `auxpow_child_heights`,
which pairs `child_block_hash` with a separate `child_block_hash_display`),
and forward order for RSK, whose keccak block hashes have no reversed
display convention. merge-mining-monitor stores child hashes in exactly
these orders, so its importer can decode the column without re-reversing.

For RSK uncle rows the fetched uncle's own `number` is cross-checked against
the recorded `rsk_height` (`height_disagrees` note on any disagreement), so
the exported (`child_height`, `child_block_hash`) pair keys uncles exactly as
merge-mining-monitor's live capture does: by the uncle's OWN height and hash,
with `uncle_parent_height` carrying the including canonical height.

Run on the archival host next to the nodes. Credentials come from
NAMECOIN_RPC_USER / NAMECOIN_RPC_PASSWORD, SYSCOIN_RPC_*, and FRACTAL_RPC_*
respectively (or the matching *_RPC_COOKIEFILE), per rpc_auth_from_env's
prefix convention; the Elastos and RSK endpoints are unauthenticated and
Hathor uses the public API.
"""

import argparse
import csv
import hashlib
import os
import struct
import sys
from pathlib import Path

import requests

# Repo `src/` is on sys.path when installed via `pip install -e .`.
from stale_blocks_analysis.auxpow_parse import read_auxpow
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.full_evidence import LIVE_CHILD_IDENTITY_CHAINS
from stale_blocks_analysis.rpc_env import load_local_rpc_env, rpc_auth_from_env

load_local_rpc_env()

# One source of truth with the export hydrator's unconditional target set.
LIVE_CHAINS = tuple(sorted(LIVE_CHILD_IDENTITY_CHAINS))

DEFAULT_URLS = {
    "namecoin": os.environ.get("NAMECOIN_RPC_URL", "http://127.0.0.1:8436"),
    "syscoin": os.environ.get("SYSCOIN_RPC_URL", "http://127.0.0.1:8370"),
    "elastos": os.environ.get("ELASTOS_RPC_URL", "http://127.0.0.1:20336"),
    "fractal": os.environ.get("FRACTAL_RPC_URL", "http://127.0.0.1:18332"),
    "rsk": os.environ.get("RSK_RPC_URL", "http://127.0.0.1:4444"),
    "hathor": os.environ.get(
        "HATHOR_API_URL", "https://node1.mainnet.hathor.network/v1a"
    ),
}

CORE_FIELDS = [
    "chain",
    "btc_header_hash",
    "child_height",
    "child_block_hash",
    "child_block_time",
    "verification",
    "note",
]

RSK_EXTRA_FIELDS = [
    "rsk_miner",
    "merge_mining_hash",
    "is_uncle",
    "uncle_index",
    "uncle_parent_height",
    "rsk_merkle_proof",
    "rsk_coinbase_tail",
]

# Fractal Cadence Mining: only version words carrying chain ID 0x2024 plus the
# 0x100 AuxPoW flag serialize CAuxPow (see extract_fractal_auxpow.py).
FRACTAL_AUXPOW_FLAG = 0x100
FRACTAL_AUXPOW_CHAIN_ID = 0x2024


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def display_hash(raw: bytes) -> str:
    """Internal-order digest -> display (RPC order) hex."""
    return raw[::-1].hex()


def display_to_internal(display_hex: str) -> str:
    """Display (RPC order) hex -> internal (wire order) hex.

    The pipeline's `child_block_hash` column contract is internal order (see
    `auxpow_child_heights`, whose outputs pair `child_block_hash` with a
    separate `child_block_hash_display`); merge-mining-monitor stores child
    hashes in the same order and reverses only at presentation boundaries.
    """
    return bytes.fromhex(display_hex)[::-1].hex()


def strip_0x(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def load_targets(evidence_path: Path) -> list[tuple[str, int]]:
    """Non-canonical ``(btc_header_hash, child_height)`` recovery work list.

    Deduplicates by header hash (one parent header commits to exactly one
    child block) and refuses a hash that appears with two different child
    heights, which would mean the source artifacts disagree. Canonical rows
    are publishable without exact child identity and are deliberately skipped;
    otherwise uniform canonical publication would turn this bounded recovery
    into a scan of entire live chains.
    """
    targets: dict[str, tuple[int, int]] = {}
    with evidence_path.open(newline="") as f:
        for row_number, row in enumerate(csv.DictReader(f), start=2):
            if (row.get("classification") or "").strip() == "canonical":
                continue
            btc_hash = row["btc_header_hash"].strip().lower()
            height_text = row["child_height"].strip()
            if not btc_hash or not height_text:
                raise SystemExit(
                    f"{evidence_path}:{row_number}: row missing "
                    "btc_header_hash/child_height"
                )
            height = int(height_text)
            if btc_hash in targets and targets[btc_hash][0] != height:
                first_height, first_row = targets[btc_hash]
                raise SystemExit(
                    f"{evidence_path}: {btc_hash} maps to child height "
                    f"{first_height} (row {first_row}) and {height} "
                    f"(row {row_number})"
                )
            targets.setdefault(btc_hash, (height, row_number))
    return sorted(
        ((btc_hash, height) for btc_hash, (height, _) in targets.items()),
        key=lambda item: (item[1], item[0]),
    )


def load_rsk_metadata(paths: list[Path]) -> dict[str, dict[str, str]]:
    """btc_header_hash -> uncle placement + sidecar metadata, first file wins."""
    meta: dict[str, dict[str, str]] = {}
    for path in paths:
        if not path.exists():
            continue
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                btc_hash = row.get("btc_header_hash", "").strip().lower()
                if not btc_hash or btc_hash in meta:
                    continue
                meta[btc_hash] = {
                    "rsk_height": row.get("rsk_height", "").strip(),
                    "rsk_timestamp": row.get("rsk_timestamp", "").strip(),
                    "rsk_miner": row.get("rsk_miner", "").strip().lower(),
                    "merge_mining_hash": row.get("merge_mining_hash", "")
                    .strip()
                    .lower(),
                    "is_uncle": row.get("is_uncle", "").strip(),
                    "uncle_index": row.get("uncle_index", "").strip(),
                    "uncle_parent_height": row.get("uncle_parent_height", "").strip(),
                }
    return meta


def parent_hash_from_auxpow_family(block: dict) -> str:
    """Display-order parent hash from a Bitcoin-family `getblock` response.

    namecoind decodes `auxpow.parentblock` into an object carrying the
    node-computed parent hash; syscoind returns the raw parent header hex, so
    the hash is recomputed from its first 80 bytes.
    """
    parentblock = block.get("auxpow", {}).get("parentblock")
    if isinstance(parentblock, dict):
        return parentblock.get("hash", "").lower()
    if isinstance(parentblock, str) and parentblock:
        return display_hash(sha256d(bytes.fromhex(parentblock)[:80]))
    return ""


def recover_auxpow_family(chain: str, url: str, targets, limit) -> list[dict]:
    user, password = rpc_auth_from_env(chain.upper())
    rpc = RpcClient(url, user=user, password=password)
    rows = []
    for btc_hash, height in targets[:limit]:
        row = {"chain": chain, "btc_header_hash": btc_hash, "child_height": height}
        try:
            child_hash = rpc.call("getblockhash", [height])
            block = rpc.call("getblock", [child_hash])
            derived = parent_hash_from_auxpow_family(block)
            if not derived:
                row["note"] = "no_auxpow_in_child_block"
            elif derived != btc_hash:
                row["note"] = f"parent_mismatch:{derived}"
            else:
                row["child_block_hash"] = display_to_internal(child_hash)
                row["child_block_time"] = block["time"]
                row["verification"] = "auxpow_parent_match"
        except (RuntimeError, ValueError, KeyError, requests.RequestException) as exc:
            row["note"] = f"rpc_error:{exc}"
        rows.append(row)
    return rows


def recover_elastos(chain: str, url: str, targets, limit) -> list[dict]:
    rpc = RpcClient(url, jsonrpc="2.0")
    rows = []
    for btc_hash, height in targets[:limit]:
        row = {"chain": chain, "btc_header_hash": btc_hash, "child_height": height}
        try:
            child_hash = rpc.call("getblockhash", {"height": height})
            block = rpc.call("getblock", {"blockhash": child_hash, "verbosity": 2})
            aux, _ = read_auxpow(bytes.fromhex(block["auxpow"]), 0)
            derived = display_hash(sha256d(aux["parent_header_raw"]))
            if derived != btc_hash:
                row["note"] = f"parent_mismatch:{derived}"
            else:
                row["child_block_hash"] = display_to_internal(child_hash)
                row["child_block_time"] = block["time"]
                row["verification"] = "auxpow_parent_match"
        except (RuntimeError, ValueError, KeyError, requests.RequestException) as exc:
            row["note"] = f"rpc_error:{exc}"
        rows.append(row)
    return rows


def recover_fractal(chain: str, url: str, targets, limit) -> list[dict]:
    user, password = rpc_auth_from_env(chain.upper())
    rpc = RpcClient(url, user=user, password=password)
    rows = []
    for btc_hash, height in targets[:limit]:
        row = {"chain": chain, "btc_header_hash": btc_hash, "child_height": height}
        try:
            child_hash = rpc.call("getblockhash", [height])
            blob = bytes.fromhex(rpc.call("getblockheader", [child_hash, False, True]))
            if len(blob) < 80:
                row["note"] = f"short_header_response:{len(blob)}"
                rows.append(row)
                continue
            fb_header = blob[:80]
            if display_hash(sha256d(fb_header)) != child_hash.lower():
                row["note"] = "fb_header_hash_mismatch"
                rows.append(row)
                continue
            version = struct.unpack_from("<i", fb_header, 0)[0]
            if not (version & FRACTAL_AUXPOW_FLAG) or (
                version >> 16 != FRACTAL_AUXPOW_CHAIN_ID
            ):
                row["note"] = f"no_auxpow_version:{version:#010x}"
                rows.append(row)
                continue
            aux, _ = read_auxpow(blob, 80)
            derived = display_hash(sha256d(aux["parent_header_raw"]))
            if derived != btc_hash:
                row["note"] = f"parent_mismatch:{derived}"
            else:
                row["child_block_hash"] = display_to_internal(child_hash)
                row["child_block_time"] = struct.unpack_from("<I", fb_header, 68)[0]
                row["verification"] = "auxpow_parent_match"
        except (
            RuntimeError,
            ValueError,
            KeyError,
            struct.error,
            requests.RequestException,
        ) as exc:
            row["note"] = f"rpc_error:{exc}"
        rows.append(row)
    return rows


def recover_rsk(chain: str, url: str, targets, limit, metadata) -> list[dict]:
    rpc = RpcClient(url, jsonrpc="2.0")
    rows = []
    for btc_hash, height in targets[:limit]:
        row = {"chain": chain, "btc_header_hash": btc_hash, "child_height": height}
        meta = metadata.get(btc_hash)
        if meta is None:
            row["note"] = "missing_recovery_metadata"
            rows.append(row)
            continue
        is_uncle = meta["is_uncle"] == "1"
        if is_uncle:
            # Malformed classified metadata is a data problem, not a node
            # problem; parse it before the RPC try so it cannot be
            # misattributed to rpc_error.
            try:
                uncle_params = [
                    hex(int(meta["uncle_parent_height"])),
                    hex(int(meta["uncle_index"])),
                ]
            except ValueError:
                row["note"] = "metadata_error:uncle_placement"
                rows.append(row)
                continue
        notes = []
        try:
            if is_uncle:
                block = rpc.call("eth_getUncleByBlockNumberAndIndex", uncle_params)
            else:
                block = rpc.call("eth_getBlockByNumber", [hex(height), False])
            if block is None:
                row["note"] = "block_not_found"
                rows.append(row)
                continue
            mm_header = strip_0x(block.get("bitcoinMergedMiningHeader") or "")
            if not mm_header:
                row["note"] = "no_merged_mining_header"
                rows.append(row)
                continue
            derived = display_hash(sha256d(bytes.fromhex(mm_header)[:80]))
            if derived != btc_hash:
                row["note"] = f"parent_mismatch:{derived}"
                rows.append(row)
                continue
            number = int(block["number"], 16)
            if number != height:
                # The dedup premise keys uncles by their OWN height; a block
                # whose number disagrees with the recorded child height must
                # be refused, not hydrated with a note.
                row["note"] = f"height_disagrees:{number}"
                rows.append(row)
                continue
            timestamp = int(block["timestamp"], 16)
            if meta["rsk_timestamp"] and int(meta["rsk_timestamp"]) != timestamp:
                notes.append(f"timestamp_disagrees:{meta['rsk_timestamp']}")
            miner = strip_0x(block.get("miner") or "").lower()
            if meta["rsk_miner"] and meta["rsk_miner"] != miner:
                notes.append(f"miner_disagrees:{meta['rsk_miner']}")
            mm_hash = strip_0x(block.get("hashForMergedMining") or "").lower()
            if meta["merge_mining_hash"] and meta["merge_mining_hash"] != mm_hash:
                notes.append(f"merge_mining_hash_disagrees:{meta['merge_mining_hash']}")
            row.update(
                {
                    "child_block_hash": strip_0x(block["hash"]).lower(),
                    "child_block_time": timestamp,
                    "verification": "merged_mining_header_match",
                    "note": ";".join(notes),
                    "rsk_miner": miner,
                    "merge_mining_hash": mm_hash,
                    "is_uncle": meta["is_uncle"],
                    "uncle_index": meta["uncle_index"],
                    "uncle_parent_height": meta["uncle_parent_height"],
                    "rsk_merkle_proof": strip_0x(
                        block.get("bitcoinMergedMiningMerkleProof") or ""
                    ),
                    "rsk_coinbase_tail": strip_0x(
                        block.get("bitcoinMergedMiningCoinbaseTransaction") or ""
                    ),
                }
            )
        except (RuntimeError, ValueError, KeyError, requests.RequestException) as exc:
            row["note"] = f"rpc_error:{exc}"
        rows.append(row)
    return rows


def recover_hathor(chain: str, url: str, targets, limit) -> list[dict]:
    session = requests.Session()
    rows = []
    for btc_hash, height in targets[:limit]:
        row = {"chain": chain, "btc_header_hash": btc_hash, "child_height": height}
        try:
            resp = session.get(
                f"{url}/block_at_height", params={"height": height}, timeout=30
            )
            resp.raise_for_status()
            payload = resp.json()
            block = payload.get("block") or {}
            tx_id = (block.get("tx_id") or "").lower()
            if not payload.get("success") or not tx_id:
                row["note"] = "block_not_found"
            elif tx_id != btc_hash:
                row["note"] = f"parent_mismatch:{tx_id}"
            elif block.get("is_voided"):
                row["note"] = "child_block_voided"
            else:
                # The API's tx_id is Hathor's display form of the block id --
                # reverse(sha256d(mined BTC header)), the same display
                # convention as btc_header_hash. merge-mining-monitor stores
                # the sha256d digest bytes unreversed (its capture reverses
                # the API hex; see its hathor convert helpers), so the column
                # carries the reversal, per the child_block_hash contract.
                row["child_block_hash"] = display_to_internal(tx_id)
                row["child_block_time"] = block["timestamp"]
                row["verification"] = "hathor_block_id_match"
        except (requests.RequestException, ValueError, KeyError) as exc:
            row["note"] = f"api_error:{exc}"
        rows.append(row)
    return rows


def write_rows(output_dir: Path, chain: str, rows: list[dict], complete: bool) -> Path:
    """Write a chain's identity rows; a run with unresolved rows lands in a
    ``.partial`` sibling so it can never replace a complete committed file."""
    fields = CORE_FIELDS + (RSK_EXTRA_FIELDS if chain == "rsk" else [])
    output_dir.mkdir(parents=True, exist_ok=True)
    name = f"{chain}_child_identity.csv" + ("" if complete else ".partial")
    path = output_dir / name
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--chains",
        default=",".join(LIVE_CHAINS),
        help="Comma-separated subset of the six live chains",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=Path("results/monitor-evidence"),
        help="Directory holding <chain>_monitor_evidence.csv work lists",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/child-identity"),
        help="Directory receiving <chain>_child_identity.csv",
    )
    parser.add_argument(
        "--validated-dir",
        type=Path,
        default=Path("data/validated-stales"),
        help="Directory holding rsk_validated_stales.csv (uncle metadata)",
    )
    parser.add_argument(
        "--chain-archive-dir",
        type=Path,
        default=None,
        help=(
            "Private chain archive root; supplies rsk/classified/"
            "rsk_stale_blocks.csv uncle metadata for full-inventory rows"
        ),
    )
    parser.add_argument("--limit", type=int, default=None, help="Rows per chain")
    args = parser.parse_args()

    if (
        args.limit is not None
        and args.output_dir.resolve() == Path("data/child-identity").resolve()
    ):
        raise SystemExit(
            "--limit writes a partial identity file that would replace the "
            "committed complete one; pass a disposable --output-dir for "
            "limited smoke runs"
        )

    chains = [chain.strip() for chain in args.chains.split(",") if chain.strip()]
    unknown = sorted(set(chains) - set(LIVE_CHAINS))
    if unknown:
        raise SystemExit(f"not live-lifecycle chains: {', '.join(unknown)}")

    rsk_metadata_paths = [args.validated_dir / "rsk_validated_stales.csv"]
    if args.chain_archive_dir:
        rsk_metadata_paths.append(
            args.chain_archive_dir / "rsk" / "classified" / "rsk_stale_blocks.csv"
        )

    exit_code = 0
    for chain in chains:
        evidence_path = args.evidence_dir / f"{chain}_monitor_evidence.csv"
        if not evidence_path.exists():
            raise SystemExit(f"missing work list: {evidence_path}")
        targets = load_targets(evidence_path)
        url = DEFAULT_URLS[chain]
        limit = args.limit if args.limit is not None else len(targets)
        if chain in ("namecoin", "syscoin"):
            rows = recover_auxpow_family(chain, url, targets, limit)
        elif chain == "elastos":
            rows = recover_elastos(chain, url, targets, limit)
        elif chain == "fractal":
            rows = recover_fractal(chain, url, targets, limit)
        elif chain == "rsk":
            rows = recover_rsk(
                chain, url, targets, limit, load_rsk_metadata(rsk_metadata_paths)
            )
        else:
            rows = recover_hathor(chain, url, targets, limit)
        recovered = sum(1 for row in rows if row.get("verification"))
        failed = [row for row in rows if not row.get("verification")]
        path = write_rows(args.output_dir, chain, rows, complete=not failed)
        print(f"{chain}: {recovered}/{len(rows)} recovered -> {path}")
        for row in failed:
            print(
                f"  UNRESOLVED {row['btc_header_hash']} "
                f"h={row['child_height']}: {row.get('note', '')}"
            )
        if failed:
            print(
                f"  incomplete recovery kept out of {chain}_child_identity.csv; "
                "resolve the rows above and re-run"
            )
            exit_code = 1
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
