#!/usr/bin/env python3
"""Recover child-chain block identity for five active chains needing hydration.

The monitor-evidence exports for namecoin, rsk, syscoin, elastos, and fractal
carry recovered Bitcoin parent evidence but need a separately authenticated
child event. Some source rows retain an exact child hash; others retain only
the child height. merge-mining-monitor keys `merge_mining_event` rows by
(source, child_height, child_block_hash), so imported rows need the exact
child identity or they can never deduplicate against live-captured rows.

All five targets still have reachable nodes. Recovery fetches an exact source
hash when one is available and falls back to height -> hash only for an
unambiguous height-only target. Every recovered row is verified by re-deriving
the Bitcoin parent linkage FROM the fetched child block and requiring it to
match the row's own `btc_header_hash`:

  namecoin  getblock().auxpow.parentblock (node-decoded CAuxPow parent)
  syscoin   same call; parentblock arrives as header hex, hash recomputed
  elastos   read_auxpow(getblock().auxpow) -> parent header (serialized form)
  fractal   getblockheader(hash, false, true): 80-byte FB header + CAuxPow;
            parent header parsed from the proof, FB hash/time from the header
  rsk       sha256d(bitcoinMergedMiningHeader[:80]); uncle rows resolved via
            eth_getUncleByBlockNumberAndIndex(uncle_parent_height, uncle_index).
            When classified metadata is absent, a height-only target tries
            the recorded height as a canonical child via eth_getBlockByNumber.
            Uncles still need archive metadata. The RSK target list also
            includes error-observation ledger parents, which ordinary
            inventories exclude.
A mismatch means the fetched child event does not satisfy the source selector
or carry the expected Bitcoin parent. For a height-only fallback, it can also
mean today's canonical child chain no longer contains the original event.
Such rows are written with an empty child identity and a reason so the exports
leave them blank and the monitor importer skips them instead of synthesizing
an identity.

Successful Bitcoin-shaped recoveries also retain the exact 80-byte child
header and its compact target. RSK uses an Ethereum-native child block, so its
rows keep those two core columns explicitly blank while retaining the RSK
sidecar fields below.

RSK rows additionally carry the fields merge-mining-monitor's
`rsk_merge_mining_evidence` sidecar requires (miner, hashForMergedMining,
uncle placement, merkle proof, coinbase tail). Miner, merge-mining hash and
timestamp are cross-checked against the classified recovery metadata; any
disagreement is recorded in `note` without blocking the row.

`btc_header_hash` stays in display (RPC) order like every other pipeline
artifact. `child_block_hash` follows the pipeline's established column
contract of INTERNAL (wire) byte order for the Bitcoin-family chains (the
reverse of the node's display hex; see `auxpow_child_heights`,
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
prefix convention; the Elastos and RSK endpoints are unauthenticated.
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
from stale_blocks_analysis.auxpow_parse import (
    ChildHeaderValidationError,
    parse_child_header,
    read_auxpow,
    serialize_block_header,
)
from stale_blocks_analysis.child_rpc import RpcClient
from stale_blocks_analysis.config import DATA_DIR
from stale_blocks_analysis.error_observations import ERROR_OBSERVATION_LEDGER
from stale_blocks_analysis.evidence_hydration import CHILD_IDENTITY_CORE_FIELDS
from stale_blocks_analysis.full_evidence import (
    CHILD_IDENTITY_HYDRATION_CHAINS,
    is_hash,
)
from stale_blocks_analysis.rpc_env import load_local_rpc_env, rpc_auth_from_env

load_local_rpc_env()

# One source of truth with the export hydrator's unconditional target set.
IDENTITY_HYDRATION_CHAINS = tuple(sorted(CHILD_IDENTITY_HYDRATION_CHAINS))

DEFAULT_URLS = {
    "namecoin": os.environ.get("NAMECOIN_RPC_URL", "http://127.0.0.1:8436"),
    "syscoin": os.environ.get("SYSCOIN_RPC_URL", "http://127.0.0.1:8370"),
    "elastos": os.environ.get("ELASTOS_RPC_URL", "http://127.0.0.1:20336"),
    "fractal": os.environ.get("FRACTAL_RPC_URL", "http://127.0.0.1:18332"),
    "rsk": os.environ.get("RSK_RPC_URL", "http://127.0.0.1:4444"),
}

CORE_FIELDS = CHILD_IDENTITY_CORE_FIELDS

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


def strip_0x(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


RecoveryTarget = tuple[str, int, str]
RskMetadata = dict[tuple[str, int], tuple[dict[str, str], ...]]


def _target_sort_key(target: RecoveryTarget) -> tuple[int, str, str]:
    btc_hash, height, child_hash = target
    return height, btc_hash, child_hash


def _record_target(
    targets: dict[RecoveryTarget, int],
    event_parents: dict[tuple[int, str], tuple[str, int]],
    *,
    btc_hash: str,
    height: int,
    child_hash: str,
    row_number: int,
    source: Path | str,
) -> None:
    """Record one source event without collapsing same-height child forks."""
    if not is_hash(btc_hash):
        raise SystemExit(f"{source}:{row_number}: invalid btc_header_hash")
    if child_hash and not is_hash(child_hash):
        raise SystemExit(f"{source}:{row_number}: invalid child_block_hash")
    target = (btc_hash, height, child_hash)
    first_row = targets.get(target)
    if first_row is not None:
        raise SystemExit(
            f"{source}: duplicate child-identity target "
            f"{btc_hash}:{height}:{child_hash or '<missing>'} at rows "
            f"{first_row} and {row_number}"
        )
    same_slot = [
        (known_hash, known_row)
        for (known_parent, known_height, known_hash), known_row in targets.items()
        if known_parent == btc_hash and known_height == height
    ]
    if same_slot and (
        not child_hash or any(not known_hash for known_hash, _ in same_slot)
    ):
        prior_rows = ",".join(str(known_row) for _, known_row in same_slot)
        raise SystemExit(
            f"{source}: ambiguous child-identity targets for {btc_hash}:{height}; "
            f"rows {prior_rows} and {row_number} do not all identify an exact "
            "child hash"
        )
    if child_hash:
        event = (height, child_hash)
        previous = event_parents.get(event)
        if previous is not None and previous[0] != btc_hash:
            raise SystemExit(
                f"{source}: child event {height}:{child_hash} is assigned to "
                f"multiple Bitcoin parents at rows {previous[1]} and {row_number}"
            )
        event_parents[event] = (btc_hash, row_number)
    targets[target] = row_number


def load_targets(evidence_path: Path) -> list[RecoveryTarget]:
    """Non-canonical exact-event recovery work list.

    The optional source ``child_block_hash`` distinguishes child-chain forks
    at the same height. A height-only target remains supported when it is the
    sole event in that parent/height slot; mixing it with another event is
    ambiguous and fails closed. Canonical rows are deliberately skipped.
    """
    targets: dict[RecoveryTarget, int] = {}
    event_parents: dict[tuple[int, str], tuple[str, int]] = {}
    with evidence_path.open(newline="") as f:
        for row_number, row in enumerate(csv.DictReader(f), start=2):
            if (row.get("classification") or "").strip() == "canonical":
                continue
            btc_hash = (row.get("btc_header_hash") or "").strip().lower()
            height_text = (row.get("child_height") or "").strip()
            if not btc_hash or not height_text:
                raise SystemExit(
                    f"{evidence_path}:{row_number}: row missing "
                    "btc_header_hash/child_height"
                )
            try:
                height = int(height_text)
            except ValueError as exc:
                raise SystemExit(
                    f"{evidence_path}:{row_number}: invalid child_height"
                ) from exc
            _record_target(
                targets,
                event_parents,
                btc_hash=btc_hash,
                height=height,
                child_hash=(row.get("child_block_hash") or "").strip().lower(),
                row_number=row_number,
                source=evidence_path,
            )
    if not targets:
        raise SystemExit(f"{evidence_path}: no non-canonical child-identity targets")
    return sorted(targets, key=_target_sort_key)


def load_error_observation_rsk_targets(ledger_path: Path) -> list[RecoveryTarget]:
    """RSK error-observation parents excluded from ordinary inventories."""
    if not ledger_path.is_file():
        raise SystemExit(f"{ledger_path}: error-observation ledger is missing")
    targets: dict[RecoveryTarget, int] = {}
    event_parents: dict[tuple[int, str], tuple[str, int]] = {}
    with ledger_path.open(newline="") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), start=2):
            if (row.get("chain") or "").strip() != "rsk":
                continue
            btc_hash = (row.get("btc_header_hash") or "").strip().lower()
            height_text = (row.get("child_height") or "").strip()
            if not btc_hash or not height_text:
                raise SystemExit(
                    f"{ledger_path}:{row_number}: RSK error-observation row "
                    "missing btc_header_hash/child_height"
                )
            try:
                height = int(height_text)
            except ValueError as exc:
                raise SystemExit(
                    f"{ledger_path}:{row_number}: invalid RSK child_height"
                ) from exc
            _record_target(
                targets,
                event_parents,
                btc_hash=btc_hash,
                height=height,
                child_hash=(row.get("child_block_hash") or "").strip().lower(),
                row_number=row_number,
                source=ledger_path,
            )
    if not targets:
        raise SystemExit(f"{ledger_path}: no RSK error-observation targets")
    return sorted(targets, key=_target_sort_key)


def merge_identity_targets(
    ordinary: list[RecoveryTarget], extra: list[RecoveryTarget]
) -> list[RecoveryTarget]:
    """Combine exact events while rejecting unresolved same-height overlap."""
    merged: dict[RecoveryTarget, int] = {}
    event_parents: dict[tuple[int, str], tuple[str, int]] = {}
    for position, target in enumerate([*ordinary, *extra], start=1):
        btc_hash, height, child_hash = target
        _record_target(
            merged,
            event_parents,
            btc_hash=btc_hash,
            height=height,
            child_hash=child_hash,
            row_number=position,
            source="merged child-identity work lists",
        )
    return sorted(merged, key=_target_sort_key)


def selected_targets(targets: list[RecoveryTarget], limit: int) -> list[RecoveryTarget]:
    """Return the deterministic prefix used by every recovery backend."""
    return sorted(targets, key=_target_sort_key)[:limit]


def load_rsk_metadata(
    paths: list[Path],
) -> RskMetadata:
    """Load every distinct RSK placement for a parent/child-height slot."""
    meta: dict[tuple[str, int], list[dict[str, str]]] = {}
    selectors: dict[tuple[str, int, str], dict[str, str]] = {}
    for path in paths:
        if not path.exists():
            continue
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                btc_hash = row.get("btc_header_hash", "").strip().lower()
                height_text = row.get("rsk_height", "").strip()
                try:
                    height = int(height_text)
                except ValueError:
                    continue
                if not btc_hash:
                    continue
                child_hash = (row.get("child_block_hash") or "").strip().lower()
                if child_hash and not is_hash(child_hash):
                    raise SystemExit(
                        f"{path}: invalid RSK child_block_hash for {btc_hash}:{height}"
                    )
                candidate = {
                    "rsk_height": height_text,
                    "child_block_hash": child_hash,
                    "rsk_timestamp": row.get("rsk_timestamp", "").strip(),
                    "rsk_miner": row.get("rsk_miner", "").strip().lower(),
                    "merge_mining_hash": row.get("merge_mining_hash", "")
                    .strip()
                    .lower(),
                    "is_uncle": row.get("is_uncle", "").strip(),
                    "uncle_index": row.get("uncle_index", "").strip(),
                    "uncle_parent_height": row.get("uncle_parent_height", "").strip(),
                }
                key = (btc_hash, height)
                selector = (btc_hash, height, child_hash)
                if not child_hash:
                    # Classified RSK inventories authenticate placement but do not
                    # carry the child hash. Preserve distinct placements so an
                    # exact source target can query each and select by RPC hash.
                    if candidate in meta.get(key, []):
                        continue
                    meta.setdefault(key, []).append(candidate)
                    continue
                previous = selectors.get(selector)
                if previous is not None:
                    if previous != candidate:
                        raise SystemExit(
                            f"{path}: conflicting RSK metadata for "
                            f"{btc_hash}:{height}:{child_hash}"
                        )
                    continue
                selectors[selector] = candidate
                meta.setdefault(key, []).append(candidate)
    return {key: tuple(candidates) for key, candidates in meta.items()}


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


def child_fields_from_raw_header(
    raw_header: bytes,
    *,
    expected_display_hash: str,
    expected_time: int | None = None,
    expected_nbits: str | int | None = None,
) -> dict[str, str | int]:
    """Authenticate and normalize an exact Bitcoin-shaped child header.

    Some AuxPoW RPCs serialize proof bytes after the pure child header. Only
    the first 80 bytes identify the child block. The independently returned
    display hash, timestamp, and compact target are corroborated when present
    so recovery cannot publish internally consistent bytes for the wrong RPC
    object.
    """
    if len(raw_header) < 80:
        raise ChildHeaderValidationError(
            f"child header response is shorter than 80 bytes: {len(raw_header)}"
        )
    fields = parse_child_header(
        raw_header[:80],
        expected_hash_display=expected_display_hash.strip().lower(),
    )
    if expected_time is not None and fields["child_block_time"] != expected_time:
        raise ChildHeaderValidationError(
            "child header timestamp disagrees with decoded RPC block"
        )
    if expected_nbits is not None:
        if isinstance(expected_nbits, int):
            normalized_nbits = f"{expected_nbits:08x}"
        else:
            normalized_nbits = expected_nbits.strip().lower()
            if normalized_nbits.startswith("0x"):
                normalized_nbits = normalized_nbits[2:]
        if fields["child_nbits"] != normalized_nbits:
            raise ChildHeaderValidationError(
                "child header nBits disagrees with decoded RPC block"
            )
    return fields


def bitcoin_child_hash_display(child_hash_internal: str) -> str:
    """Convert the normalized wire-order child hash to RPC display order."""
    return bytes.fromhex(child_hash_internal)[::-1].hex()


def recover_auxpow_family(
    chain: str, url: str, targets: list[RecoveryTarget], limit: int
) -> list[dict]:
    user, password = rpc_auth_from_env(chain.upper())
    rpc = RpcClient(url, user=user, password=password)
    rows = []
    for btc_hash, height, source_child_hash in selected_targets(targets, limit):
        row = {"chain": chain, "btc_header_hash": btc_hash, "child_height": height}
        try:
            child_hash = (
                bitcoin_child_hash_display(source_child_hash)
                if source_child_hash
                else rpc.call("getblockhash", [height])
            )
            block = rpc.call("getblock", [child_hash])
            derived = parent_hash_from_auxpow_family(block)
            if not derived:
                row["note"] = "no_auxpow_in_child_block"
            elif derived != btc_hash:
                row["note"] = f"parent_mismatch:{derived}"
            else:
                child_header_hex = rpc.call("getblockheader", [child_hash, False])
                if not isinstance(child_header_hex, str):
                    raise ChildHeaderValidationError(
                        "getblockheader returned a non-string payload"
                    )
                row.update(
                    child_fields_from_raw_header(
                        bytes.fromhex(child_header_hex),
                        expected_display_hash=child_hash,
                        expected_time=block["time"],
                        expected_nbits=block.get("bits"),
                    )
                )
                row["verification"] = "auxpow_parent_match"
        except (RuntimeError, ValueError, KeyError, requests.RequestException) as exc:
            row["note"] = f"rpc_error:{exc}"
        rows.append(row)
    return rows


def recover_elastos(
    chain: str, url: str, targets: list[RecoveryTarget], limit: int
) -> list[dict]:
    rpc = RpcClient(url, jsonrpc="2.0")
    rows = []
    for btc_hash, height, source_child_hash in selected_targets(targets, limit):
        row = {"chain": chain, "btc_header_hash": btc_hash, "child_height": height}
        try:
            child_hash = (
                bitcoin_child_hash_display(source_child_hash)
                if source_child_hash
                else rpc.call("getblockhash", {"height": height})
            )
            block = rpc.call("getblock", {"blockhash": child_hash, "verbosity": 2})
            aux, _ = read_auxpow(bytes.fromhex(block["auxpow"]), 0)
            derived = display_hash(sha256d(aux["parent_header_raw"]))
            if derived != btc_hash:
                row["note"] = f"parent_mismatch:{derived}"
            else:
                child_header = serialize_block_header(
                    version=block["version"],
                    previous_block_hash=block["previousblockhash"],
                    merkle_root=block["merkleroot"],
                    timestamp=block["time"],
                    bits=block["bits"],
                    nonce=block["nonce"],
                )
                row.update(
                    child_fields_from_raw_header(
                        child_header,
                        expected_display_hash=child_hash,
                        expected_time=block["time"],
                        expected_nbits=block["bits"],
                    )
                )
                row["verification"] = "auxpow_parent_match"
        except (RuntimeError, ValueError, KeyError, requests.RequestException) as exc:
            row["note"] = f"rpc_error:{exc}"
        rows.append(row)
    return rows


def recover_fractal(
    chain: str, url: str, targets: list[RecoveryTarget], limit: int
) -> list[dict]:
    user, password = rpc_auth_from_env(chain.upper())
    rpc = RpcClient(url, user=user, password=password)
    rows = []
    for btc_hash, height, source_child_hash in selected_targets(targets, limit):
        row = {"chain": chain, "btc_header_hash": btc_hash, "child_height": height}
        try:
            child_hash = (
                bitcoin_child_hash_display(source_child_hash)
                if source_child_hash
                else rpc.call("getblockhash", [height])
            )
            blob = bytes.fromhex(rpc.call("getblockheader", [child_hash, False, True]))
            if len(blob) < 80:
                row["note"] = f"short_header_response:{len(blob)}"
                rows.append(row)
                continue
            fb_header = blob[:80]
            child_fields = child_fields_from_raw_header(
                fb_header,
                expected_display_hash=child_hash,
            )
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
                row.update(child_fields)
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


def _default_rsk_metadata(height: int) -> dict[str, str]:
    return {
        "rsk_height": str(height),
        "child_block_hash": "",
        "rsk_timestamp": "",
        "rsk_miner": "",
        "merge_mining_hash": "",
        "is_uncle": "0",
        "uncle_index": "",
        "uncle_parent_height": "",
    }


def _rsk_metadata_candidates(
    metadata: RskMetadata, btc_hash: str, height: int
) -> tuple[dict[str, str], ...]:
    candidates = metadata.get((btc_hash, height), ())
    if not isinstance(candidates, tuple):
        raise TypeError("RSK metadata values must be tuples of candidate rows")
    return candidates


def _recover_rsk_candidate(
    rpc: RpcClient,
    *,
    chain: str,
    btc_hash: str,
    height: int,
    source_child_hash: str,
    meta: dict[str, str],
) -> tuple[dict | None, str]:
    row = {"chain": chain, "btc_header_hash": btc_hash, "child_height": height}
    is_uncle = meta["is_uncle"] == "1"
    metadata_child_hash = (meta.get("child_block_hash") or "").strip().lower()
    effective_child_hash = source_child_hash or metadata_child_hash
    if is_uncle:
        try:
            uncle_params = [
                hex(int(meta["uncle_parent_height"])),
                hex(int(meta["uncle_index"])),
            ]
        except ValueError:
            return None, "metadata_error:uncle_placement"
    try:
        if is_uncle:
            block = rpc.call("eth_getUncleByBlockNumberAndIndex", uncle_params)
        elif effective_child_hash:
            # An exact source or metadata hash authenticates this event even
            # when the source target supplied only a height. RSK hashes remain
            # in forward order, unlike the Bitcoin-family wire-order hashes
            # converted before their RPC lookups.
            block = rpc.call("eth_getBlockByHash", [f"0x{effective_child_hash}", False])
        else:
            block = rpc.call("eth_getBlockByNumber", [hex(height), False])
        if block is None:
            return None, "block_not_found"
        child_hash = strip_0x(block.get("hash") or "").lower()
        if effective_child_hash and child_hash != effective_child_hash:
            return None, f"child_hash_disagrees:{child_hash or '<missing>'}"
        mm_header = strip_0x(block.get("bitcoinMergedMiningHeader") or "")
        if not mm_header:
            return None, "no_merged_mining_header"
        derived = display_hash(sha256d(bytes.fromhex(mm_header)[:80]))
        if derived != btc_hash:
            return None, f"parent_mismatch:{derived}"
        number = int(block["number"], 16)
        if number != height:
            return None, f"height_disagrees:{number}"
        timestamp = int(block["timestamp"], 16)
        notes = []
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
                "child_block_hash": child_hash,
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
        return row, ""
    except (RuntimeError, ValueError, KeyError, requests.RequestException) as exc:
        return None, f"rpc_error:{exc}"


def recover_rsk(
    chain: str,
    url: str,
    targets: list[RecoveryTarget],
    limit: int,
    metadata: RskMetadata,
) -> list[dict]:
    rpc = RpcClient(url, jsonrpc="2.0")
    rows = []
    for btc_hash, height, source_child_hash in selected_targets(targets, limit):
        unresolved = {
            "chain": chain,
            "btc_header_hash": btc_hash,
            "child_height": height,
        }
        candidates = _rsk_metadata_candidates(metadata, btc_hash, height)
        if source_child_hash and candidates:
            exact = tuple(
                candidate
                for candidate in candidates
                if (candidate.get("child_block_hash") or "").strip().lower()
                == source_child_hash
            )
            generic = tuple(
                candidate
                for candidate in candidates
                if not (candidate.get("child_block_hash") or "").strip()
            )
            if exact:
                candidates = exact
            elif generic:
                # Classified RSK metadata has placement but no child hash. Try all
                # distinct placements and accept only the one whose RPC object
                # matches the source event hash.
                candidates = generic
            else:
                unresolved["note"] = "metadata_error:no_matching_child_hash"
                rows.append(unresolved)
                continue
        elif not candidates:
            # Exact hashes can be fetched directly as canonical blocks. A
            # height-only row uses the historical canonical-height fallback.
            candidates = (_default_rsk_metadata(height),)
        elif len(candidates) > 1:
            unresolved["note"] = "metadata_error:ambiguous_child_event"
            rows.append(unresolved)
            continue

        recovered = []
        failures = []
        for candidate in candidates:
            recovered_row, failure = _recover_rsk_candidate(
                rpc,
                chain=chain,
                btc_hash=btc_hash,
                height=height,
                source_child_hash=source_child_hash,
                meta=candidate,
            )
            if recovered_row is not None:
                recovered.append(recovered_row)
            elif failure:
                failures.append(failure)
        if len(recovered) == 1:
            rows.append(recovered[0])
        else:
            unresolved["note"] = (
                "metadata_error:ambiguous_child_event"
                if len(recovered) > 1
                else (failures[0] if failures else "block_not_found")
            )
            rows.append(unresolved)
    return rows


def _ordered_identity_rows(chain: str, rows: list[dict]) -> list[dict]:
    """Validate exact recovered events and return deterministic output order."""
    event_parents: dict[tuple[int, str], str] = {}
    for row_number, row in enumerate(rows, start=1):
        try:
            child_height = int(row.get("child_height", ""))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{chain} recovery row {row_number} has invalid child_height"
            ) from exc
        child_hash = str(row.get("child_block_hash") or "").strip().lower()
        if not child_hash:
            continue
        parent_hash = str(row.get("btc_header_hash") or "").strip().lower()
        event = (child_height, child_hash)
        previous_parent = event_parents.get(event)
        if previous_parent is not None:
            if previous_parent != parent_hash:
                raise ValueError(
                    f"{chain} child event {event} is assigned to multiple "
                    f"Bitcoin parents: {previous_parent} and {parent_hash}"
                )
            raise ValueError(
                f"{chain} recovery contains duplicate exact child event "
                f"{parent_hash}:{child_height}:{child_hash}"
            )
        event_parents[event] = parent_hash
    return sorted(
        rows,
        key=lambda row: (
            int(row.get("child_height", "")),
            str(row.get("btc_header_hash") or "").strip().lower(),
            str(row.get("child_block_hash") or "").strip().lower(),
        ),
    )


def write_rows(output_dir: Path, chain: str, rows: list[dict], complete: bool) -> Path:
    """Write a chain's identity rows; a run with unresolved rows lands in a
    ``.partial`` sibling so it can never replace a complete committed file."""
    ordered_rows = _ordered_identity_rows(chain, rows)
    fields = CORE_FIELDS + (RSK_EXTRA_FIELDS if chain == "rsk" else [])
    output_dir.mkdir(parents=True, exist_ok=True)
    name = f"{chain}_child_identity.csv" + ("" if complete else ".partial")
    path = output_dir / name
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in ordered_rows:
            writer.writerow({field: row.get(field, "") for field in fields})
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--chains",
        default=",".join(IDENTITY_HYDRATION_CHAINS),
        help="Comma-separated subset of the identity-hydration chains",
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
    unknown = sorted(set(chains) - set(IDENTITY_HYDRATION_CHAINS))
    if unknown:
        raise SystemExit(f"not identity-hydration chains: {', '.join(unknown)}")

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
        if chain == "rsk":
            targets = merge_identity_targets(
                targets,
                load_error_observation_rsk_targets(
                    DATA_DIR / "error-blocks" / ERROR_OBSERVATION_LEDGER
                ),
            )
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
