"""Observation loading and validation for stale-ancestry reconciliation."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from stale_blocks_analysis.btc_rpc import BtcRpc
from stale_blocks_analysis.error_blocks import load_consensus_invalid_stale_keys
from stale_blocks_analysis.full_evidence import (
    first_present,
    get_value,
    int_or_none,
    is_hash,
    normalize_hash,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DOCS_CHAINS_DIR = PROJECT_ROOT / "docs" / "chains"

HASH_COLUMNS = ("btc_header_hash", "btc_hash", "hash")
PREV_COLUMNS = ("btc_prev_hash",)
BITS_COLUMNS = ("btc_bits", "btc_bits_hex")
HEADER_HEX_COLUMNS = ("btc_header_hex", "header")
BTC_HEIGHT_COLUMNS = ("btc_height", "btc_stale_height", "height", "btc_bip34_height")
NON_CHILD_HEIGHT_COLUMNS = {
    "btc_height",
    "btc_stale_height",
    "btc_parent_height",
    "btc_bip34_height",
    "height",
}


@dataclass(slots=True)
class StaleObservation:
    """One source row reporting a known-stale BTC header.

    `source_kind` is `upstream`, `full_inventory`, or `validated_stales`.
    `btc_height` is the BTC parent height; `child_height`
    is the sibling-chain block height that carries the AuxPoW (empty for the
    upstream sources, which have no child-chain column).
    """

    chain: str
    source_kind: str
    source_path: str
    row_number: int
    block_hash: str
    prev_hash: str
    btc_height: str
    child_height: str
    btc_time: str
    bits: str


@dataclass(slots=True)
class UnknownObservation:
    """One source row reporting an unknown-classified (legacy "orphan") BTC parent.

    Always comes from a per-chain full-inventory CSV. `scriptsig_hex` and
    `outputs` are the coinbase scriptSig/outputs hex, if present; `header_hex`
    is the raw 80-byte BTC header hex used to recompute the header hash and
    self-PoW during descendant validation.
    """

    chain: str
    source_path: str
    row_number: int
    block_hash: str
    prev_hash: str
    btc_height: str
    child_height: str
    btc_time: str
    bits: str
    scriptsig_hex: str
    outputs: str
    header_hex: str


def rel(path: Path) -> str:
    """Return `path` relative to the project root, or unchanged if it is not inside the project."""
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def parse_header_fields(header_hex: str) -> dict[str, str]:
    """Parse `prev_hash`, `time`, and `bits` out of an 80-byte BTC header hex string.

    Returns `{}` for empty/invalid hex or a header shorter than 80 bytes.
    `prev_hash` is converted to display-order (big-endian) lowercase hex;
    `time` is a decimal string; `bits` is lowercase compact-bits hex (both
    read little-endian off the wire, per the header's on-disk byte order).
    """
    header_hex = (header_hex or "").strip()
    if not header_hex:
        return {}
    try:
        raw = bytes.fromhex(header_hex)
    except ValueError:
        return {}
    if len(raw) < 80:
        return {}
    return {
        "version": str(int.from_bytes(raw[:4], "little", signed=True)),
        "prev_hash": raw[4:36][::-1].hex(),
        "time": str(int.from_bytes(raw[68:72], "little")),
        "bits": raw[72:76][::-1].hex(),
    }


def header_hash(header_hex: str) -> str:
    """Compute the display-order (big-endian) SHA256d hash of an 80-byte BTC header hex string.

    Returns `""` for empty/invalid hex or a header shorter than 80 bytes;
    only the first 80 bytes are hashed, so trailing AuxPoW data is ignored.
    """
    try:
        raw = bytes.fromhex((header_hex or "").strip())
    except ValueError:
        return ""
    if len(raw) < 80:
        return ""
    return hashlib.sha256(hashlib.sha256(raw[:80]).digest()).digest()[::-1].hex()


def compact_target(bits_hex: str) -> int | None:
    """Expand a compact-bits hex string to its full integer PoW target.

    Returns None for invalid hex or for the negative-mantissa encoding (the
    sign bit, 0x00800000, set in the mantissa), which Bitcoin Core also
    treats as invalid.
    """
    try:
        bits = int(bits_hex, 16)
    except ValueError:
        return None
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if bits & 0x00800000:
        return None
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def hash_meets_bits(block_hash: str, bits_hex: str) -> bool:
    """True if `block_hash`, as a big-endian int, is at or below the target encoded in `bits_hex`."""
    target = compact_target(bits_hex)
    if target is None or not is_hash(block_hash):
        return False
    return int(block_hash, 16) <= target


def get_hash(row: dict[str, str], hash_col: str) -> str:
    """Return the normalized hash from `row[hash_col]`, or `""` if `hash_col` is empty."""
    return normalize_hash(row.get(hash_col, "")) if hash_col else ""


def get_prev(row: dict[str, str], prev_col: str, header_col: str) -> tuple[str, bool]:
    """Return the row's prev-hash, recovering it from `header_col`'s header
    hex when the prev-hash column is empty.

    Returns `(prev_hash, recovered)` where `recovered` is True only when the
    value came from parsing the header hex rather than `prev_col` directly.
    """
    prev_hash = normalize_hash(row.get(prev_col, "")) if prev_col else ""
    if prev_hash:
        return prev_hash, False
    parsed = parse_header_fields(row.get(header_col, "")) if header_col else {}
    return parsed.get("prev_hash", ""), bool(parsed.get("prev_hash"))


def get_child_height(row: dict[str, str], fieldnames: Iterable[str] | None) -> str:
    """Return the sibling-chain block height for `row`.

    Looks for the first `*_height`-suffixed column not in
    `NON_CHILD_HEIGHT_COLUMNS` (the per-chain child-height column, e.g.
    `ixc_height`) with a non-empty value, falling back to a literal
    `child_height` column.
    """
    for field in fieldnames or []:
        if field.endswith("_height") and field not in NON_CHILD_HEIGHT_COLUMNS:
            value = row.get(field, "").strip()
            if value:
                return value
    return row.get("child_height", "").strip()


def load_epoch_bits(path: Path) -> dict[int, str]:
    """Load the epoch-start-height -> lowercase-hex-bits table from `path`.

    Returns `{}` if `path` does not exist. Keys are BTC epoch-start heights
    (multiples of 2016); values are lowercased compact-bits hex.
    """
    if not path.exists():
        return {}
    with path.open() as f:
        raw = json.load(f)
    return {int(k): str(v).lower() for k, v in raw.items()}


def expected_bits_for_height(height: str, epoch_bits: dict[int, str]) -> str:
    """Return the expected compact-bits hex for `height`'s retarget epoch, or `""`.

    Looks up `epoch_bits[(height // 2016) * 2016]`; returns `""` when
    `height` does not parse as an int or the epoch has no cached entry.
    """
    h = int_or_none(height)
    if h is None:
        return ""
    return epoch_bits.get((h // 2016) * 2016, "")


def discover_chain_names(
    data_dir: Path,
) -> tuple[set[str], dict[str, Path], dict[str, Path]]:
    """Discover per-chain full-inventory and validated-stales CSVs under `data_dir`.

    Chain names also include any `docs/chains/<chain>.md` stem even when
    neither CSV exists for it, so chains documented but not yet extracted
    still show up (as excluded) in the reconciliation inventory. Returns
    `(chain_names, stale_inventory_paths, unknown_inventory_paths,
    validated_stales_paths)`. The stale and unknown inventories are the two
    halves of the classifier's bucket split; a never-split chain has only the
    (commingled) stale file and no unknown file.
    """
    full = {
        p.name.removesuffix("_stale_blocks.csv"): p
        for p in data_dir.glob("*_stale_blocks.csv")
    }
    unknown = {
        p.name.removesuffix("_unknown_blocks.csv"): p
        for p in data_dir.glob("*_unknown_blocks.csv")
    }
    validated = {
        p.name.removesuffix("_validated_stales.csv"): p
        for p in data_dir.glob("validated-stales/*_validated_stales.csv")
    }
    chain_names = set(full) | set(unknown) | set(validated)
    if DOCS_CHAINS_DIR.exists():
        chain_names.update(p.stem for p in DOCS_CHAINS_DIR.glob("*.md"))
    return chain_names, full, unknown, validated


def join_sorted(values: Iterable[str]) -> str:
    """Return the pipe-joined sorted non-empty values."""
    return "|".join(sorted(value for value in values if value))


def load_mainchain_cache(cache_dir: Path) -> dict[str, dict]:
    """Load and merge the shadow-resolver and unknown-origin mainchain-status caches.

    Reads `shadow-resolver-mainchain-cache.json` then
    `unknown_origin_btc_headers_by_hash.json` from `cache_dir` (the second
    overwrites entries for the same hash), normalizing each value: a bare
    bool is treated as `{"exists": v, "on_mainchain": v}`; a dict with a
    `confirmations` field derives `on_mainchain` as `confirmations >= 0`; a
    `null` value is recorded as `{"exists": False, "on_mainchain": False}`
    only if the hash was not already present. Entries with a malformed hash
    are skipped.
    """
    out: dict[str, dict] = {}
    paths = [
        cache_dir / "shadow-resolver-mainchain-cache.json",
        cache_dir / "unknown_origin_btc_headers_by_hash.json",
    ]
    for path in paths:
        if not path.exists():
            continue
        with path.open() as f:
            raw = json.load(f)
        for block_hash, value in raw.items():
            h = normalize_hash(block_hash)
            if not is_hash(h):
                continue
            if value is None:
                out.setdefault(h, {"exists": False, "on_mainchain": False})
            elif isinstance(value, bool):
                out[h] = {"exists": value, "on_mainchain": value}
            elif isinstance(value, dict):
                confirmations = value.get("confirmations")
                on_mainchain = bool(value.get("on_mainchain"))
                if confirmations is not None:
                    on_mainchain = int(confirmations) >= 0
                out[h] = {
                    "exists": bool(value.get("exists", True)),
                    "on_mainchain": on_mainchain,
                    "confirmations": confirmations,
                    "height": value.get("height"),
                    "time": value.get("time"),
                    "bits": value.get("bits"),
                }
    return out


def save_mainchain_cache(cache_dir: Path, cache: dict[str, dict]) -> None:
    """Write `cache` as pretty-printed, sorted JSON under `cache_dir`.

    Target file: `unknown-stale-reconciliation-mainchain-cache.json`.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / "unknown-stale-reconciliation-mainchain-cache.json"
    path.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n")


def fetch_mainchain_status(
    hashes: Iterable[str],
    rpc: BtcRpc,
    batch_size: int,
) -> dict[str, dict]:
    """Query Bitcoin Core for the mainchain status of `hashes`.

    Deduplicates and filters `hashes` to well-formed hashes, then issues
    batched `getblockheader` calls (chunked at `batch_size`) through `rpc` and
    returns each hash's `{exists, on_mainchain, confirmations, height, time,
    bits}`. Returns `{}` immediately if there are no valid hashes to query.

    `rpc` reaches Bitcoin Core over HTTP; when the node is on another host,
    forward its RPC port locally (`ssh -L 8332:localhost:8332 <host>`) and
    point `--rpc-url` at the forward.
    """
    uniq = sorted(set(h for h in hashes if is_hash(h)))
    if not uniq:
        return {}
    out: dict[str, dict] = {}
    for start in range(0, len(uniq), batch_size):
        chunk = uniq[start : start + batch_size]
        payload = [
            {
                "jsonrpc": "1.0",
                "id": i,
                "method": "getblockheader",
                "params": [block_hash, True],
            }
            for i, block_hash in enumerate(chunk)
        ]
        # BtcRpc.batch returns responses sorted by id, so responses[i] lines up
        # with chunk[i].
        responses = rpc.batch(payload)
        for i, block_hash in enumerate(chunk):
            result = responses[i].get("result")
            if not result:
                out[block_hash] = {"exists": False, "on_mainchain": False}
                continue
            confirmations = result.get("confirmations", -1)
            out[block_hash] = {
                "exists": True,
                "on_mainchain": confirmations >= 0,
                "confirmations": confirmations,
                "height": result.get("height"),
                "time": result.get("time"),
                "bits": result.get("bits"),
            }
    return out


def scan_upstream_stales(
    path: Path,
    stale_by_hash: dict[str, list[StaleObservation]],
    all_hash_chains: dict[str, set[str]],
    prevs_by_hash: dict[str, set[str]],
    excluded_keys: set[tuple[int, str]] | None = None,
) -> int:
    """Scan an upstream `stale-blocks.csv`-shaped file into the shared stale-index dicts.

    Each row's 80-byte `header` hex is parsed for prev_hash/time/bits, tagged
    as upstream evidence, and appended to `stale_by_hash[block_hash]`;
    `all_hash_chains` and `prevs_by_hash` are updated in the same pass. Rows
    with a malformed `hash` column are skipped. Mutates `stale_by_hash`,
    `all_hash_chains`, and `prevs_by_hash` in place; returns the number of
    rows added (0 if `path` does not exist).
    """
    if not path.exists():
        return 0
    excluded = excluded_keys
    if excluded is None:
        excluded = load_consensus_invalid_stale_keys()
    count = 0
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row_number, row in enumerate(reader, start=2):
            block_hash = normalize_hash(row.get("hash", ""))
            if not is_hash(block_hash):
                continue
            try:
                height = int(row.get("height", ""))
            except ValueError:
                continue
            if (height, block_hash) in excluded:
                continue
            parsed = parse_header_fields(row.get("header", ""))
            prev_hash = parsed.get("prev_hash", "")
            btc_time = parsed.get("time", "")
            bits = parsed.get("bits", "")
            obs = StaleObservation(
                chain="upstream",
                source_kind="upstream",
                source_path=rel(path),
                row_number=row_number,
                block_hash=block_hash,
                prev_hash=prev_hash,
                btc_height=row.get("height", "").strip(),
                child_height="",
                btc_time=btc_time,
                bits=bits,
            )
            stale_by_hash[block_hash].append(obs)
            all_hash_chains[block_hash].add(obs.chain)
            if prev_hash:
                prevs_by_hash[block_hash].add(prev_hash)
            count += 1
    return count


def stale_identity_key(
    row: dict[str, str], fieldnames: list[str], hash_col: str | None
) -> tuple[int, str] | None:
    """Return the authoritative ``(height, hash)`` key for a stale row."""
    block_hash = get_hash(row, hash_col)
    if not is_hash(block_hash):
        return None

    height_text = ""
    fields = set(fieldnames)
    for column in ("btc_height", "btc_stale_height", "height"):
        if column in fields and row.get(column, "").strip():
            height_text = row[column].strip()
            break
    if not height_text:
        parent_height = int_or_none(row.get("btc_parent_height", ""))
        if parent_height is not None:
            height_text = str(parent_height + 1)
    if not height_text and "btc_bip34_height" in fields:
        # Legacy inventories sometimes expose no height other than a decoded
        # BIP34 claim. This fallback can match an exclusion only when that claim
        # agrees with the overlay's independently established height; a mismatch
        # deliberately leaves the row unmatched rather than guessing ancestry.
        height_text = row.get("btc_bip34_height", "").strip()
    try:
        height = int(height_text)
    except (TypeError, ValueError):
        return None
    return height, block_hash


def accepted_stale_root(row: dict[str, str]) -> bool:
    """Return whether a stale-labelled row can anchor descendant recovery."""
    if row.get("classification", "stale").strip().lower() != "stale":
        return False
    status = row.get("validation_status", "").strip()
    return not status or status.startswith("VALID")


def stale_sources(
    observations: list[StaleObservation],
) -> tuple[str, str, str, str, str]:
    """Summarize a known-stale hash's observations for a CSV output row.

    Returns `(sources, chains, heights, times, bits)`, each a `|`-joined
    sorted string: `sources` is `chain:source_kind` labels, and the rest are
    the distinct non-empty values seen across `observations`.
    """
    source_labels = []
    chains = set()
    heights = set()
    times = set()
    bits = set()
    for obs in observations:
        source_labels.append(f"{obs.chain}:{obs.source_kind}")
        chains.add(obs.chain)
        if obs.btc_height:
            heights.add(obs.btc_height)
        if obs.btc_time:
            times.add(obs.btc_time)
        if obs.bits:
            bits.add(obs.bits.lower())
    return (
        join_sorted(source_labels),
        join_sorted(chains),
        join_sorted(heights),
        join_sorted(times),
        join_sorted(bits),
    )


def load_observations(
    *,
    data_dir: Path,
    chain_names: set[str],
    full_files: dict[str, Path],
    unknown_files: dict[str, Path],
    validated_files: dict[str, Path],
    epoch_bits: dict[int, str],
    excluded_keys: set[tuple[int, str]],
    consensus_invalid_keys: set[tuple[int, str]],
) -> dict[str, object]:
    """Load inventories and return the reconciliation indexes and anomalies."""
    direct_stale_only_keys = excluded_keys - consensus_invalid_keys
    stale_by_hash: dict[str, list[StaleObservation]] = defaultdict(list)
    all_hash_chains: dict[str, set[str]] = defaultdict(set)
    full_classifications_by_hash: dict[str, set[str]] = defaultdict(set)
    prevs_by_hash: dict[str, set[str]] = defaultdict(set)
    malformed_counts: Counter[tuple[str, str, str, str]] = Counter()
    nbits_mismatch_counts: Counter[tuple[str, str, str, str, str, str]] = Counter()
    nbits_mismatch_first_row: dict[tuple[str, str, str, str, str, str], int] = {}
    anomalies: list[dict[str, object]] = []

    unknown_rows: list[UnknownObservation] = []
    unknown_row_counts_by_hash: Counter[str] = Counter()
    unknown_chains_by_hash: dict[str, set[str]] = defaultdict(set)
    unknown_prev_chains: dict[str, set[str]] = defaultdict(set)
    unknown_prevs_by_hash: dict[str, set[str]] = defaultdict(set)
    unknown_example_by_hash: dict[str, UnknownObservation] = {}
    unknown_observations_by_hash: dict[str, list[UnknownObservation]] = defaultdict(
        list
    )

    upstream_count = scan_upstream_stales(
        data_dir / "stale-blocks" / "stale-blocks.csv",
        stale_by_hash,
        all_hash_chains,
        prevs_by_hash,
        excluded_keys,
    )

    inventory_rows: list[dict[str, object]] = []

    def check_bits(
        chain: str,
        source: str,
        row_number: int,
        classification: str,
        height: str,
        bits: str,
        explicit_expected: str,
    ) -> None:
        """Record an nBits/epoch mismatch for one row into `nbits_mismatch_counts`.

        Prefers `explicit_expected` (the source's own `expected_nbits`
        column) over computing the epoch's bits from `height`; only counts a
        mismatch when both the actual and expected bits are known and
        differ. The first `row_number` seen for each mismatch group is kept
        so the anomaly report can point at a concrete row.
        """
        actual = (bits or "").strip().lower()
        expected = (explicit_expected or "").strip().lower()
        height_source = "expected_nbits"
        if not expected and height and epoch_bits:
            expected = expected_bits_for_height(height, epoch_bits)
            height_source = "btc_height_epoch"
        if expected and actual and actual != expected:
            key = (chain, source, classification, height_source, expected, actual)
            nbits_mismatch_counts[key] += 1
            nbits_mismatch_first_row.setdefault(key, row_number)

    def scan_inventory_file(inv_path, chain, notes):
        """Scan one classifier inventory file (stale-only or unknown) into the
        shared observation indices, dispatching each row by its ``classification``.

        Reading both the stale and unknown files keeps split chains (stale in one
        file, unknown in the other) and never-split chains (both commingled in the
        stale file, no unknown file) correct without changing the per-row dispatch.
        Returns per-file ``(total, stale, unknown, missing_hash, missing_prev,
        recovered_prev, hash_col, prev_col, header_col)``.
        """
        with inv_path.open(newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            hash_col = first_present(fieldnames, HASH_COLUMNS)
            prev_col = first_present(fieldnames, PREV_COLUMNS)
            bits_col = first_present(fieldnames, BITS_COLUMNS)
            header_col = first_present(fieldnames, HEADER_HEX_COLUMNS)
            height_col = first_present(fieldnames, BTC_HEIGHT_COLUMNS)
            if not hash_col:
                notes.append("no recognized header-hash column")
            if not prev_col and header_col:
                notes.append("prev hash recovered from header hex where needed")
            elif not prev_col:
                notes.append("no recognized prev-hash column")

            total_rows = stale_rows = unknown_count = missing_hash = missing_prev = 0
            recovered_prev_rows = 0

            for row_number, row in enumerate(reader, start=2):
                total_rows += 1
                classification = row.get("classification", "").strip().lower()
                block_hash = get_hash(row, hash_col)
                prev_hash, recovered_prev = get_prev(row, prev_col, header_col)
                bits = row.get(bits_col, "").strip().lower() if bits_col else ""
                btc_height = row.get(height_col, "").strip() if height_col else ""
                btc_time = get_value(row, fieldnames, ("btc_time",))
                child_height = get_child_height(row, fieldnames)

                exclusion_key = stale_identity_key(row, fieldnames, hash_col)
                if classification == "stale":
                    if exclusion_key in consensus_invalid_keys:
                        continue
                    if exclusion_key in direct_stale_only_keys:
                        # This is valid stale-chain evidence, but not a direct
                        # stale root. Feed it through the ancestry walk as an
                        # unknown observation so it can be published only as a
                        # stale descendant.
                        classification = "unknown"

                if recovered_prev:
                    recovered_prev_rows += 1

                if classification == "stale":
                    stale_rows += 1
                elif classification in (
                    "orphan",
                    "unknown",
                ):  # legacy artifacts wrote "orphan"
                    unknown_count += 1

                if classification in {"stale", "orphan", "unknown"}:
                    if not is_hash(block_hash):
                        missing_hash += 1
                        malformed_counts[
                            (chain, rel(inv_path), classification, "header_hash")
                        ] += 1
                    if not is_hash(prev_hash):
                        missing_prev += 1
                        malformed_counts[
                            (chain, rel(inv_path), classification, "prev_hash")
                        ] += 1
                    check_bits(
                        chain,
                        rel(inv_path),
                        row_number,
                        classification,
                        btc_height,
                        bits,
                        row.get("expected_nbits", ""),
                    )

                if is_hash(block_hash):
                    all_hash_chains[block_hash].add(chain)
                    if classification:
                        full_classifications_by_hash[block_hash].add(
                            f"{chain}:{classification}"
                        )
                    if is_hash(prev_hash):
                        prevs_by_hash[block_hash].add(prev_hash)

                if (
                    classification == "stale"
                    and accepted_stale_root(row)
                    and is_hash(block_hash)
                ):
                    stale_by_hash[block_hash].append(
                        StaleObservation(
                            chain=chain,
                            source_kind="full_inventory",
                            source_path=rel(inv_path),
                            row_number=row_number,
                            block_hash=block_hash,
                            prev_hash=prev_hash,
                            btc_height=btc_height,
                            child_height=child_height,
                            btc_time=btc_time,
                            bits=bits,
                        )
                    )
                elif (
                    classification in ("orphan", "unknown")
                    and is_hash(block_hash)
                    and is_hash(prev_hash)
                ):  # legacy artifacts wrote "orphan"
                    obs = UnknownObservation(
                        chain=chain,
                        source_path=rel(inv_path),
                        row_number=row_number,
                        block_hash=block_hash,
                        prev_hash=prev_hash,
                        btc_height=btc_height,
                        child_height=child_height,
                        btc_time=btc_time,
                        bits=bits,
                        scriptsig_hex=row.get("coinbase_scriptsig_hex", "").strip(),
                        outputs=row.get("coinbase_outputs", "").strip(),
                        header_hex=row.get(header_col, "").strip()
                        if header_col
                        else "",
                    )
                    unknown_rows.append(obs)
                    unknown_row_counts_by_hash[block_hash] += 1
                    unknown_chains_by_hash[block_hash].add(chain)
                    unknown_prev_chains[prev_hash].add(chain)
                    unknown_prevs_by_hash[block_hash].add(prev_hash)
                    unknown_example_by_hash.setdefault(block_hash, obs)
                    unknown_observations_by_hash[block_hash].append(obs)

        return (
            total_rows,
            stale_rows,
            unknown_count,
            missing_hash,
            missing_prev,
            recovered_prev_rows,
            hash_col,
            prev_col,
            header_col,
        )

    for chain in sorted(chain_names):
        full_path = full_files.get(chain)
        unknown_path = unknown_files.get(chain)
        validated_path = validated_files.get(chain)
        notes: list[str] = []
        inventory_paths = [pth for pth in (full_path, unknown_path) if pth is not None]

        if not inventory_paths:
            if validated_path is not None:
                notes.append("excluded from unknown reconciliation: no full inventory")
            else:
                notes.append(
                    "excluded from unknown reconciliation: no data file discovered"
                )
            inventory_rows.append(
                {
                    "chain": chain,
                    "full_inventory_path": "",
                    "validated_stale_path": rel(validated_path)
                    if validated_path
                    else "",
                    "header_hash_column_used": "",
                    "prev_hash_column_used": "",
                    "total_rows": 0,
                    "stale_rows": 0,
                    "unknown_rows": 0,
                    "rows_missing_header_hash": 0,
                    "rows_missing_prev_hash": 0,
                    "notes": "; ".join(notes),
                }
            )
            continue

        total_rows = stale_rows = unknown_count = missing_hash = missing_prev = 0
        recovered_prev_rows = 0
        hash_col = prev_col = header_col = None
        for inv_path in inventory_paths:
            (t_, s_, u_, mh_, mp_, rp_, hc_, pc_, hdc_) = scan_inventory_file(
                inv_path, chain, notes
            )
            total_rows += t_
            stale_rows += s_
            unknown_count += u_
            missing_hash += mh_
            missing_prev += mp_
            recovered_prev_rows += rp_
            hash_col = hash_col or hc_
            prev_col = prev_col or pc_
            header_col = header_col or hdc_

        if recovered_prev_rows:
            notes.append(f"{recovered_prev_rows} prev hashes recovered from header hex")
        notes = list(
            dict.fromkeys(notes)
        )  # dedup: stale + unknown files share one schema
        inventory_rows.append(
            {
                "chain": chain,
                "full_inventory_path": rel(full_path) if full_path else "",
                "validated_stale_path": rel(validated_path) if validated_path else "",
                "header_hash_column_used": hash_col,
                "prev_hash_column_used": prev_col
                or ("derived_from_header_hex" if header_col else ""),
                "total_rows": total_rows,
                "stale_rows": stale_rows,
                "unknown_rows": unknown_count,
                "rows_missing_header_hash": missing_hash,
                "rows_missing_prev_hash": missing_prev,
                "notes": "; ".join(notes),
            }
        )

    for chain, validated_path in sorted(validated_files.items()):
        with validated_path.open(newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            hash_col = first_present(fieldnames, HASH_COLUMNS)
            prev_col = first_present(fieldnames, PREV_COLUMNS)
            bits_col = first_present(fieldnames, BITS_COLUMNS)
            header_col = first_present(fieldnames, HEADER_HEX_COLUMNS)
            height_col = first_present(fieldnames, BTC_HEIGHT_COLUMNS)
            for row_number, row in enumerate(reader, start=2):
                block_hash = get_hash(row, hash_col)
                if not is_hash(block_hash):
                    continue
                prev_hash, _recovered_prev = get_prev(row, prev_col, header_col)
                bits = row.get(bits_col, "").strip().lower() if bits_col else ""
                btc_height = row.get(height_col, "").strip() if height_col else ""
                btc_time = get_value(row, fieldnames, ("btc_time",))
                child_height = get_child_height(row, fieldnames)
                if not accepted_stale_root(row):
                    continue
                if stale_identity_key(row, fieldnames, hash_col) in excluded_keys:
                    continue
                stale_by_hash[block_hash].append(
                    StaleObservation(
                        chain=chain,
                        source_kind="validated_stales",
                        source_path=rel(validated_path),
                        row_number=row_number,
                        block_hash=block_hash,
                        prev_hash=prev_hash,
                        btc_height=btc_height,
                        child_height=child_height,
                        btc_time=btc_time,
                        bits=bits,
                    )
                )
                all_hash_chains[block_hash].add(chain)
                full_classifications_by_hash[block_hash].add(f"{chain}:stale")
                if is_hash(prev_hash):
                    prevs_by_hash[block_hash].add(prev_hash)
                check_bits(
                    chain,
                    rel(validated_path),
                    row_number,
                    "stale",
                    btc_height,
                    bits,
                    row.get("expected_nbits", ""),
                )

    known_stale_hashes = set(stale_by_hash)
    auxpow_stale_hashes = {
        h
        for h, observations in stale_by_hash.items()
        if any(
            obs.source_kind in {"full_inventory", "validated_stales"}
            for obs in observations
        )
    }

    conflicting_prev_hashes = {
        h
        for h, prevs in prevs_by_hash.items()
        if len({p for p in prevs if is_hash(p)}) > 1
    }
    conflicting_unknown_prevs = {
        h for h, prevs in unknown_prevs_by_hash.items() if len(prevs) > 1
    }

    for h in sorted(conflicting_prev_hashes):
        anomalies.append(
            {
                "issue_type": "duplicate_hash_conflicting_prev",
                "severity": "error",
                "count": 1,
                "chain": join_sorted(all_hash_chains.get(h, set())),
                "source_path": "",
                "row_number": "",
                "btc_header_hash": h,
                "btc_prev_hash": join_sorted(prevs_by_hash[h]),
                "details": "same BTC header hash appears with multiple prev_hash values",
            }
        )

    for h, labels in sorted(full_classifications_by_hash.items()):
        classes = {label.split(":", 1)[1] for label in labels}
        if len(classes) > 1:
            anomalies.append(
                {
                    "issue_type": "hash_classified_differently",
                    "severity": "warning",
                    "count": 1,
                    "chain": join_sorted(label.split(":", 1)[0] for label in labels),
                    "source_path": "",
                    "row_number": "",
                    "btc_header_hash": h,
                    "btc_prev_hash": "",
                    "details": join_sorted(labels),
                }
            )

    for obs in unknown_rows:
        if obs.block_hash in known_stale_hashes:
            sources, chains, _heights, _times, _bits = stale_sources(
                stale_by_hash[obs.block_hash]
            )
            anomalies.append(
                {
                    "issue_type": "unknown_hash_also_known_stale",
                    "severity": "warning",
                    "count": 1,
                    "chain": obs.chain,
                    "source_path": obs.source_path,
                    "row_number": obs.row_number,
                    "btc_header_hash": obs.block_hash,
                    "btc_prev_hash": obs.prev_hash,
                    "details": f"known_stale_sources={sources}; known_stale_chains={chains}",
                }
            )

    for (chain, source_path, classification, field), count in sorted(
        malformed_counts.items()
    ):
        anomalies.append(
            {
                "issue_type": "missing_or_malformed_hash",
                "severity": "error",
                "count": count,
                "chain": chain,
                "source_path": source_path,
                "row_number": "",
                "btc_header_hash": "",
                "btc_prev_hash": "",
                "details": f"classification={classification}; field={field}",
            }
        )

    nbits_groups: dict[tuple[str, str, str, str], dict[str, object]] = defaultdict(
        lambda: {"count": 0, "samples": []}
    )
    for key in sorted(nbits_mismatch_counts):
        chain, source_path, classification, height_source, expected, actual = key
        count = nbits_mismatch_counts[key]
        first_row = nbits_mismatch_first_row[key]
        group = nbits_groups[(chain, source_path, classification, height_source)]
        group["count"] = int(group["count"]) + count
        first = group.get("first_row")
        if first is None or first_row < first:
            group["first_row"] = first_row
        samples = group["samples"]
        if len(samples) < 20:
            samples.append(f"{expected}->{actual} ({count}, first at row {first_row})")

    for (chain, source_path, classification, height_source), group in sorted(
        nbits_groups.items()
    ):
        anomalies.append(
            {
                "issue_type": "nbits_inconsistent_with_btc_epoch",
                "severity": "warning",
                "count": group["count"],
                "chain": chain,
                "source_path": source_path,
                "row_number": group.get("first_row", ""),
                "btc_header_hash": "",
                "btc_prev_hash": "",
                "details": (
                    f"classification={classification}; check={height_source}; "
                    f"sample_expected_actual_counts={'; '.join(group['samples'])}"
                ),
            }
        )

    unknown_prev_by_hash = {
        h: next(iter(prevs))
        for h, prevs in unknown_prevs_by_hash.items()
        if len(prevs) == 1 and h not in conflicting_unknown_prevs
    }

    return {
        "stale_by_hash": stale_by_hash,
        "all_hash_chains": all_hash_chains,
        "full_classifications_by_hash": full_classifications_by_hash,
        "prevs_by_hash": prevs_by_hash,
        "anomalies": anomalies,
        "unknown_rows": unknown_rows,
        "unknown_row_counts_by_hash": unknown_row_counts_by_hash,
        "unknown_chains_by_hash": unknown_chains_by_hash,
        "unknown_prev_chains": unknown_prev_chains,
        "unknown_prevs_by_hash": unknown_prevs_by_hash,
        "unknown_example_by_hash": unknown_example_by_hash,
        "unknown_observations_by_hash": unknown_observations_by_hash,
        "inventory_rows": inventory_rows,
        "upstream_count": upstream_count,
        "known_stale_hashes": known_stale_hashes,
        "auxpow_stale_hashes": auxpow_stale_hashes,
        "unknown_prev_by_hash": unknown_prev_by_hash,
    }
