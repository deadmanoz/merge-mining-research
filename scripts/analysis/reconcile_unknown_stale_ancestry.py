#!/usr/bin/env python3
"""Reconcile AuxPoW unknown BTC parents against known BTC stale headers.

The script is read-only over raw inputs in data/. It discovers available full
classifier inventories, builds the canonical known-stale hash set from
upstream plus local AuxPoW stale files, walks unknown prev-hash ancestry
through the union of unknown inventories, writes reproducible CSV/JSON evidence
under results/analysis/stale-ancestry/, and writes the derived canonical promotion file at
data/stale_descendants.csv. A candidate whose own authenticated bytes prove a
consensus rule broken is not a descendant at all; it goes to the sidecar's
_error_blocks peer with the derived rules_violated instead.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from stale_blocks_analysis.btc_classify import derive_split_paths  # noqa: E402
from stale_blocks_analysis.btc_rpc import BtcRpc, get_btc_auth  # noqa: E402
from stale_blocks_analysis.btc_stale_validation import (  # noqa: E402
    BIP34_HEIGHT_MISSING_PREFIX,
    VERSION_RULES,
    bip34_height_error,
    block_version_error,
    consensus_violations,
)
from stale_blocks_analysis.config import (  # noqa: E402
    BIP34_HEIGHT,
    BIP34_VERSION_2_HEIGHT,
    BITCOIN_EPOCH_REFERENCE_DIR,
)

# These CSV/hash helpers have one canonical home in the package
# (full_evidence); import rather than re-implement. The namecoin header-hex
# loader lives there too now, shared with the evidence-export hydration path
# (full_evidence must not import this script, so the direction is reconcile ->
# full_evidence, the same as the generic helpers). Sibling scripts that reach
# any of these as reconcile.<name> keep working; imported names stay module
# attributes.
from stale_blocks_analysis.full_evidence import (  # noqa: E402
    first_present,
    get_value,
    int_or_none,
    is_hash,
    load_namecoin_header_hexes,
    normalize_hash,
)
from stale_blocks_analysis.error_blocks import (  # noqa: E402
    load_consensus_invalid_stale_keys,
    load_stale_exclusion_keys,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DOCS_CHAINS_DIR = PROJECT_ROOT / "docs" / "chains"
RESULTS_DIR = PROJECT_ROOT / "results" / "analysis" / "stale-ancestry"
CACHE_DIR = PROJECT_ROOT / "cache"
PROMOTED_CSV = DATA_DIR / "stale_descendants.csv"


def error_blocks_csv_for(promoted_csv: Path) -> Path:
    """Return the ``_error_blocks`` sibling of a promoted-descendant path.

    Uses the shared bucket-split derivation so the descendant sidecar's
    consensus-invalid peer is named the same way as every classifier's.
    """
    return Path(derive_split_paths(str(promoted_csv))[2])


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

OUTPUT_INVENTORY = "unknown-stale-reconciliation-inventory.csv"
OUTPUT_DIRECT = "unknown-stale-direct-matches.csv"
OUTPUT_PATHS = "unknown-stale-descendant-paths.csv"
OUTPUT_ROOTS = "unknown-stale-root-summary.csv"
OUTPUT_ANOMALIES = "unknown-stale-anomalies.csv"
OUTPUT_SUMMARY = "unknown-stale-reconciliation-summary.json"

# Column order of the promoted descendant sidecar. The consensus-invalid peer
# reuses it and appends the pipe-joined full rule set, the column name and
# format ``build_error_blocks.py`` honors verbatim on import.
PROMOTED_FIELDS = [
    "classification",
    "promotion_subclass",
    "validation_status",
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "expected_nbits",
    "pow_valid",
    "header_hash_match",
    "bip34_height_status",
    "observed_btc_heights",
    "observed_btc_times",
    "observed_btc_bits",
    "root_stale_hash",
    "root_stale_height",
    "root_stale_sources",
    "root_stale_chains",
    "root_stale_btc_times",
    "root_stale_bits",
    "stale_fork_depth",
    "path_hashes",
    "path_chain_sets",
    "observed_chains",
    "unknown_rows",
    "source_rows",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "notes",
]
PROMOTED_ERROR_BLOCK_FIELDS = [*PROMOTED_FIELDS, "rules_violated"]


@dataclass(frozen=True, slots=True)
class PublicationBaseline:
    """Committed descendant rows and the private inventories they depend on."""

    statuses_by_hash: dict[str, str]
    observed_chains_by_hash: dict[str, frozenset[str]]
    unknown_rows_by_hash: dict[str, int]
    source_observation_counts_by_hash: dict[str, Counter[str]]
    notes_by_hash: dict[str, str]
    required_inventory_chains: frozenset[str]


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


@dataclass(frozen=True, slots=True)
class WalkResult:
    """Outcome of walking an unknown header's prev-hash chain to its terminal node.

    `terminal_kind` is the raw walk outcome (`known_stale`, `mainchain`,
    `cross_seen_root`, `cycle_or_bad_data`, or `dangling_unknown`);
    `terminal_hash` is the hash the walk stopped at; `depth` is the number of
    prev-hash hops from the walk's start to that terminal. `category` derives
    the reporting bucket from `terminal_kind` (see its docstring).
    """

    terminal_kind: str
    terminal_hash: str
    depth: int

    @property
    def category(self) -> str:
        """Map `terminal_kind` to the reporting category used in output rows.

        `known_stale` becomes `direct_stale_child` at depth 1 (the unknown
        row's own prev-hash is a known stale) or `stale_descendant` at
        greater depth; `mainchain` becomes `mainchain_descendant`;
        `cross_seen_root` becomes `unknown_root_seen_elsewhere`;
        `cycle_or_bad_data` passes through unchanged; anything else is
        `dangling_unknown`.
        """
        if self.terminal_kind == "known_stale":
            return "direct_stale_child" if self.depth == 1 else "stale_descendant"
        if self.terminal_kind == "mainchain":
            return "mainchain_descendant"
        if self.terminal_kind == "cross_seen_root":
            return "unknown_root_seen_elsewhere"
        if self.terminal_kind == "cycle_or_bad_data":
            return "cycle_or_bad_data"
        return "dangling_unknown"


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


DESCENDANT_UNJUDGEABLE_FAILURES = frozenset(
    {
        "missing_header_hex",
        "header_hash_mismatch",
        "prev_hash_path_mismatch",
        "pow_target_mismatch",
    }
)


def descendant_consensus_rules(
    header_hex: str,
    scriptsig_hex: str,
    inferred_height: int | None,
    validation_failures: list[str],
    *,
    header_bits: str,
    expected_nbits: str,
) -> list[str]:
    """Return the consensus rules a descendant candidate's bytes prove broken.

    A candidate with a non-empty result is not a rejected descendant, it is an
    error block: a Bitcoin block carrying full proof of work that breaks a
    rule. It uses the same shared derivation the classifier uses, so that a
    rejection means the same thing wherever it is produced.

    Two premises have to hold before any rule is derived, and the difficulty
    one is required as POSITIVE evidence rather than as a missing failure.

    First, every one of ``DESCENDANT_UNJUDGEABLE_FAILURES`` must be absent:

    - ``missing_header_hex`` / ``header_hash_mismatch``: the supplied bytes are
      not authenticated as this block's. Every rule below is read straight out
      of those bytes, so publishing a violation under the claimed hash would
      attribute another block's (or nobody's) header to it. Corroborating the
      published hash against the serialized header is the precondition for
      every downstream verdict in this repo, not an extra.
    - ``prev_hash_path_mismatch`` / ``pow_target_mismatch``: the height is not
      sound enough to judge against, and the digest is not known to meet the
      target its own bits encode. The height is the root's confirmed height
      plus the fork depth, walked along links this run already verified.
      Without them a coinbase-height mismatch would be equally consistent with
      a wrong height.

    Second, ``expected_nbits`` and ``header_bits`` must both be present and
    equal. The absence of an ``nbits_epoch_mismatch`` failure does NOT prove
    that: the caller derives ``expected_nbits`` from the committed epoch
    reference, which returns ``""`` for a height the table does not reach, and
    the comparison is then skipped rather than failed. Reading that silence as
    a match would let a foreign or easy-target header be published as an error
    block with its canonical difficulty never checked, so the match is required
    outright.

    Requiring it also settles the canonical proof of work without a second
    digest check, which is why none is made here. ``pow_target_mismatch`` being
    absent proves the digest meets the target ``header_bits`` encodes, and
    ``header_bits`` equalling ``expected_nbits`` makes that target the
    canonical one for this height. The classification-time twin
    (``btc_classify._meets_canonical_btc_difficulty``) does need its own digest
    check because it admits the unapplied-retarget rule, whose rows carry the
    PREVIOUS epoch's easier bits by definition; no such exception exists here.

    ``nbits_by_epoch`` is deliberately not supplied for the same reason: the
    bits are proven equal to the canonical value, so the unapplied-retarget
    rule cannot apply.
    """
    if inferred_height is None:
        return []
    if DESCENDANT_UNJUDGEABLE_FAILURES & set(validation_failures):
        return []
    canonical_bits = expected_nbits.strip().lower()
    observed_bits = header_bits.strip().lower()
    if not canonical_bits or not observed_bits or observed_bits != canonical_bits:
        return []
    rules = consensus_violations(
        {"btc_header_hex": header_hex, "coinbase_scriptsig_hex": scriptsig_hex},
        inferred_height,
    )
    # A version rule rests on a fixed-height cutover standing in for Core's
    # rolling IsSuperMajority vote, and Core counts that vote over the block's
    # OWN ancestors. For a direct stale those ancestors are the main chain, so
    # its window is the main chain's window and the cutover is exact. A
    # descendant's is not: its ancestry leaves the main chain at the fork root,
    # so a fork spanning an activation boundary can carry a different version
    # mix and a different verdict. Reconstructing the branch's own threshold
    # state is out of scope (GitHub issue #21), so a version rule cannot
    # promote a descendant to a block proven consensus-invalid. Rules that are
    # settled by the bytes alone are unaffected.
    return [rule for rule in rules if rule not in VERSION_RULES]


def bip34_height_absent(bip34_error: str) -> bool:
    """Report whether a BIP34 rejection is an absent height, not a wrong one.

    Two of the gate's verdicts mean the height is not there: no coinbase
    scriptSig to read at all, and a present, well-formed scriptSig carrying no
    decodable height push (``BIP34_HEIGHT_MISSING_PREFIX``, which the shared
    ``consensus_violations`` tokens as ``bip34_coinbase_height_missing``).
    Reporting the second as a mismatch would put ``rules_violated`` and
    ``validation_status`` in contradiction over the same committed bytes.
    """
    return "missing coinbase scriptSig" in bip34_error or bip34_error.startswith(
        BIP34_HEIGHT_MISSING_PREFIX
    )


def descendant_bip34_verdict(
    header_hex: str, scriptsig_hex: str, expected_height: int
) -> tuple[str, str | None]:
    """Return the descendant report status and validation-failure token.

    The shared consensus validator checks the raw header version and exact
    coinbase prefix. Source-reported height columns remain provenance only.
    """
    if expected_height < BIP34_VERSION_2_HEIGHT:
        return "not_applicable", None

    row = {
        "btc_header_hex": header_hex,
        "coinbase_scriptsig_hex": scriptsig_hex,
    }
    version_error = block_version_error(row, expected_height)
    bip34_error = bip34_height_error(row, expected_height)
    if bip34_error is None:
        parsed = parse_header_fields(header_hex)
        version = int_or_none(parsed.get("version", ""))
        if expected_height < BIP34_HEIGHT and version is not None and version < 2:
            return "not_applicable", None
        status = "match"
    elif bip34_error.startswith("UNKNOWN:"):
        status = "unknown"
    elif bip34_height_absent(bip34_error):
        status = "missing"
    else:
        status = "mismatch"

    if version_error is not None:
        if version_error.startswith("UNKNOWN:"):
            return status, "block_version_unknown"
        return status, "btc_block_version_below_minimum"
    if bip34_error is None:
        return status, None
    if bip34_error.startswith("UNKNOWN:"):
        return "unknown", "bip34_validation_unknown"
    if bip34_height_absent(bip34_error):
        return "missing", "bip34_height_missing"
    if "version below 2" in bip34_error:
        return "mismatch", "bip34_block_version"
    return "mismatch", "bip34_height_mismatch"


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


def build_parser() -> argparse.ArgumentParser:
    """Build the reconciliation CLI parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    parser.add_argument(
        "--epoch-reference-dir",
        type=Path,
        default=BITCOIN_EPOCH_REFERENCE_DIR,
        help="Committed public Bitcoin epoch nBits reference directory.",
    )
    parser.add_argument("--promoted-csv", type=Path, default=PROMOTED_CSV)
    parser.add_argument(
        "--error-blocks-csv",
        type=Path,
        default=None,
        help=(
            "Consensus-invalid descendant candidates; defaults to the "
            "_error_blocks sibling of --promoted-csv."
        ),
    )
    parser.add_argument("--max-depth", type=int, default=10_000)
    parser.add_argument(
        "--check-mainchain",
        action="store_true",
        help=(
            "Query Bitcoin Core for dangling terminal roots and reclassify "
            "mainchain hits."
        ),
    )
    parser.add_argument(
        "--rpc-url",
        default=os.environ.get("BTC_RPC_URL", "http://127.0.0.1:8332"),
        help=(
            "Bitcoin Core JSON-RPC URL; forward a remote node with "
            "ssh -L 8332:localhost:8332 <host>."
        ),
    )
    parser.add_argument("--rpc-user", default=None)
    parser.add_argument("--rpc-pass", default=None)
    parser.add_argument("--rpc-batch-size", type=int, default=500)
    parser.add_argument(
        "--max-mainchain-rpc",
        type=int,
        default=0,
        help=(
            "Maximum dangling terminal roots to query when --check-mainchain "
            "is set; 0 means all."
        ),
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help=(
            "Permit incomplete diagnostic reconciliation. Requires explicit "
            "non-publication --results-dir and --promoted-csv paths."
        ),
    )
    return parser


def source_observation_counts(
    source_rows: object, observed_chains: frozenset[str] | set[str]
) -> Counter[str]:
    """Count pipe-delimited source observations by their chain prefix.

    Paths and line numbers are deliberately excluded from the identity floor:
    complete inventories may move or be regenerated with different row
    numbers. Every nonempty token must still identify a chain represented in
    ``observed_chains``.
    """
    tokens = tuple(
        token.strip() for token in str(source_rows or "").split("|") if token.strip()
    )
    if not tokens:
        raise ValueError("source_rows has no observations")
    counts: Counter[str] = Counter()
    for token in tokens:
        chain = token.split(":", 1)[0].strip()
        if not chain:
            raise ValueError(f"source_rows token has an empty chain prefix: {token!r}")
        if chain not in observed_chains:
            raise ValueError(
                f"source_rows chain prefix {chain!r} is not present in observed_chains"
            )
        counts[chain] += 1
    return counts


def load_publication_baseline(path: Path = PROMOTED_CSV) -> PublicationBaseline:
    """Load the committed descendant floor used to reject degraded rebuilds."""
    if not path.is_file():
        raise ValueError(f"publication descendant baseline is missing: {path}")
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required_fields = {
            "classification",
            "validation_status",
            "btc_header_hash",
            "observed_chains",
            "unknown_rows",
            "source_rows",
        }
        missing_fields = required_fields - set(reader.fieldnames or [])
        if missing_fields:
            raise ValueError(
                f"publication descendant baseline lacks fields: {path}: "
                + ", ".join(sorted(missing_fields))
            )
        statuses: dict[str, str] = {}
        observed_chains_by_hash: dict[str, frozenset[str]] = {}
        unknown_rows_by_hash: dict[str, int] = {}
        source_observation_counts_by_hash: dict[str, Counter[str]] = {}
        notes_by_hash: dict[str, str] = {}
        required_chains: set[str] = set()
        for row_number, row in enumerate(reader, start=2):
            block_hash = normalize_hash(row.get("btc_header_hash"))
            status = (row.get("validation_status") or "").strip()
            classification = (row.get("classification") or "").strip()
            if not is_hash(block_hash):
                raise ValueError(
                    f"{path}:{row_number}: malformed publication descendant hash"
                )
            if classification != "stale_descendant" or not status:
                raise ValueError(
                    f"{path}:{row_number}: malformed publication descendant verdict"
                )
            if block_hash in statuses:
                raise ValueError(
                    f"{path}:{row_number}: duplicate publication descendant hash "
                    f"{block_hash}"
                )
            observed_chains = tuple(
                token.strip()
                for token in (row.get("observed_chains") or "").split("|")
                if token.strip()
            )
            try:
                unknown_rows = int((row.get("unknown_rows") or "").strip())
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{row_number}: invalid publication unknown_rows"
                ) from exc
            if unknown_rows < 1:
                raise ValueError(
                    f"{path}:{row_number}: publication unknown_rows must be positive"
                )
            if not observed_chains:
                raise ValueError(
                    f"{path}:{row_number}: publication descendant has no observed chains"
                )
            observed_chain_set = frozenset(observed_chains)
            try:
                source_counts = source_observation_counts(
                    row.get("source_rows"), observed_chain_set
                )
            except ValueError as exc:
                raise ValueError(f"{path}:{row_number}: {exc}") from exc
            if source_counts.total() != unknown_rows:
                raise ValueError(
                    f"{path}:{row_number}: publication source_rows count does not "
                    "match unknown_rows"
                )
            statuses[block_hash] = status
            observed_chains_by_hash[block_hash] = observed_chain_set
            unknown_rows_by_hash[block_hash] = unknown_rows
            source_observation_counts_by_hash[block_hash] = source_counts
            notes_by_hash[block_hash] = (row.get("notes") or "").strip()
            required_chains.update(observed_chains)
    if not statuses:
        raise ValueError(f"publication descendant baseline is empty: {path}")
    if not required_chains:
        raise ValueError(
            f"publication descendant baseline has no observed chains: {path}"
        )
    return PublicationBaseline(
        statuses_by_hash=statuses,
        observed_chains_by_hash=observed_chains_by_hash,
        unknown_rows_by_hash=unknown_rows_by_hash,
        source_observation_counts_by_hash=source_observation_counts_by_hash,
        notes_by_hash=notes_by_hash,
        required_inventory_chains=frozenset(required_chains),
    )


def descendant_notes(
    block_hash: str,
    validation_failures: list[str],
    baseline: PublicationBaseline | None,
) -> str:
    """Return current failures or immutable audit notes from the prior row."""
    if validation_failures:
        return ";".join(validation_failures)
    if baseline is not None:
        baseline_notes = baseline.notes_by_hash.get(block_hash, "")
        return ";".join(
            note
            for note in baseline_notes.split(";")
            if note == "reclassified_from_direct_stale"
            or note.startswith("branch_mtp=")
        )
    return ""


def validate_output_mode(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> None:
    """Resolve the derived output path, then guard the publication defaults.

    ``--error-blocks-csv`` defaults to the sibling of whatever
    ``--promoted-csv`` names, so a disposable promoted path already yields a
    disposable error-block path; only an explicit committed one is refused.

    Every artifact this run generates must also resolve to a distinct file.
    They are written in sequence, so an aliased pair fails silently and
    destructively: the later write replaces one the run has just finished.
    Checking the error-block path against ``--promoted-csv`` alone would leave
    the six ``--results-dir`` artifacts open, and pointing it at, say,
    ``unknown-stale-root-summary.csv`` would have the error-block rows written
    and then immediately replaced by the root summary.
    """
    if args.error_blocks_csv is None:
        args.error_blocks_csv = error_blocks_csv_for(args.promoted_csv)
    labelled = {
        "reconciliation-inventory output": args.results_dir / OUTPUT_INVENTORY,
        "direct-matches output": args.results_dir / OUTPUT_DIRECT,
        "descendant-paths output": args.results_dir / OUTPUT_PATHS,
        "root-summary output": args.results_dir / OUTPUT_ROOTS,
        "anomalies output": args.results_dir / OUTPUT_ANOMALIES,
        "reconciliation-summary output": args.results_dir / OUTPUT_SUMMARY,
        "--promoted-csv": args.promoted_csv,
        "--error-blocks-csv": args.error_blocks_csv,
    }
    seen: dict[Path, str] = {}
    for label, path in labelled.items():
        resolved = path.resolve()
        previous = seen.get(resolved)
        if previous is not None:
            parser.error(f"{label} aliases {previous}: {resolved}")
        seen[resolved] = label
    if not args.allow_partial:
        return
    default_outputs: list[str] = []
    if args.results_dir.resolve() == RESULTS_DIR.resolve():
        default_outputs.append("--results-dir")
    if args.promoted_csv.resolve() == PROMOTED_CSV.resolve():
        default_outputs.append("--promoted-csv")
    if args.error_blocks_csv.resolve() == error_blocks_csv_for(PROMOTED_CSV).resolve():
        default_outputs.append("--error-blocks-csv")
    if default_outputs:
        parser.error(
            "--allow-partial requires explicit disposable output paths; refusing "
            "the publication defaults for " + ", ".join(default_outputs)
        )


def validate_publication_discovery(
    baseline: PublicationBaseline,
    full_files: dict[str, Path],
    unknown_files: dict[str, Path],
    parser: argparse.ArgumentParser,
) -> None:
    """Require source inventories for every chain represented in the baseline."""
    discovered = set(full_files) | set(unknown_files)
    missing = sorted(baseline.required_inventory_chains - discovered)
    if missing:
        parser.error(
            "refusing an incomplete publication reconciliation; missing full/unknown "
            "inventories for baseline chains: "
            + ", ".join(missing)
            + ". Use --allow-partial only with disposable output paths."
        )


def validate_publication_rows(
    rows: Iterable[dict[str, object]],
    baseline: PublicationBaseline,
    parser: argparse.ArgumentParser,
) -> None:
    """Reject a computed descendant set that regresses the committed baseline.

    ``rows`` is every computed row, including the ones routed to the
    error-block peer: moving artifact is not losing evidence. Proving a
    committed VALID descendant consensus-invalid is a separate regression,
    because that row does leave the published sidecar.
    """
    statuses: dict[str, str] = {}
    computed_rows_by_hash: dict[str, dict[str, object]] = {}
    duplicate_hashes: set[str] = set()
    for row in rows:
        block_hash = normalize_hash(str(row.get("btc_header_hash", "")))
        if block_hash in statuses:
            duplicate_hashes.add(block_hash)
        statuses[block_hash] = str(row.get("validation_status", ""))
        computed_rows_by_hash[block_hash] = row

    missing = sorted(set(baseline.statuses_by_hash) - set(statuses))
    validity_regressions = sorted(
        block_hash
        for block_hash, expected_status in baseline.statuses_by_hash.items()
        if expected_status == "VALID_STALE_DESCENDANT"
        and statuses.get(block_hash) != "VALID_STALE_DESCENDANT"
    )
    consensus_invalid_regressions = sorted(
        block_hash
        for block_hash, expected_status in baseline.statuses_by_hash.items()
        if expected_status == "VALID_STALE_DESCENDANT"
        and str(computed_rows_by_hash.get(block_hash, {}).get("classification", ""))
        == "error_block"
    )
    problems: list[str] = []
    if duplicate_hashes:
        problems.append(
            "duplicate computed descendant hashes: "
            + ", ".join(sorted(duplicate_hashes))
        )
    if missing:
        problems.append(
            f"missing {len(missing)} committed descendant hashes (first: {missing[0]})"
        )
    if validity_regressions:
        problems.append(
            f"{len(validity_regressions)} committed VALID descendants no longer VALID"
            f" (first: {validity_regressions[0]})"
        )
    if consensus_invalid_regressions:
        problems.append(
            f"{len(consensus_invalid_regressions)} committed VALID descendants are "
            "now consensus-invalid error blocks and would leave the sidecar "
            f"(first: {consensus_invalid_regressions[0]})"
        )
    if len(statuses) < len(baseline.statuses_by_hash):
        problems.append(
            "computed descendant coverage is below the publication baseline "
            f"({len(statuses)} < {len(baseline.statuses_by_hash)})"
        )

    chain_regressions: list[tuple[str, list[str]]] = []
    unknown_row_regressions: list[tuple[str, int | None, int]] = []
    source_row_regressions: list[tuple[str, str, int]] = []
    malformed_source_rows: list[tuple[str, str]] = []
    for block_hash in sorted(set(baseline.statuses_by_hash) & set(statuses)):
        computed_row = computed_rows_by_hash[block_hash]
        computed_chains = {
            token.strip()
            for token in str(computed_row.get("observed_chains", "")).split("|")
            if token.strip()
        }
        missing_chains = sorted(
            baseline.observed_chains_by_hash[block_hash] - computed_chains
        )
        if missing_chains:
            chain_regressions.append((block_hash, missing_chains))

        try:
            computed_unknown_rows: int | None = int(
                str(computed_row.get("unknown_rows", "")).strip()
            )
        except ValueError:
            computed_unknown_rows = None
        baseline_unknown_rows = baseline.unknown_rows_by_hash[block_hash]
        if (
            computed_unknown_rows is None
            or computed_unknown_rows < baseline_unknown_rows
        ):
            unknown_row_regressions.append(
                (block_hash, computed_unknown_rows, baseline_unknown_rows)
            )

        try:
            computed_source_counts = source_observation_counts(
                computed_row.get("source_rows", ""), computed_chains
            )
        except ValueError as exc:
            malformed_source_rows.append((block_hash, str(exc)))
            computed_source_counts = Counter()
        missing_source_counts = (
            baseline.source_observation_counts_by_hash[block_hash]
            - computed_source_counts
        )
        for chain, count in sorted(missing_source_counts.items()):
            source_row_regressions.append((block_hash, chain, count))

    if chain_regressions:
        block_hash, missing_chains = chain_regressions[0]
        problems.append(
            f"{len(chain_regressions)} committed descendants lost observed chains "
            f"(first: {block_hash} missing {','.join(missing_chains)})"
        )
    if unknown_row_regressions:
        block_hash, computed_count, baseline_count = unknown_row_regressions[0]
        problems.append(
            f"{len(unknown_row_regressions)} committed descendants lost unknown-row "
            f"observations (first: {block_hash} has {computed_count!s}, requires at "
            f"least {baseline_count})"
        )
    if malformed_source_rows:
        block_hash, detail = malformed_source_rows[0]
        problems.append(
            f"{len(malformed_source_rows)} computed descendants have malformed "
            f"source-row provenance (first: {block_hash}: {detail})"
        )
    if source_row_regressions:
        block_hash, chain, count = source_row_regressions[0]
        problems.append(
            f"{len(source_row_regressions)} committed per-chain source-observation "
            f"counts were lost (first: {block_hash} missing {chain!r} x{count})"
        )
    if problems:
        parser.error(
            "refusing a degraded publication reconciliation: "
            + "; ".join(problems)
            + ". Use --allow-partial only with disposable output paths."
        )


def write_csv(
    path: Path, rows: Iterable[dict[str, object]], fieldnames: list[str]
) -> None:
    """Write `rows` to `path` as a CSV with header `fieldnames`.

    Creates parent directories as needed. A row missing a field is written
    with `""` for that column.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def join_sorted(values: Iterable[str]) -> str:
    """Join the non-empty values of `values`, sorted, with `|` as the CSV-friendly delimiter."""
    return "|".join(sorted(v for v in values if v))


def select_promoted_evidence(
    observations: list[UnknownObservation], fallback_header_hex: str
) -> tuple[str, str, str, str, str, str]:
    """Select coherent header and coinbase evidence from ordered observations."""
    header_observation = next(
        (observation for observation in observations if observation.header_hex),
        observations[0],
    )
    coinbase_observation = next(
        (observation for observation in observations if observation.scriptsig_hex),
        None,
    ) or next(
        (observation for observation in observations if observation.outputs), None
    )
    return (
        header_observation.header_hex or fallback_header_hex,
        header_observation.prev_hash,
        header_observation.btc_time,
        header_observation.bits,
        coinbase_observation.scriptsig_hex if coinbase_observation else "",
        coinbase_observation.outputs if coinbase_observation else "",
    )


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


def main(argv: list[str] | None = None) -> None:
    """Reconcile unknown-classified BTC parents against known stale headers.

    CLI entry point. Builds the known-stale hash index from upstream and
    per-chain full-inventory/validated-stales CSVs, collects unknown-classified
    rows from the full inventories, then walks each unique unknown hash's
    prev-hash chain (via `classify_walks`) to a terminal node: a known stale
    (direct child or deeper descendant), the mainchain, another unknown root
    seen under a different chain, a cycle/bad data, or a dangling root.
    Detects and records duplicate-hash/conflicting-prev and
    mixed-classification anomalies along the way, and flags rows whose
    `btc_bits` disagrees with the epoch-bits table.

    With `--check-mainchain`, queries Bitcoin Core
    for still-dangling terminal roots and re-walks with the refreshed cache.
    Rows that terminate at a known stale are validated (header hash,
    prev-hash-path consistency, self-PoW, epoch nBits, and BIP34 height) and
    written to `data/stale_descendants.csv` as either
    `VALID_STALE_DESCENDANT` or `REJECTED_<reason>`, except for the ones whose
    authenticated bytes prove a consensus rule broken, which go to the
    `--error-blocks-csv` peer instead; every output CSV
    (inventory/direct-matches/descendant-paths/root-summary/anomalies/promoted)
    and the JSON summary are written under `results/analysis/stale-ancestry/`, and the
    summary is also printed to stdout.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_output_mode(args, parser)
    publication_baseline: PublicationBaseline | None = None
    if args.allow_partial:
        print(
            "WARNING: running a partial ancestry reconciliation; do not replace "
            "publication artifacts with these outputs",
            file=sys.stderr,
        )
    else:
        try:
            publication_baseline = load_publication_baseline(PROMOTED_CSV)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))

    data_dir = args.data_dir
    results_dir = args.results_dir
    cache_dir = args.cache_dir
    chain_names, full_files, unknown_files, validated_files = discover_chain_names(
        data_dir
    )
    if publication_baseline is not None:
        validate_publication_discovery(
            publication_baseline, full_files, unknown_files, parser
        )
    epoch_bits = load_epoch_bits(args.epoch_reference_dir / "btc_nbits_by_epoch.json")
    excluded_keys = load_stale_exclusion_keys()
    consensus_invalid_keys = load_consensus_invalid_stale_keys()
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

    mainchain_cache = load_mainchain_cache(cache_dir)

    def is_mainchain(block_hash: str) -> bool:
        """True if `block_hash` is a cache entry with `on_mainchain` set."""
        value = mainchain_cache.get(block_hash)
        return bool(value and value.get("on_mainchain"))

    def classify_walks() -> dict[str, WalkResult]:
        """Resolve every unique unknown hash's prev-hash chain to a memoized `WalkResult`.

        Walks `unknown_prev_by_hash` from each hash in
        `unknown_row_counts_by_hash`, via `resolve`'s per-call memoization so
        shared chain suffixes are only walked once. Returns a fresh dict each
        call, so callers re-walk (against a refreshed `mainchain_cache`) by
        calling this again.
        """
        memo: dict[str, WalkResult] = {}

        def cross_seen_root(block_hash: str) -> bool:
            """True if `block_hash` looks like an unknown root claimed by more than one chain.

            True when more than one chain reports `block_hash` as an
            unknown-row prev hash, or when `block_hash` itself appears as a
            header hash under more than one chain and is not already a known
            stale.
            """
            if len(unknown_prev_chains.get(block_hash, set())) > 1:
                return True
            header_chains = all_hash_chains.get(block_hash, set())
            return len(header_chains) > 1 and block_hash not in known_stale_hashes

        def resolve(start: str) -> WalkResult:
            """Walk `start`'s prev-hash chain to its terminal node.

            Memoizes every hash visited along the way. Follows
            `unknown_prev_by_hash` hop by hop, stopping at (and
            classifying via `assign`) the first prev-hash that is a known
            stale, on the mainchain, no longer chained to another unknown row
            (a `cross_seen_root` or `dangling_unknown`), already memoized, or
            revisited within this walk (`cycle_or_bad_data`); also stops as
            `cycle_or_bad_data` once the walk reaches `args.max_depth` hops.
            """
            if start in memo:
                return memo[start]
            path: list[str] = []
            seen: dict[str, int] = {}
            current = start

            def assign(
                kind: str, terminal_hash: str, base_depth: int = 0
            ) -> WalkResult:
                """Memoize the same `WalkResult` for every hash on `path` and return the result for `start`.

                Each node's recorded depth is its distance along `path` to
                `terminal_hash`, offset by `base_depth` (non-zero when the
                walk terminated by reusing an already-memoized suffix).
                """
                for idx, node in enumerate(path):
                    memo[node] = WalkResult(
                        kind, terminal_hash, len(path) - idx + base_depth
                    )
                return memo[start]

            while True:
                if current in memo:
                    base = memo[current]
                    return assign(base.terminal_kind, base.terminal_hash, base.depth)
                if current in seen:
                    return assign("cycle_or_bad_data", current)
                seen[current] = len(path)
                path.append(current)

                if (
                    current in conflicting_unknown_prevs
                    or current not in unknown_prev_by_hash
                ):
                    return assign("cycle_or_bad_data", current)

                prev_hash = unknown_prev_by_hash[current]
                if prev_hash in known_stale_hashes:
                    return assign("known_stale", prev_hash)
                if is_mainchain(prev_hash):
                    return assign("mainchain", prev_hash)
                if (
                    prev_hash in unknown_prev_by_hash
                    or prev_hash in conflicting_unknown_prevs
                ):
                    current = prev_hash
                    if len(path) >= args.max_depth:
                        return assign("cycle_or_bad_data", prev_hash)
                    continue

                if cross_seen_root(prev_hash):
                    return assign("cross_seen_root", prev_hash)
                return assign("dangling_unknown", prev_hash)

        for block_hash in sorted(unknown_row_counts_by_hash):
            resolve(block_hash)
        return memo

    walk_results = classify_walks()

    mainchain_cache_dirty = False
    if args.check_mainchain:
        unknown_terminals = sorted(
            {
                result.terminal_hash
                for result in walk_results.values()
                if result.terminal_kind in {"dangling_unknown", "cross_seen_root"}
                and result.terminal_hash not in mainchain_cache
            }
        )
        if args.max_mainchain_rpc:
            unknown_terminals = unknown_terminals[: args.max_mainchain_rpc]
        rpc = BtcRpc(url=args.rpc_url, auth=get_btc_auth(args.rpc_user, args.rpc_pass))
        fetched = fetch_mainchain_status(unknown_terminals, rpc, args.rpc_batch_size)
        if fetched:
            mainchain_cache.update(fetched)
            mainchain_cache_dirty = True
            walk_results = classify_walks()

    def path_for(start: str) -> list[str]:
        """Rebuild the concrete prev-hash path from `start` to its terminal hash, for reporting.

        Re-walks `unknown_prev_by_hash` independently of `classify_walks`'
        memoization, stopping as soon as it reaches a known stale or
        mainchain hash (appended as the path's last element), or stopping
        early without a terminal on a cycle or dead end. Used to render
        `path_hashes` in the descendant-paths and promoted-rows output.
        """
        path = []
        current = start
        seen = set()
        while current and current not in seen and current in unknown_prev_by_hash:
            seen.add(current)
            path.append(current)
            prev_hash = unknown_prev_by_hash[current]
            if prev_hash in known_stale_hashes or is_mainchain(prev_hash):
                path.append(prev_hash)
                break
            current = prev_hash
        return path

    direct_rows = []
    for obs in unknown_rows:
        if obs.prev_hash not in known_stale_hashes:
            continue
        sources, chains, heights, times, bits = stale_sources(
            stale_by_hash[obs.prev_hash]
        )
        direct_rows.append(
            {
                "unknown_chain": obs.chain,
                "unknown_source_path": obs.source_path,
                "unknown_row_number": obs.row_number,
                "unknown_child_height": obs.child_height,
                "unknown_btc_height": obs.btc_height,
                "unknown_btc_header_hash": obs.block_hash,
                "unknown_btc_prev_hash": obs.prev_hash,
                "matched_stale_hash": obs.prev_hash,
                "matched_stale_sources": sources,
                "matched_stale_chains": chains,
                "matched_stale_btc_heights": heights,
                "unknown_btc_time": obs.btc_time,
                "matched_stale_btc_times": times,
                "unknown_bits": obs.bits,
                "matched_stale_bits": bits,
            }
        )

    descendant_path_rows = []
    for block_hash, result in sorted(walk_results.items()):
        if result.category not in {"direct_stale_child", "stale_descendant"}:
            continue
        path = path_for(block_hash)
        stale_hash = result.terminal_hash
        sources, chains, heights, times, bits = stale_sources(stale_by_hash[stale_hash])
        example = unknown_example_by_hash[block_hash]
        descendant_path_rows.append(
            {
                "unknown_btc_header_hash": block_hash,
                "terminal_category": result.category,
                "depth": result.depth,
                "unknown_rows": unknown_row_counts_by_hash[block_hash],
                "unknown_chains": join_sorted(unknown_chains_by_hash[block_hash]),
                "example_source_path": example.source_path,
                "example_row_number": example.row_number,
                "example_child_height": example.child_height,
                "example_btc_height": example.btc_height,
                "path_hashes": ">".join(path),
                "path_chain_sets": ">".join(
                    join_sorted(unknown_chains_by_hash.get(h, set()))
                    for h in path
                    if h in unknown_chains_by_hash
                ),
                "terminal_stale_hash": stale_hash,
                "terminal_stale_sources": sources,
                "terminal_stale_chains": chains,
                "terminal_stale_btc_heights": heights,
                "terminal_stale_btc_times": times,
                "terminal_stale_bits": bits,
            }
        )

    promoted_hashes = {
        h
        for h, result in walk_results.items()
        if result.category in {"direct_stale_child", "stale_descendant"}
    }
    missing_header_hashes = {
        h
        for h in promoted_hashes
        if not any(obs.header_hex for obs in unknown_observations_by_hash[h])
    }
    namecoin_header_hexes = load_namecoin_header_hexes(
        missing_header_hashes,
        [
            data_dir / "prototype" / "namecoin_blkdat_classified.csv",
            data_dir / "prototype" / "namecoin_blkdat_candidates.csv",
        ],
    )

    promoted_rows = []
    for block_hash in sorted(promoted_hashes):
        result = walk_results[block_hash]
        path = path_for(block_hash)
        stale_hash = result.terminal_hash
        root_heights = sorted(
            {
                int(obs.btc_height)
                for obs in stale_by_hash[stale_hash]
                if int_or_none(obs.btc_height) is not None
            }
        )
        root_height = root_heights[0] if root_heights else None
        inferred_height = (
            root_height + result.depth if root_height is not None else None
        )

        observations = sorted(
            unknown_observations_by_hash[block_hash],
            key=lambda obs: (
                not bool(obs.header_hex),
                obs.chain,
                obs.source_path,
                obs.row_number,
            ),
        )
        (
            header_hex,
            observed_prev,
            observed_time,
            observed_bits,
            scriptsig_hex,
            coinbase_outputs,
        ) = select_promoted_evidence(
            observations, namecoin_header_hexes.get(block_hash, "")
        )
        parsed = parse_header_fields(header_hex)
        path_prev = path[1] if len(path) > 1 else ""
        row_prev = parsed.get("prev_hash") or observed_prev
        row_time = parsed.get("time") or observed_time
        row_bits = parsed.get("bits") or observed_bits
        observed_heights = sorted(
            {obs.btc_height for obs in observations if obs.btc_height}
        )
        observed_times = sorted({obs.btc_time for obs in observations if obs.btc_time})
        observed_bits = sorted({obs.bits for obs in observations if obs.bits})
        expected_nbits = (
            expected_bits_for_height(str(inferred_height), epoch_bits)
            if inferred_height is not None
            else ""
        )

        validation_failures: list[str] = []
        if not header_hex:
            validation_failures.append("missing_header_hex")
        elif header_hash(header_hex) != block_hash:
            validation_failures.append("header_hash_mismatch")
        if path_prev and row_prev != path_prev:
            validation_failures.append("prev_hash_path_mismatch")
        if not row_bits or not hash_meets_bits(block_hash, row_bits):
            validation_failures.append("pow_target_mismatch")
        if expected_nbits and row_bits and row_bits.lower() != expected_nbits:
            validation_failures.append("nbits_epoch_mismatch")
        if inferred_height is None:
            validation_failures.append("missing_root_height")

        if inferred_height is None:
            bip34_height_status = "not_applicable"
        else:
            bip34_height_status, bip34_failure = descendant_bip34_verdict(
                header_hex,
                scriptsig_hex,
                inferred_height,
            )
            if bip34_failure is not None:
                validation_failures.append(bip34_failure)

        consensus_rules = descendant_consensus_rules(
            header_hex,
            scriptsig_hex,
            inferred_height,
            validation_failures,
            header_bits=row_bits,
            expected_nbits=expected_nbits,
        )
        # The descendant verdict and the classification are the same judgement
        # on one row, so they must not disagree. The BIP34 verdict above passes
        # a scriptSig that is over-long but correctly prefixed, and never looks
        # at the length at all, so without this a row would be emitted to the
        # error-block peer still carrying VALID_STALE_DESCENDANT. Rows that
        # already carry a failure are already rejections and keep their primary
        # reason; the derived rules travel in ``rules_violated`` either way.
        if consensus_rules and not validation_failures:
            validation_failures.extend(consensus_rules)
        validation_status = (
            "VALID_STALE_DESCENDANT"
            if not validation_failures
            else "REJECTED_" + "|".join(validation_failures)
        )
        sources, chains, heights, times, bits = stale_sources(stale_by_hash[stale_hash])

        promoted_rows.append(
            {
                "classification": (
                    "error_block" if consensus_rules else "stale_descendant"
                ),
                "rules_violated": "|".join(consensus_rules),
                "promotion_subclass": result.category,
                "validation_status": validation_status,
                "btc_height": "" if inferred_height is None else inferred_height,
                "btc_header_hash": block_hash,
                "btc_prev_hash": row_prev,
                "btc_time": row_time,
                "btc_bits": row_bits,
                "expected_nbits": expected_nbits,
                "pow_valid": "true"
                if row_bits and hash_meets_bits(block_hash, row_bits)
                else "false",
                "header_hash_match": "true"
                if header_hex and header_hash(header_hex) == block_hash
                else "false",
                "bip34_height_status": bip34_height_status,
                "observed_btc_heights": join_sorted(observed_heights),
                "observed_btc_times": join_sorted(observed_times),
                "observed_btc_bits": join_sorted(observed_bits),
                "root_stale_hash": stale_hash,
                "root_stale_height": "" if root_height is None else root_height,
                "root_stale_sources": sources,
                "root_stale_chains": chains,
                "root_stale_btc_times": times,
                "root_stale_bits": bits,
                "stale_fork_depth": result.depth,
                "path_hashes": ">".join(path),
                "path_chain_sets": ">".join(
                    join_sorted(unknown_chains_by_hash.get(h, set()))
                    for h in path
                    if h in unknown_chains_by_hash
                ),
                "observed_chains": join_sorted(unknown_chains_by_hash[block_hash]),
                "unknown_rows": unknown_row_counts_by_hash[block_hash],
                "source_rows": join_sorted(
                    f"{obs.chain}:{obs.source_path}:{obs.row_number}"
                    for obs in observations
                ),
                "coinbase_scriptsig_hex": scriptsig_hex,
                "coinbase_outputs": coinbase_outputs,
                "btc_header_hex": header_hex,
                "notes": descendant_notes(
                    block_hash, validation_failures, publication_baseline
                ),
            }
        )

    # A candidate whose own bytes prove a consensus rule broken is not a stale
    # descendant, so it leaves the sidecar entirely for the error-block peer.
    # Publishing it here instead would put a second classification into a file
    # whose reader accepts exactly one, and would hand nothing the derived rules.
    descendant_rows = [
        row for row in promoted_rows if row["classification"] == "stale_descendant"
    ]
    error_block_rows = [
        row for row in promoted_rows if row["classification"] == "error_block"
    ]

    # The baseline is an evidence-coverage floor, so it is checked against every
    # computed row rather than the published subset: a committed hash that moved
    # to the error-block peer is still recovered, not lost. Losing one from both
    # artifacts, or proving a committed VALID descendant consensus-invalid, is
    # still a regression and still fails the run.
    if publication_baseline is not None:
        validate_publication_rows(promoted_rows, publication_baseline, parser)
    if mainchain_cache_dirty:
        save_mainchain_cache(cache_dir, mainchain_cache)

    root_summary: dict[tuple[str, str], dict[str, object]] = {}
    for block_hash, result in walk_results.items():
        key = (result.category, result.terminal_hash)
        item = root_summary.setdefault(
            key,
            {
                "terminal_category": result.category,
                "terminal_hash": result.terminal_hash,
                "unique_unknown_hashes": 0,
                "unknown_rows": 0,
                "chains": set(),
                "max_depth": 0,
                "example_unknown_hash": block_hash,
                "example_path": "",
            },
        )
        item["unique_unknown_hashes"] = int(item["unique_unknown_hashes"]) + 1
        item["unknown_rows"] = (
            int(item["unknown_rows"]) + unknown_row_counts_by_hash[block_hash]
        )
        item["chains"].update(unknown_chains_by_hash[block_hash])
        item["max_depth"] = max(int(item["max_depth"]), result.depth)

    compact_roots: dict[tuple[str, str], dict[str, object]] = {}
    for item in root_summary.values():
        category = str(item["terminal_category"])
        terminal_hash = str(item["terminal_hash"])
        compact_key = (
            category,
            terminal_hash
            if category in {"direct_stale_child", "stale_descendant"}
            else "(multiple)",
        )
        compact = compact_roots.setdefault(
            compact_key,
            {
                "terminal_category": category,
                "terminal_hash": compact_key[1],
                "terminal_root_count": 0,
                "unique_unknown_hashes": 0,
                "unknown_rows": 0,
                "chains": set(),
                "max_depth": 0,
                "sample_terminal_hashes": [],
                "sample_unknown_hashes": [],
                "example_path": "",
            },
        )
        compact["terminal_root_count"] = int(compact["terminal_root_count"]) + 1
        compact["unique_unknown_hashes"] = int(compact["unique_unknown_hashes"]) + int(
            item["unique_unknown_hashes"]
        )
        compact["unknown_rows"] = int(compact["unknown_rows"]) + int(
            item["unknown_rows"]
        )
        compact["chains"].update(item["chains"])
        compact["max_depth"] = max(int(compact["max_depth"]), int(item["max_depth"]))
        if len(compact["sample_terminal_hashes"]) < 25:
            compact["sample_terminal_hashes"].append(terminal_hash)
        if len(compact["sample_unknown_hashes"]) < 25:
            compact["sample_unknown_hashes"].append(str(item["example_unknown_hash"]))
        if not compact["example_path"]:
            compact["example_path"] = ">".join(
                path_for(str(item["example_unknown_hash"]))
            )

    root_rows = [
        {
            "terminal_category": item["terminal_category"],
            "terminal_hash": item["terminal_hash"],
            "terminal_root_count": item["terminal_root_count"],
            "unique_unknown_hashes": item["unique_unknown_hashes"],
            "unknown_rows": item["unknown_rows"],
            "chains": join_sorted(item["chains"]),
            "max_depth": item["max_depth"],
            "sample_terminal_hashes": join_sorted(item["sample_terminal_hashes"]),
            "sample_unknown_hashes": join_sorted(item["sample_unknown_hashes"]),
            "example_path": item["example_path"],
        }
        for item in compact_roots.values()
    ]
    root_rows.sort(
        key=lambda row: (
            str(row["terminal_category"]),
            -int(row["unknown_rows"]),
            str(row["terminal_hash"]),
        )
    )

    category_unique_counts = Counter(
        result.category for result in walk_results.values()
    )
    category_row_counts: Counter[str] = Counter()
    for block_hash, result in walk_results.items():
        category_row_counts[result.category] += unknown_row_counts_by_hash[block_hash]

    stale_descendant_hashes = {
        h for h, result in walk_results.items() if result.category == "stale_descendant"
    }
    direct_hashes = {
        h
        for h, result in walk_results.items()
        if result.category == "direct_stale_child"
    }
    stale_child_rollup = defaultdict(
        lambda: {"direct": 0, "descendants": 0, "chains": set()}
    )
    for block_hash, result in walk_results.items():
        if result.category not in {"direct_stale_child", "stale_descendant"}:
            continue
        rollup = stale_child_rollup[result.terminal_hash]
        if result.category == "direct_stale_child":
            rollup["direct"] += unknown_row_counts_by_hash[block_hash]
        else:
            rollup["descendants"] += unknown_row_counts_by_hash[block_hash]
        rollup["chains"].update(unknown_chains_by_hash[block_hash])

    valid_promoted_hashes = {
        row["btc_header_hash"]
        for row in descendant_rows
        if row["validation_status"] == "VALID_STALE_DESCENDANT"
    }
    rejected_promoted_hashes = {
        row["btc_header_hash"]
        for row in descendant_rows
        if row["validation_status"] != "VALID_STALE_DESCENDANT"
    }
    error_block_hashes = {row["btc_header_hash"] for row in error_block_rows}

    summary = {
        "known_stale_hashes": len(known_stale_hashes),
        "upstream_stale_hashes": upstream_count,
        "auxpow_stale_hashes": len(auxpow_stale_hashes),
        "total_unknown_rows": len(unknown_rows),
        "unique_unknown_hashes": len(unknown_row_counts_by_hash),
        "direct_stale_child_unknown_rows": sum(
            unknown_row_counts_by_hash[h] for h in direct_hashes
        ),
        "unique_direct_stale_child_unknown_hashes": len(direct_hashes),
        "stale_descendant_unknown_rows": sum(
            unknown_row_counts_by_hash[h] for h in stale_descendant_hashes
        ),
        "unique_stale_descendant_unknown_hashes": len(stale_descendant_hashes),
        "promoted_stale_descendant_hashes": len(valid_promoted_hashes),
        "rejected_stale_descendant_hashes": len(rejected_promoted_hashes),
        "error_block_descendant_hashes": len(error_block_hashes),
        "promoted_csv": rel(args.promoted_csv),
        "error_blocks_csv": rel(args.error_blocks_csv),
        "dangling_unknown_roots": sum(
            1 for category, _terminal in root_summary if category == "dangling_unknown"
        ),
        "unknown_root_seen_elsewhere_roots": sum(
            1
            for category, _terminal in root_summary
            if category == "unknown_root_seen_elsewhere"
        ),
        "mainchain_descendant_anomalies": category_row_counts.get(
            "mainchain_descendant", 0
        ),
        "cycle_or_bad_data_rows": category_row_counts.get("cycle_or_bad_data", 0),
        "category_counts_by_unique_unknown_hash": dict(
            sorted(category_unique_counts.items())
        ),
        "category_counts_by_unknown_row": dict(sorted(category_row_counts.items())),
        "chains_included": [
            row["chain"] for row in inventory_rows if int(row["total_rows"]) > 0
        ],
        "chains_excluded": {
            row["chain"]: row["notes"]
            for row in inventory_rows
            if int(row["total_rows"]) == 0
        },
        "stale_hash_rollups": {
            h: {
                "direct_unknown_rows": data["direct"],
                "descendant_unknown_rows": data["descendants"],
                "chains_with_descendants": join_sorted(data["chains"]),
            }
            for h, data in sorted(stale_child_rollup.items())
        },
        "mainchain_check": {
            "used_existing_cache_entries": len(mainchain_cache),
            "queried_bitcoin_core": bool(args.check_mainchain),
            "rpc_url": args.rpc_url if args.check_mainchain else "",
        },
    }

    write_csv(
        results_dir / OUTPUT_INVENTORY,
        inventory_rows,
        [
            "chain",
            "full_inventory_path",
            "validated_stale_path",
            "header_hash_column_used",
            "prev_hash_column_used",
            "total_rows",
            "stale_rows",
            "unknown_rows",
            "rows_missing_header_hash",
            "rows_missing_prev_hash",
            "notes",
        ],
    )
    write_csv(
        results_dir / OUTPUT_DIRECT,
        direct_rows,
        [
            "unknown_chain",
            "unknown_source_path",
            "unknown_row_number",
            "unknown_child_height",
            "unknown_btc_height",
            "unknown_btc_header_hash",
            "unknown_btc_prev_hash",
            "matched_stale_hash",
            "matched_stale_sources",
            "matched_stale_chains",
            "matched_stale_btc_heights",
            "unknown_btc_time",
            "matched_stale_btc_times",
            "unknown_bits",
            "matched_stale_bits",
        ],
    )
    write_csv(
        results_dir / OUTPUT_PATHS,
        descendant_path_rows,
        [
            "unknown_btc_header_hash",
            "terminal_category",
            "depth",
            "unknown_rows",
            "unknown_chains",
            "example_source_path",
            "example_row_number",
            "example_child_height",
            "example_btc_height",
            "path_hashes",
            "path_chain_sets",
            "terminal_stale_hash",
            "terminal_stale_sources",
            "terminal_stale_chains",
            "terminal_stale_btc_heights",
            "terminal_stale_btc_times",
            "terminal_stale_bits",
        ],
    )
    write_csv(args.promoted_csv, descendant_rows, PROMOTED_FIELDS)
    write_csv(args.error_blocks_csv, error_block_rows, PROMOTED_ERROR_BLOCK_FIELDS)
    write_csv(
        results_dir / OUTPUT_ROOTS,
        root_rows,
        [
            "terminal_category",
            "terminal_hash",
            "terminal_root_count",
            "unique_unknown_hashes",
            "unknown_rows",
            "chains",
            "max_depth",
            "sample_terminal_hashes",
            "sample_unknown_hashes",
            "example_path",
        ],
    )
    write_csv(
        results_dir / OUTPUT_ANOMALIES,
        anomalies,
        [
            "issue_type",
            "severity",
            "count",
            "chain",
            "source_path",
            "row_number",
            "btc_header_hash",
            "btc_prev_hash",
            "details",
        ],
    )
    (results_dir / OUTPUT_SUMMARY).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )

    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
