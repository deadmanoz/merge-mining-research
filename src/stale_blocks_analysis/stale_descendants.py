"""Canonical parent and witness interfaces for accepted stale descendants.

The parent-verdict interface proves the Bitcoin-header verdict. The observation ledger
proves which child-chain blocks witnessed each parent.  Historical classifier
bucket names are retained only as provenance and never select a final category.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from .auxpow_chainid import hash_from_display_hex, hash_to_internal_hex
from .auxpow_parse import (
    ChildHeaderValidationError,
    validate_available_child_header_fields,
)
from .config import CHAIN_SPECS, DATA_DIR
from .evidence_normalization import (
    is_hash,
    parse_header_fields,
    reconcile_parent_header_fields,
)

PARENTS_PATH = DATA_DIR / "stale_descendants.csv"
OBSERVATIONS_PATH = DATA_DIR / "stale_descendant_observations.csv"

OBSERVATION_FIELDS = (
    "btc_height",
    "btc_header_hash",
    "chain",
    "child_height",
    "child_block_hash",
    "child_block_hash_order",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
    "source_btc_height",
    "source_kind",
    "source_path",
    "source_row_number",
    "source_sha256",
    "source_classification",
    "btc_height_provenance",
    "child_height_provenance",
    "identity_provenance",
    "parent_row_number",
    "provenance",
)


@dataclass(frozen=True, slots=True)
class StaleDescendantParent:
    """One accepted Bitcoin stale-fork parent verdict."""

    height: int
    block_hash: str
    row_number: int
    row: dict[str, str]


@dataclass(frozen=True, slots=True)
class StaleDescendantObservation:
    """One authenticated child-chain witness of an accepted parent."""

    parent_height: int
    parent_hash: str
    chain: str
    child_height: int
    child_hash: str
    row_number: int
    row: dict[str, str]

    @property
    def logical_identity(self) -> tuple[str, int, str, str]:
        """Stable witness identity independent of archive bucket and row order."""
        return self.chain, self.child_height, self.child_hash, self.parent_hash

    @property
    def source_identity(self) -> tuple[str, str, int, str]:
        """Exact authenticated archive coordinate for audit and rebuilds."""
        return (
            self.chain,
            self.row["source_path"],
            int(self.row["source_row_number"]),
            self.row["source_sha256"],
        )


def _required(row: dict[str, str], field: str, *, path: Path, row_number: int) -> str:
    value = (row.get(field) or "").strip()
    if not value:
        raise ValueError(f"{path}:{row_number}: missing {field}")
    return value


def _exact_hash(value: str, *, path: Path, row_number: int, field: str) -> str:
    if value != value.strip() or value != value.lower() or not is_hash(value):
        raise ValueError(f"{path}:{row_number}: {field} must be exact lowercase hex")
    return value


def _exact_nonnegative_int(
    value: str, *, path: Path, row_number: int, field: str
) -> int:
    if (
        not value
        or value != value.strip()
        or not value.isascii()
        or not value.isdigit()
        or str(int(value)) != value
    ):
        raise ValueError(
            f"{path}:{row_number}: {field} must be an exact non-negative integer"
        )
    return int(value)


def load_stale_descendant_parents(
    path: Path = PARENTS_PATH,
) -> dict[tuple[int, str], StaleDescendantParent]:
    """Load and validate the one-row-per-parent accepted verdict interface."""
    if not path.is_file():
        raise ValueError(
            f"stale-descendant parent-verdict interface is missing: {path}"
        )
    parents: dict[tuple[int, str], StaleDescendantParent] = {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        required = {
            "active_mainchain_status",
            "active_mainchain_hash_at_height",
            "active_mainchain_verification_source",
            "classification",
            "root_active_mainchain_status",
            "root_active_mainchain_hash_at_height",
            "root_stale_hash",
            "observed_chains",
            "source_observation_count",
            "validation_status",
            "btc_height",
            "btc_header_hash",
            "btc_header_hex",
        }
        missing = required - set(fields)
        if missing:
            raise ValueError(f"{path}: missing columns: {', '.join(sorted(missing))}")
        if "source_rows" in fields or "unknown_rows" in fields:
            raise ValueError(
                f"{path}: witness coordinates/counts belong in the observation ledger"
            )
        for row_number, row in enumerate(reader, start=2):
            if row["classification"] != "stale_descendant" or (
                row["validation_status"] != "VALID_STALE_DESCENDANT"
            ):
                raise ValueError(f"{path}:{row_number}: parent verdict is not accepted")
            if row["active_mainchain_status"] != "verified_not_active":
                raise ValueError(
                    f"{path}:{row_number}: parent lacks the active-mainchain gate"
                )
            if row["root_active_mainchain_status"] != "verified_not_active":
                raise ValueError(
                    f"{path}:{row_number}: trusted root lacks the active-mainchain gate"
                )
            _exact_nonnegative_int(
                row["source_observation_count"],
                path=path,
                row_number=row_number,
                field="source_observation_count",
            )
            height = _exact_nonnegative_int(
                row["btc_height"], path=path, row_number=row_number, field="btc_height"
            )
            block_hash = _exact_hash(
                row["btc_header_hash"],
                path=path,
                row_number=row_number,
                field="btc_header_hash",
            )
            root_hash = _exact_hash(
                row["root_stale_hash"],
                path=path,
                row_number=row_number,
                field="root_stale_hash",
            )
            active_hash = _exact_hash(
                row["active_mainchain_hash_at_height"],
                path=path,
                row_number=row_number,
                field="active_mainchain_hash_at_height",
            )
            root_active_hash = _exact_hash(
                row["root_active_mainchain_hash_at_height"],
                path=path,
                row_number=row_number,
                field="root_active_mainchain_hash_at_height",
            )
            if active_hash == block_hash or root_active_hash == root_hash:
                raise ValueError(
                    f"{path}:{row_number}: active-mainchain comparison contradicts "
                    "the accepted stale-fork verdict"
                )
            verification_source = _required(
                row,
                "active_mainchain_verification_source",
                path=path,
                row_number=row_number,
            )
            if not verification_source.startswith("bitcoin-core-rpc:"):
                raise ValueError(
                    f"{path}:{row_number}: active-mainchain source is not "
                    "authenticated Bitcoin Core RPC"
                )
            parsed = parse_header_fields(row["btc_header_hex"])
            if not parsed:
                raise ValueError(
                    f"{path}:{row_number}: btc_header_hex does not authenticate parent"
                )
            reconcile_parent_header_fields(
                row,
                context=f"{path}:{row_number}",
                parsed=parsed,
            )
            key = (height, block_hash)
            if key in parents:
                raise ValueError(f"{path}:{row_number}: duplicate parent identity")
            parents[key] = StaleDescendantParent(height, block_hash, row_number, row)
    if not parents:
        raise ValueError(f"stale-descendant parent-verdict interface is empty: {path}")
    return parents


def load_stale_descendant_observations(
    path: Path = OBSERVATIONS_PATH,
    *,
    parents_path: Path = PARENTS_PATH,
) -> tuple[StaleDescendantObservation, ...]:
    """Load the canonical witness ledger and validate it against parent verdicts."""
    parents = load_stale_descendant_parents(parents_path)
    if not path.is_file():
        raise ValueError(f"stale-descendant observation ledger is missing: {path}")
    observations: list[StaleDescendantObservation] = []
    logical_seen: set[tuple[str, int, str, str]] = set()
    source_seen: set[tuple[str, str, int, str]] = set()
    parent_counts: dict[tuple[int, str], int] = {key: 0 for key in parents}
    parent_chains: dict[tuple[int, str], set[str]] = {key: set() for key in parents}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        missing = set(OBSERVATION_FIELDS) - set(fields)
        if missing:
            raise ValueError(f"{path}: missing columns: {', '.join(sorted(missing))}")
        for row_number, row in enumerate(reader, start=2):
            parent_height = _exact_nonnegative_int(
                _required(row, "btc_height", path=path, row_number=row_number),
                path=path,
                row_number=row_number,
                field="btc_height",
            )
            parent_hash = _exact_hash(
                _required(row, "btc_header_hash", path=path, row_number=row_number),
                path=path,
                row_number=row_number,
                field="btc_header_hash",
            )
            parent_key = (parent_height, parent_hash)
            parent = parents.get(parent_key)
            if parent is None:
                raise ValueError(f"{path}:{row_number}: observation parent is absent")
            expected_parent_row = str(parent.row_number)
            if (
                _required(row, "parent_row_number", path=path, row_number=row_number)
                != expected_parent_row
            ):
                raise ValueError(
                    f"{path}:{row_number}: parent_row_number does not match "
                    "parent verdict"
                )
            chain = _required(row, "chain", path=path, row_number=row_number)
            if chain not in CHAIN_SPECS:
                raise ValueError(f"{path}:{row_number}: unsupported chain {chain!r}")
            child_height = _exact_nonnegative_int(
                _required(row, "child_height", path=path, row_number=row_number),
                path=path,
                row_number=row_number,
                field="child_height",
            )
            child_hash = _exact_hash(
                _required(row, "child_block_hash", path=path, row_number=row_number),
                path=path,
                row_number=row_number,
                field="child_block_hash",
            )
            order = _required(
                row, "child_block_hash_order", path=path, row_number=row_number
            )
            if order not in {"display", "internal"}:
                raise ValueError(f"{path}:{row_number}: invalid child hash order")
            validation_hash = child_hash
            if order == "display" and chain != "rsk":
                validation_hash = hash_to_internal_hex(
                    hash_from_display_hex(child_hash)
                )
            try:
                validate_available_child_header_fields(
                    {
                        "child_block_hash": validation_hash,
                        "child_header_hex": row["child_header_hex"].strip().lower(),
                        "child_block_time": row["child_block_time"].strip(),
                        "child_nbits": row["child_nbits"].strip().lower(),
                    },
                    nbits_from_header=CHAIN_SPECS[chain].child_nbits_from_header,
                )
            except ChildHeaderValidationError as exc:
                raise ValueError(f"{path}:{row_number}: {exc}") from exc
            child_hash = validation_hash
            row["child_block_hash"] = child_hash
            source_row = _exact_nonnegative_int(
                _required(row, "source_row_number", path=path, row_number=row_number),
                path=path,
                row_number=row_number,
                field="source_row_number",
            )
            if source_row < 2:
                raise ValueError(f"{path}:{row_number}: source_row_number must be >= 2")
            source_sha = _exact_hash(
                _required(row, "source_sha256", path=path, row_number=row_number),
                path=path,
                row_number=row_number,
                field="source_sha256",
            )
            for required_field in (
                "source_kind",
                "source_path",
                "source_classification",
                "btc_height_provenance",
                "child_height_provenance",
                "identity_provenance",
                "provenance",
            ):
                _required(row, required_field, path=path, row_number=row_number)
            obs = StaleDescendantObservation(
                parent_height,
                parent_hash,
                chain,
                child_height,
                child_hash,
                row_number,
                row,
            )
            if obs.logical_identity in logical_seen:
                raise ValueError(f"{path}:{row_number}: duplicate logical observation")
            source_identity = (chain, row["source_path"], source_row, source_sha)
            if source_identity in source_seen:
                raise ValueError(f"{path}:{row_number}: duplicate source coordinate")
            logical_seen.add(obs.logical_identity)
            source_seen.add(source_identity)
            parent_counts[parent_key] += 1
            parent_chains[parent_key].add(chain)
            observations.append(obs)
    missing_parents = [key for key, count in parent_counts.items() if count == 0]
    if missing_parents:
        raise ValueError(
            f"{path}: {len(missing_parents)} accepted parents have no observations"
        )
    for key, count in parent_counts.items():
        expected = int(parents[key].row["source_observation_count"])
        if count != expected:
            raise ValueError(
                f"{path}: parent {key[1]} observation count {count} does not "
                f"match source_observation_count {expected}"
            )
        observed_chains = {
            chain for chain in parents[key].row["observed_chains"].split("|") if chain
        }
        if parent_chains[key] != observed_chains:
            raise ValueError(
                f"{path}: parent {key[1]} ledger chains "
                f"{'|'.join(sorted(parent_chains[key]))} do not match "
                f"observed_chains {'|'.join(sorted(observed_chains))}"
            )
    return tuple(observations)
