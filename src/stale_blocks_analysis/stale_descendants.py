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
from .config import (
    ACCEPTED_STALE_VALIDATION_STATUSES,
    BIP34_HEIGHT,
    BIP34_VERSION_2_HEIGHT,
    CHAINS_BY_AUXPOW_ACTIVATION,
    CHAIN_SPECS,
    DATA_DIR,
    ERROR_BLOCKS_CSV,
    STALE_CSV,
    VALIDATED_STALES_DIR,
)
from .error_blocks import load_stale_exclusion_keys
from .evidence_normalization import (
    is_hash,
    parse_header_fields,
    reconcile_parent_header_fields,
)

PARENTS_PATH = DATA_DIR / "stale_descendants.csv"
OBSERVATIONS_PATH = DATA_DIR / "stale_descendant_observations.csv"

# Exact column order of the canonical accepted-parent verdict interface.
PARENT_VERDICT_FIELDS = [
    "classification",
    "ancestry_relation",
    "validation_status",
    "active_mainchain_status",
    "active_mainchain_hash_at_height",
    "root_active_mainchain_status",
    "root_active_mainchain_hash_at_height",
    "active_mainchain_verification_source",
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
    "source_observation_count",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "notes",
]

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
    def child_event_identity(self) -> tuple[str, int, str]:
        """Authenticated child block, which can prove only one Bitcoin parent."""
        return self.chain, self.child_height, self.child_hash

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


def _validate_persisted_parent_verdict(
    row: dict[str, str],
    *,
    height: int,
    parsed_header: dict[str, str],
    path: Path,
    row_number: int,
) -> None:
    """Require the exact persisted gates of an accepted parent verdict.

    The canonical loader authenticates the serialized header separately. It
    does not rerun the classification-time consensus profile, so every gate
    which made the persisted row publishable must still carry its exact
    accepting verdict here.
    """
    expected_nbits = row["expected_nbits"]
    if (
        len(expected_nbits) != 8
        or expected_nbits != expected_nbits.lower()
        or any(char not in "0123456789abcdef" for char in expected_nbits)
        or expected_nbits != parsed_header["bits"]
    ):
        raise ValueError(
            f"{path}:{row_number}: accepted parent verdict has invalid expected_nbits"
        )
    for field in ("pow_valid", "header_hash_match"):
        if row[field] != "true":
            raise ValueError(
                f"{path}:{row_number}: accepted parent verdict requires {field}=true"
            )
    header_version = int.from_bytes(
        bytes.fromhex(row["btc_header_hex"])[:4], "little", signed=True
    )
    expected_bip34_status = (
        "match"
        if height >= BIP34_HEIGHT
        or (height >= BIP34_VERSION_2_HEIGHT and header_version >= 2)
        else "not_applicable"
    )
    if row["bip34_height_status"] != expected_bip34_status:
        raise ValueError(
            f"{path}:{row_number}: accepted parent verdict requires "
            f"bip34_height_status={expected_bip34_status}"
        )


def _load_trusted_stale_root_keys(
    *,
    validated_dir: Path = VALIDATED_STALES_DIR,
    upstream_path: Path = STALE_CSV,
    error_blocks_path: Path = ERROR_BLOCKS_CSV,
) -> set[tuple[int, str]]:
    """Load the exact direct-stale identities allowed to terminate a walk.

    Per-chain accepted rows and the pinned upstream stale census are the two
    canonical direct-stale inputs used by reconciliation. Consensus-invalid
    keys never qualify, even if an older source still contains them. Exact
    Bitcoin Core off-active-chain evidence remains a separate required field
    on every published parent verdict.
    """
    validated_paths = tuple(
        validated_dir / f"{chain}_validated_stales.csv"
        for chain, _activation_date in CHAINS_BY_AUXPOW_ACTIVATION
        if (validated_dir / f"{chain}_validated_stales.csv").is_file()
    )
    if not upstream_path.is_file():
        raise ValueError(f"pinned upstream stale census is missing: {upstream_path}")

    excluded = load_stale_exclusion_keys(error_blocks_path)
    roots: set[tuple[int, str]] = set()
    for source_path in validated_paths:
        with source_path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            fields = set(reader.fieldnames or ())
            missing = {
                "btc_height",
                "btc_header_hash",
                "classification",
                "validation_status",
            } - fields
            if missing:
                raise ValueError(
                    f"{source_path}: missing columns: {', '.join(sorted(missing))}"
                )
            for row_number, row in enumerate(reader, start=2):
                if row["classification"] != "stale" or (
                    row["validation_status"] not in ACCEPTED_STALE_VALIDATION_STATUSES
                ):
                    continue
                height = _exact_nonnegative_int(
                    row["btc_height"],
                    path=source_path,
                    row_number=row_number,
                    field="btc_height",
                )
                block_hash = _exact_hash(
                    row["btc_header_hash"],
                    path=source_path,
                    row_number=row_number,
                    field="btc_header_hash",
                )
                key = (height, block_hash)
                if key not in excluded:
                    roots.add(key)

    with upstream_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or ())
        missing = {"height", "hash"} - fields
        if missing:
            raise ValueError(
                f"{upstream_path}: missing columns: {', '.join(sorted(missing))}"
            )
        for row_number, row in enumerate(reader, start=2):
            height = _exact_nonnegative_int(
                row["height"],
                path=upstream_path,
                row_number=row_number,
                field="height",
            )
            block_hash = _exact_hash(
                row["hash"],
                path=upstream_path,
                row_number=row_number,
                field="hash",
            )
            key = (height, block_hash)
            if key not in excluded:
                roots.add(key)
    if not roots:
        raise ValueError("canonical direct-stale inputs contain no trusted roots")
    return roots


def load_stale_descendant_parents(
    path: Path = PARENTS_PATH,
    *,
    data_dir: Path = DATA_DIR,
    upstream_path: Path | None = None,
) -> dict[tuple[int, str], StaleDescendantParent]:
    """Load and validate the one-row-per-parent accepted verdict interface.

    ``data_dir`` selects the matching accepted direct-stale and error-block
    trust inputs. ``upstream_path`` can select the pinned stale census
    explicitly; canonical calls otherwise honor ``STALE_BLOCKS_DIR``, while an
    alternate data tree defaults to its own ``stale-blocks/stale-blocks.csv``.
    Callers that stage or inspect another data tree must pass that tree
    explicitly instead of mixing it with repository-global verdicts.
    """
    if not path.is_file():
        raise ValueError(
            f"stale-descendant parent-verdict interface is missing: {path}"
        )
    parents: dict[tuple[int, str], StaleDescendantParent] = {}
    ancestry_paths: dict[tuple[int, str], tuple[str, ...]] = {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        missing = set(PARENT_VERDICT_FIELDS) - set(fields)
        if missing:
            raise ValueError(f"{path}: missing columns: {', '.join(sorted(missing))}")
        if fields != PARENT_VERDICT_FIELDS:
            raise ValueError(
                f"{path}: parent verdict header must exactly match the canonical schema"
            )
        for row_number, row in enumerate(reader, start=2):
            if None in row:
                raise ValueError(
                    f"{path}:{row_number}: parent verdict row has extra CSV values"
                )
            if any(value is None for value in row.values()):
                raise ValueError(
                    f"{path}:{row_number}: parent verdict row has missing CSV values"
                )
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
            root_height = _exact_nonnegative_int(
                row["root_stale_height"],
                path=path,
                row_number=row_number,
                field="root_stale_height",
            )
            fork_depth = _exact_nonnegative_int(
                row["stale_fork_depth"],
                path=path,
                row_number=row_number,
                field="stale_fork_depth",
            )
            if fork_depth < 1 or height - root_height != fork_depth:
                raise ValueError(
                    f"{path}:{row_number}: stale_fork_depth does not match "
                    "btc_height - root_stale_height"
                )
            expected_relation = (
                "direct_stale_child" if fork_depth == 1 else "stale_descendant"
            )
            if row["ancestry_relation"] != expected_relation:
                raise ValueError(
                    f"{path}:{row_number}: ancestry_relation does not match "
                    "stale_fork_depth"
                )
            path_hashes = tuple(
                _exact_hash(
                    value,
                    path=path,
                    row_number=row_number,
                    field="path_hashes",
                )
                for value in _required(
                    row, "path_hashes", path=path, row_number=row_number
                ).split(">")
            )
            if len(path_hashes) != fork_depth + 1:
                raise ValueError(
                    f"{path}:{row_number}: path_hashes length does not match "
                    "stale_fork_depth"
                )
            if path_hashes[0] != block_hash or path_hashes[-1] != root_hash:
                raise ValueError(
                    f"{path}:{row_number}: path_hashes endpoints do not match "
                    "the candidate and stale root"
                )
            if len(set(path_hashes)) != len(path_hashes):
                raise ValueError(f"{path}:{row_number}: path_hashes contains a cycle")
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
            _validate_persisted_parent_verdict(
                row,
                height=height,
                parsed_header=parsed,
                path=path,
                row_number=row_number,
            )
            key = (height, block_hash)
            if key in parents:
                raise ValueError(f"{path}:{row_number}: duplicate parent identity")
            parents[key] = StaleDescendantParent(height, block_hash, row_number, row)
            ancestry_paths[key] = path_hashes
    if not parents:
        raise ValueError(f"stale-descendant parent-verdict interface is empty: {path}")
    trusted_upstream_path = upstream_path
    if trusted_upstream_path is None:
        trusted_upstream_path = (
            STALE_CSV
            if data_dir.resolve() == DATA_DIR.resolve()
            else data_dir / "stale-blocks" / "stale-blocks.csv"
        )
    trusted_root_keys = _load_trusted_stale_root_keys(
        validated_dir=data_dir / "validated-stales",
        upstream_path=trusted_upstream_path,
        error_blocks_path=data_dir / "error-blocks" / "error_blocks.csv",
    )
    for key, path_hashes in ancestry_paths.items():
        descendant = parents[key]
        root_key = (
            int(descendant.row["root_stale_height"]),
            descendant.row["root_stale_hash"],
        )
        if root_key in parents:
            raise ValueError(
                f"{path}:{descendant.row_number}: path_hashes terminates at "
                "another stale-descendant parent instead of a trusted stale root"
            )
        for offset, (node_hash, predecessor_hash) in enumerate(
            zip(path_hashes, path_hashes[1:])
        ):
            node_height = descendant.height - offset
            node = parents.get((node_height, node_hash))
            if node is None:
                raise ValueError(
                    f"{path}:{descendant.row_number}: path_hashes node "
                    f"{node_hash} at height {node_height} has no authenticated "
                    "parent verdict"
                )
            if node.row["btc_prev_hash"] != predecessor_hash:
                raise ValueError(
                    f"{path}:{descendant.row_number}: path_hashes predecessor "
                    f"link disagrees at {node_hash}"
                )
        if root_key not in trusted_root_keys:
            raise ValueError(
                f"{path}:{descendant.row_number}: path_hashes terminal is not "
                "present in the canonical accepted direct-stale inputs"
            )
    return parents


def load_stale_descendant_observations(
    path: Path = OBSERVATIONS_PATH,
    *,
    parents_path: Path = PARENTS_PATH,
    data_dir: Path = DATA_DIR,
    upstream_path: Path | None = None,
) -> tuple[StaleDescendantObservation, ...]:
    """Load the canonical witness ledger and validate it against parent verdicts."""
    parents = load_stale_descendant_parents(
        parents_path,
        data_dir=data_dir,
        upstream_path=upstream_path,
    )
    if not path.is_file():
        raise ValueError(f"stale-descendant observation ledger is missing: {path}")
    observations: list[StaleDescendantObservation] = []
    logical_seen: set[tuple[str, int, str, str]] = set()
    child_event_parents: dict[tuple[str, int, str], tuple[int, str]] = {}
    source_seen: set[tuple[str, str, int, str]] = set()
    parent_counts: dict[tuple[int, str], int] = {key: 0 for key in parents}
    parent_chains: dict[tuple[int, str], set[str]] = {key: set() for key in parents}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        missing = set(OBSERVATION_FIELDS) - set(fields)
        if missing:
            raise ValueError(f"{path}: missing columns: {', '.join(sorted(missing))}")
        if tuple(fields) != OBSERVATION_FIELDS:
            raise ValueError(
                f"{path}: observation ledger header must exactly match the "
                "canonical schema"
            )
        for row_number, row in enumerate(reader, start=2):
            if None in row:
                raise ValueError(
                    f"{path}:{row_number}: observation ledger row has extra CSV values"
                )
            if any(value is None for value in row.values()):
                raise ValueError(
                    f"{path}:{row_number}: observation ledger row has missing CSV values"
                )
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
            prior_parent = child_event_parents.get(obs.child_event_identity)
            if prior_parent is not None and prior_parent != parent_key:
                raise ValueError(
                    f"{path}:{row_number}: authenticated child event is assigned "
                    "to multiple Bitcoin parents"
                )
            source_identity = (chain, row["source_path"], source_row, source_sha)
            if source_identity in source_seen:
                raise ValueError(f"{path}:{row_number}: duplicate source coordinate")
            logical_seen.add(obs.logical_identity)
            child_event_parents[obs.child_event_identity] = parent_key
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
