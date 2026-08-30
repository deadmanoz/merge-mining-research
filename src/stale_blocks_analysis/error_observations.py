"""Build the monitor's error-block aggregate from the recovered witness ledger."""

from __future__ import annotations

import csv
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .auxpow_chainid import (
    hash_from_display_hex,
    hash_from_header_bytes,
    hash_to_internal_hex,
)
from .auxpow_parse import (
    ChildHeaderValidationError,
    validate_available_child_header_fields,
)
from .config import CHAIN_SPECS, DATA_DIR
from .coinbase_output_claims import (
    merge_coinbase_output_claim_sets,
    parse_coinbase_output_claims,
    render_coinbase_output_claims,
)
from .evidence_hydration import (
    RSK_SIDECAR_EXPORT_FIELDS,
    load_child_identity,
)
from .full_evidence import (
    int_or_none,
    is_hash,
    normalize_hash,
    parse_header_fields,
    safe_path,
    write_csv,
)
from .monitor_exports import MONITOR_EVIDENCE_FIELDS

ERROR_OBSERVATION_ARTIFACT = "error-block-observations"
ERROR_OBSERVATION_SCOPE = "error-block-observations"
ERROR_OBSERVATION_STATUS = "VALID_ERROR_BLOCK"
ERROR_OBSERVATION_FIELDS = MONITOR_EVIDENCE_FIELDS + RSK_SIDECAR_EXPORT_FIELDS
ERROR_OBSERVATION_LEDGER = "error_block_observations.csv"

ERROR_OBSERVATION_LEDGER_FIELDS = (
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
    "catalogue_row_number",
    "provenance",
)


@dataclass(frozen=True, slots=True)
class ErrorBlock:
    height: int
    block_hash: str
    prev_hash: str
    btc_time: str
    btc_bits: str
    expected_nbits: str
    header_hex: str
    coinbase_scriptsig_hex: str
    rejection_reason: str
    observations: tuple[tuple[str, int], ...]


def _required(row: dict[str, str], name: str, *, row_number: int, path: Path) -> str:
    value = (row.get(name) or "").strip()
    if not value:
        raise ValueError(f"{path}:{row_number}: missing {name}")
    return value


def _observations(
    value: str, *, row_number: int, path: Path
) -> tuple[tuple[str, int], ...]:
    observations: list[tuple[str, int]] = []
    for item in value.split("|"):
        chain, separator, height = item.partition(":")
        parsed_height = int_or_none(height)
        if not separator or not chain or parsed_height is None or parsed_height < 0:
            raise ValueError(
                f"{path}:{row_number}: malformed source_child_observations"
            )
        observations.append((chain, parsed_height))
    if not observations or len(set(observations)) != len(observations):
        raise ValueError(f"{path}:{row_number}: duplicate or empty child observations")
    return tuple(observations)


def _bits(value: str, *, row_number: int, path: Path, name: str) -> str:
    bits = _required(value, name, row_number=row_number, path=path).lower()
    if len(bits) != 8:
        raise ValueError(f"{path}:{row_number}: malformed {name}")
    try:
        int(bits, 16)
    except ValueError as exc:
        raise ValueError(f"{path}:{row_number}: malformed {name}") from exc
    return bits


def load_error_blocks(
    path: Path = DATA_DIR / "error-blocks" / "error_blocks.csv",
) -> list[ErrorBlock]:
    """Load and validate the parent catalogue and its child witness tuples."""
    required_fields = {
        "height",
        "hash",
        "btc_prev_hash",
        "btc_time",
        "btc_bits",
        "expected_nbits",
        "btc_header_hex",
        "coinbase_scriptsig_hex",
        "source_chains",
        "source_child_observations",
        "classification",
        "rejection_reason",
    }
    blocks: list[ErrorBlock] = []
    seen: set[tuple[int, str]] = set()
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        missing = required_fields - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path}: missing columns: {', '.join(sorted(missing))}")
        for row_number, row in enumerate(reader, start=2):
            height = int_or_none(
                _required(row, "height", row_number=row_number, path=path)
            )
            block_hash = normalize_hash(
                _required(row, "hash", row_number=row_number, path=path)
            )
            header_hex = _required(
                row, "btc_header_hex", row_number=row_number, path=path
            )
            parsed = parse_header_fields(header_hex)
            header_bits = _bits(row, row_number=row_number, path=path, name="btc_bits")
            expected_nbits = _bits(
                row, row_number=row_number, path=path, name="expected_nbits"
            )
            if (
                height is None
                or height < 0
                or not is_hash(block_hash)
                or not parsed
                or parsed["hash"] != block_hash
                or parsed["prev_hash"]
                != normalize_hash(
                    _required(row, "btc_prev_hash", row_number=row_number, path=path)
                )
                or parsed["time"]
                != _required(row, "btc_time", row_number=row_number, path=path)
                or parsed["bits"] != header_bits
                or (row.get("classification") or "").strip() != "error_block"
            ):
                raise ValueError(
                    f"{path}:{row_number}: inconsistent error-block parent fields"
                )
            observations = _observations(
                _required(
                    row,
                    "source_child_observations",
                    row_number=row_number,
                    path=path,
                ),
                row_number=row_number,
                path=path,
            )
            source_chains = {
                item.strip() for item in (row.get("source_chains") or "").split("|")
            }
            if source_chains != {chain for chain, _height in observations}:
                raise ValueError(
                    f"{path}:{row_number}: source chains disagree with observations"
                )
            if not source_chains <= set(CHAIN_SPECS):
                raise ValueError(f"{path}:{row_number}: unknown source chain")
            key = (height, block_hash)
            if key in seen:
                raise ValueError(f"{path}:{row_number}: duplicate error block {key}")
            seen.add(key)
            blocks.append(
                ErrorBlock(
                    height=height,
                    block_hash=block_hash,
                    prev_hash=parsed["prev_hash"],
                    btc_time=parsed["time"],
                    btc_bits=header_bits,
                    expected_nbits=expected_nbits,
                    header_hex=header_hex.lower(),
                    coinbase_scriptsig_hex=_required(
                        row, "coinbase_scriptsig_hex", row_number=row_number, path=path
                    ).lower(),
                    rejection_reason=_required(
                        row, "rejection_reason", row_number=row_number, path=path
                    ),
                    observations=observations,
                )
            )
    if not blocks:
        raise ValueError(f"{path}: no error blocks")
    return blocks


def _load_ledger(path: Path) -> dict[tuple[str, int, str], dict[str, str]]:
    if not path.is_file():
        raise ValueError(f"{path}: missing recovered error-block witness ledger")
    observations: dict[tuple[str, int, str], dict[str, str]] = {}
    seen_child_identities: set[tuple[str, str]] = set()
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = tuple(reader.fieldnames or ())
        if fieldnames != ERROR_OBSERVATION_LEDGER_FIELDS:
            raise ValueError(
                f"{path}: error-observation ledger header is not canonical; "
                f"expected {','.join(ERROR_OBSERVATION_LEDGER_FIELDS)}"
            )
        for row_number, row in enumerate(reader, start=2):
            chain = _required(row, "chain", row_number=row_number, path=path)
            child_height = int_or_none(
                _required(row, "child_height", row_number=row_number, path=path)
            )
            btc_height = int_or_none(
                _required(row, "btc_height", row_number=row_number, path=path)
            )
            block_hash = normalize_hash(
                _required(row, "btc_header_hash", row_number=row_number, path=path)
            )
            if (
                child_height is None
                or child_height < 0
                or btc_height is None
                or btc_height < 0
            ):
                raise ValueError(f"{path}:{row_number}: malformed witness height")
            if chain not in CHAIN_SPECS or not is_hash(block_hash):
                raise ValueError(f"{path}:{row_number}: malformed witness identity")
            for name in (
                "source_kind",
                "source_path",
                "source_classification",
                "btc_height_provenance",
                "child_height_provenance",
                "identity_provenance",
                "provenance",
            ):
                _required(row, name, row_number=row_number, path=path)
            source_btc_height = int_or_none(row.get("source_btc_height"))
            if row.get("source_btc_height", "").strip():
                if source_btc_height is None or source_btc_height < 0:
                    raise ValueError(
                        f"{path}:{row_number}: malformed source_btc_height"
                    )
            elif row["btc_height_provenance"] != "catalogue-active-parent-placement":
                raise ValueError(f"{path}:{row_number}: missing source_btc_height")
            source_row = int_or_none(
                _required(row, "source_row_number", row_number=row_number, path=path)
            )
            catalogue_row = int_or_none(
                _required(row, "catalogue_row_number", row_number=row_number, path=path)
            )
            source_sha256 = normalize_hash(row.get("source_sha256"))
            if (
                source_row is None
                or source_row < 1
                or catalogue_row is None
                or catalogue_row < 2
                or (source_sha256 and not is_hash(source_sha256))
                or (not source_sha256 and row["source_kind"] != "monitor_live_event")
            ):
                raise ValueError(f"{path}:{row_number}: malformed source coordinate")
            child_hash = normalize_hash(row.get("child_block_hash"))
            if child_hash and not is_hash(child_hash):
                raise ValueError(f"{path}:{row_number}: malformed child_block_hash")
            child_hash_order = _required(
                row, "child_block_hash_order", row_number=row_number, path=path
            ).lower()
            if child_hash_order not in {"display", "internal"}:
                raise ValueError(
                    f"{path}:{row_number}: malformed child_block_hash_order"
                )
            if child_hash_order == "display" and child_hash and chain != "rsk":
                child_hash = hash_to_internal_hex(hash_from_display_hex(child_hash))
            child_header = (row.get("child_header_hex") or "").strip().lower()
            child_header_bytes: bytes | None = None
            if child_header and len(child_header) != 160:
                raise ValueError(f"{path}:{row_number}: malformed child_header_hex")
            if child_header:
                try:
                    child_header_bytes = bytes.fromhex(child_header)
                except ValueError as exc:
                    raise ValueError(
                        f"{path}:{row_number}: malformed child_header_hex"
                    ) from exc
            if not child_hash and child_header_bytes is not None:
                child_hash = hash_from_header_bytes(child_header_bytes).hex()
            if not child_hash:
                raise ValueError(
                    f"{path}:{row_number}: missing child_block_hash and child_header_hex"
                )
            child_time = (row.get("child_block_time") or "").strip()
            if child_time and int_or_none(child_time) is None:
                raise ValueError(f"{path}:{row_number}: malformed child_block_time")
            child_nbits = (row.get("child_nbits") or "").strip().lower()
            if child_nbits:
                _bits(
                    {"child_nbits": child_nbits},
                    row_number=row_number,
                    path=path,
                    name="child_nbits",
                )
            try:
                validate_available_child_header_fields(
                    {
                        "child_block_hash": child_hash,
                        "child_header_hex": child_header,
                        "child_block_time": child_time,
                        "child_nbits": child_nbits,
                    },
                    nbits_from_header=CHAIN_SPECS[chain].child_nbits_from_header,
                )
            except ChildHeaderValidationError as exc:
                raise ValueError(
                    f"{path}:{row_number}: invalid child header evidence: {exc}"
                ) from exc
            row["child_block_hash"] = child_hash
            child_identity = (chain, child_hash)
            if child_identity in seen_child_identities:
                raise ValueError(
                    f"{path}:{row_number}: duplicate child identity {child_identity}"
                )
            seen_child_identities.add(child_identity)
            key = (chain, child_height, block_hash)
            if key in observations:
                raise ValueError(f"{path}:{row_number}: duplicate witness {key}")
            observations[key] = row
    return observations


I32_MAX = 2_147_483_647
_PUBLISHED_HEX = re.compile(r"^[0-9a-fA-F]+$")
_PUBLISHED_I32 = re.compile(r"^[+]?[0-9]+$")


def _published_hex_byte_length(value: str) -> int | None:
    """Count bytes in unprefixed hex the monitor's `hex::decode` will accept."""
    stripped = (value or "").strip()
    if not stripped or len(stripped) % 2 or not _PUBLISHED_HEX.fullmatch(stripped):
        return None
    return len(stripped) // 2


def _published_i32(value: str) -> int | None:
    """Parse a monitor-importable signed 32-bit cell (`i32::from_str`)."""
    stripped = (value or "").strip()
    if not _PUBLISHED_I32.fullmatch(stripped):
        return None
    parsed = int(stripped)
    if parsed < 0 or parsed > I32_MAX:
        return None
    return parsed


def validate_rsk_sidecar_cells(row: dict[str, str], *, row_id: str) -> None:
    """Reject RSK sidecar values that the monitor importer would skip."""
    miner_len = _published_hex_byte_length(row.get("rsk_miner") or "")
    if miner_len != 20:
        raise ValueError(f"{row_id}: rsk_miner must be unprefixed 20-byte hex")
    mm_len = _published_hex_byte_length(row.get("merge_mining_hash") or "")
    if mm_len != 32:
        raise ValueError(f"{row_id}: merge_mining_hash must be unprefixed 32-byte hex")
    is_uncle = (row.get("is_uncle") or "").strip()
    if is_uncle not in {"0", "1"}:
        raise ValueError(f"{row_id}: is_uncle must be 0 or 1")
    uncle_index = (row.get("uncle_index") or "").strip()
    uncle_parent_height = (row.get("uncle_parent_height") or "").strip()
    if is_uncle == "1":
        if (
            _published_i32(uncle_index) is None
            or _published_i32(uncle_parent_height) is None
        ):
            raise ValueError(
                f"{row_id}: uncle placement must be a non-negative signed 32-bit int"
            )
    elif uncle_index or uncle_parent_height:
        raise ValueError(f"{row_id}: uncle placement must be blank for is_uncle=0")
    for name in ("rsk_merkle_proof", "rsk_coinbase_tail"):
        value = (row.get(name) or "").strip()
        if value and _published_hex_byte_length(value) is None:
            raise ValueError(f"{row_id}: {name} must be blank or unprefixed hex")


def _attach_rsk_error_observation_sidecars(
    rows: list[dict[str, str]], *, data_dir: Path
) -> None:
    """Copy RSK sidecar fields only; never replace the ledger child hash."""
    identity = load_child_identity(data_dir)
    for row in rows:
        if row["chain"] != "rsk":
            continue
        parent_hash = normalize_hash(row["btc_header_hash"])
        candidate = identity.get(("rsk", parent_hash))
        row_id = f"error-observation rsk {parent_hash}"
        if candidate is None:
            raise ValueError(f"{row_id}: missing child-identity")
        ledger_hash = normalize_hash(row.get("child_block_hash"))
        identity_hash = normalize_hash(candidate.get("child_block_hash"))
        if ledger_hash != identity_hash:
            raise ValueError(
                f"{row_id}: child_block_hash disagrees with child-identity"
            )
        candidate_height = int_or_none(candidate.get("child_height"))
        row_height = int_or_none(row.get("child_height"))
        if (
            candidate_height is None
            or row_height is None
            or candidate_height != row_height
        ):
            raise ValueError(f"{row_id}: child_height disagrees with child-identity")
        identity_time = (candidate.get("child_block_time") or "").strip()
        ledger_time = (row.get("child_block_time") or "").strip()
        if ledger_time and identity_time and ledger_time != identity_time:
            raise ValueError(
                f"{row_id}: child_block_time disagrees with child-identity"
            )
        if not ledger_time and identity_time:
            row["child_block_time"] = identity_time
        for field in RSK_SIDECAR_EXPORT_FIELDS:
            row[field] = (candidate.get(field) or "").strip()
        validate_rsk_sidecar_cells(row, row_id=row_id)


def build_error_observation_rows(
    *,
    data_dir: Path = DATA_DIR,
    source_evidence_rows: Iterable[dict[str, str]] = (),
) -> tuple[list[dict[str, str]], dict[str, object]]:
    """Expand the recovered witness ledger against the current parent catalogue."""
    blocks, ledger = validate_error_observation_ledger(
        catalogue_path=data_dir / "error-blocks" / "error_blocks.csv",
        ledger_path=data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER,
    )

    source_evidence_by_coordinate: dict[
        tuple[str, str, str, str, str], list[dict[str, str]]
    ] = {}
    for source_row in source_evidence_rows:
        coordinate = (
            (source_row.get("chain") or "").strip(),
            normalize_hash(source_row.get("btc_header_hash")),
            (source_row.get("source_path") or "").strip(),
            (source_row.get("source_row_number") or "").strip(),
            normalize_hash(source_row.get("source_sha256")),
        )
        source_evidence_by_coordinate.setdefault(coordinate, []).append(source_row)

    rows: list[dict[str, str]] = []
    targets = {
        (chain, child_height, block.block_hash): block
        for block in blocks
        for chain, child_height in block.observations
    }
    for key, block in targets.items():
        chain, child_height, _block_hash = key
        witness = ledger[key]
        row = dict.fromkeys(ERROR_OBSERVATION_FIELDS, "")
        row.update(
            {
                "chain": chain,
                "source_kind": witness["source_kind"],
                "source_path": witness["source_path"],
                "source_row_number": witness["source_row_number"],
                "artifact_scope": ERROR_OBSERVATION_SCOPE,
                "provenance": witness["provenance"],
                "child_height": str(child_height),
                "child_block_hash": normalize_hash(witness.get("child_block_hash")),
                "child_header_hex": (witness.get("child_header_hex") or "").lower(),
                "child_block_time": (witness.get("child_block_time") or "").strip(),
                "child_nbits": (witness.get("child_nbits") or "").lower(),
                "btc_height": str(block.height),
                "btc_header_hash": block.block_hash,
                "btc_prev_hash": block.prev_hash,
                "btc_time": block.btc_time,
                "btc_bits": block.btc_bits,
                "btc_nonce": parse_header_fields(block.header_hex)["nonce"],
                "btc_header_hex": block.header_hex,
                "coinbase_scriptsig_hex": block.coinbase_scriptsig_hex,
                "classification": "error_block",
                "validation_status": ERROR_OBSERVATION_STATUS,
                "expected_nbits": block.expected_nbits,
                "rejection_reason": block.rejection_reason,
            }
        )
        coordinate = (
            chain,
            block.block_hash,
            witness["source_path"],
            witness["source_row_number"],
            normalize_hash(witness.get("source_sha256")),
        )
        source_rows = source_evidence_by_coordinate.get(coordinate, [])
        if source_rows:
            claim_sets = []
            full_coinbases: set[str] = set()
            for source_row in source_rows:
                if (
                    normalize_hash(source_row.get("btc_header_hash"))
                    != block.block_hash
                ):
                    raise ValueError(
                        f"error source coordinate disagrees with parent hash for {key}"
                    )
                source_header = (source_row.get("btc_header_hex") or "").strip().lower()
                if source_header and source_header != block.header_hex:
                    raise ValueError(
                        f"error source coordinate disagrees with parent header for {key}"
                    )
                source_scriptsig = (
                    (source_row.get("coinbase_scriptsig_hex") or "").strip().lower()
                )
                if (
                    source_scriptsig
                    and source_scriptsig != block.coinbase_scriptsig_hex
                ):
                    raise ValueError(
                        f"error source coordinate disagrees with coinbase scriptSig for {key}"
                    )
                source_child_height = int_or_none(source_row.get("child_height"))
                if (
                    source_child_height is not None
                    and source_child_height != child_height
                ):
                    raise ValueError(
                        f"error source coordinate disagrees with child height for {key}"
                    )
                for field in (
                    "child_block_hash",
                    "child_header_hex",
                    "child_block_time",
                    "child_nbits",
                ):
                    source_value = (source_row.get(field) or "").strip().lower()
                    witness_value = (row.get(field) or "").strip().lower()
                    if source_value and witness_value and source_value != witness_value:
                        raise ValueError(
                            f"error source coordinate disagrees with {field} for {key}"
                        )
                full_coinbase = (
                    (source_row.get("full_coinbase_hex") or "").strip().lower()
                )
                if full_coinbase:
                    full_coinbases.add(full_coinbase)
                claim_sets.append(
                    parse_coinbase_output_claims(
                        source_row.get("coinbase_outputs") or "",
                        full_coinbase,
                    )
                )
            if len(full_coinbases) > 1:
                raise ValueError(
                    f"error source coordinates disagree on full coinbase for {key}"
                )
            row["coinbase_outputs"] = render_coinbase_output_claims(
                merge_coinbase_output_claim_sets(*claim_sets)
            )
            row["full_coinbase_hex"] = next(iter(full_coinbases), "")
        rows.append(row)
    _attach_rsk_error_observation_sidecars(rows, data_dir=data_dir)
    rows.sort(
        key=lambda row: (
            row["chain"],
            int(row["child_height"]),
            row["btc_header_hash"],
        )
    )
    counts = Counter(row["chain"] for row in rows)
    return rows, {
        "artifact": ERROR_OBSERVATION_ARTIFACT,
        "rows": len(rows),
        "parents": len(blocks),
        "source_chain_counts": dict(sorted(counts.items())),
    }


def validate_error_observation_ledger(
    *, catalogue_path: Path, ledger_path: Path
) -> tuple[list[ErrorBlock], dict[tuple[str, int, str], dict[str, str]]]:
    """Validate exact catalogue-to-ledger witness coverage without exporting."""
    blocks = load_error_blocks(catalogue_path)
    ledger = _load_ledger(ledger_path)
    targets = {
        (chain, child_height, block.block_hash): block
        for block in blocks
        for chain, child_height in block.observations
    }
    catalogue_row_numbers = {
        (block.height, block.block_hash): row_number
        for row_number, block in enumerate(blocks, start=2)
    }
    unexpected = set(ledger) - set(targets)
    missing = set(targets) - set(ledger)
    if unexpected or missing:
        details = []
        if unexpected:
            details.append(f"{len(unexpected)} unexpected")
        if missing:
            details.append(f"{len(missing)} missing")
        raise ValueError(
            "error-observation ledger disagrees with catalogue: " + ", ".join(details)
        )
    for key, block in targets.items():
        witness = ledger[key]
        if int(witness["btc_height"]) != block.height:
            raise ValueError(
                f"error-observation ledger has wrong parent height for {key}"
            )
        expected_catalogue_row = catalogue_row_numbers[(block.height, block.block_hash)]
        if int(witness["catalogue_row_number"]) != expected_catalogue_row:
            raise ValueError(
                "error-observation ledger has wrong catalogue_row_number for "
                f"{key}: expected {expected_catalogue_row}, got "
                f"{witness['catalogue_row_number']}"
            )
    child_identities = load_child_identity(catalogue_path.parent.parent)
    for (chain, child_height, parent_hash), witness in ledger.items():
        identity = child_identities.get((chain, parent_hash))
        if identity is None:
            continue
        expected_height = int_or_none(identity.get("child_height"))
        if expected_height != child_height:
            raise ValueError(
                "error-observation ledger child_height disagrees with generic "
                f"child identity for {chain}:{parent_hash}"
            )
        for field in (
            "child_block_hash",
            "child_block_time",
            "child_header_hex",
            "child_nbits",
        ):
            expected = (identity.get(field) or "").strip().lower()
            if not expected:
                continue
            actual = (witness.get(field) or "").strip().lower()
            # The generic identity ledger may enrich a compact error witness at
            # export time.  Only a competing populated claim is a disagreement.
            if not actual:
                continue
            if actual != expected:
                raise ValueError(
                    f"error-observation ledger {field} disagrees with generic "
                    f"child identity for {chain}:{parent_hash}"
                )
    return blocks, ledger


def write_error_observation_artifact(
    output_dir: Path,
    *,
    data_dir: Path = DATA_DIR,
    source_evidence_rows: Iterable[dict[str, str]] = (),
) -> dict[str, object]:
    """Write the complete aggregate from the compact, recovered witness ledger."""
    rows, inventory = build_error_observation_rows(
        data_dir=data_dir,
        source_evidence_rows=source_evidence_rows,
    )
    path = output_dir / f"{ERROR_OBSERVATION_ARTIFACT}_monitor_evidence.csv"
    write_csv(path, rows, ERROR_OBSERVATION_FIELDS)
    return {**inventory, "path": path}


def error_observation_count_row(
    artifact: dict[str, object], *, data_dir: Path, artifact_path: Path
) -> dict[str, object]:
    """Render the error aggregate's row in the monitor publication manifest."""
    return {
        "chain": ERROR_OBSERVATION_ARTIFACT,
        "source_kind": "error_block_catalogue",
        "artifact_scope": ERROR_OBSERVATION_SCOPE,
        "artifact_path": safe_path(artifact_path),
        "source_path": safe_path(data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER),
        "canonical": 0,
        "stale": 0,
        "stale_descendant": 0,
        "strict_btc_orphan": 0,
        "weak_btc_orphan": 0,
        "error_block": artifact["rows"],
        "monitor_rows": artifact["rows"],
        "source_rows": artifact["rows"],
        "canonical_evidence_status": "not_applicable",
        "notes": f"parents={artifact['parents']}",
    }
