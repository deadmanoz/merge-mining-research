"""Build the monitor's error-block aggregate from the recovered witness ledger."""

from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .auxpow_parse import (
    ChildHeaderValidationError,
    validate_available_child_header_fields,
)
from .config import CHAIN_SPECS, DATA_DIR
from .full_evidence import (
    MONITOR_EVIDENCE_FIELDS,
    int_or_none,
    is_hash,
    normalize_hash,
    parse_header_fields,
    safe_path,
    write_csv,
)

ERROR_OBSERVATION_ARTIFACT = "error-block-observations"
ERROR_OBSERVATION_SCOPE = "error-block-observations"
ERROR_OBSERVATION_STATUS = "VALID_ERROR_BLOCK"
ERROR_OBSERVATION_FIELDS = MONITOR_EVIDENCE_FIELDS
ERROR_OBSERVATION_LEDGER = "error_block_observations.csv"

_LEDGER_FIELDS = {
    "btc_height",
    "btc_header_hash",
    "chain",
    "child_height",
    "child_block_hash",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
    "source_kind",
    "source_path",
    "source_row_number",
    "source_sha256",
    "provenance",
}


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
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        missing = _LEDGER_FIELDS - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path}: missing columns: {', '.join(sorted(missing))}")
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
            for name in ("source_kind", "source_path", "provenance"):
                _required(row, name, row_number=row_number, path=path)
            source_row = int_or_none(
                _required(row, "source_row_number", row_number=row_number, path=path)
            )
            source_sha256 = normalize_hash(row.get("source_sha256"))
            if (
                source_row is None
                or source_row < 1
                or (source_sha256 and not is_hash(source_sha256))
                or (not source_sha256 and row["source_kind"] != "monitor_live_event")
            ):
                raise ValueError(f"{path}:{row_number}: malformed source coordinate")
            child_hash = normalize_hash(row.get("child_block_hash"))
            if child_hash and not is_hash(child_hash):
                raise ValueError(f"{path}:{row_number}: malformed child_block_hash")
            child_header = (row.get("child_header_hex") or "").strip().lower()
            if child_header and len(child_header) != 160:
                raise ValueError(f"{path}:{row_number}: malformed child_header_hex")
            if child_header:
                try:
                    bytes.fromhex(child_header)
                except ValueError as exc:
                    raise ValueError(
                        f"{path}:{row_number}: malformed child_header_hex"
                    ) from exc
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
            key = (chain, child_height, block_hash)
            if key in observations:
                raise ValueError(f"{path}:{row_number}: duplicate witness {key}")
            observations[key] = row
    return observations


def build_error_observation_rows(
    *, data_dir: Path = DATA_DIR
) -> tuple[list[dict[str, str]], dict[str, object]]:
    """Expand the recovered witness ledger against the current parent catalogue."""
    blocks = load_error_blocks(data_dir / "error-blocks" / "error_blocks.csv")
    ledger = _load_ledger(data_dir / "error-blocks" / ERROR_OBSERVATION_LEDGER)
    targets = {
        (chain, child_height, block.block_hash): block
        for block in blocks
        for chain, child_height in block.observations
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

    rows: list[dict[str, str]] = []
    for key, block in targets.items():
        chain, child_height, _block_hash = key
        witness = ledger[key]
        if int(witness["btc_height"]) != block.height:
            raise ValueError(
                f"error-observation ledger has wrong parent height for {key}"
            )
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
        rows.append(row)
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


def write_error_observation_artifact(
    output_dir: Path, *, data_dir: Path = DATA_DIR
) -> dict[str, object]:
    """Write the complete aggregate from the compact, recovered witness ledger."""
    rows, inventory = build_error_observation_rows(data_dir=data_dir)
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
        "source_chain_counts": artifact["source_chain_counts"],
    }
