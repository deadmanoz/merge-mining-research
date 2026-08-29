"""Convert classifier-emitted descendant error blocks into publication inputs."""

from __future__ import annotations

import csv
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .auxpow_chainid import hash_from_display_hex, hash_to_internal_hex
from .auxpow_parse import ChildHeaderValidationError, validate_child_header_fields
from .full_evidence import int_or_none, is_hash, normalize_hash

IDENTITY_FIELDS = (
    "btc_height",
    "btc_header_hash",
    "chain",
    "child_height",
    "child_block_hash",
    "child_block_hash_order",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
    "source_path",
    "source_row_number",
    "source_sha256",
    "source_classification",
    "identity_provenance",
)

LEDGER_FIELDS = (
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

_PARENT_HASH_COLUMNS = ("btc_header_hash", "btc_hash", "hash")
_BTC_HEADER_COLUMNS = ("btc_header_hex", "header")
_COINBASE_SCRIPTSIG_COLUMNS = (
    "coinbase_scriptsig_hex",
    "btc_coinbase_scriptsig_hex",
)
_BTC_HEIGHT_COLUMNS = (
    "btc_height",
    "btc_stale_height",
    "height",
    "btc_bip34_height",
)
_NON_CHILD_HEIGHT_COLUMNS = frozenset(
    {
        "btc_height",
        "btc_stale_height",
        "btc_parent_height",
        "btc_bip34_height",
        "height",
    }
)
_CATALOGUE_PROVENANCE = "classifier-emitted:stale-descendant-reconciliation"


@dataclass(frozen=True, slots=True)
class ReconciledImport:
    """Self-contained parent rows and their authenticated witness ledger rows."""

    catalogue_rows: tuple[dict[str, str], ...]
    ledger_rows: tuple[dict[str, str], ...]


def _required(row: dict[str, str], name: str, *, label: str) -> str:
    value = (row.get(name) or "").strip()
    if not value:
        raise ValueError(f"{label}: missing {name}")
    return value


def _normalized_hex(
    value: str, *, label: str, name: str, byte_length: int | None = None
) -> str:
    normalized = value.strip().lower()
    if (
        not normalized
        or len(normalized) % 2
        or (byte_length is not None and len(normalized) != byte_length * 2)
        or any(char not in "0123456789abcdef" for char in normalized)
    ):
        expected = f" exactly {byte_length} bytes of" if byte_length is not None else ""
        raise ValueError(f"{label}: {name} must be{expected} hexadecimal data")
    return normalized


def _load_identity_rows(path: Path) -> dict[tuple[int, str, str, int], dict[str, str]]:
    if not path.is_file():
        raise ValueError(f"{path}: missing reconciled child-identity manifest")
    identities: dict[tuple[int, str, str, int], dict[str, str]] = {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        missing = set(IDENTITY_FIELDS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path}: missing columns: {', '.join(sorted(missing))}")
        for row_number, row in enumerate(reader, start=2):
            label = f"{path}:{row_number}"
            parent_height = int_or_none(_required(row, "btc_height", label=label))
            parent_hash = normalize_hash(_required(row, "btc_header_hash", label=label))
            chain = _required(row, "chain", label=label)
            child_height = int_or_none(_required(row, "child_height", label=label))
            child_hash = normalize_hash(_required(row, "child_block_hash", label=label))
            child_hash_order = _required(
                row, "child_block_hash_order", label=label
            ).lower()
            child_time = _required(row, "child_block_time", label=label)
            if (
                parent_height is None
                or parent_height < 0
                or child_height is None
                or child_height < 0
                or not is_hash(parent_hash)
                or not is_hash(child_hash)
                or child_hash_order not in {"display", "internal"}
                or not child_time.isdigit()
                or int(child_time) <= 0
            ):
                raise ValueError(f"{label}: malformed reconciled child identity")
            child_header = _required(row, "child_header_hex", label=label)
            if (
                len(child_header) != 160
                or child_header != child_header.lower()
                or any(char not in "0123456789abcdef" for char in child_header)
            ):
                raise ValueError(f"{label}: malformed child_header_hex")
            child_nbits = _required(row, "child_nbits", label=label)
            if (
                len(child_nbits) != 8
                or child_nbits != child_nbits.lower()
                or any(char not in "0123456789abcdef" for char in child_nbits)
            ):
                raise ValueError(f"{label}: malformed child_nbits")
            validation_hash = child_hash
            if child_hash_order == "display":
                validation_hash = hash_to_internal_hex(
                    hash_from_display_hex(child_hash)
                )
            try:
                validate_child_header_fields(
                    {
                        "child_block_hash": validation_hash,
                        "child_header_hex": child_header,
                        "child_block_time": child_time,
                        "child_nbits": child_nbits,
                    }
                )
            except ChildHeaderValidationError as exc:
                raise ValueError(
                    f"{label}: invalid child header evidence: {exc}"
                ) from exc
            source_path = _required(row, "source_path", label=label)
            source_row_number = int_or_none(
                _required(row, "source_row_number", label=label)
            )
            if source_row_number is None or source_row_number < 2:
                raise ValueError(f"{label}: malformed source_row_number")
            manifest_path = Path(source_path)
            if (
                manifest_path.is_absolute()
                or not manifest_path.parts
                or manifest_path.parts[0] != "data"
                or ".." in manifest_path.parts
            ):
                raise ValueError(f"{label}: malformed source_path")
            source_sha256 = normalize_hash(row.get("source_sha256"))
            source_classification = (row.get("source_classification") or "").strip()
            identity_provenance = (row.get("identity_provenance") or "").strip()
            if (
                not is_hash(source_sha256)
                or source_classification
                not in {
                    "orphan",
                    "unknown",
                }
                or identity_provenance != f"node-verified-rpc:{chain}"
            ):
                raise ValueError(f"{label}: malformed source authentication")
            key = (parent_height, parent_hash, chain, child_height)
            if key in identities:
                raise ValueError(f"{label}: duplicate reconciled child identity")
            identities[key] = {
                field: (row.get(field) or "").strip() for field in IDENTITY_FIELDS
            }
    if not identities:
        raise ValueError(f"{path}: no reconciled child identities")
    return identities


def _source_path(data_dir: Path, source: str) -> Path:
    path = Path(source)
    parts = path.parts
    if path.is_absolute() or not parts or parts[0] != "data":
        raise ValueError(
            f"reconciliation source path must be relative beneath data/: {source!r}"
        )
    root = data_dir.resolve()
    resolved = data_dir.joinpath(*parts[1:]).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"reconciliation source escapes data/: {source!r}")
    return resolved


def _source_row(path: Path, row_number: int) -> tuple[dict[str, str], list[str], str]:
    if row_number < 2:
        raise ValueError(f"{path}:{row_number}: source row must follow the header")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for current, row in enumerate(reader, start=2):
            if current == row_number:
                return row, list(reader.fieldnames or ()), digest
    raise ValueError(f"{path}:{row_number}: source row does not exist")


def _first(row: dict[str, str], columns: tuple[str, ...]) -> str:
    for column in columns:
        value = (row.get(column) or "").strip()
        if value:
            return value
    return ""


def _child_height(row: dict[str, str], fieldnames: list[str]) -> int | None:
    for field in fieldnames:
        if field.endswith("_height") and field not in _NON_CHILD_HEIGHT_COLUMNS:
            value = int_or_none(row.get(field))
            if value is not None:
                return value
    return int_or_none(row.get("child_height"))


def _parse_source_token(token: str) -> tuple[str, str, int]:
    chain, separator, remainder = token.partition(":")
    source, row_separator, row_number = remainder.rpartition(":")
    parsed_row = int_or_none(row_number)
    if (
        not separator
        or not row_separator
        or not chain
        or not source
        or parsed_row is None
    ):
        raise ValueError(f"malformed reconciliation source_rows token {token!r}")
    return chain, source, parsed_row


def build_reconciled_import(
    *, peer_path: Path, identity_path: Path, data_dir: Path
) -> ReconciledImport:
    """Verify reconciliation output and derive catalogue plus ledger imports."""
    identities = _load_identity_rows(identity_path)
    catalogue_rows: list[dict[str, str]] = []
    ledger_rows: list[dict[str, str]] = []
    used_identities: set[tuple[int, str, str, int]] = set()
    with peer_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "classification",
            "validation_status",
            "btc_height",
            "btc_header_hash",
            "btc_prev_hash",
            "expected_nbits",
            "btc_header_hex",
            "observed_btc_heights",
            "observed_chains",
            "source_rows",
            "coinbase_scriptsig_hex",
            "rules_violated",
        }
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"{peer_path}: missing reconciliation columns: "
                + ", ".join(sorted(missing))
            )
        for row_number, peer in enumerate(reader, start=2):
            label = f"{peer_path}:{row_number}"
            if peer["classification"] != "error_block" or not peer[
                "validation_status"
            ].startswith("REJECTED_"):
                raise ValueError(f"{label}: row is not a rejected error block")
            parent_height = int_or_none(_required(peer, "btc_height", label=label))
            parent_hash = normalize_hash(
                _required(peer, "btc_header_hash", label=label)
            )
            if parent_height is None or parent_height < 0 or not is_hash(parent_hash):
                raise ValueError(f"{label}: malformed parent identity")
            claimed_heights = {
                int(value)
                for value in peer["observed_btc_heights"].split("|")
                if value.strip()
            }
            if len(claimed_heights) != 1:
                raise ValueError(f"{label}: ambiguous encoded coinbase height")
            encoded_height = next(iter(claimed_heights))
            if encoded_height != parent_height + 1:
                raise ValueError(
                    f"{label}: encoded coinbase height must equal parent height + 1"
                )
            peer_scriptsig = _normalized_hex(
                _required(peer, "coinbase_scriptsig_hex", label=label),
                label=label,
                name="coinbase_scriptsig_hex",
            )
            peer_header = _normalized_hex(
                _required(peer, "btc_header_hex", label=label),
                label=label,
                name="btc_header_hex",
                byte_length=80,
            )

            witnesses: list[dict[str, str]] = []
            for token in peer["source_rows"].split("|"):
                chain, source_text, source_row_number = _parse_source_token(token)
                source_path = _source_path(data_dir, source_text)
                source, fieldnames, source_sha256 = _source_row(
                    source_path, source_row_number
                )
                source_parent_hash = normalize_hash(
                    _first(source, _PARENT_HASH_COLUMNS)
                )
                source_scriptsig_text = _first(source, _COINBASE_SCRIPTSIG_COLUMNS)
                if not source_scriptsig_text:
                    raise ValueError(
                        f"{source_path}:{source_row_number}: source row is missing "
                        "coinbase_scriptsig_hex"
                    )
                source_scriptsig = _normalized_hex(
                    source_scriptsig_text,
                    label=f"{source_path}:{source_row_number}",
                    name="source coinbase_scriptsig_hex",
                )
                if source_scriptsig != peer_scriptsig:
                    raise ValueError(
                        f"{source_path}:{source_row_number}: source "
                        "coinbase_scriptsig_hex disagrees with reconciliation peer"
                    )
                source_header_text = _first(source, _BTC_HEADER_COLUMNS)
                if source_header_text:
                    source_header = _normalized_hex(
                        source_header_text,
                        label=f"{source_path}:{source_row_number}",
                        name="source btc_header_hex",
                        byte_length=80,
                    )
                    if source_header != peer_header:
                        raise ValueError(
                            f"{source_path}:{source_row_number}: source btc_header_hex "
                            "disagrees with reconciliation peer"
                        )
                child_height = _child_height(source, fieldnames)
                source_btc_height = _first(source, _BTC_HEIGHT_COLUMNS)
                if source_parent_hash != parent_hash or child_height is None:
                    raise ValueError(
                        f"{source_path}:{source_row_number}: source identity "
                        f"disagrees with {label}"
                    )
                if int_or_none(source_btc_height) != encoded_height:
                    raise ValueError(
                        f"{source_path}:{source_row_number}: archive btc_height "
                        "must be the encoded coinbase height"
                    )
                identity_key = (parent_height, parent_hash, chain, child_height)
                identity = identities.get(identity_key)
                if identity is None:
                    raise ValueError(
                        f"{label}: missing child identity for {chain}:{child_height}"
                    )
                used_identities.add(identity_key)
                if source_text != identity["source_path"]:
                    raise ValueError(
                        f"{label}: source path for {chain}:{child_height} disagrees "
                        "with the committed identity manifest"
                    )
                if source_row_number != int(identity["source_row_number"]):
                    raise ValueError(
                        f"{label}: source row for {chain}:{child_height} disagrees "
                        "with the committed identity manifest"
                    )
                if source_sha256 != identity["source_sha256"].lower():
                    raise ValueError(
                        f"{source_path}: sha256 {source_sha256} disagrees with "
                        f"the committed identity manifest"
                    )
                public_source_path = (
                    f"<chain-archive>/{chain}/classified/{source_path.name}"
                )
                source_classification = (source.get("classification") or "").strip()
                if source_classification != identity["source_classification"]:
                    raise ValueError(
                        f"{source_path}:{source_row_number}: source classification "
                        "disagrees with the committed identity manifest"
                    )
                witness = {
                    "btc_height": str(parent_height),
                    "btc_header_hash": parent_hash,
                    "chain": chain,
                    "child_height": str(child_height),
                    "child_block_hash": identity["child_block_hash"].lower(),
                    "child_block_hash_order": identity[
                        "child_block_hash_order"
                    ].lower(),
                    "child_header_hex": identity["child_header_hex"].lower(),
                    "child_block_time": identity["child_block_time"],
                    "child_nbits": identity["child_nbits"].lower(),
                    "source_btc_height": source_btc_height,
                    "source_kind": "archive_row",
                    "source_path": public_source_path,
                    "source_row_number": str(source_row_number),
                    "source_sha256": source_sha256,
                    "source_classification": source_classification,
                    "btc_height_provenance": "reconciliation-ancestry-path",
                    "child_height_provenance": "source-row",
                    "identity_provenance": identity["identity_provenance"],
                    "catalogue_row_number": "",
                    "provenance": (
                        f"catalogue:{_CATALOGUE_PROVENANCE}|observation:"
                        f"{public_source_path}:{source_row_number}"
                    ),
                }
                witnesses.append(witness)

            observed_chains = sorted(
                value for value in peer["observed_chains"].split("|") if value
            )
            witness_chains = sorted(witness["chain"] for witness in witnesses)
            if observed_chains != witness_chains or len(set(witness_chains)) != len(
                witness_chains
            ):
                raise ValueError(f"{label}: source observations disagree with chains")
            witnesses.sort(key=lambda witness: witness["chain"])
            rule = _required(peer, "rules_violated", label=label)
            if rule != "bip34_coinbase_height_mismatch":
                raise ValueError(f"{label}: unsupported reconciliation rule {rule!r}")
            catalogue_rows.append(
                {
                    "height": str(parent_height),
                    "hash": parent_hash,
                    "btc_prev_hash": _required(peer, "btc_prev_hash", label=label),
                    "btc_header_hex": peer_header,
                    "expected_nbits": _required(peer, "expected_nbits", label=label),
                    "coinbase_height": str(encoded_height),
                    "coinbase_scriptsig_hex": peer_scriptsig,
                    "source_chains": "|".join(witness_chains),
                    "source_child_observations": "|".join(
                        f"{witness['chain']}:{witness['child_height']}"
                        for witness in witnesses
                    ),
                    "rejection_reason": rule.split("|", 1)[0],
                    "rules_violated": rule,
                    "first_observed_child_time": str(
                        min(int(witness["child_block_time"]) for witness in witnesses)
                    ),
                    "provenance": _CATALOGUE_PROVENANCE,
                }
            )
            ledger_rows.extend(witnesses)

    if not catalogue_rows:
        raise ValueError(f"{peer_path}: no classifier-emitted error blocks")
    unused = set(identities) - used_identities
    if unused:
        raise ValueError(
            f"{identity_path}: {len(unused)} child identities were not used by "
            "the reconciliation peer"
        )
    catalogue_rows.sort(key=lambda row: (int(row["height"]), row["hash"]))
    ledger_rows.sort(
        key=lambda row: (
            row["chain"],
            int(row["child_height"]),
            row["btc_header_hash"],
        )
    )
    return ReconciledImport(tuple(catalogue_rows), tuple(ledger_rows))


def merge_ledger_rows(
    *,
    ledger_path: Path,
    imported_rows: tuple[dict[str, str], ...],
    catalogue_rows: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Merge new witnesses and refresh every catalogue row-number reference."""
    rows: dict[tuple[str, int, str], dict[str, str]] = {}
    with ledger_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        missing = set(LEDGER_FIELDS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"{ledger_path}: missing columns: {', '.join(sorted(missing))}"
            )
        for row in reader:
            key = (
                row["chain"],
                int(row["child_height"]),
                normalize_hash(row["btc_header_hash"]),
            )
            if key in rows:
                raise ValueError(f"{ledger_path}: duplicate witness {key}")
            rows[key] = {field: (row.get(field) or "") for field in LEDGER_FIELDS}
    for row in imported_rows:
        key = (row["chain"], int(row["child_height"]), row["btc_header_hash"])
        existing = rows.get(key)
        if existing is not None:
            comparable_existing = {**existing, "catalogue_row_number": ""}
            comparable_imported = {**row, "catalogue_row_number": ""}
            if comparable_existing != comparable_imported:
                raise ValueError(f"{ledger_path}: conflicting witness {key}")
        rows[key] = dict(row)
    catalogue_numbers = {
        (int(row["height"]), normalize_hash(row["hash"])): str(index)
        for index, row in enumerate(catalogue_rows, start=2)
    }
    for row in rows.values():
        key = (int(row["btc_height"]), normalize_hash(row["btc_header_hash"]))
        number = catalogue_numbers.get(key)
        if number is None:
            raise ValueError(
                f"{ledger_path}: witness parent is absent from catalogue {key}"
            )
        row["catalogue_row_number"] = number
    return sorted(
        rows.values(),
        key=lambda row: (
            row["chain"],
            int(row["child_height"]),
            row["btc_header_hash"],
        ),
    )


def write_ledger(rows: list[dict[str, str]], path: Path) -> None:
    """Write an LF-terminated recovered witness ledger."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEDGER_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
