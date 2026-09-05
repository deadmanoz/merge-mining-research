"""Hydrate the canonical subset of the archived VCash explorer sample.

The private VCash Wayback scrape preserves a child-chain height/hash to Bitcoin
parent-hash mapping, but not the 80-byte Bitcoin parent header or its coinbase.
For mappings independently classified as canonical, Bitcoin Core can supply
that missing evidence losslessly.  This module joins the two private TSVs,
reconfirms every selected parent against Bitcoin Core, and emits normalized
monitor-facing rows.

This is deliberately a *partial canonical subset*.  It is not a VCash chain
recovery, and it never promotes the hash-only ``unknown`` rows to stale or
unknown-classified evidence.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from .auxpow_chainid import hash_from_header_bytes, hash_to_display_hex
from .bitcoin_binary import format_outputs_canonical


CHAIN = "vcash"
SOURCE_KIND = "wayback_canonical_hydration"
ARTIFACT_SCOPE = "partial_canonical_subset"
PROVENANCE = "wayback:vcash.tech/block + bitcoin-core:canonical"

OUTPUT_FIELDS = [
    "chain",
    "source_kind",
    "source_path",
    "source_row_number",
    "classification_source_path",
    "classification_source_row_number",
    "artifact_scope",
    "provenance",
    "child_height",
    "child_block_hash",
    "child_block_hash_byte_order",
    "vcash_height",
    "vcash_block_hash_display",
    "vcash_prev_hash_display",
    "vcash_pow_hash_display",
    "vcash_block_version",
    "vcash_block_time_display",
    "child_block_time",
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_nonce",
    "btc_header_hex",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "full_coinbase_hex",
    "classification",
    "validation_status",
    "expected_nbits",
    "rejection_reason",
]


class RpcClient(Protocol):
    """Subset of :class:`BtcRpc` used by the hydrator."""

    def call(self, method: str, params: list | None = None) -> Any:
        """Make a single JSON-RPC call and return its ``result``."""
        ...


@dataclass(frozen=True, slots=True)
class CanonicalMapping:
    vcash_height: int
    vcash_hash_display: str
    vcash_prev_hash_display: str
    vcash_pow_hash_display: str
    vcash_block_version: str
    vcash_block_time_display: str
    child_block_time: int
    btc_hash: str
    btc_height: int
    source_row_number: int
    classification_row_number: int


def _require_fields(
    path: Path, fieldnames: list[str] | None, required: set[str]
) -> None:
    """Raise ``ValueError`` naming any ``required`` column missing from ``fieldnames``."""
    missing = required - set(fieldnames or [])
    if missing:
        raise ValueError(
            f"{path}: missing required columns: {', '.join(sorted(missing))}"
        )


def _require_hash(value: str | None, *, field: str, path: Path, row_number: int) -> str:
    """Return ``value`` normalized to 64-char lowercase hex, or raise ``ValueError``."""
    normalized = (value or "").strip().lower()
    if len(normalized) != 64:
        raise ValueError(f"{path}:{row_number}: {field} must be 64 hex characters")
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(
            f"{path}:{row_number}: {field} must be 64 hex characters"
        ) from exc
    return normalized


def _require_nonnegative_int(
    value: str | int | None, *, field: str, path: Path, row_number: int
) -> int:
    """Parse ``value`` as a non-negative int, or raise ``ValueError`` naming the field/row."""
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{path}:{row_number}: {field} must be an integer") from exc
    if parsed < 0:
        raise ValueError(f"{path}:{row_number}: {field} must be non-negative")
    return parsed


def _archive_path(path: Path) -> str:
    """Return stable provenance without leaking the operator's archive root."""
    return f"<chain-archive>/vcash/wayback_scrape/{path.name}"


def _parse_wayback_utc(
    value: str | None, *, path: Path, row_number: int
) -> tuple[str, int]:
    """Normalize the archived explorer's UTC display time to Unix seconds."""
    display = (value or "").strip()
    try:
        parsed = datetime.strptime(display, "%Y-%m-%d, %H:%M:%S UTC").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValueError(
            f"{path}:{row_number}: age must use YYYY-MM-DD, HH:MM:SS UTC"
        ) from exc
    return display, int(parsed.timestamp())


def load_canonical_mappings(
    wayback_results_path: Path, canonical_classification_path: Path
) -> list[CanonicalMapping]:
    """Join canonical classification rows to their Wayback source mappings."""
    source_by_key: dict[tuple[int, str], tuple[dict[str, str], int]] = {}
    with wayback_results_path.open(newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        _require_fields(
            wayback_results_path,
            reader.fieldnames,
            {
                "vcash_height",
                "vcash_hash",
                "btc_parent_hash",
                "pow_hash",
                "version",
                "age",
                "prev_hash",
            },
        )
        for row_number, row in enumerate(reader, start=2):
            vcash_height = _require_nonnegative_int(
                row.get("vcash_height"),
                field="vcash_height",
                path=wayback_results_path,
                row_number=row_number,
            )
            btc_hash = _require_hash(
                row.get("btc_parent_hash"),
                field="btc_parent_hash",
                path=wayback_results_path,
                row_number=row_number,
            )
            key = (vcash_height, btc_hash)
            if key in source_by_key:
                raise ValueError(
                    f"{wayback_results_path}:{row_number}: duplicate VCash/BTC mapping"
                )
            source_by_key[key] = (row, row_number)

    selected: list[CanonicalMapping] = []
    seen: set[tuple[int, str]] = set()
    with canonical_classification_path.open(newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        _require_fields(
            canonical_classification_path,
            reader.fieldnames,
            {"vcash_height", "btc_parent_hash", "class", "btc_height"},
        )
        for classification_row_number, classification_row in enumerate(reader, start=2):
            if (classification_row.get("class") or "").strip().lower() != "canonical":
                continue
            vcash_height = _require_nonnegative_int(
                classification_row.get("vcash_height"),
                field="vcash_height",
                path=canonical_classification_path,
                row_number=classification_row_number,
            )
            btc_hash = _require_hash(
                classification_row.get("btc_parent_hash"),
                field="btc_parent_hash",
                path=canonical_classification_path,
                row_number=classification_row_number,
            )
            btc_height = _require_nonnegative_int(
                classification_row.get("btc_height"),
                field="btc_height",
                path=canonical_classification_path,
                row_number=classification_row_number,
            )
            key = (vcash_height, btc_hash)
            if key in seen:
                raise ValueError(
                    f"{canonical_classification_path}:{classification_row_number}: "
                    "duplicate canonical VCash/BTC mapping"
                )
            seen.add(key)
            try:
                source_row, source_row_number = source_by_key[key]
            except KeyError as exc:
                raise ValueError(
                    f"{canonical_classification_path}:{classification_row_number}: "
                    "canonical mapping is absent from the Wayback results TSV"
                ) from exc

            vcash_pow_hash = _require_hash(
                source_row.get("pow_hash"),
                field="pow_hash",
                path=wayback_results_path,
                row_number=source_row_number,
            )
            if vcash_pow_hash != btc_hash:
                raise ValueError(
                    f"{wayback_results_path}:{source_row_number}: canonical row's "
                    "pow_hash does not match btc_parent_hash"
                )

            block_time_display, child_block_time = _parse_wayback_utc(
                source_row.get("age"),
                path=wayback_results_path,
                row_number=source_row_number,
            )
            selected.append(
                CanonicalMapping(
                    vcash_height=vcash_height,
                    vcash_hash_display=_require_hash(
                        source_row.get("vcash_hash"),
                        field="vcash_hash",
                        path=wayback_results_path,
                        row_number=source_row_number,
                    ),
                    vcash_prev_hash_display=_require_hash(
                        source_row.get("prev_hash"),
                        field="prev_hash",
                        path=wayback_results_path,
                        row_number=source_row_number,
                    ),
                    vcash_pow_hash_display=vcash_pow_hash,
                    vcash_block_version=(source_row.get("version") or "").strip(),
                    vcash_block_time_display=block_time_display,
                    child_block_time=child_block_time,
                    btc_hash=btc_hash,
                    btc_height=btc_height,
                    source_row_number=source_row_number,
                    classification_row_number=classification_row_number,
                )
            )

    if not selected:
        raise ValueError(
            f"{canonical_classification_path}: no canonical mappings found"
        )
    return sorted(selected, key=lambda item: (item.vcash_height, item.btc_hash))


def _rpc_mapping(value: Any, *, method: str, btc_hash: str) -> Mapping[str, Any]:
    """Return ``value`` if it is a mapping, else raise ``ValueError`` naming the RPC call."""
    if not isinstance(value, Mapping):
        raise ValueError(f"Bitcoin Core {method} returned no object for {btc_hash}")
    return value


def _require_rpc_hash(value: Any, *, field: str, expected: str, method: str) -> None:
    """Raise ``ValueError`` unless ``value`` is a string equal to ``expected`` (case-insensitive)."""
    if not isinstance(value, str) or value.lower() != expected:
        raise ValueError(
            f"Bitcoin Core {method} {field} mismatch: expected {expected}, got {value!r}"
        )


def _require_canonical(
    value: Mapping[str, Any], *, method: str, btc_hash: str, expected_height: int
) -> None:
    """Raise ``ValueError`` unless ``value`` reports positive confirmations and ``expected_height``."""
    confirmations = value.get("confirmations")
    if not isinstance(confirmations, int) or confirmations <= 0:
        raise ValueError(
            f"Bitcoin Core {method} does not report {btc_hash} as canonical"
        )
    height = value.get("height")
    if height != expected_height:
        raise ValueError(
            f"Bitcoin Core {method} height mismatch for {btc_hash}: "
            f"expected {expected_height}, got {height!r}"
        )


def _header_fields(header_hex: str, *, expected_hash: str) -> dict[str, str]:
    """Parse an 80-byte raw Bitcoin header hex string into row-ready fields.

    Verifies the header hashes (SHA256d) to ``expected_hash`` and returns
    ``btc_prev_hash``/``btc_bits`` as display-order lowercase hex,
    ``btc_time``/``btc_nonce`` as decimal strings, and ``btc_header_hex`` as
    the normalized 80-byte header hex. Raises ``ValueError`` on malformed hex,
    wrong length, or a hash mismatch.
    """
    normalized = header_hex.strip().lower()
    try:
        raw = bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(
            f"Bitcoin Core returned malformed header hex for {expected_hash}"
        ) from exc
    if len(raw) != 80:
        raise ValueError(
            f"Bitcoin Core returned a non-80-byte header for {expected_hash}"
        )
    actual_hash = hash_to_display_hex(hash_from_header_bytes(raw))
    if actual_hash != expected_hash:
        raise ValueError(
            f"Bitcoin Core raw header hash mismatch: expected {expected_hash}, got {actual_hash}"
        )
    return {
        "btc_prev_hash": raw[4:36][::-1].hex(),
        "btc_time": str(int.from_bytes(raw[68:72], "little")),
        "btc_bits": raw[72:76][::-1].hex(),
        "btc_nonce": str(int.from_bytes(raw[76:80], "little")),
        "btc_header_hex": normalized,
    }


def _coinbase_fields(block: Mapping[str, Any], *, btc_hash: str) -> dict[str, str]:
    """Extract coinbase fields from a verbosity-2 ``getblock`` result.

    Returns ``coinbase_scriptsig_hex``, ``coinbase_outputs`` (the shared
    canonical rendering via ``format_outputs_canonical``), and
    ``full_coinbase_hex`` (empty string if Core did not include it), all
    lowercase. Raises ``ValueError``
    if the block carries no decoded coinbase transaction, no coinbase input,
    or a malformed scriptSig/output script.
    """
    txs = block.get("tx")
    if not isinstance(txs, list) or not txs or not isinstance(txs[0], Mapping):
        raise ValueError(
            f"Bitcoin Core getblock returned no decoded coinbase for {btc_hash}"
        )
    coinbase = txs[0]
    vin = coinbase.get("vin")
    if not isinstance(vin, list) or not vin or not isinstance(vin[0], Mapping):
        raise ValueError(
            f"Bitcoin Core getblock returned no coinbase input for {btc_hash}"
        )
    scriptsig = vin[0].get("coinbase")
    if not isinstance(scriptsig, str) or not scriptsig:
        raise ValueError(
            f"Bitcoin Core getblock returned no coinbase scriptSig for {btc_hash}"
        )
    try:
        bytes.fromhex(scriptsig)
    except ValueError as exc:
        raise ValueError(
            f"Bitcoin Core getblock returned malformed coinbase scriptSig for {btc_hash}"
        ) from exc

    vout = coinbase.get("vout")
    if not isinstance(vout, list) or not vout:
        raise ValueError(
            f"Bitcoin Core getblock returned no coinbase outputs for {btc_hash}"
        )
    for output in vout:
        if not isinstance(output, Mapping):
            raise ValueError(
                f"Bitcoin Core getblock returned a malformed output for {btc_hash}"
            )
        script = output.get("scriptPubKey")
        script_hex = script.get("hex") if isinstance(script, Mapping) else None
        if not isinstance(script_hex, str):
            raise ValueError(
                f"Bitcoin Core getblock returned an output without script hex for {btc_hash}"
            )
        try:
            bytes.fromhex(script_hex)
        except ValueError as exc:
            raise ValueError(
                f"Bitcoin Core getblock returned malformed output script for {btc_hash}"
            ) from exc

    full_coinbase = coinbase.get("hex", "")
    if full_coinbase in (None, ""):
        full_coinbase = ""
    else:
        if not isinstance(full_coinbase, str):
            raise ValueError(
                f"Bitcoin Core getblock returned malformed coinbase hex for {btc_hash}"
            )
        try:
            bytes.fromhex(full_coinbase)
        except ValueError as exc:
            raise ValueError(
                f"Bitcoin Core getblock returned malformed coinbase hex for {btc_hash}"
            ) from exc

    return {
        "coinbase_scriptsig_hex": scriptsig.lower(),
        "coinbase_outputs": format_outputs_canonical(vout),
        "full_coinbase_hex": full_coinbase.lower(),
    }


def hydrate_mapping(
    mapping: CanonicalMapping,
    rpc: RpcClient,
    *,
    wayback_results_path: Path,
    canonical_classification_path: Path,
) -> dict[str, str]:
    """Hydrate and revalidate one canonical Wayback mapping."""
    verbose_header = _rpc_mapping(
        rpc.call("getblockheader", [mapping.btc_hash, True]),
        method="getblockheader",
        btc_hash=mapping.btc_hash,
    )
    _require_rpc_hash(
        verbose_header.get("hash"),
        field="hash",
        expected=mapping.btc_hash,
        method="getblockheader",
    )
    _require_canonical(
        verbose_header,
        method="getblockheader",
        btc_hash=mapping.btc_hash,
        expected_height=mapping.btc_height,
    )

    raw_header = rpc.call("getblockheader", [mapping.btc_hash, False])
    if not isinstance(raw_header, str):
        raise ValueError(
            f"Bitcoin Core getblockheader returned no raw header for {mapping.btc_hash}"
        )
    header = _header_fields(raw_header, expected_hash=mapping.btc_hash)

    for field, verbose_field in (
        ("btc_prev_hash", "previousblockhash"),
        ("btc_time", "time"),
        ("btc_bits", "bits"),
        ("btc_nonce", "nonce"),
    ):
        verbose_value = verbose_header.get(verbose_field)
        if verbose_value is not None and str(verbose_value).lower() != header[field]:
            raise ValueError(
                f"Bitcoin Core verbose/raw header {verbose_field} mismatch for {mapping.btc_hash}"
            )

    block = _rpc_mapping(
        rpc.call("getblock", [mapping.btc_hash, 2]),
        method="getblock",
        btc_hash=mapping.btc_hash,
    )
    _require_rpc_hash(
        block.get("hash"), field="hash", expected=mapping.btc_hash, method="getblock"
    )
    _require_canonical(
        block,
        method="getblock",
        btc_hash=mapping.btc_hash,
        expected_height=mapping.btc_height,
    )
    coinbase = _coinbase_fields(block, btc_hash=mapping.btc_hash)

    # MMM stores child hashes using rust-bitcoin's internal/to_byte_array order.
    # Preserve the Wayback display-order value separately as raw provenance.
    child_hash_internal = bytes.fromhex(mapping.vcash_hash_display)[::-1].hex()

    return {
        "chain": CHAIN,
        "source_kind": SOURCE_KIND,
        "source_path": _archive_path(wayback_results_path),
        "source_row_number": str(mapping.source_row_number),
        "classification_source_path": _archive_path(canonical_classification_path),
        "classification_source_row_number": str(mapping.classification_row_number),
        "artifact_scope": ARTIFACT_SCOPE,
        "provenance": PROVENANCE,
        "child_height": str(mapping.vcash_height),
        "child_block_hash": child_hash_internal,
        "child_block_hash_byte_order": "internal",
        "vcash_height": str(mapping.vcash_height),
        "vcash_block_hash_display": mapping.vcash_hash_display,
        "vcash_prev_hash_display": mapping.vcash_prev_hash_display,
        "vcash_pow_hash_display": mapping.vcash_pow_hash_display,
        "vcash_block_version": mapping.vcash_block_version,
        "vcash_block_time_display": mapping.vcash_block_time_display,
        "child_block_time": str(mapping.child_block_time),
        "btc_height": str(mapping.btc_height),
        "btc_header_hash": mapping.btc_hash,
        **header,
        **coinbase,
        "classification": "canonical",
        "validation_status": "CANONICAL_CONFIRMED",
        "expected_nbits": "",
        "rejection_reason": "",
    }


def build_vcash_canonical_hydration(
    *,
    wayback_results_path: Path,
    canonical_classification_path: Path,
    output_path: Path,
    rpc: RpcClient,
) -> dict[str, Any]:
    """Build a complete, fail-closed canonical hydration CSV."""
    mappings = load_canonical_mappings(
        wayback_results_path, canonical_classification_path
    )
    rows = [
        hydrate_mapping(
            mapping,
            rpc,
            wayback_results_path=wayback_results_path,
            canonical_classification_path=canonical_classification_path,
        )
        for mapping in mappings
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    return {
        "chain": CHAIN,
        "artifact_scope": ARTIFACT_SCOPE,
        "canonical_rows": len(rows),
        "output": str(output_path),
    }
