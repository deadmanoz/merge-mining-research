"""Shared driver for the per-chain stale/unknown classifier.

Phase 1 checks each 80-byte parent header against the target in its own nBits
(self-consistency, not Bitcoin's contemporaneous target) and deduplicates by
header hash. Phase 2 uses Bitcoin Core: positive ``getblockheader``
confirmations mean canonical; a confirmed parent means STALE at the
authoritative prev-height+1; the remainder are UNKNOWN. Phase 3 is
NON-SKIPPABLE: active-chain parent at the expected height, nBits,
median-time-past, historical minimum block versions, the 2..100-byte coinbase
scriptSig limit, and BIP34's two-stage coinbase-height rule. Passing this
profile is not full-block validation.

``run_classifier`` needs an RPC client, so it is not on the stdlib-only
deployment surface. Its Phase 1 predicate, ``hash_meets_btc_difficulty``,
lives in the stdlib-only ``auxpow_parse`` module.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Optional

from .auxpow_chainid import hash_from_header_bytes
from .auxpow_parse import (
    CHILD_HEADER_FIELDS,
    ChildHeaderValidationError,
    hash_meets_btc_difficulty,
    parse_parent_header,
    validate_child_header_fields,
)
from .btc_rpc import BtcRpc, get_btc_auth
from .bitcoin_epoch_reference import load_nbits_by_epoch
from .btc_nbits_validation import NBITS_MISMATCH_PREFIX
from .btc_stale_validation import (
    NBITS_RETARGET_RULE,
    PLACEMENT_REJECTION,
    consensus_violations,
    validate_stale_header_context,
)
from .config import (
    BITCOIN_EPOCH_REFERENCE_DIR,
    ERROR_BLOCKS_CSV,
    HISTORICAL_CHILD_HEADER_CHAINS,
    ChainSpec,
)

from .error_blocks import load_error_block_keys

# Default RPC batch size, matching the inline copies.
BATCH_SIZE = 200
NOT_FOUND_ERROR_CODE = -5


def _header_result(response: object, *, block_hash: str) -> dict[str, Any] | None:
    """Validate one getblockheader response, allowing only block-not-found."""
    if not isinstance(response, dict):
        raise ValueError(f"getblockheader response for {block_hash} is not an object")
    error = response.get("error")
    if error is not None:
        if isinstance(error, dict) and error.get("code") == NOT_FOUND_ERROR_CODE:
            return None
        raise RuntimeError(f"getblockheader failed for {block_hash}: {error!r}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise ValueError(f"getblockheader returned no header for {block_hash}")
    returned_hash = result.get("hash")
    if (
        not isinstance(returned_hash, str)
        or returned_hash.lower() != block_hash.lower()
    ):
        raise ValueError(
            f"getblockheader hash mismatch for {block_hash}: {returned_hash!r}"
        )
    return result


def _is_active_chain_header(result: object, *, block_hash: str) -> bool:
    """Validate a verbose getblockheader result and test active-chain status."""
    if result is None:
        return False
    if not isinstance(result, dict):
        raise ValueError(f"getblockheader result for {block_hash} is not an object")
    confirmations = result.get("confirmations")
    if not isinstance(confirmations, int) or isinstance(confirmations, bool):
        raise ValueError(
            f"getblockheader result for {block_hash} lacks integer confirmations"
        )
    return confirmations > 0


def _ordered_batch_responses(
    responses: object, *, expected_count: int, method: str
) -> list[dict[str, Any]]:
    """JSON-RPC batch ids may arrive in any order.

    Missing, duplicate, boolean, negative, or out-of-range ids fail the whole
    batch closed.
    """
    if not isinstance(responses, list):
        raise ValueError(f"{method} batch response is not a list")
    by_id: dict[int, dict[str, Any]] = {}
    for response in responses:
        if not isinstance(response, dict):
            raise ValueError(f"{method} batch response contains a non-object")
        response_id = response.get("id")
        if (
            not isinstance(response_id, int)
            or isinstance(response_id, bool)
            or response_id < 0
            or response_id >= expected_count
        ):
            raise ValueError(f"{method} batch response has an invalid id")
        if response_id in by_id:
            raise ValueError(f"{method} batch response has duplicate id {response_id}")
        by_id[response_id] = response
    if len(by_id) != expected_count:
        missing = sorted(set(range(expected_count)) - set(by_id))
        raise ValueError(f"{method} batch response is missing ids {missing}")
    return [by_id[i] for i in range(expected_count)]


# Shared column order. The child-height column is inserted before
# ``classification`` so the layout stays stable across chains.
_BASE_OUTPUT_COLUMNS = [
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
]
_TRAILING_OUTPUT_COLUMNS = [
    "classification",
    "validation_status",
    "expected_nbits",
]
_CHILD_OUTPUT_COLUMNS = [
    "child_block_hash",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
]

# Pipe-joined consensus rules the row's own bytes prove. Error-block artifact
# only. The name and ``|`` separator are the authored error-catalogue contract.
RULES_VIOLATED_COLUMN = "rules_violated"


def output_columns(height_col: str) -> list[str]:
    """``height_col`` stays present even when a row cannot authenticate it.

    ``validation_status`` and ``expected_nbits`` trail the row so the Phase 3
    annotations are always carried.
    """
    if (
        not isinstance(height_col, str)
        or not height_col
        or height_col.strip() != height_col
    ):
        raise ValueError("height_col must be a non-empty stripped string")
    cols = list(_BASE_OUTPUT_COLUMNS)
    cols.append(height_col)
    cols.extend(_CHILD_OUTPUT_COLUMNS)
    cols.extend(_TRAILING_OUTPUT_COLUMNS)
    return cols


def normalize_bits_hex(value: object, *, source_is_decimal: bool = False) -> str:
    """Normalize ``btc_bits`` to lowercase 8-char hex. Never infer the base.

    ``validate_stale_nbits`` compares the value with Bitcoin Core's hex
    ``bits``. ``19548732`` is valid hex; ``386924253`` (Bitcoin Vault) is
    decimal. ``source_is_decimal`` names the input artifact, not the chain.
    Decimal values are re-emitted as hex; hex values are only lowercased. A
    non-conforming value raises ``ValueError``.
    """
    text = str(value).strip()
    if source_is_decimal:
        return f"{int(text):08x}"
    lowered = text.lower()
    if len(lowered) != 8 or any(c not in "0123456789abcdef" for c in lowered):
        raise ValueError(f"btc_bits is not 8-char hex: {value!r}")
    return lowered


def _meets_btc_difficulty(header_hex: str) -> bool:
    """Phase 1 self-target check through ``hash_from_header_bytes``.

    Display order comes from that helper and ``hash_meets_btc_difficulty``,
    not ad hoc ``[::-1]`` slicing.
    """
    try:
        raw = bytes.fromhex(header_hex)
    except (ValueError, TypeError):
        return False
    if len(raw) != 80:
        return False
    bits = int.from_bytes(raw[72:76], "little")
    header_hash_internal = hash_from_header_bytes(raw)
    return hash_meets_btc_difficulty(header_hash_internal, bits)


def _validate_candidate_header(
    row: dict[str, Any],
    *,
    row_number: int,
    bits_source_is_decimal: bool,
) -> dict[str, Any]:
    """Corroborate candidate identity fields against its serialized header."""
    header_hex = str(row.get("btc_header_hex", "") or "").strip()
    if len(header_hex) != 160:
        raise ValueError(
            f"candidate row {row_number}: btc_header_hex must be exactly "
            "160 hex characters"
        )
    try:
        raw_header = bytes.fromhex(header_hex)
    except ValueError as exc:
        raise ValueError(
            f"candidate row {row_number}: btc_header_hex must be exactly "
            "160 hex characters"
        ) from exc

    parsed = parse_parent_header(raw_header)
    stated_hash = str(row.get("btc_header_hash", "") or "").strip().lower()
    stated_prev = str(row.get("btc_prev_hash", "") or "").strip().lower()
    stated_time = str(row.get("btc_time", "") or "").strip()
    try:
        stated_bits = normalize_bits_hex(
            row.get("btc_bits", ""),
            source_is_decimal=bits_source_is_decimal,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"candidate row {row_number}: malformed btc_bits") from exc

    if parsed["hash"] != stated_hash:
        raise ValueError(
            f"candidate row {row_number}: btc_header_hash does not match btc_header_hex"
        )
    if parsed["prev_hash"] != stated_prev:
        raise ValueError(
            f"candidate row {row_number}: btc_prev_hash does not match btc_header_hex"
        )
    if str(parsed["time"]) != stated_time:
        raise ValueError(
            f"candidate row {row_number}: btc_time does not match btc_header_hex"
        )
    if parsed["bits_hex"] != stated_bits:
        raise ValueError(
            f"candidate row {row_number}: btc_bits does not match btc_header_hex"
        )

    row["btc_bits"] = stated_bits
    return parsed


def classify_candidates(
    candidates: list[dict],
    rpc: BtcRpc,
) -> list[dict]:
    """Active-chain header is canonical; active-chain parent is direct stale.

    Stale height is the canonical prev height + 1. Phase 3 rejects a mandatory
    BIP34 coinbase-height mismatch rather than correcting it.
    """
    results: list[dict] = []
    if not candidates:
        return results

    for i, candidate in enumerate(candidates, start=1):
        parsed_header = _validate_candidate_header(
            candidate,
            row_number=i,
            bits_source_is_decimal=False,
        )
        if not hash_meets_btc_difficulty(
            hash_from_header_bytes(bytes.fromhex(parsed_header["header_hex"])),
            parsed_header["bits"],
        ):
            raise ValueError(
                f"candidate row {i}: btc_header_hex does not satisfy its nBits target"
            )

    # Canonical parents are merge-mining evidence and are emitted, not dropped.
    calls = [
        {
            "jsonrpc": "1.0",
            "id": i,
            "method": "getblockheader",
            "params": [c["btc_header_hash"]],
        }
        for i, c in enumerate(candidates)
    ]
    responses = _ordered_batch_responses(
        rpc.batch(calls), expected_count=len(calls), method="getblockheader"
    )

    non_canonical: list[dict] = []
    for idx, resp in enumerate(responses):
        candidate = candidates[idx]
        result = _header_result(resp, block_hash=candidate["btc_header_hash"])
        if _is_active_chain_header(result, block_hash=candidate["btc_header_hash"]):
            candidate["classification"] = "canonical"
            height = result.get("height")
            if not isinstance(height, int) or isinstance(height, bool) or height < 0:
                raise ValueError(
                    "active-chain getblockheader result lacks a valid height for "
                    f"{candidate['btc_header_hash']}"
                )
            candidate["btc_height"] = str(height)
            results.append(candidate)
            continue
        non_canonical.append(candidates[idx])

    if not non_canonical:
        return results

    prev_calls = [
        {
            "jsonrpc": "1.0",
            "id": i,
            "method": "getblockheader",
            "params": [c["btc_prev_hash"]],
        }
        for i, c in enumerate(non_canonical)
    ]
    prev_responses = _ordered_batch_responses(
        rpc.batch(prev_calls),
        expected_count=len(prev_calls),
        method="getblockheader parent",
    )

    for idx, resp in enumerate(prev_responses):
        candidate = non_canonical[idx]
        prev_data = _header_result(resp, block_hash=candidate["btc_prev_hash"])
        if _is_active_chain_header(prev_data, block_hash=candidate["btc_prev_hash"]):
            candidate["classification"] = "stale"
            # prev+1 height is authoritative. A mandatory BIP34 mismatch is
            # rejected by the Phase 3 consensus gate.
            prev_height = prev_data.get("height")
            if (
                not isinstance(prev_height, int)
                or isinstance(prev_height, bool)
                or prev_height < 0
            ):
                raise ValueError(
                    "active-chain getblockheader result lacks a valid height for "
                    f"{candidate['btc_prev_hash']}"
                )
            candidate["btc_height"] = str(prev_height + 1)
            results.append(candidate)
        else:
            # Prev not found => parent state unknown (not canonical, not
            # linkable to a known stale). The merge-mining-monitor uses the
            # same vocabulary (ParentKind::Unknown); legacy artifacts wrote
            # "orphan" here, and readers still accept both.
            candidate["classification"] = "unknown"
            results.append(candidate)

    return results


def _contamination_evidence(
    row: dict[str, Any],
    *,
    status: str,
    bits_key: str,
    expected_key: str,
) -> Optional[bool]:
    """Whether this header's difficulty is not Bitcoin's at its height.

    ``True`` is another SHA-256 chain, ``False`` matches, ``None`` is
    inconclusive. A later context REJECTED can overwrite an nBits status, so
    the durable evidence is ``expected_nbits``.
    """
    if status.startswith(NBITS_MISMATCH_PREFIX):
        return True
    expected = str(row.get(expected_key, "") or "").strip().lower()
    bits = str(row.get(bits_key, "") or "").strip().lower()
    if not expected or not bits:
        return None
    return expected != bits


def _meets_canonical_btc_difficulty(
    row: dict[str, Any],
    *,
    expected_key: str,
    header_hex_key: str = "btc_header_hex",
) -> bool:
    """Whether the digest meets Bitcoin's canonical target at this height.

    Phase 1 only checks the header's own nBits. At a rising retarget those
    bits are easier, so a header can clear its embedded target and still be a
    share. Fails closed: an unusable header or ``expected_nbits`` is False.
    """
    try:
        raw = bytes.fromhex(str(row.get(header_hex_key, "") or "").strip())
    except (ValueError, TypeError):
        return False
    if len(raw) != 80:
        return False
    try:
        expected_bits = int(str(row.get(expected_key, "") or "").strip(), 16)
    except ValueError:
        return False
    return hash_meets_btc_difficulty(hash_from_header_bytes(raw), expected_bits)


def rejection_route(
    row: dict[str, Any],
    rules: list[str],
    *,
    status: str,
    bits_key: str = "btc_bits",
    expected_key: str = "expected_nbits",
) -> Optional[str]:
    """Classification a REJECTED verdict supports, or ``None`` to leave it.

    Several claims can hold at once. The weakest wins, in order:

    1. Placement rejection: no active-chain predecessor, so the height was
       never established and the row is ``unknown``. Only unknown rows are
       walked back to a stale root.
    2. Contamination beats a broken rule, except ``NBITS_RETARGET_RULE`` once
       the digest also meets the canonical target. Phase 1 only proved the
       embedded target; at a rising retarget the previous epoch's bits are
       easier, so a share must not be published as full proof of work.
    3. Re-derived rules then make the row an error block.
    4. Unusable evidence stays put. A contamination comparison that cannot be
       made is not evidence the header is Bitcoin's.
    """
    if status == PLACEMENT_REJECTION:
        return "unknown"
    contaminated = _contamination_evidence(
        row, status=status, bits_key=bits_key, expected_key=expected_key
    )
    if contaminated is None:
        return None
    retarget_exception = (
        NBITS_RETARGET_RULE in rules
        and _meets_canonical_btc_difficulty(row, expected_key=expected_key)
    )
    if contaminated and not retarget_exception:
        return "unknown"
    if rules:
        return "error_block"
    return None


def route_rejected_stale_rows(
    stales: list[dict[str, Any]],
    *,
    nbits_by_epoch: Optional[dict[int, int]] = None,
) -> None:
    """Re-route rejected stale rows in place by ``rejection_route``.

    Rules come from the bytes, not the verdict string, so unusable evidence
    stays put. An ``error_block`` row stores the full pipe-joined set on
    ``RULES_VIOLATED_COLUMN``: ``validation_status`` names only the first
    gate, and an unapplied retarget is rejected as a generic nBits mismatch.
    The epoch table is read only when routing consults it.
    """
    rejected = [
        row
        for row in stales
        if str(row.get("validation_status", "")).startswith("REJECTED:")
    ]
    if not rejected:
        return
    for row in rejected:
        status = str(row.get("validation_status", ""))
        if status == PLACEMENT_REJECTION:
            # Settle placement before the epoch table. A height past the
            # committed reference fails closed in the retarget check and would
            # abort a run whose route never needed that rule.
            route = rejection_route(row, [], status=status)
            if route is not None:
                row["classification"] = route
            continue
        if nbits_by_epoch is None:
            nbits_by_epoch = load_nbits_by_epoch(BITCOIN_EPOCH_REFERENCE_DIR)
        rules = consensus_violations(
            row,
            int(row["btc_height"]),
            parent_median_time_past=row.get("_parent_median_time_past"),
            nbits_by_epoch=nbits_by_epoch,
        )
        route = rejection_route(row, rules, status=status)
        if route is not None:
            row["classification"] = route
            if route == "error_block":
                # ``rejection_route`` only returns ``error_block`` when
                # ``rules`` is non-empty, so this is never a blank claim.
                row[RULES_VIOLATED_COLUMN] = "|".join(rules)


def _derive_tag_path(stale_path: str, tag: str) -> str:
    """Replace ``_stale_blocks`` in the basename, or append ``tag`` to the stem."""
    p = Path(stale_path)
    name = p.name
    if "_stale_blocks" in name:
        return str(p.with_name(name.replace("_stale_blocks", tag)))
    return str(p.with_name(p.stem + tag + ".csv"))


def derive_split_paths(stale_path: str) -> tuple[str, str, str]:
    """Map ``_stale_blocks`` to the canonical, unknown, and error-block peers.

    Every path ``write_classifier_outputs`` needs comes from here.
    """
    return (
        _derive_tag_path(stale_path, "_canonical_blocks"),
        _derive_tag_path(stale_path, "_unknown_blocks"),
        _derive_tag_path(stale_path, "_error_blocks"),
    )


def _write_split_file(path: str, rows: list[dict], *, columns: list[str]) -> None:
    """Sort by ``btc_height`` and always write the header, even when empty."""
    rows.sort(key=lambda x: int(x.get("btc_height", 0) or 0))
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _validate_distinct_outputs(labelled: dict[str, str]) -> None:
    """Refuse aliased outputs before any file is opened.

    Later writes replace earlier ones, so a VALID-only loader path pointed at
    a derived peer would be overwritten by that bucket. Near and all-valid
    files are written outside the shared writer and must be in the same check.
    """
    seen: dict[Path, str] = {}
    for label, path in labelled.items():
        resolved = Path(path).resolve()
        previous = seen.get(resolved)
        if previous is not None:
            raise ValueError(f"{label} aliases {previous}: {resolved}")
        seen[resolved] = label


def write_classifier_outputs(
    all_results: list[dict],
    *,
    columns: list[str],
    canonical_path: str,
    stale_path: str,
    unknown_path: str,
    validated_path: str,
    error_block_path: str,
    error_blocks_path: Path = ERROR_BLOCKS_CSV,
) -> dict[str, int]:
    """Partition on primary ``classification`` and write the five bucket files.

    Only the error-block file appends ``RULES_VIOLATED_COLUMN``. Peers keep
    the caller's schema, including the committed validated-stale loader input
    the monitor importer reads. ``validated`` is ``stale`` with
    ``validation_status == "VALID"``, minus exact catalogue keys. Canonical
    and unresolved-unknown rows clear stale-gate annotations. A missing or
    unrecognised classification raises rather than dropping the row. ``near``
    rows never reach here. ``rejected`` counts every bucket, because counting
    only stale rows would hide a fully re-routed run. Aliased paths raise
    before anything is written.
    """
    _validate_distinct_outputs(
        {
            "canonical output": canonical_path,
            "stale output": stale_path,
            "unknown output": unknown_path,
            "validated-stale output": validated_path,
            "error-block output": error_block_path,
        }
    )
    buckets: dict[str, list[dict]] = {
        "canonical": [],
        "stale": [],
        "unknown": [],
        "error_block": [],
    }
    rejected_by_bucket: dict[str, int] = dict.fromkeys(buckets, 0)
    for row_number, row in enumerate(all_results, start=1):
        classification = row.get("classification")
        bucket = buckets.get(classification)
        if bucket is None:
            raise ValueError(
                f"row {row_number} has unrecognised classification "
                f"{classification!r} (expected one of {sorted(buckets)}); "
                f"btc_header_hash={row.get('btc_header_hash', '')!r}"
            )
        if str(row.get("validation_status", "")).startswith("REJECTED"):
            rejected_by_bucket[classification] += 1
        output_row = dict(row)
        if classification in ("canonical", "unknown"):
            output_row["validation_status"] = ""
            output_row["expected_nbits"] = ""
            output_row["rejection_reason"] = ""
        bucket.append(output_row)
    excluded = load_error_block_keys(error_blocks_path)
    validated = [
        s
        for s in buckets["stale"]
        if s.get("validation_status") == "VALID"
        and (int(s["btc_height"]), str(s["btc_header_hash"]).lower()) not in excluded
    ]

    error_block_columns = list(columns)
    if RULES_VIOLATED_COLUMN not in error_block_columns:
        error_block_columns.append(RULES_VIOLATED_COLUMN)

    _write_split_file(canonical_path, buckets["canonical"], columns=columns)
    _write_split_file(stale_path, buckets["stale"], columns=columns)
    _write_split_file(unknown_path, buckets["unknown"], columns=columns)
    _write_split_file(validated_path, validated, columns=columns)
    _write_split_file(
        error_block_path, buckets["error_block"], columns=error_block_columns
    )

    return {
        "canonical": len(buckets["canonical"]),
        "stale": len(buckets["stale"]),
        "unknown": len(buckets["unknown"]),
        "error_block": len(buckets["error_block"]),
        "valid": len(validated),
        "rejected": sum(rejected_by_bucket.values()),
        "rejected_stale": rejected_by_bucket["stale"],
        "rejected_error_block": rejected_by_bucket["error_block"],
        "rejected_unknown": rejected_by_bucket["unknown"],
        "validation_unknown": sum(
            1
            for s in buckets["stale"]
            if str(s.get("validation_status", "")).startswith("UNKNOWN")
        ),
    }


def run_classifier(
    spec: ChainSpec,
    *,
    input_path: Optional[str] = None,
    output_path: Optional[str] = None,
    validated_output_path: Optional[str] = None,
    canonical_output_path: Optional[str] = None,
    unknown_output_path: Optional[str] = None,
    error_block_output_path: Optional[str] = None,
    keep_near: bool = False,
    near_output_path: Optional[str] = None,
    all_valid: bool = False,
    all_valid_path: Optional[str] = None,
    bits_source_is_decimal: bool = False,
    rpc: Optional[BtcRpc] = None,
) -> dict[str, Any]:
    """Run Phases 1--3 for one chain. Phase 3 is NON-SKIPPABLE.

    The validated output is ``stale`` with ``validation_status == "VALID"``,
    the committed loader input. ``bits_source_is_decimal`` describes the input
    artifact, not the chain; ``btc_bits`` is lowercase 8-char hex before the
    gate. Near rows miss their own encoded target and stay out of Phase 2/3
    unless ``keep_near``; the default run stays byte-identical. Every path
    this run writes must be distinct. ``getblockcount`` preflights before
    Phase 1, and a failed Phase 2 batch is retried one row at a time. Passing
    this profile is not full-block validation.
    """
    in_path = input_path or str(spec.input_csv)
    out_path = output_path or str(spec.output_csv)
    validated_path = validated_output_path or str(spec.validated_csv)
    # Canonical parents stay in their own artifact so the stale inventory
    # keeps its established composition.
    default_canonical, default_unknown, default_error_block = derive_split_paths(
        out_path
    )
    if canonical_output_path is None:
        canonical_output_path = default_canonical
    if unknown_output_path is None:
        unknown_output_path = default_unknown
    error_block_path = error_block_output_path or default_error_block
    height_col = spec.height_column

    # Check every path this run will write before opening one. Near and
    # all-valid files sit outside the shared writer, so an alias would replace
    # a bucket. Unused defaults are not in the set.
    near_path_out: Optional[str] = None
    if keep_near:
        near_path_out = near_output_path or _derive_tag_path(out_path, "_near_blocks")
    all_valid_out: Optional[str] = None
    if all_valid:
        all_valid_out = (
            all_valid_path or out_path.rsplit(".csv", 1)[0] + ".btc_valid.csv"
        )
    run_destinations = {
        "canonical output": canonical_output_path,
        "stale output": out_path,
        "unknown output": unknown_output_path,
        "validated-stale output": validated_path,
        "error-block output": error_block_path,
    }
    if near_path_out is not None:
        run_destinations["near output"] = near_path_out
    if all_valid_out is not None:
        run_destinations["all-valid output"] = all_valid_out
    _validate_distinct_outputs(run_destinations)

    if rpc is None:
        auth = get_btc_auth()
        rpc = BtcRpc(auth=auth)

    try:
        probe = rpc.batch(
            [{"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}]
        )
        if not probe or probe[0].get("result") is None:
            raise RuntimeError("getblockcount preflight returned no result")
    except Exception as exc:  # noqa: BLE001 - surface any transport/auth failure
        raise RuntimeError(
            f"Bitcoin Core RPC preflight failed before classifying {spec.key}: {exc}"
        ) from exc

    valid_headers: list[dict] = []
    near_headers: list[dict] = []
    seen_near: set[str] = set()
    total = 0
    seen_hashes: set[str] = set()
    with open(in_path, newline="") as f:
        reader = csv.DictReader(f)
        for row_number, row in enumerate(reader, start=2):
            total += 1
            parsed_header = _validate_candidate_header(
                row,
                row_number=row_number,
                bits_source_is_decimal=bits_source_is_decimal,
            )
            populated_child_fields = [
                field for field in CHILD_HEADER_FIELDS if (row.get(field) or "").strip()
            ]
            # Target historical chains require a complete authenticated
            # bundle. Non-target live-chain evidence may expose only a source-
            # native subset; complete bundles are always authenticated.
            if spec.key in HISTORICAL_CHILD_HEADER_CHAINS or len(
                populated_child_fields
            ) == len(CHILD_HEADER_FIELDS):
                try:
                    validate_child_header_fields(
                        row,
                        nbits_from_header=spec.child_nbits_from_header,
                    )
                except ChildHeaderValidationError as exc:
                    raise ChildHeaderValidationError(
                        f"{spec.key} classifier input row {row_number} "
                        f"(btc_header_hash={parsed_header['hash']}): {exc}"
                    ) from exc
            if hash_meets_btc_difficulty(
                hash_from_header_bytes(bytes.fromhex(parsed_header["header_hex"])),
                parsed_header["bits"],
            ):
                btc_hash = parsed_header["hash"]
                if btc_hash not in seen_hashes:
                    seen_hashes.add(btc_hash)
                    valid_headers.append(row)
            elif keep_near:
                # Misses its own encoded target. Kept, deduped by hash, as
                # sibling evidence for shared-parent fork detection.
                btc_hash = parsed_header["hash"]
                if btc_hash and btc_hash not in seen_near:
                    seen_near.add(btc_hash)
                    near_headers.append(row)

    if all_valid_out is not None and valid_headers:
        with open(all_valid_out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(valid_headers[0].keys()))
            writer.writeheader()
            writer.writerows(valid_headers)

    # A failed batch is retried one candidate at a time.
    all_results: list[dict] = []
    for batch_start in range(0, len(valid_headers), BATCH_SIZE):
        batch = valid_headers[batch_start : batch_start + BATCH_SIZE]
        try:
            all_results.extend(classify_candidates(batch, rpc))
        except Exception:  # noqa: BLE001 - retry the batch one row at a time
            for candidate in batch:
                all_results.extend(classify_candidates([candidate], rpc))

    if len(all_results) != len(valid_headers):
        raise RuntimeError(
            "classification produced a partial result set "
            f"({len(all_results)} of {len(valid_headers)} headers)"
        )
    result_hashes = [str(row.get("btc_header_hash", "")) for row in all_results]
    if len(set(result_hashes)) != len(result_hashes):
        raise RuntimeError("classification produced duplicate header results")

    # Phase 1 already normalized each source value in
    # ``_validate_candidate_header`` and mutated the retained row to canonical
    # lowercase hex. Revalidate that canonical representation here without
    # applying the source-specific decimal conversion a second time.
    for row in all_results:
        if row.get("btc_bits"):
            row["btc_bits"] = normalize_bits_hex(row["btc_bits"])

    stales = [r for r in all_results if r["classification"] == "stale"]

    # NON-SKIPPABLE. Mutates the stale dicts the writer later re-partitions.
    validate_stale_header_context(
        stales,
        rpc.batch,
        height_key="btc_height",
        bits_key="btc_bits",
        status_key="validation_status",
        expected_key="expected_nbits",
    )

    route_rejected_stale_rows(stales)
    stales = [row for row in stales if row["classification"] == "stale"]

    validation_unknown = [
        row
        for row in stales
        if str(row.get("validation_status", "")).startswith("UNKNOWN:")
    ]
    if validation_unknown:
        raise RuntimeError(
            "stale validation is incomplete; refusing to replace outputs "
            f"({len(validation_unknown)} of {len(stales)} stale candidates UNKNOWN)"
        )

    counts = write_classifier_outputs(
        all_results,
        columns=output_columns(height_col),
        canonical_path=canonical_output_path,
        stale_path=out_path,
        unknown_path=unknown_output_path,
        error_block_path=error_block_path,
        validated_path=validated_path,
    )

    if near_path_out is not None:
        for row in near_headers:
            row["classification"] = "near"
        _write_split_file(
            near_path_out, near_headers, columns=output_columns(height_col)
        )

    return {
        "total": total,
        "btc_valid": len(valid_headers),
        "canonical": counts["canonical"],
        "stale": counts["stale"],
        "unknown": counts["unknown"],
        "error_block": counts["error_block"],
        "valid": counts["valid"],
        "rejected": counts["rejected"],
        "rejected_stale": counts["rejected_stale"],
        "rejected_error_block": counts["rejected_error_block"],
        "rejected_unknown": counts["rejected_unknown"],
        "validation_unknown": counts["validation_unknown"],
        "near": len(near_headers) if keep_near else 0,
        "output_path": out_path,
        "unknown_output_path": unknown_output_path,
        "error_block_output_path": error_block_path,
        "validated_output_path": validated_path,
        "canonical_output_path": canonical_output_path,
        "near_output_path": near_path_out,
    }
