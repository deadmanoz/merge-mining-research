"""Shared driver for the per-chain stale/unknown classifier family.

The ``scripts/classify_<chain>_stales.py`` family (ixcoin, devcoin, unobtanium,
myriadcoin, crown, terracoin, syscoin, elastos, emercoin, ...) duplicates the
same three-phase pipeline roughly seventeen times. The canonical template is
``scripts/classify_ixcoin_stales.py``:

  Phase 1 -- PoW filter (pure Python, no RPC):
    Compute SHA256d of each 80-byte parent header and check it meets the
    target encoded in its own nBits. This is a self-consistency check, not a
    comparison with Bitcoin's contemporaneous target. Deduplicate by header
    hash so each unique candidate header is classified once.

  Phase 2 -- Bitcoin Core classification (batched RPC):
    For each surviving unique header, ``getblockheader <hash>`` with positive
    confirmations means canonical. Otherwise, ``getblockheader <prev_hash>``
    with positive confirmations means STALE (with the authoritative
    prev-height+1 override); the remainder are UNKNOWN.

  Phase 3 -- available-evidence header/context gates (NON-SKIPPABLE):
    Require an active-chain parent at the expected height, validate nBits and
    median-time-past, enforce historical minimum block versions, enforce the
    2..100-byte coinbase scriptSig limit, and apply BIP34's two-stage
    coinbase-height rule. Passing this profile is not full-block validation.

This module provides the reusable driver. The Bucket-A ``classify_*_stales.py``
scripts have since been reduced to thin ``main()`` wrappers that call
``run_classifier(CHAIN_SPECS['<chain>'])`` (preserved by
``tests/test_classifier_wrappers.py``); Bucket-B chains keep a bespoke ``main()``
where their pipeline diverges from the three-phase template.

DEPLOYMENT NOTE: ``run_classifier`` needs an RPC client, so it is not part of
the stdlib-only deployment surface. The Phase 1 PoW predicate it leans on
(``hash_meets_btc_difficulty``) lives in the stdlib-only ``auxpow_parse``
module.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Optional

from .auxpow_chainid import hash_from_header_bytes
from .auxpow_parse import hash_meets_btc_difficulty, parse_parent_header
from .btc_rpc import BtcRpc, get_btc_auth
from .btc_stale_validation import validate_stale_header_context
from .config import ChainSpec

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
    """Validate batch response ids and return exact request order.

    JSON-RPC batch responses may arrive in any order. Missing, duplicate,
    boolean, negative, or out-of-range ids make positional association unsafe,
    so the entire batch fails closed instead of silently omitting candidates.
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


# Standard output column order for confirmed stale/unknown rows, matching the
# canonical ixcoin template. The per-chain child-height column is appended
# before ``classification`` so the layout is stable across chains.
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


def output_columns(height_col: Optional[str]) -> list[str]:
    """Build the OUTPUT_COLUMNS list for a chain.

    ``height_col`` is the per-chain child-height column (e.g. ``ixc_height``).
    When ``None`` no child-height column is emitted. The nBits-gate annotation
    columns (``validation_status`` / ``expected_nbits``) trail the row so the
    Phase 3 gate output is always carried.
    """
    cols = list(_BASE_OUTPUT_COLUMNS)
    if height_col:
        cols.append(height_col)
    cols.extend(_TRAILING_OUTPUT_COLUMNS)
    return cols


def normalize_bits_hex(value: object, *, source_is_decimal: bool = False) -> str:
    """Normalize a ``btc_bits`` value to lowercase 8-char hex compact bits.

    ``validate_stale_nbits`` compares ``btc_bits`` directly against Bitcoin
    Core's hex ``bits``, so every row must carry lowercase 8-char hex. The base
    is NEVER inferred from the value's digits: an 8-char all-digit string such as
    ``19548732`` is valid hex, while a 9-digit string such as ``386924253``
    (legacy bitcoin-vault) is decimal. The caller states which by passing
    ``source_is_decimal`` based on the INPUT ARTIFACT it is reading (only the
    legacy bitcoin-vault committed CSV is decimal), not the chain identity.

    With ``source_is_decimal`` true, ``value`` is parsed as a decimal int and
    re-emitted as hex. Otherwise the value must already be 8 hex chars and is
    only lowercased; a non-conforming value raises ``ValueError`` so a real
    data problem is loud rather than silently mis-gated.
    """
    text = str(value).strip()
    if source_is_decimal:
        return f"{int(text):08x}"
    lowered = text.lower()
    if len(lowered) != 8 or any(c not in "0123456789abcdef" for c in lowered):
        raise ValueError(f"btc_bits is not 8-char hex: {value!r}")
    return lowered


def _meets_btc_difficulty(header_hex: str) -> bool:
    """Phase 1 PoW predicate for a hex parent header.

    Mirrors the inline ``hash_meets_target`` but routes through the mandated
    byte-order helper (``hash_from_header_bytes``) and the shared
    ``hash_meets_btc_difficulty`` rather than ad hoc ``[::-1]`` slicing.
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
    """Classify a batch of headers that pass their encoded self-target.

    For each candidate:
      1. ``getblockheader <btc_header_hash>`` -- if it resolves on the active
         chain, the header is CANONICAL and is emitted with Bitcoin Core's
         authoritative height.
      2. Otherwise ``getblockheader <btc_prev_hash>`` -- if the prev resolves
         on the active chain, the candidate is a direct STALE block; otherwise
         its parent state is UNKNOWN.

    For stale rows the canonical prev height + 1 is authoritative. The Phase 3
    BIP34 gate then rejects, rather than silently corrects, any mandatory
    coinbase-height mismatch. Chain-specific columns on each candidate (such
    as the child height) pass through untouched.
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

    # Step 1: canonical check via getblockheader(hash). Canonical parents are
    # merge-mining evidence in their own right (which pool built on which
    # canonical block, via which chain), so they are emitted, not dropped.
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

    # Step 2: prev-hash linkage for non-canonical headers.
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
            # Active-chain prev exists => direct-stale header candidate.
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


def _derive_tag_path(stale_path: str, tag: str) -> str:
    """Substitute a bucket tag into the stale-inventory path's basename.

    ``_stale_blocks`` -> ``tag`` in the basename; when the name has no
    ``_stale_blocks`` marker the tag is appended to the stem. Shared by
    ``derive_split_paths`` and the near-file derivation in ``run_classifier``.
    """
    p = Path(stale_path)
    name = p.name
    if "_stale_blocks" in name:
        return str(p.with_name(name.replace("_stale_blocks", tag)))
    return str(p.with_name(p.stem + tag + ".csv"))


def derive_split_paths(stale_path: str) -> tuple[str, str]:
    """Derive the canonical and unknown output paths from the stale-inventory
    path: ``_stale_blocks`` -> ``_canonical_blocks`` / ``_unknown_blocks``. When
    the name has no ``_stale_blocks`` marker, the tag is appended to the stem.
    Returns ``(canonical_path, unknown_path)``.
    """
    return (
        _derive_tag_path(stale_path, "_canonical_blocks"),
        _derive_tag_path(stale_path, "_unknown_blocks"),
    )


def _write_split_file(path: str, rows: list[dict], *, columns: list[str]) -> None:
    """Write ``rows`` to ``path`` on the shared ``columns`` schema.

    Rows are sorted by ``btc_height`` and the header is always written, even
    when the bucket is empty. Extra keys are ignored so a raw candidate row can
    be written against the split schema unchanged.
    """
    rows.sort(key=lambda x: int(x.get("btc_height", 0) or 0))
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_classifier_outputs(
    all_results: list[dict],
    *,
    columns: list[str],
    canonical_path: str,
    stale_path: str,
    unknown_path: str,
    validated_path: str,
) -> dict[str, int]:
    """Partition classified rows by ``classification`` and write the four
    bucket-split output files, each on the same ``columns`` schema.

    ``canonical`` / ``stale`` / ``unknown`` are partitioned on the primary
    ``classification`` -- never on ``validation_status`` (a canonical row with a
    stray status still lands in the canonical file). ``validated`` is the
    ``classification == "stale"`` AND ``validation_status == "VALID"`` subset --
    the committed loader input the ``stale_blocks.py`` loaders read. Each file
    is sorted by ``btc_height`` and its header is always written, even when the
    bucket is empty. Returns bucket counts for the caller's summary.
    """
    buckets: dict[str, list[dict]] = {"canonical": [], "stale": [], "unknown": []}
    for row in all_results:
        bucket = buckets.get(row.get("classification"))
        if bucket is not None:
            bucket.append(row)
    validated = [s for s in buckets["stale"] if s.get("validation_status") == "VALID"]

    _write_split_file(canonical_path, buckets["canonical"], columns=columns)
    _write_split_file(stale_path, buckets["stale"], columns=columns)
    _write_split_file(unknown_path, buckets["unknown"], columns=columns)
    _write_split_file(validated_path, validated, columns=columns)

    return {
        "canonical": len(buckets["canonical"]),
        "stale": len(buckets["stale"]),
        "unknown": len(buckets["unknown"]),
        "valid": len(validated),
        "rejected": sum(
            1
            for s in buckets["stale"]
            if str(s.get("validation_status", "")).startswith("REJECTED")
        ),
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
    keep_near: bool = False,
    near_output_path: Optional[str] = None,
    all_valid: bool = False,
    all_valid_path: Optional[str] = None,
    bits_source_is_decimal: bool = False,
    rpc: Optional[BtcRpc] = None,
) -> dict[str, Any]:
    """Run the full Phase 1/2/3 classifier for one chain.

    ``input_path`` / ``output_path`` default to ``spec.input_csv`` /
    ``spec.output_csv`` (the full stale/unknown inventory). ``validated_output_path``
    defaults to ``spec.validated_csv`` and receives the VALID-only loader input
    (``classification == "stale"`` AND ``validation_status == "VALID"``) -- this
    is the committed artifact the ``stale_blocks.py`` loaders read. ``rpc``
    defaults to a stdlib-transport ``BtcRpc`` using cookie/conf auth from
    ``get_btc_auth``; inject a client (a fake or an SSH-tunnelled transport) to
    avoid the network.

    ``bits_source_is_decimal`` is a property of the INPUT ARTIFACT, not the
    chain: leave it False for normal hex raw inputs; set it True only when
    reading the legacy decimal bitcoin-vault artifact. Either way ``btc_bits`` is
    normalized to canonical lowercase 8-char hex via ``normalize_bits_hex``
    before the gate and before writing, so the gate never falsely rejects a
    decimal value.

    ``near`` rows, whose hashes do not meet the targets encoded in their own
    headers, are dropped by design. When ``keep_near`` is
    true they are instead retained (deduped by header hash, the same as the
    valid path), tagged ``classification == "near"``, and written to a fifth
    file: ``near_output_path`` or the ``_stale_blocks`` -> ``_near_blocks``
    derivation of ``output_path``, on the same split schema. ``keep_near`` is
    off by default so a standard run is byte-identical to omitting it. Near rows
    never enter Phase 2/3, so the canonical/stale/unknown/validated files are
    unaffected.

    When ``all_valid`` is true the deduplicated self-target-PoW-valid headers are
    also written to ``all_valid_path`` or ``<output>.btc_valid.csv`` for
    debugging.

    Before the (potentially large) Phase 1 scan, a single ``getblockcount``
    preflight fails fast on an unreachable/misconfigured node. Each Phase 2 batch
    that raises is retried one candidate at a time so a single bad row or
    transient error does not abort the whole run.

    The Phase 3 header-context gates (``validate_stale_header_context``) are always run
    over the stale rows and are not skippable. Output is bucket-split by the shared
    ``write_classifier_outputs`` into four files on one schema: canonical ->
    ``canonical_output_path`` (``_stale_blocks`` -> ``_canonical_blocks``),
    unknown -> ``unknown_output_path`` (``_stale_blocks`` -> ``_unknown_blocks``),
    stale -> ``output_path`` (stale rows only), and the VALID-stale subset ->
    ``validated_output_path``. Returns a summary count dict:
    ``{total, btc_valid, canonical, stale, unknown, valid, rejected,
    validation_unknown, output_path, unknown_output_path,
    validated_output_path, canonical_output_path}``.
    """
    in_path = input_path or str(spec.input_csv)
    out_path = output_path or str(spec.output_csv)
    validated_path = validated_output_path or str(spec.validated_csv)
    # Canonical parents are a distinct output, kept in a separate artifact
    # (the <chain>_canonical_blocks.csv convention) so the stale/unknown
    # inventory keeps its established composition.
    default_canonical, default_unknown = derive_split_paths(out_path)
    if canonical_output_path is None:
        canonical_output_path = default_canonical
    if unknown_output_path is None:
        unknown_output_path = default_unknown
    height_col = spec.height_column

    if rpc is None:
        auth = get_btc_auth()
        rpc = BtcRpc(auth=auth)

    # --- Preflight: fail fast on an unreachable/misconfigured node before the
    # potentially large Phase 1 scan. ---
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

    # --- Phase 1: PoW filter + dedup by header hash ---
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
            if hash_meets_btc_difficulty(
                hash_from_header_bytes(bytes.fromhex(parsed_header["header_hex"])),
                parsed_header["bits"],
            ):
                btc_hash = parsed_header["hash"]
                if btc_hash not in seen_hashes:
                    seen_hashes.add(btc_hash)
                    valid_headers.append(row)
            elif keep_near:
                # Header fails its own encoded target: dropped by the standard run, kept
                # here (deduped by hash, same as the valid path) as sibling
                # evidence for shared-parent fork detection.
                btc_hash = parsed_header["hash"]
                if btc_hash and btc_hash not in seen_near:
                    seen_near.add(btc_hash)
                    near_headers.append(row)

    if all_valid and valid_headers:
        valid_path = all_valid_path or out_path.rsplit(".csv", 1)[0] + ".btc_valid.csv"
        with open(valid_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(valid_headers[0].keys()))
            writer.writeheader()
            writer.writerows(valid_headers)

    # --- Phase 2: batched classification, with batch-to-single fallback ---
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

    # Normalize btc_bits to canonical lowercase 8-char hex before the gate and
    # before writing, so a decimal-sourced value (legacy bitcoin-vault) is never
    # falsely REJECTED by the direct string comparison in validate_stale_nbits.
    for row in all_results:
        if row.get("btc_bits"):
            row["btc_bits"] = normalize_bits_hex(
                row["btc_bits"], source_is_decimal=bits_source_is_decimal
            )

    stales = [r for r in all_results if r["classification"] == "stale"]

    # --- Phase 3: header-context gates (NON-SKIPPABLE) --- (mutates the stale rows,
    # which are the same dicts the shared writer re-partitions out of all_results)
    validate_stale_header_context(
        stales,
        rpc.batch,
        height_key="btc_height",
        bits_key="btc_bits",
        status_key="validation_status",
        expected_key="expected_nbits",
    )

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

    # --- Output: four bucket-split files (canonical / stale / unknown / validated) ---
    counts = write_classifier_outputs(
        all_results,
        columns=output_columns(height_col),
        canonical_path=canonical_output_path,
        stale_path=out_path,
        unknown_path=unknown_output_path,
        validated_path=validated_path,
    )

    # --- Optional fifth file: retained near rows (sibling evidence) ---
    near_path_out: Optional[str] = None
    if keep_near:
        near_path_out = near_output_path or _derive_tag_path(out_path, "_near_blocks")
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
        "valid": counts["valid"],
        "rejected": counts["rejected"],
        "validation_unknown": counts["validation_unknown"],
        "near": len(near_headers) if keep_near else 0,
        "output_path": out_path,
        "unknown_output_path": unknown_output_path,
        "validated_output_path": validated_path,
        "canonical_output_path": canonical_output_path,
        "near_output_path": near_path_out,
    }
