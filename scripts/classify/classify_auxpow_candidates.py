#!/usr/bin/env python3
"""Classify extracted AuxPoW Bitcoin headers against the canonical chain.

Takes the CSV output from extract_auxpow_from_blkdat.py (all self-target-PoW-
valid headers) and queries a local Bitcoin Core node to classify each as:

  canonical    — hash exists in the canonical chain (the common case)
  stale        — not canonical, but prev_hash IS in the canonical chain
  unknown      — neither hash nor prev_hash in the canonical chain
  error_block  — a full-proof-of-work stale candidate whose own bytes prove it
                 broke a Bitcoin consensus rule

For direct-stale candidates, applies the shared available-evidence validation
profile: active-parent placement, median-time-past, historical minimum block
version, coinbase scriptSig bounds, BIP34 height commitment, and expected
Bitcoin nBits at the recovered height. The rejections are then handed to the
shared ``route_rejected_stale_rows``, which re-derives the broken rules from
each row's own bytes: a proven consensus violation becomes an ``error_block``
written to its own sibling artifact, a contamination (nBits) rejection becomes
an ``unknown``, and a rejection whose evidence proves nothing stays a stale.

Usage:
    python3 classify_auxpow_candidates.py \
        --input ~/i0coin-snapshot/i0coin_auxpow_test.csv \
        --output ~/i0coin-snapshot/i0coin_stales.csv \
        --classified-output ~/i0coin-snapshot/i0coin_classified.csv \
        --evidence-output ~/i0coin-snapshot/i0coin_evidence.csv \
        --rpc-url http://127.0.0.1:8332 \
        --rpc-user bitcoin

RPC credentials resolve via the shared ``get_btc_auth`` cascade: explicit
``--rpc-user``/``--rpc-pass``, then ``BITCOIN_RPC_USER``/``BITCOIN_RPC_PASSWORD``,
then the node's ``.cookie``, then ``bitcoin.conf`` -- so a secret need not be
put in the process arguments.

Requires: Python 3.10+
"""

import argparse
import csv
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from stale_blocks_analysis.btc_rpc import BtcRpc  # noqa: E402
from stale_blocks_analysis.btc_classify import (  # noqa: E402
    RULES_VIOLATED_COLUMN,
    derive_split_paths,
    route_rejected_stale_rows,
)
from stale_blocks_analysis.btc_nbits_validation import (  # noqa: E402
    NBITS_MISMATCH_PREFIX,
)
from stale_blocks_analysis.btc_stale_validation import (  # noqa: E402
    stale_header_context_error,
)
from stale_blocks_analysis.classifier_cli import add_rpc_args, rpc_from_args  # noqa: E402
from stale_blocks_analysis.auxpow_chainid import hash_from_header_bytes  # noqa: E402
from stale_blocks_analysis.auxpow_parse import (  # noqa: E402
    CHILD_HEADER_FIELDS,
    ChildHeaderValidationError,
    hash_meets_btc_difficulty,
    parse_parent_header,
    validate_child_header_fields,
)


# ---------------------------------------------------------------------------
# Batched RPC client with caching
# ---------------------------------------------------------------------------

RPC_BATCH_SIZE = 500
NOT_FOUND_ERROR_CODE = -5
HEIGHT_OUT_OF_RANGE_ERROR_CODE = -8


class RpcProtocolError(RuntimeError):
    """Raised when a batch response cannot be matched safely to its calls."""


class _RpcFailure:
    """Cached JSON-RPC error that a specific classification phase may allow."""

    def __init__(self, code, message):
        self.code = code
        self.message = message


class RpcClient:
    """Bounded, cached adapter over the shared stdlib-only ``BtcRpc`` client."""

    def __init__(
        self,
        url="http://127.0.0.1:8332",
        user=None,
        password=None,
        *,
        batch_size=RPC_BATCH_SIZE,
        rpc=None,
    ):
        if not isinstance(batch_size, int) or isinstance(batch_size, bool):
            raise ValueError("RPC batch size must be an integer")
        if batch_size < 1 or batch_size > RPC_BATCH_SIZE:
            raise ValueError(f"RPC batch size must be between 1 and {RPC_BATCH_SIZE}")

        auth = None if user is None and password is None else (user, password)
        self._rpc = rpc or BtcRpc(url=url, auth=auth)
        self._batch_size = batch_size
        self._next_id = 0
        self._cache = {}
        self._stats = {"calls": 0, "cache_hits": 0, "batches": 0}

    @staticmethod
    def _validate_response(response, expected_id):
        """Reject batch responses that are malformed or out of contract.

        Requires a dict with the expected ``id``, both ``result`` and
        ``error`` fields present, and never both populated at once.
        """
        if not isinstance(response, dict):
            raise RpcProtocolError(
                f"RPC batch response for id {expected_id} is not an object"
            )
        if response.get("id") != expected_id:
            raise RpcProtocolError(
                f"RPC batch response id mismatch: expected {expected_id}, "
                f"got {response.get('id')!r}"
            )
        if "result" not in response or "error" not in response:
            raise RpcProtocolError(
                f"RPC batch response for id {expected_id} lacks result/error fields"
            )
        if response["error"] is not None and response["result"] is not None:
            raise RpcProtocolError(
                f"RPC batch response for id {expected_id} has both result and error"
            )

    def _request_batch(self, pending, allowed_error_codes):
        """Issue one RPC batch for the pending cache keys and fill the cache.

        Errors whose code is in ``allowed_error_codes`` cache as None
        (block not found); any other error aborts the run.
        """
        calls = []
        call_keys = {}
        for cache_key in pending:
            request_id = self._next_id
            self._next_id += 1
            method, params = cache_key
            calls.append(
                {
                    "jsonrpc": "1.0",
                    "id": request_id,
                    "method": method,
                    "params": list(params),
                }
            )
            call_keys[request_id] = cache_key

        try:
            responses = self._rpc.batch(calls)
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise RpcProtocolError(f"invalid RPC batch response: {exc}") from exc

        if not isinstance(responses, list):
            raise RpcProtocolError("RPC batch response is not a list")
        if len(responses) != len(calls):
            raise RpcProtocolError(
                f"RPC batch response count mismatch: sent {len(calls)}, "
                f"received {len(responses)}"
            )

        responses_by_id = {}
        for response in responses:
            if not isinstance(response, dict):
                raise RpcProtocolError("RPC batch contains a non-object response")
            response_id = response.get("id")
            if not isinstance(response_id, int) or isinstance(response_id, bool):
                raise RpcProtocolError(f"invalid RPC response id {response_id!r}")
            if response_id not in call_keys:
                raise RpcProtocolError(f"unexpected RPC response id {response_id}")
            if response_id in responses_by_id:
                raise RpcProtocolError(f"duplicate RPC response id {response_id}")
            responses_by_id[response_id] = response

        if set(responses_by_id) != set(call_keys):
            missing = sorted(set(call_keys) - set(responses_by_id))
            raise RpcProtocolError(f"missing RPC response ids: {missing}")

        for request_id, cache_key in call_keys.items():
            response = responses_by_id[request_id]
            self._validate_response(response, request_id)
            error = response["error"]
            if error is None:
                self._cache[cache_key] = response["result"]
                continue

            if not isinstance(error, dict):
                raise RpcProtocolError(
                    f"RPC error for id {request_id} is not an object"
                )
            code = error.get("code")
            message = error.get("message", "")
            if not isinstance(code, int) or isinstance(code, bool):
                raise RpcProtocolError(
                    f"RPC error for id {request_id} has invalid code"
                )
            if not isinstance(message, str):
                raise RpcProtocolError(
                    f"RPC error for id {request_id} has invalid message"
                )
            if code not in allowed_error_codes:
                method, params = cache_key
                raise RuntimeError(
                    f"RPC error for {method}{params}: code {code}: {message}"
                )
            self._cache[cache_key] = _RpcFailure(code, message)

        self._stats["calls"] += len(calls)
        self._stats["batches"] += 1

    def call_many(
        self,
        method,
        params_by_call,
        *,
        allowed_error_codes=frozenset(),
        progress_label=None,
    ):
        """Return results aligned with ``params_by_call`` using bounded batches.

        Only explicitly allowed JSON-RPC errors are converted to ``None``.
        Transport errors, unexpected RPC errors, and malformed or mismatched
        batch responses abort the run instead of being mistaken for absent
        blocks.
        """
        keys = [(method, tuple(params)) for params in params_by_call]
        pending = []
        pending_set = set()
        for key in keys:
            if key in self._cache or key in pending_set:
                self._stats["cache_hits"] += 1
                continue
            pending.append(key)
            pending_set.add(key)

        total = len(pending)
        next_progress = 10_000
        for offset in range(0, total, self._batch_size):
            batch = pending[offset : offset + self._batch_size]
            self._request_batch(batch, allowed_error_codes)
            completed = offset + len(batch)
            if progress_label and (completed >= next_progress or completed == total):
                print(f"  {progress_label}: {completed:,} / {total:,} RPC lookups")
                while next_progress <= completed:
                    next_progress += 10_000

        results = []
        for key in keys:
            value = self._cache[key]
            if isinstance(value, _RpcFailure):
                if value.code not in allowed_error_codes:
                    method_name, params = key
                    raise RuntimeError(
                        f"RPC error for {method_name}{params}: "
                        f"code {value.code}: {value.message}"
                    )
                results.append(None)
            else:
                results.append(value)
        return results

    def call(self, method, *params):
        """Single-call convenience wrapper over ``call_many``."""
        return self.call_many(method, [params])[0]

    def call_safe(self, method, *params):
        """Return ``None`` only for Bitcoin Core's block-not-found error."""
        return self.call_many(
            method,
            [params],
            allowed_error_codes=frozenset({NOT_FOUND_ERROR_CODE}),
        )[0]


# ---------------------------------------------------------------------------
# BCH fork boundary
# ---------------------------------------------------------------------------

BCH_FORK_HEIGHT = 478_559

OUTPUT_FIELDS = [
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "child_height",
    "child_block_hash",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
    "classification",
    "validation_status",
    "expected_nbits",
]

# The error-block peer alone carries the pipe-joined rule set the routing
# derived, matching the shared writer, Hathor phase C, and the reconciler. Its
# three publication siblings keep OUTPUT_FIELDS unchanged.
ERROR_BLOCK_FIELDS = [*OUTPUT_FIELDS, RULES_VIOLATED_COLUMN]

EVIDENCE_FIELDS = [
    "btc_stale_height",
    "btc_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits_hex",
    "btc_bip34_height",
    "btc_nonce",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "child_height",
    "child_block_hash",
    "child_header_hex",
    "child_block_time",
    "child_nbits",
    "classification",
    "expected_nbits",
    "nbits_match",
    "post_bch_fork",
    "validation_status",
]

CLASSIFIED_ANNOTATION_FIELDS = [
    "btc_stale_height",
    "classification",
    "expected_nbits",
    "nbits_match",
    "post_bch_fork",
    "validation_status",
]


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _validate_header_result(
    block_hash,
    header,
    *,
    require_height=False,
    require_mediantime=False,
):
    """Validate the verbose ``getblockheader`` shape used for classification."""
    if header is None:
        return
    if not isinstance(header, dict):
        raise RpcProtocolError(f"header result for {block_hash} is not an object")
    returned_hash = header.get("hash")
    if (
        not isinstance(returned_hash, str)
        or returned_hash.lower() != block_hash.lower()
    ):
        raise RpcProtocolError(
            f"header hash mismatch for {block_hash}: got {returned_hash!r}"
        )
    confirmations = header.get("confirmations")
    if not isinstance(confirmations, int) or isinstance(confirmations, bool):
        raise RpcProtocolError(f"header for {block_hash} lacks integer confirmations")
    if require_height:
        height = header.get("height")
        if not isinstance(height, int) or isinstance(height, bool) or height < 0:
            raise RpcProtocolError(f"header for {block_hash} lacks a valid height")
    if require_mediantime:
        mediantime = header.get("mediantime")
        if (
            not isinstance(mediantime, int)
            or isinstance(mediantime, bool)
            or mediantime < 0
            or mediantime > 0xFFFFFFFF
        ):
            raise RpcProtocolError(f"header for {block_hash} lacks a valid mediantime")


def _is_canonical(header):
    """True when a getblockheader result is on the active chain."""
    return header is not None and header["confirmations"] > 0


def _validate_block_hash_result(block_hash):
    """Raise RpcProtocolError unless ``block_hash`` is a 64-character hex string."""
    if not isinstance(block_hash, str) or len(block_hash) != 64:
        raise RpcProtocolError(f"getblockhash returned invalid hash {block_hash!r}")
    try:
        bytes.fromhex(block_hash)
    except ValueError as exc:
        raise RpcProtocolError(
            f"getblockhash returned non-hex hash {block_hash!r}"
        ) from exc


def _require_authenticated_child_header(row):
    """Reject evidence rows whose authenticated child header is malformed."""
    for field in CHILD_HEADER_FIELDS:
        value = row.get(field)
        if not isinstance(value, str) or value != value.strip():
            raise ValueError(f"evidence output requires exact string {field}")
    try:
        validate_child_header_fields(row)
    except ChildHeaderValidationError as exc:
        raise ValueError(f"evidence output requires {exc}") from exc


def _validate_child_height(row):
    """Validate a populated consensus height; an unavailable value stays blank."""
    child_height = row.get("child_height")
    if child_height == "":
        return
    if (
        not isinstance(child_height, str)
        or child_height != child_height.strip()
        or not child_height.isascii()
        or not child_height.isdigit()
    ):
        raise ValueError("child_height must be blank or an exact non-negative integer")


def _require_authenticated_child_header_with_context(row, *, row_number):
    """Add a stable row and Bitcoin-parent identifier to validation errors."""
    try:
        _validate_child_height(row)
        _require_authenticated_child_header(row)
    except ValueError as exc:
        parent_hash = row.get("btc_header_hash") or row.get("btc_hash") or "<missing>"
        raise ValueError(
            f"evidence row {row_number} (btc_header_hash={parent_hash}): {exc}"
        ) from exc


def _require_hex(value, *, field, length):
    """Validate an exact-length, unpadded hex field; return it lowercased."""
    if not isinstance(value, str) or len(value) != length or value != value.strip():
        raise ValueError(f"candidate {field} must be exactly {length} hex characters")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            f"candidate {field} must be exactly {length} hex characters"
        ) from exc
    return value.lower()


def _require_uint(value, *, field, maximum):
    """Validate an unsigned decimal string within its wire range."""
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or not value.isascii()
        or not value.isdigit()
    ):
        raise ValueError(f"candidate {field} must be an unsigned integer")
    parsed = int(value)
    if parsed > maximum:
        raise ValueError(f"candidate {field} is outside its wire range")
    return parsed


def _validate_candidate_parent_header(row, *, row_number):
    """Derive every parent identity field from the serialized 80-byte header."""
    try:
        header_hex = _require_hex(
            row.get("btc_header_hex"), field="btc_header_hex", length=160
        )
        stated_hash = _require_hex(row.get("btc_hash"), field="btc_hash", length=64)
        stated_prev = _require_hex(
            row.get("btc_prev_hash"), field="btc_prev_hash", length=64
        )
        stated_bits = _require_hex(
            row.get("btc_bits_hex"), field="btc_bits_hex", length=8
        )
        stated_time = _require_uint(
            row.get("btc_time"), field="btc_time", maximum=0xFFFFFFFF
        )
        stated_nonce = _require_uint(
            row.get("btc_nonce"), field="btc_nonce", maximum=0xFFFFFFFF
        )
        raw_header = bytes.fromhex(header_hex)
        parsed = parse_parent_header(raw_header)
        if parsed["hash"] != stated_hash:
            raise ValueError(
                f"candidate btc_hash does not match btc_header_hex: "
                f"expected {parsed['hash']}, got {stated_hash}"
            )
        if parsed["prev_hash"] != stated_prev:
            raise ValueError("candidate btc_prev_hash does not match btc_header_hex")
        if parsed["time"] != stated_time:
            raise ValueError("candidate btc_time does not match btc_header_hex")
        if parsed["bits_hex"] != stated_bits:
            raise ValueError("candidate btc_bits_hex does not match btc_header_hex")
        if parsed["nonce"] != stated_nonce:
            raise ValueError("candidate btc_nonce does not match btc_header_hex")
        header_hash_internal = hash_from_header_bytes(raw_header)
        if not hash_meets_btc_difficulty(header_hash_internal, parsed["bits"]):
            raise ValueError(
                "candidate btc_header_hex does not meet its claimed Bitcoin target"
            )
    except ValueError as exc:
        raise ValueError(f"candidate row {row_number}: {exc}") from exc


def _validate_distinct_paths(
    input_csv,
    output_csv,
    rejected_csv,
    error_blocks_csv,
    evidence_csv,
    classified_csv,
    publication_csv,
):
    """Refuse to run when any two input/output paths resolve to the same file."""
    labelled = {
        "input": Path(input_csv).resolve(),
        "validated-stale output": Path(output_csv).resolve(),
        "rejected output": Path(rejected_csv).resolve(),
        "error-block output": Path(error_blocks_csv).resolve(),
    }
    if evidence_csv is not None:
        labelled["evidence output"] = Path(evidence_csv).resolve()
    if classified_csv is not None:
        labelled["classified output"] = Path(classified_csv).resolve()
    if publication_csv is not None:
        canonical_csv, unknown_csv, error_block_csv = _derive_publication_split_paths(
            publication_csv
        )
        labelled["publication stale output"] = Path(publication_csv).resolve()
        labelled["publication canonical output"] = canonical_csv.resolve()
        labelled["publication unknown output"] = unknown_csv.resolve()
        labelled["publication error-block output"] = error_block_csv.resolve()
    seen = {}
    for label, path in labelled.items():
        previous = seen.get(path)
        if previous is not None:
            raise ValueError(f"{label} aliases {previous}: {path}")
        seen[path] = label


def _fsync_directory(path):
    """Persist completed same-directory renames and unlinks."""
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _fsync_directories(paths):
    """Persist each distinct output directory in deterministic order."""
    for path in sorted(set(paths), key=str):
        _fsync_directory(path)


def _write_dict_rows_atomic(path, rows, fieldnames):
    """Write dict rows via a same-directory temp file and rename.

    A crash mid-write can never leave a truncated CSV at the destination.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _write_publication_rows_atomic(path, rows):
    """Write normalized publication-schema rows, not diagnostic-schema rows."""
    _write_dict_rows_atomic(
        path,
        (_publication_row(row) for row in rows),
        OUTPUT_FIELDS,
    )


def _write_error_block_rows_atomic(path, rows):
    """Write error blocks on the publication schema plus their rule set.

    The rules are the evidence for the error-block claim, and
    ``validation_status`` does not carry them: it names the one gate that fired
    first, which for an unapplied retarget is a generic nBits mismatch and for
    a multi-rule header is only the primary violation. ``route_rejected_stale_rows``
    stashes the set on every row it routes here, so a missing key means the
    contract broke and should raise rather than publish a blank claim.
    """
    _write_dict_rows_atomic(
        path,
        (
            {**_publication_row(row), RULES_VIOLATED_COLUMN: row[RULES_VIOLATED_COLUMN]}
            for row in rows
        ),
        ERROR_BLOCK_FIELDS,
    )


def _publication_row(row):
    """Map the i0coin classifier row contract to the compact CSV schema.

    Stale validation diagnostics belong to the rows the gate actually judged:
    stale rows, and the error blocks routing carved out of them, whose REJECTED
    verdict is the whole content of the row. Canonical and unknown publication
    rows use the same empty diagnostic fields emitted by the shared classifiers
    (a re-routed unknown's verdict survives in the full classified output);
    the full classified and evidence outputs retain their richer annotations.
    """
    classification = row.get("classification", "")
    is_gated = classification in ("stale", "error_block")
    return {
        "btc_height": row.get("btc_stale_height", ""),
        "btc_header_hash": row.get("btc_hash", ""),
        "btc_prev_hash": row.get("btc_prev_hash", ""),
        "btc_time": row.get("btc_time", ""),
        "btc_bits": row.get("btc_bits_hex", ""),
        "coinbase_scriptsig_hex": row.get("coinbase_scriptsig_hex", ""),
        "coinbase_outputs": row.get("coinbase_outputs", ""),
        "btc_header_hex": row.get("btc_header_hex", ""),
        "child_height": row.get("child_height", ""),
        "child_block_hash": row.get("child_block_hash", ""),
        "child_header_hex": row.get("child_header_hex", ""),
        "child_block_time": row.get("child_block_time", ""),
        "child_nbits": row.get("child_nbits", ""),
        "classification": classification,
        "validation_status": row.get("validation_status", "") if is_gated else "",
        "expected_nbits": row.get("expected_nbits", "") if is_gated else "",
    }


def _derive_publication_split_paths(stale_csv):
    """Return the canonical, unknown, and error-block peers a refresh owns.

    Publication output is a four-bucket artifact family, matching the shared
    classifiers. Re-running a refresh transactionally replaces the family.

    The error-block peer is owned here because this classifier's own pass now
    produces error blocks: routing moves a rejected row whose bytes prove a
    consensus violation out of the stale bucket, so a refresh that did not
    republish that file would silently drop those rows from every bucket of a
    family it claims to replace completely.
    """
    canonical, unknown, error_blocks = derive_split_paths(str(stale_csv))
    return Path(canonical), Path(unknown), Path(error_blocks)


def _publish_artifact_family(staged_destinations):
    """Install a staged family, retaining sibling backups if rollback fails."""
    staged_destinations = list(staged_destinations)
    destination_directories = {
        destination.parent for _staged, destination in staged_destinations
    }
    moved_previous = []
    installed = []
    try:
        for _staged, destination in staged_destinations:
            if destination.exists() or destination.is_symlink():
                backup_fd, backup_name = tempfile.mkstemp(
                    prefix=f".{destination.name}.previous-", dir=destination.parent
                )
                os.close(backup_fd)
                backup = Path(backup_name)
                # Reserve a unique sibling name, then move the live artifact
                # onto it.
                backup.unlink()
                os.replace(destination, backup)
                moved_previous.append((backup, destination))
        if moved_previous:
            _fsync_directories(destination_directories)
        for staged, destination in staged_destinations:
            os.replace(staged, destination)
            installed.append((destination, staged))
        _fsync_directories(destination_directories)
    except BaseException as original_error:
        rollback_errors = []
        for destination, staged in reversed(installed):
            if destination.exists() or destination.is_symlink():
                try:
                    os.replace(destination, staged)
                except OSError as exc:
                    rollback_errors.append(exc)
        for backup, destination in reversed(moved_previous):
            if backup.exists() or backup.is_symlink():
                try:
                    os.replace(backup, destination)
                except OSError as exc:
                    rollback_errors.append(exc)
        try:
            _fsync_directories(destination_directories)
        except OSError as exc:
            rollback_errors.append(exc)
        if rollback_errors:
            raise RuntimeError(
                "publication-family install failed and rollback was incomplete; "
                "previous artifacts remain in sibling .previous-* backup files"
            ) from original_error
        raise
    removed_backup = False
    for backup, _destination in moved_previous:
        try:
            backup.unlink(missing_ok=True)
            removed_backup = True
        except OSError as exc:
            print(
                f"WARNING: could not remove publication backup {backup}: {exc}",
                file=sys.stderr,
            )
    if removed_backup:
        try:
            _fsync_directories(destination_directories)
        except OSError as exc:
            print(
                f"WARNING: could not persist publication backup cleanup: {exc}",
                file=sys.stderr,
            )


def _write_publication_inventory(stale_csv, rows):
    """Authenticate, normalize, and transactionally publish four buckets.

    The error bucket is written on ERROR_BLOCK_FIELDS and keeps its rule set;
    its three siblings keep OUTPUT_FIELDS byte-identical.
    """
    buckets = {"canonical": [], "stale": [], "unknown": [], "error_block": []}
    for row_number, row in enumerate(rows, start=2):
        _require_authenticated_child_header_with_context(row, row_number=row_number)
        publication_row = _publication_row(row)
        classification = publication_row["classification"]
        bucket = buckets.get(classification)
        if bucket is None:
            raise RuntimeError(
                "internal error: unsupported publication classification "
                f"{classification!r}"
            )
        if classification == "error_block":
            # Same contract as ``_write_error_block_rows_atomic``: the error
            # bucket alone keeps the pipe-joined rule set that justifies its
            # rows, and a missing key raises rather than publishing a blank
            # claim. ``_publication_row`` drops it with every other diagnostic
            # column, so it is restored here.
            publication_row[RULES_VIOLATED_COLUMN] = row[RULES_VIOLATED_COLUMN]
        bucket.append(publication_row)

    for bucket in buckets.values():
        bucket.sort(key=lambda row: int(row.get("btc_height") or 0))

    canonical_csv, unknown_csv, error_block_csv = _derive_publication_split_paths(
        stale_csv
    )
    stale_csv = Path(stale_csv)
    stale_csv.parent.mkdir(parents=True, exist_ok=True)
    destinations = [canonical_csv, stale_csv, unknown_csv, error_block_csv]
    bucket_names = ["canonical", "stale", "unknown", "error_block"]
    with tempfile.TemporaryDirectory(
        prefix=".publication-build-", dir=stale_csv.parent
    ) as transaction_dir:
        transaction_root = Path(transaction_dir)
        staged_destinations = []
        for bucket_name, destination in zip(bucket_names, destinations, strict=True):
            staged = transaction_root / destination.name
            fields = (
                ERROR_BLOCK_FIELDS if bucket_name == "error_block" else OUTPUT_FIELDS
            )
            _write_dict_rows_atomic(staged, buckets[bucket_name], fields)
            staged_destinations.append((staged, destination))
        _publish_artifact_family(staged_destinations)
    return canonical_csv, unknown_csv, error_block_csv


def _canonical_evidence_row(row, canonical_header):
    """Build an import-ready evidence row for a canonical Bitcoin parent."""
    btc_hash = row["btc_hash"]
    _validate_header_result(btc_hash, canonical_header, require_height=True)
    if not _is_canonical(canonical_header):
        raise RpcProtocolError(
            f"cannot emit noncanonical header {btc_hash} as canonical evidence"
        )
    bits = canonical_header.get("bits")
    if not isinstance(bits, str):
        raise RpcProtocolError(f"canonical header {btc_hash} lacks string bits")
    expected_nbits = bits.lower()
    if row["btc_bits_hex"].lower() != expected_nbits:
        raise RpcProtocolError(
            f"canonical header bits mismatch for {btc_hash}: "
            f"candidate has {row['btc_bits_hex']}, Core has {bits}"
        )

    height = canonical_header["height"]
    return {
        "btc_stale_height": height,
        "btc_hash": btc_hash,
        "btc_prev_hash": row["btc_prev_hash"],
        "btc_time": row["btc_time"],
        "btc_bits_hex": row["btc_bits_hex"],
        "btc_bip34_height": row.get("btc_bip34_height", ""),
        "btc_nonce": row.get("btc_nonce", ""),
        "coinbase_scriptsig_hex": row["coinbase_scriptsig_hex"],
        "coinbase_outputs": row["coinbase_outputs"],
        "btc_header_hex": row.get("btc_header_hex", ""),
        "child_height": row.get("child_height", ""),
        "child_block_hash": row.get("child_block_hash", ""),
        "child_header_hex": row.get("child_header_hex", ""),
        "child_block_time": row.get("child_block_time", ""),
        "child_nbits": row.get("child_nbits", ""),
        "classification": "canonical",
        "expected_nbits": expected_nbits,
        "nbits_match": "true",
        "post_bch_fork": str(height >= BCH_FORK_HEIGHT).lower(),
        "validation_status": "VALID (canonical Bitcoin block)",
    }


def classify_and_validate(
    input_csv,
    output_csv,
    rejected_csv,
    btc,
    evidence_csv=None,
    classified_csv=None,
    publication_csv=None,
    error_blocks_csv=None,
):
    """Read extracted headers, classify against Bitcoin Core, write results."""

    if error_blocks_csv is None:
        error_blocks_csv = derive_split_paths(str(output_csv))[2]
    _validate_distinct_paths(
        input_csv,
        output_csv,
        rejected_csv,
        error_blocks_csv,
        evidence_csv,
        classified_csv,
        publication_csv,
    )

    # Read all candidate rows
    with open(input_csv, newline="") as f:
        reader = csv.DictReader(f)
        input_fields = reader.fieldnames or []
        rows = list(reader)
    if "child_height" not in input_fields:
        raise ValueError("input schema must include child_height")

    for row_number, row in enumerate(rows, start=2):
        _validate_candidate_parent_header(row, row_number=row_number)
        if evidence_csv is not None or publication_csv is not None:
            _require_authenticated_child_header_with_context(row, row_number=row_number)
        else:
            _validate_child_height(row)

    print(f"Loaded {len(rows):,} self-target-PoW-valid headers to classify")

    stats = {
        "canonical": 0,
        "stale": 0,
        "unknown": 0,
        "validated": 0,
        "rejected_consensus": 0,
        "rejected_nbits": 0,
        "rejected_other": 0,
        "error_block": 0,
        "rerouted_unknown": 0,
    }

    validated = []
    rejected = []
    stale_inventory_rows = []
    evidence = []
    classified = (
        [None] * len(rows)
        if classified_csv is not None or publication_csv is not None
        else None
    )
    t0 = time.time()

    # Step 1: classify every candidate hash in bounded getblockheader batches.
    candidate_headers = btc.call_many(
        "getblockheader",
        [(row["btc_hash"],) for row in rows],
        allowed_error_codes=frozenset({NOT_FOUND_ERROR_CODE}),
        progress_label="candidate headers",
    )
    noncanonical = []
    for i, (row, header) in enumerate(zip(rows, candidate_headers, strict=True)):
        btc_hash = row["btc_hash"]
        _validate_header_result(btc_hash, header)
        if _is_canonical(header):
            stats["canonical"] += 1
            canonical_row = _canonical_evidence_row(row, header)
            if classified is not None:
                classified[i] = {**row, **canonical_row}
            if evidence_csv is not None:
                evidence.append((i, canonical_row))
        else:
            noncanonical.append((i, row))

        if (i + 1) % 10_000 == 0 or i + 1 == len(rows):
            elapsed = max(time.time() - t0, 0.001)
            rate = (i + 1) / elapsed
            print(
                f"  {i + 1:>9,} / {len(rows):,} | "
                f"{stats['canonical']:,} canonical | "
                f"{len(noncanonical):,} noncanonical | "
                f"{rate:.0f} hdr/s | "
                f"RPC: {btc._stats['calls']:,} calls in "
                f"{btc._stats['batches']:,} batches"
            )

    # Step 2: only a noncanonical candidate whose parent is canonical is stale.
    parent_headers = btc.call_many(
        "getblockheader",
        [(row["btc_prev_hash"],) for _, row in noncanonical],
        allowed_error_codes=frozenset({NOT_FOUND_ERROR_CODE}),
        progress_label="parent headers",
    )
    stales = []
    for (input_index, row), parent_header in zip(
        noncanonical, parent_headers, strict=True
    ):
        prev_hash = row["btc_prev_hash"]
        _validate_header_result(
            prev_hash,
            parent_header,
            require_height=True,
            require_mediantime=True,
        )
        if not _is_canonical(parent_header):
            stats["unknown"] += 1
            if classified is not None:
                # Deliberately NOT the shared PLACEMENT_REJECTION string. That
                # verdict is REJECTED-prefixed because the shared gate meets the
                # row later, after Phase 2 already called it a stale, and the
                # driver has to take the stale label back. Here the row never
                # became a stale: the parent lookup resolves to unknown in the
                # same step that would have made it one, so the row's state is
                # already final on the primary axis and there is nothing to
                # reject. An UNKNOWN prefix also keeps it out of the REJECTED-row
                # sweeps, which would otherwise count every unknown as an
                # unrecognised rejection.
                classified[input_index] = {
                    **row,
                    "btc_stale_height": "",
                    "classification": "unknown",
                    "expected_nbits": "",
                    "nbits_match": "unknown",
                    "post_bch_fork": "",
                    "validation_status": (
                        "UNKNOWN: parent is not on the active Bitcoin chain"
                    ),
                }
            continue

        stats["stale"] += 1
        parent_height = parent_header["height"]
        stale_height = parent_height + 1
        stales.append((input_index, row, stale_height, parent_header["mediantime"]))

    # Step 3: resolve expected Bitcoin nBits for each stale height in batches.
    canonical_hashes = btc.call_many(
        "getblockhash",
        [(stale_height,) for _, _, stale_height, _ in stales],
        allowed_error_codes=frozenset({HEIGHT_OUT_OF_RANGE_ERROR_CODE}),
        progress_label="canonical hashes",
    )
    known_canonical_hashes = [h for h in canonical_hashes if h is not None]
    for canonical_hash in known_canonical_hashes:
        _validate_block_hash_result(canonical_hash)

    canonical_headers = btc.call_many(
        "getblockheader",
        [(canonical_hash,) for canonical_hash in known_canonical_hashes],
        progress_label="difficulty headers",
    )
    headers_by_hash = {}
    for canonical_hash, canonical_header in zip(
        known_canonical_hashes, canonical_headers, strict=True
    ):
        _validate_header_result(canonical_hash, canonical_header, require_height=True)
        if not _is_canonical(canonical_header):
            raise RpcProtocolError(
                f"getblockhash returned noncanonical header {canonical_hash}"
            )
        headers_by_hash[canonical_hash] = canonical_header

    for stale_number, (
        (input_index, row, stale_height, parent_median_time_past),
        canonical_hash,
    ) in enumerate(zip(stales, canonical_hashes, strict=True), start=1):
        expected_nbits = None
        if canonical_hash is not None:
            canonical_header = headers_by_hash[canonical_hash]
            if canonical_header["height"] != stale_height:
                raise RpcProtocolError(
                    f"canonical header height mismatch: expected {stale_height}, "
                    f"got {canonical_header['height']}"
                )
            bits = canonical_header.get("bits")
            if not isinstance(bits, str):
                raise RpcProtocolError(
                    f"canonical header {canonical_hash} lacks string bits"
                )
            expected_nbits = bits.lower()

        btc_hash = row["btc_hash"]
        post_bch = stale_height >= BCH_FORK_HEIGHT
        stale_nbits = row["btc_bits_hex"].lower()
        consensus_error = stale_header_context_error(
            row,
            stale_height,
            parent_median_time_past=parent_median_time_past,
            bip34_key="btc_bip34_height",
            scriptsig_key="coinbase_scriptsig_hex",
        )

        if consensus_error is not None:
            nbits_match = (
                "unknown"
                if expected_nbits is None
                else str(stale_nbits == expected_nbits).lower()
            )
            status = consensus_error
            entry_list = rejected
            stats["rejected_consensus"] += 1
        elif expected_nbits is None:
            nbits_match = "unknown"
            status = "UNKNOWN: could not determine expected difficulty"
            entry_list = rejected
            stats["rejected_other"] += 1
        elif stale_nbits == expected_nbits:
            nbits_match = "true"
            status = "VALID"
            if post_bch:
                status = "VALID (post-BCH, difficulty matches BTC)"
            entry_list = validated
            stats["validated"] += 1
        else:
            # The shared contamination verdict: this row's difficulty is not
            # Bitcoin's at the recovered height, so the header belongs to
            # another SHA-256 chain. Carrying NBITS_MISMATCH_PREFIX verbatim is
            # what lets route_rejected_stale_rows recognise it as contamination
            # rather than a judgement on a Bitcoin block. The post-BCH-fork hint
            # is appended, not spliced into the prefix.
            nbits_match = "false"
            status = (
                f"{NBITS_MISMATCH_PREFIX} "
                f"(got {stale_nbits}, expected {expected_nbits})"
            )
            if post_bch:
                status += "; likely BCH/BSV block"
            entry_list = rejected
            stats["rejected_nbits"] += 1

        out_row = {
            "btc_stale_height": stale_height,
            "btc_hash": btc_hash,
            "btc_prev_hash": row["btc_prev_hash"],
            "btc_time": row["btc_time"],
            "btc_bits_hex": row["btc_bits_hex"],
            "btc_bip34_height": row.get("btc_bip34_height", ""),
            "btc_nonce": row.get("btc_nonce", ""),
            "coinbase_scriptsig_hex": row["coinbase_scriptsig_hex"],
            "coinbase_outputs": row["coinbase_outputs"],
            "btc_header_hex": row.get("btc_header_hex", ""),
            "child_height": row.get("child_height", ""),
            "child_block_hash": row.get("child_block_hash", ""),
            "child_header_hex": row.get("child_header_hex", ""),
            "child_block_time": row.get("child_block_time", ""),
            "child_nbits": row.get("child_nbits", ""),
            "classification": "stale",
            "expected_nbits": expected_nbits or "",
            "nbits_match": nbits_match,
            "post_bch_fork": str(post_bch).lower(),
            "validation_status": status,
            # Internal keys the shared router needs and this pass already holds:
            # the authoritative prev+1 height, the canonical parent's
            # median-time-past, and the candidate bits under the shared gates'
            # own column name. Every writer here either builds its fields
            # explicitly or drops extras, so none of these can reach a CSV.
            "btc_height": str(stale_height),
            "btc_bits": stale_nbits,
            "_parent_median_time_past": parent_median_time_past,
        }
        entry_list.append(out_row)
        stale_inventory_rows.append((input_index, row, out_row))
        if evidence_csv is not None and status.startswith("VALID"):
            evidence.append((input_index, out_row))

        print(
            f"  STALE #{stale_number}: "
            f"BTC height {stale_height:,} | "
            f"hash {btc_hash[:16]}... | "
            f"status: {status}"
        )

    # Routing: sort the rejections by what each one actually means. A row whose
    # bytes prove a broken consensus rule is an error block, not a stale; a
    # contamination (nBits) rejection is not a direct stale at all; a rejection
    # whose evidence proves nothing stays a stale. The router mutates each row
    # in place, so the classified inventory is filled in only afterwards.
    route_rejected_stale_rows(rejected)
    error_blocks = [row for row in rejected if row["classification"] == "error_block"]
    rerouted_unknowns = [row for row in rejected if row["classification"] == "unknown"]
    rejected = [row for row in rejected if row["classification"] == "stale"]
    stats["error_block"] = len(error_blocks)
    stats["rerouted_unknown"] = len(rerouted_unknowns)
    if classified is not None:
        for input_index, source_row, out_row in stale_inventory_rows:
            classified[input_index] = {**source_row, **out_row}

    if evidence_csv is not None:
        evidence.sort(key=lambda item: item[0])
        for input_index, evidence_row in evidence:
            _require_authenticated_child_header_with_context(
                evidence_row, row_number=input_index + 2
            )

    if classified is not None and any(row is None for row in classified):
        raise RuntimeError("internal error: classified inventory is incomplete")

    # Write normalized publication outputs. The full classifier inventory below
    # retains the source-specific diagnostic columns. The rejection log keeps
    # every row the gate turned down, including the ones routing moved to
    # unknown -- those have no artifact of their own in this mode, and dropping
    # them would lose them from the run entirely. Error blocks do have their own
    # artifact, so they are written there instead of counted as rejected stales.
    _write_publication_rows_atomic(output_csv, validated)
    _write_publication_rows_atomic(rejected_csv, rejected + rerouted_unknowns)
    _write_error_block_rows_atomic(error_blocks_csv, error_blocks)

    if evidence_csv is not None:
        _write_dict_rows_atomic(
            evidence_csv,
            (row for _, row in evidence),
            EVIDENCE_FIELDS,
        )

    if classified_csv is not None:
        classified_fields = list(input_fields)
        classified_fields.extend(
            field
            for field in CLASSIFIED_ANNOTATION_FIELDS
            if field not in classified_fields
        )
        _write_dict_rows_atomic(classified_csv, classified, classified_fields)

    if publication_csv is not None:
        canonical_csv, unknown_csv, error_block_csv = _write_publication_inventory(
            publication_csv, classified
        )

    elapsed = time.time() - t0
    print(f"\n{'=' * 60}")
    print(f"Classification complete in {elapsed:.1f}s")
    print(f"  Total headers:     {len(rows):>10,}")
    print(f"  Canonical:         {stats['canonical']:>10,}")
    print(f"  Stale (total):     {stats['stale']:>10,}")
    print(f"    Validated:       {stats['validated']:>10,}")
    print(f"    Rejected context: {stats['rejected_consensus']:>10,}")
    print(f"    Rejected nBits:  {stats['rejected_nbits']:>10,}")
    print(f"    Rejected other:  {stats['rejected_other']:>10,}")
    print(f"    Error blocks:    {stats['error_block']:>10,}")
    print(f"    Re-routed to unknown: {stats['rerouted_unknown']:>10,}")
    print(f"  Unknown:           {stats['unknown']:>10,}")
    print(f"  RPC calls:         {btc._stats['calls']:>10,}")
    print(f"  RPC batches:       {btc._stats['batches']:>10,}")
    print(f"  Cache hits:        {btc._stats['cache_hits']:>10,}")
    print(f"\n  Gate-accepted stales: {output_csv}")
    print(f"  Rejected:          {rejected_csv}")
    print(f"  Error blocks:      {error_blocks_csv}")
    if evidence_csv is not None:
        print(f"  Import evidence:   {evidence_csv}")
    if classified_csv is not None:
        print(f"  Full inventory:    {classified_csv}")
    if publication_csv is not None:
        print(f"  Publication stale: {publication_csv}")
        print(f"  Publication canonical: {canonical_csv}")
        print(f"  Publication unknown: {unknown_csv}")
        print(f"  Publication error blocks: {error_block_csv}")


def main():
    """Run the generic classifier CLI over one extraction CSV."""
    parser = argparse.ArgumentParser(
        description="Classify AuxPoW-extracted BTC headers against canonical chain"
    )
    parser.add_argument("--input", required=True, help="Input CSV from extraction")
    parser.add_argument(
        "--output",
        required=True,
        help="Normalized publication CSV of gate-accepted stale candidates",
    )
    parser.add_argument(
        "--rejected",
        default="",
        help=(
            "Normalized publication CSV of gate rejections that are not error "
            "blocks: rejections still classified stale plus the ones routing "
            "moved to unknown; use --classified-output to retain "
            "source-specific diagnostic columns"
        ),
    )
    parser.add_argument(
        "--error-blocks-out",
        default=None,
        help=(
            "Normalized publication CSV of consensus-invalid full-proof-of-work "
            "rejections (default: the _error_blocks sibling of --output)"
        ),
    )
    parser.add_argument(
        "--evidence-output",
        help=(
            "Optional import-ready CSV of canonical and validated stale evidence. "
            "Every input row must carry a complete authenticated child-header "
            "bundle and the uniform child_height column. Heights that cannot be "
            "authenticated remain blank; populated values must be exact and "
            "non-negative"
        ),
    )
    parser.add_argument(
        "--classified-output",
        help=(
            "Optional all-candidate inventory preserving input columns and adding "
            "canonical/stale/unknown plus validation annotations"
        ),
    )
    parser.add_argument(
        "--publication-output",
        help=(
            "Optional normalized four-bucket publication family. This path is "
            "the stale CSV; canonical, unknown, and error-block peer paths are "
            "derived from its filename, and a refresh transactionally replaces "
            "the complete four-file family. Every input row must carry a complete authenticated "
            "child-header bundle and the uniform child_height column. Unavailable "
            "heights remain blank; populated values must be exact and non-negative. "
            "This is checked before any Bitcoin RPC classification"
        ),
    )
    add_rpc_args(parser)
    args = parser.parse_args()

    output_path = Path(args.output)
    if args.rejected:
        rejected_csv = args.rejected
    elif output_path.suffix.lower() == ".csv":
        rejected_csv = str(output_path.with_name(f"{output_path.stem}_rejected.csv"))
    else:
        rejected_csv = f"{args.output}_rejected.csv"

    btc = RpcClient(rpc=rpc_from_args(args))

    # Quick connection test
    try:
        info = btc.call("getblockchaininfo")
        print(f"Bitcoin Core: chain={info['chain']}, blocks={info['blocks']:,}")
    except Exception as e:
        print(f"ERROR: cannot connect to Bitcoin Core RPC: {e}")
        sys.exit(1)

    classify_and_validate(
        args.input,
        args.output,
        rejected_csv,
        btc,
        evidence_csv=args.evidence_output,
        classified_csv=args.classified_output,
        publication_csv=args.publication_output,
        error_blocks_csv=args.error_blocks_out,
    )


if __name__ == "__main__":
    main()
