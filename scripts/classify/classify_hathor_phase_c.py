#!/usr/bin/env python3
"""Phase C: parse coinbase + format Hathor stales into standard schema.

Reads ``data/hathor_stale_blocks.csv`` (Phase B output), filters to
``classification == "stale"`` rows, preserves Phase B's validation status,
parses each coinbase to extract scriptSig and outputs, applies Bitcoin's
historical minimum-version and exact BIP34 height-prefix checks, then writes
``data/validated-stales/hathor_validated_stales.csv`` in the same schema as the other
chains' validated CSVs (devcoin/syscoin/elastos/etc.).

Standard schema::

    btc_height, btc_header_hash, btc_prev_hash, btc_time, btc_bits,
    coinbase_scriptsig_hex, coinbase_outputs, btc_header_hex,
    hathor_height, classification, validation_status, expected_nbits

``coinbase_outputs`` uses the project's standard ``addr:value|addr:value``
format with semicolon-separated pkscript_hex for unparseable scripts.

A rejected row whose bytes prove a consensus rule broken is an error block, not
a dropped candidate. Those rows are written to the ``_error_blocks`` peer of the
Phase B input on the same schema plus ``rules_violated``. A rejection whose
evidence was merely unusable yields no rules and is still dropped, but the drop
is counted and reported rather than silent.

Phase B's status vocabulary was renamed to the shared ``VALID`` /
``REJECTED: <reason>`` / ``UNKNOWN: <reason>`` convention. Archived Phase B
intermediates on the archival host still carry the pre-rename tokens, so this
reader accepts both and normalizes on load.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stale_blocks_analysis.bitcoin_binary import parse_coinbase  # noqa: E402
from stale_blocks_analysis.btc_classify import derive_split_paths  # noqa: E402
from stale_blocks_analysis.btc_nbits_validation import (  # noqa: E402
    NBITS_MISMATCH_PREFIX,
)
from stale_blocks_analysis.btc_stale_validation import (  # noqa: E402
    PLACEMENT_REJECTION,
    consensus_violations,
    stale_header_context_error,
)


# The verdict ``btc_stale_validation._set_parent_context_unknown`` writes. It is
# not an exported constant there, so it is duplicated here as a literal.
PARENT_CONTEXT_UNKNOWN = "UNKNOWN: canonical parent context unavailable"

# Phase B's pre-rename status vocabulary. Archived Phase B intermediates still
# carry these tokens, so they are normalized onto the shared verdict convention
# on read -- the same way this repo's readers accept legacy ``orphan`` where a
# writer now emits ``unknown``.
LEGACY_VALIDATION_STATUS = {
    "PARENT_NOT_CANONICAL": PLACEMENT_REJECTION,
    "PARENT_CONTEXT_UNAVAILABLE": PARENT_CONTEXT_UNKNOWN,
    # The legacy token carried no operands, so the bare prefix is all it
    # asserted; the "(got ..., expected ...)" suffix is not part of that record.
    "NBITS_MISMATCH": NBITS_MISMATCH_PREFIX,
}


OUTPUT_COLUMNS = [
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "hathor_height",
    "classification",
    "validation_status",
    "expected_nbits",
]

# Error blocks carry the standard row plus the pipe-joined full rule set, the
# column name and format ``build_error_blocks.py`` honors verbatim on import.
ERROR_BLOCK_COLUMNS = [*OUTPUT_COLUMNS, "rules_violated"]

PHASE_B_REQUIRED_COLUMNS = {
    "classification",
    "full_coinbase_hex",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "btc_header_hex",
    "hathor_height",
    "validation_status",
    "btc_parent_height",
    "btc_parent_mediantime",
    "expected_nbits",
}


def format_outputs(outputs: list[tuple[int, bytes]]) -> str:
    """Format coinbase outputs as ``addr_or_pkscript:value|...`` matching
    the project's standard schema. Use raw pkscript_hex when address
    decoding is not trivial so later attribution can decode it."""
    if not outputs:
        return ""
    parts = []
    for value, pkscript in outputs:
        parts.append(f"{pkscript.hex()}:{value}")
    return "|".join(parts)


def parse_coinbase_tx(tx_bytes: bytes) -> dict | None:
    """Adapt parse_coinbase (expects raw block) to a bare coinbase tx."""
    fake_block = b"\x00" * 80 + b"\x01" + tx_bytes
    return parse_coinbase(fake_block)


def normalize_validation_status(status: str) -> str:
    """Map a legacy Phase B status token onto the shared verdict vocabulary.

    Current Phase B verdicts pass through unchanged, as does legacy ``VALID``
    (the one token the rename left alone); only the three renamed tokens are
    rewritten.
    """
    return LEGACY_VALIDATION_STATUS.get(status, status)


def resolved_height_and_status(
    row: dict[str, str], scriptsig_hex: str
) -> tuple[int | str, str]:
    """Resolve parent-derived height and apply historical header-context gates."""
    status = normalize_validation_status(row.get("validation_status", "") or "")
    if status.startswith("UNKNOWN:"):
        return "", status
    parent_height = row.get("btc_parent_height", "")
    try:
        parent_height_int = int(parent_height)
    except (TypeError, ValueError):
        return "", "REJECTED: missing canonical parent height"
    if parent_height_int < 0:
        return "", "REJECTED: invalid canonical parent height"

    btc_height = parent_height_int + 1
    if status == "VALID":
        try:
            parent_mediantime = _parse_parent_mediantime(row)
        except ValueError as exc:
            return btc_height, f"REJECTED: {exc}"
        error = stale_header_context_error(
            {
                "btc_header_hex": row.get("btc_header_hex", ""),
                "btc_time": row.get("btc_time", ""),
                "coinbase_scriptsig_hex": scriptsig_hex,
            },
            btc_height,
            parent_median_time_past=parent_mediantime,
        )
        if error is not None:
            status = error
    return btc_height, status


def _parse_parent_mediantime(row: dict[str, str]) -> int:
    """Return Phase B's persisted active-parent MTP or raise a clear error."""
    value = row.get("btc_parent_mediantime", "")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("missing canonical parent median-time-past") from exc
    if parsed < 0 or parsed > 0xFFFFFFFF:
        raise ValueError("invalid canonical parent median-time-past")
    return parsed


def _optional_parent_mediantime(row: dict[str, str]) -> int | None:
    """Return the persisted parent MTP, or None when the row does not carry one.

    Phase B only resolves the MTP once it has an active-chain parent, so a
    placement rejection legitimately has none. ``consensus_violations`` skips
    the median-time-past rule when the context is None, which is the honest
    answer here: not evaluated rather than not violated.
    """
    try:
        return _parse_parent_mediantime(row)
    except ValueError:
        return None


def derived_error_block_rules(
    row: dict, btc_height: object, *, parent_row: dict[str, str]
) -> list[str]:
    """Return the consensus rules a rejected row's own bytes prove it violated.

    ``row`` carries the parsed header and coinbase evidence; ``parent_row`` is
    the Phase B input row, which is where the canonical parent's
    median-time-past lives.

    Empty when the height is unresolved (that rejection is about missing parent
    context, not about the block) or when the evidence is merely unusable. The
    epoch retarget rule is not evaluated: Phase C does not load the retarget
    reference table.
    """
    if not isinstance(btc_height, int) or isinstance(btc_height, bool):
        return []
    return consensus_violations(
        row,
        btc_height,
        parent_median_time_past=_optional_parent_mediantime(parent_row),
    )


def _write_rows_atomically(
    output: Path, rows: list[dict], *, columns: list[str]
) -> None:
    """Replace ``output`` only after a complete CSV has been written."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as f:
            temp_path = Path(f.name)
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temp_path, output)
    except BaseException:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise


def main():
    """Filter Phase B's stale rows, parse each coinbase, and write the
    standard-schema ``hathor_validated_stales.csv`` plus the error-block peer.
    """
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--input", default="data/hathor_stale_blocks.csv")
    p.add_argument(
        "--output", default="data/validated-stales/hathor_validated_stales.csv"
    )
    p.add_argument(
        "--error-block-output",
        default=None,
        help=(
            "consensus-invalid rejected rows; defaults to the _error_blocks "
            "peer of --input, matching the shared bucket-split naming"
        ),
    )
    args = p.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    # derive_split_paths names the canonical/unknown/error-block peers of a
    # stale inventory. Phase C only writes the third; Phase B owns the rest.
    error_block_path = Path(
        args.error_block_output or derive_split_paths(str(in_path))[2]
    )

    n_in = 0
    n_stale = 0
    n_rejected_undetermined = 0
    rows_out = []
    error_rows = []
    vstatus = {}

    with open(in_path) as f:
        reader = csv.DictReader(f)
        missing_columns = PHASE_B_REQUIRED_COLUMNS.difference(reader.fieldnames or [])
        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise ValueError(f"Phase B input is missing required columns: {missing}")
        for row in reader:
            n_in += 1
            classification = row.get("classification")
            if classification == "canonical":
                continue
            if classification != "stale":
                raise ValueError(
                    f"invalid classification in Phase C input row {n_in}: "
                    f"{classification!r}"
                )
            n_stale += 1

            cb_hex = row.get("full_coinbase_hex", "")
            try:
                cb_bytes = bytes.fromhex(cb_hex)
            except ValueError as exc:
                raise ValueError(
                    f"invalid coinbase hex in Phase C input row {n_in}"
                ) from exc
            cb = parse_coinbase_tx(cb_bytes)
            if not cb:
                raise ValueError(
                    f"could not parse coinbase in Phase C input row {n_in}"
                )
            scriptsig_hex = cb["scriptsig"].hex()
            outputs_str = format_outputs(cb["outputs"])

            # Authoritative BTC height = parent_height + 1 (Phase B
            # resolved the parent against the active chain). The exact BIP34
            # prefix is a mandatory cross-check, never a height fallback.
            btc_height, status = resolved_height_and_status(row, scriptsig_hex)
            vstatus[status or "(none)"] = vstatus.get(status or "(none)", 0) + 1
            if status.startswith("UNKNOWN:"):
                raise RuntimeError(
                    "Phase C validation context is incomplete; refusing to "
                    f"replace output at input row {n_in}: {status}"
                )

            out = {
                "btc_height": btc_height,
                "btc_header_hash": row["btc_header_hash"],
                "btc_prev_hash": row["btc_prev_hash"],
                "btc_time": row["btc_time"],
                "btc_bits": row["btc_bits"],
                "coinbase_scriptsig_hex": scriptsig_hex,
                "coinbase_outputs": outputs_str,
                "btc_header_hex": row["btc_header_hex"],
                "hathor_height": row["hathor_height"],
                "classification": "stale",
                "validation_status": status,
                "expected_nbits": row.get("expected_nbits", ""),
            }
            if status == "VALID":
                rows_out.append(out)
            elif status.startswith("REJECTED:"):
                # A rejection means one of three unrelated things and only the
                # first is a verdict on the block: a consensus rule the bytes
                # prove broken (an error block), a header we cannot place on
                # Bitcoin, or evidence too incomplete to judge. Re-derive the
                # rules rather than reading them back out of the verdict string,
                # so only the first case is published.
                rules = derived_error_block_rules(out, btc_height, parent_row=row)
                if rules:
                    error_rows.append(
                        {
                            **out,
                            "classification": "error_block",
                            "rules_violated": "|".join(rules),
                        }
                    )
                else:
                    n_rejected_undetermined += 1

    rows_out.sort(key=lambda r: (r["btc_height"] or 0, r["hathor_height"]))
    error_rows.sort(key=lambda r: (r["btc_height"] or 0, r["hathor_height"]))

    _write_rows_atomically(out_path, rows_out, columns=OUTPUT_COLUMNS)
    _write_rows_atomically(error_block_path, error_rows, columns=ERROR_BLOCK_COLUMNS)

    print("Phase C complete:", file=sys.stderr)
    print(f"  read:        {n_in:,} rows", file=sys.stderr)
    print(f"  stale rows:  {n_stale:,}", file=sys.stderr)
    print(f"  written:     {len(rows_out):,} rows to {out_path}", file=sys.stderr)
    print(
        f"  error blocks: {len(error_rows):,} rows to {error_block_path}",
        file=sys.stderr,
    )
    print(
        f"  dropped:     {n_rejected_undetermined:,} rejected rows with no "
        "derivable consensus rule",
        file=sys.stderr,
    )
    print("  validation_status:", file=sys.stderr)
    for k, v in sorted(vstatus.items()):
        print(f"    {k:>18s}: {v:,}", file=sys.stderr)


if __name__ == "__main__":
    main()
