#!/usr/bin/env python3
"""Build data/error-blocks/error_blocks.csv from reachable evidence archives.

Seeds from the committed error-blocks dataset
(``data/error-blocks/error_blocks.csv``; every row is an error block) and
joins each seed key to its evidence per a fixed source map:

- Group A: 15 heights / 16 rows: sibling full-evidence exports
  (``<chain>_evidence.csv`` for ixcoin/devcoin/i0coin).
- Group B: 4 heights / 5 rows: ``rsk_evidence.csv`` (coinbase from the
  committed dataset; RSK does not expose the real parent coinbase).
- Group C: 3 heights / 8 rows: upstream ``stale-blocks.csv`` 80-byte header hex
  (coinbase from the committed dataset).
- Group D: 2 heights / 2 rows: namecoin-node-recovered headers staged in
  ``cache/recovered_seed_headers.json``.

An optional ``--monitor-export PATH`` merges one merge-mining-monitor live
evidence row (a self-contained JSON export) into the seed set before assembly.
The monitor row carries every dataset column; it is verified the same way
(sha256d(header)[::-1] must equal ``hash``) and, once merged, persists in the
committed CSV so plain regeneration without ``--monitor-export`` keeps it.
When the export provides ``parent_median_time_past``, the builder also records
it in the committed ``data/error-blocks/mtp_context.csv`` sidecar so the
validator can re-derive time-rule violations offline.

An optional ``--extra-rows PATH`` merges classifier- or sweep-emitted rows (a
JSON list of self-contained row objects, each carrying the same fields as a
monitor export) into the seed set the same way. Extra rows carry no MTP
context; their provenance starts with one of the prefixes in
``SELF_CONTAINED_PROVENANCE_PREFIXES`` and they persist in the committed CSV
so plain regeneration without ``--extra-rows`` keeps them. Every
self-contained import (monitor export or extra row) MUST carry a provenance
starting with one of those recognized prefixes: ingest fails closed
otherwise, because the transient ``_self_contained`` ingest tag is not a
dataset column and a plain rebuild recognizes a committed self-contained row
only by its provenance prefix — an unrecognized prefix would commit a row
the next rebuild cannot place (it is not in the verified source map).

A self-contained row may carry an optional ``rules_violated`` field: the
pipe-joined FULL rule set (``rejection_reason`` remains the primary/first
rule). When present it is used verbatim; when absent, ``rules_violated``
defaults to ``rejection_reason`` (the existing single-rule rows).

Every assembled row is verified: sha256d(header)[::-1] must equal the seed
``hash`` (display order). Self-contained monitor/sweep rows additionally
re-derive through the offline validator's ``validate_row`` (own-target PoW,
``expected_nbits`` against the epoch table, and every claimed
``rules_violated`` token) before a non-partial run may write the committed
dataset; a row that fails validation fails the build closed (no write).
Read-only against all sources. Fails closed (no
write, non-zero exit) when any seed row's evidence is missing or a hash check
fails, unless ``--allow-partial`` writes to a disposable ``--output-dir``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from pathlib import Path

from stale_blocks_analysis.auxpow_chainid import hash_to_display_hex
from stale_blocks_analysis.config import (
    ERROR_BLOCKS_CSV,
    ERROR_BLOCKS_MTP_CONTEXT_CSV,
)
from stale_blocks_analysis.error_observations import (
    ERROR_OBSERVATION_LEDGER,
    validate_error_observation_ledger,
)
from stale_blocks_analysis.reconciled_error_blocks import (
    build_reconciled_import,
    merge_ledger_rows,
    write_ledger,
)

# The offline re-derivation validator lives under scripts/analysis/; import it
# via the established scripts sibling-import pattern (the sweeps do the same
# for _sweep_common) so self-contained rows can be validated before a
# committed-dataset write.
_ANALYSIS_DIR = Path(__file__).resolve().parents[1] / "analysis"
if str(_ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(_ANALYSIS_DIR))

from validate_error_blocks import _load_mtp_context, validate_row  # noqa: E402

COLUMNS = [
    "height",
    "hash",
    "btc_prev_hash",
    "btc_header_version",
    "btc_time",
    "btc_bits",
    "expected_nbits",
    "btc_header_hex",
    "coinbase_height",
    "coinbase_scriptsig_hex",
    "source_chains",
    "source_child_observations",
    "classification",
    "rejection_reason",
    "rules_violated",
    "first_observed_child_time",
    "provenance",
]

DEFAULT_FULL_EVIDENCE_DIR = Path(
    "~/dev/bitcoin/stale-blocks-research/results/full-evidence"
).expanduser()
DEFAULT_UPSTREAM_STALE_BLOCKS = Path(
    "~/dev/bitcoin/stale-blocks-research/data/stale-blocks/stale-blocks.csv"
).expanduser()
DEFAULT_RECOVERED_HEADERS = Path("cache/recovered_seed_headers.json")
DEFAULT_ERROR_OBSERVATION_LEDGER = ERROR_BLOCKS_CSV.parent / ERROR_OBSERVATION_LEDGER
DEFAULT_RECONCILED_CHILD_IDENTITIES = (
    ERROR_BLOCKS_CSV.parent / "reconciled_child_identities.csv"
)

MTP_CONTEXT_COLUMNS = ["height", "hash", "parent_median_time_past", "provenance"]

# Provenance prefixes marking a self-contained row: the row carries its own
# header hex and provenance in the committed dataset, so it persists across
# plain rebuilds without re-supplying --monitor-export / --extra-rows. Every
# sweep that emits promotable rows gets its own explicit prefix here (an
# over-broad ``sweep-`` wildcard would treat any future sweep's rows as
# self-contained without review).
SELF_CONTAINED_PROVENANCE_PREFIXES = (
    "classifier-emitted:",
    "monitor-live-capture:",
    "sweep-rejected-rows:",
    "sweep-version-bip:",
    "sweep-coinbase-form:",
    "sweep-time-rule:",
)

# Group A: seed (height, hash) prefixes mapped to their full-evidence file.
# Keys are (height, hash); values are the evidence filename stem.
GROUP_A_CHAINS = {
    225013: "ixcoin",
    225015: "ixcoin",
    225134: "ixcoin",
    225145: "ixcoin",
    225221: "devcoin",
    225430: "ixcoin",
    225464: "ixcoin",
    226230: "ixcoin",
    226845: "devcoin",
    226895: "ixcoin",
    226912: "ixcoin",
    277975: "ixcoin",
    331735: "ixcoin",
    364341: "ixcoin",
    367047: "i0coin",
}
GROUP_B_HEIGHTS = {543804, 544024, 544600, 789038}
GROUP_C_HEIGHTS = {229388, 380992, 383540}
GROUP_D_HEIGHTS = {363967, 389043}


def sha256d_display_hash(header_hex: str) -> str:
    """Return the display-order block hash of an 80-byte header hex."""
    raw = bytes.fromhex(header_hex)
    digest = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    return digest[::-1].hex()


def parse_header_fields(header_hex: str) -> dict[str, str]:
    """Derive version/time/bits from an 80-byte header hex (display order out)."""
    raw = bytes.fromhex(header_hex)
    if len(raw) != 80:
        raise ValueError(f"header hex must be 80 bytes, got {len(raw)}")
    version = int.from_bytes(raw[0:4], "little", signed=True)
    time_ = int.from_bytes(raw[68:72], "little")
    bits = int.from_bytes(raw[72:76], "little")
    return {
        "btc_header_version": str(version),
        "btc_time": str(time_),
        "btc_bits": f"{bits:08x}",
    }


def parse_header_prev_hash(header_hex: str) -> str:
    """Derive the parent block hash (display order) from an 80-byte header hex.

    The parent hash sits at bytes 4..36 of the serialized header in internal
    (little-endian) order; ``hash_to_display_hex`` reverses it to display
    order, so the value is derived from the authoritative header bytes rather
    than trusted from a seed/import column.
    """
    raw = bytes.fromhex(header_hex)
    if len(raw) != 80:
        raise ValueError(f"header hex must be 80 bytes, got {len(raw)}")
    return hash_to_display_hex(raw[4:36])


def load_seed_rows(path: Path) -> list[dict[str, str]]:
    """Read the seed rows from the committed error-blocks dataset.

    Fails closed on a malformed row: a seed row whose ``classification`` is
    missing or not exactly ``error_block`` raises rather than being silently
    dropped — silently dropping it would make a normal rebuild write a SMALLER
    dataset without error, removing that exclusion key and letting the known
    invalid block back into publications. This mirrors the gate loader's
    fail-closed check in ``stale_blocks_analysis.error_blocks``.
    """
    rows: list[dict[str, str]] = []
    with path.open(newline="") as f:
        for row_number, row in enumerate(csv.DictReader(f), start=2):
            if row.get("classification") != "error_block":
                raise ValueError(
                    f"invalid seed row {row_number} in {path}: classification "
                    f"{row.get('classification')!r} is not 'error_block'"
                )
            rows.append(row)
    return rows


def load_monitor_export(path: Path) -> dict[str, str]:
    """Read one merge-mining-monitor live evidence export as a dataset row.

    The export is a self-contained JSON object carrying every dataset column
    plus validation context (``parent_median_time_past``). Returns a row dict
    keyed by the dataset columns; the MTP context is carried under the
    ``_parent_median_time_past`` key for the sidecar, not the dataset.
    """
    with path.open() as f:
        export = json.load(f)
    if not isinstance(export, dict):
        raise ValueError("monitor export must be a JSON object")
    return _self_contained_row(export)


def _self_contained_row(export: dict) -> dict[str, str]:
    """Normalize one self-contained row object (monitor export or extra row)."""

    def text(key: str) -> str:
        value = export.get(key)
        if value is None:
            raise ValueError(f"row missing required field {key!r}")
        return str(value)

    row = {
        "height": text("height"),
        "hash": text("hash"),
        "btc_prev_hash": text("btc_prev_hash"),
        "btc_header_hex": text("btc_header_hex"),
        "expected_nbits": text("expected_nbits"),
        "coinbase_height": text("coinbase_height"),
        "coinbase_scriptsig_hex": text("coinbase_scriptsig_hex"),
        "source_chains": text("source_chains"),
        "source_child_observations": text("source_child_observations"),
        "rejection_reason": text("rejection_reason"),
        "first_observed_child_time": text("first_observed_child_time"),
        "provenance": text("provenance"),
    }
    # A row with no witnessing chain is not merge-mining evidence: fail closed
    # on empty source fields (``text`` above rejects only a missing key).
    for evidence_key in ("source_chains", "source_child_observations"):
        if not row[evidence_key].strip():
            raise ValueError(
                f"row has empty {evidence_key!r}: a witnessing chain is required"
            )
    # The child observations must correspond to the source chains: exactly one
    # pipe-joined ``chain:child_height`` observation per pipe-joined source
    # chain, each naming one of those chains, with the mapping one-to-one (no
    # empty or duplicate source chain, no chain observed twice, and no chain
    # left unobserved). A count mismatch (e.g. two chains but one observation),
    # an observation without the ``chain:child_height`` form, one naming a
    # chain outside ``source_chains``, or a duplicate source/observation chain
    # means the witnessing evidence does not match the declared sources; fail
    # closed.
    source_chains = [chain.strip() for chain in row["source_chains"].split("|")]
    observations = [
        observation.strip()
        for observation in row["source_child_observations"].split("|")
    ]
    observed_chains = [
        observation.split(":", 1)[0] if ":" in observation else ""
        for observation in observations
    ]
    if (
        any(not chain for chain in source_chains)
        or len(set(source_chains)) != len(source_chains)
        or len(observations) != len(source_chains)
        or any(
            ":" not in observation
            or observation.split(":", 1)[0] not in source_chains
            or not observation.split(":", 1)[1]
            for observation in observations
        )
        or sorted(observed_chains) != sorted(source_chains)
    ):
        raise ValueError(
            f"source_child_observations {row['source_child_observations']!r} "
            f"does not match source_chains {row['source_chains']!r}: each "
            "source chain must have exactly one chain:child_height observation"
        )
    # Fail closed on an unrecognized provenance prefix. The ``_self_contained``
    # ingest tag set below is NOT a dataset column, so a plain rebuild
    # recognizes a committed self-contained row only by its provenance prefix
    # (see build_rows). Committing a row with an unrecognized prefix would
    # leave the next ordinary rebuild unable to place it (its height is not in
    # the verified source map), making the committed dataset
    # non-reproducible. Register a new sweep's prefix in
    # SELF_CONTAINED_PROVENANCE_PREFIXES before importing its rows.
    if not row["provenance"].startswith(SELF_CONTAINED_PROVENANCE_PREFIXES):
        raise ValueError(
            f"unrecognized self-contained provenance {row['provenance']!r}: "
            "must start with one of "
            + ", ".join(repr(p) for p in SELF_CONTAINED_PROVENANCE_PREFIXES)
            + " (register the sweep's prefix in SELF_CONTAINED_PROVENANCE_PREFIXES"
            " before importing its rows)"
        )
    # Honor an input rules_violated (the pipe-joined full rule set;
    # rejection_reason stays the primary/first rule). When the input carries
    # only rejection_reason, rules_violated defaults to it (the existing
    # single-rule rows). Not a required field: single-rule exports omit it.
    rules_violated = export.get("rules_violated")
    if rules_violated is not None:
        row["rules_violated"] = str(rules_violated)
    # Validation context for the committed MTP sidecar; not a dataset column.
    mtp = export.get("parent_median_time_past")
    row["_parent_median_time_past"] = "" if mtp is None else str(mtp)
    # Self-contained rows are validated via validate_row before a
    # committed-dataset write (see main); not a dataset column.
    row["_self_contained"] = "1"
    return row


def load_extra_rows(path: Path) -> list[dict[str, str]]:
    """Read sweep-found rows as dataset rows.

    The file is a JSON list of self-contained row objects carrying the same
    fields as a monitor export (``parent_median_time_past`` is optional and
    typically absent for sweep rows). Each row is verified and persisted the
    same way as a monitor row.
    """
    with path.open() as f:
        payload = json.load(f)
    if not isinstance(payload, list) or not all(
        isinstance(item, dict) for item in payload
    ):
        raise ValueError("extra rows must be a JSON list of objects")
    return [_self_contained_row(item) for item in payload]


def _dedup_key(row: dict[str, str]) -> tuple[int, str]:
    """Return the canonical (height, hash) dedup key for a seed/import row.

    Height is parsed as an int and the hash is lowercased/stripped, so a
    monitor/extra-row import that identifies an existing block with a
    noncanonical height string (``"0946213"``) or a mixed-case hash dedups
    against the seed's canonical ``"946213"`` / lowercase form instead of
    writing a duplicate row.
    """
    return (int(row["height"]), row["hash"].strip().lower())


def merge_self_contained_row(
    seeds: list[dict[str, str]], row: dict[str, str]
) -> list[dict[str, str]]:
    """Merge a self-contained row (monitor export or extra row) into the
    seed set, deduping by the canonical (height, hash) key."""
    key = _dedup_key(row)
    merged = [seed for seed in seeds if _dedup_key(seed) != key]
    merged.append(row)
    return merged


def load_full_evidence(path: Path) -> dict[tuple[int, str], dict[str, str]]:
    """Index a full-evidence export by (btc_height, btc_header_hash)."""
    out: dict[tuple[int, str], dict[str, str]] = {}
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            height = (row.get("btc_height") or "").strip()
            block_hash = (row.get("btc_header_hash") or "").strip()
            if height and block_hash:
                out[(int(height), block_hash)] = row
    return out


def load_upstream_headers(path: Path) -> dict[tuple[int, str], str]:
    """Index upstream stale-blocks.csv header hex by (height, hash)."""
    out: dict[tuple[int, str], str] = {}
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            out[(int(row["height"]), row["hash"])] = row["header"]
    return out


def group_for_seed(height: int) -> str:
    if height in GROUP_A_CHAINS:
        return "A"
    if height in GROUP_B_HEIGHTS:
        return "B"
    if height in GROUP_C_HEIGHTS:
        return "C"
    if height in GROUP_D_HEIGHTS:
        return "D"
    raise ValueError(f"seed height {height} is not in the verified source map")


def assemble_row(
    seed: dict[str, str],
    *,
    header_hex: str,
    expected_nbits: str,
    coinbase_scriptsig_hex: str,
    provenance: str,
    first_observed_child_time: str = "",
) -> dict[str, str]:
    """Build one output row, deriving audit columns from the header hex."""
    fields = parse_header_fields(header_hex)
    derived_hash = sha256d_display_hash(header_hex)
    if derived_hash != seed["hash"]:
        raise ValueError(
            f"hash check failed for {seed['height']}:{seed['hash'][-12:]}: "
            f"sha256d(header)={derived_hash[-12:]}..."
        )
    # The authoritative 80-byte header is available, so derive the parent hash
    # from its bytes rather than trust the seed/import column: a mistyped seed
    # btc_prev_hash is otherwise copied verbatim into the committed dataset.
    # Fail closed on a mismatch (the header-derived value is authoritative).
    derived_prev_hash = parse_header_prev_hash(header_hex)
    seed_prev_hash = (seed["btc_prev_hash"] or "").strip().lower()
    if seed_prev_hash and seed_prev_hash != derived_prev_hash:
        raise ValueError(
            f"btc_prev_hash mismatch for {seed['height']}:{seed['hash'][-12:]}: "
            f"seed={seed_prev_hash[-12:]}... but header derives "
            f"{derived_prev_hash[-12:]}..."
        )
    return {
        "height": seed["height"],
        "hash": seed["hash"],
        "btc_prev_hash": derived_prev_hash,
        "btc_header_version": fields["btc_header_version"],
        "btc_time": fields["btc_time"],
        "btc_bits": fields["btc_bits"],
        # The fallback to the header bits is deliberate for groups C/D: epoch
        # bits == header bits for all seed heights, and the Task 3 validator
        # cross-checks the column against the epoch reference.
        "expected_nbits": expected_nbits or fields["btc_bits"],
        "btc_header_hex": header_hex,
        "coinbase_height": seed["coinbase_height"],
        "coinbase_scriptsig_hex": coinbase_scriptsig_hex,
        "source_chains": seed["source_chains"],
        "source_child_observations": seed["source_child_observations"],
        "classification": "error_block",
        "rejection_reason": seed["rejection_reason"],
        # rules_violated is the pipe-joined FULL rule set (rejection_reason is
        # the primary/first rule). A self-contained seed may carry an input
        # rules_violated; every other row is single-rule, so it defaults to
        # the rejection_reason.
        "rules_violated": seed.get("rules_violated") or seed["rejection_reason"],
        "first_observed_child_time": first_observed_child_time,
        "provenance": provenance,
    }


def build_rows(
    seeds: list[dict[str, str]],
    *,
    full_evidence_dir: Path,
    upstream_stale_blocks: Path,
    recovered_headers: Path,
) -> tuple[list[dict[str, str]], list[str]]:
    """Assemble all seed rows; return (rows, errors)."""
    rows: list[dict[str, str]] = []
    errors: list[str] = []

    evidence_cache: dict[str, dict[tuple[int, str], dict[str, str]]] = {}

    def evidence(chain: str) -> dict[tuple[int, str], dict[str, str]]:
        if chain not in evidence_cache:
            evidence_cache[chain] = load_full_evidence(
                full_evidence_dir / f"{chain}_evidence.csv"
            )
        return evidence_cache[chain]

    upstream: dict[tuple[int, str], str] | None = None
    recovered: dict[str, dict] | None = None

    for seed in seeds:
        label = f"{seed['height']}:{seed['hash'][-12:]}"
        try:
            key = (int(seed["height"]), seed["hash"])
            if seed["provenance"].startswith(SELF_CONTAINED_PROVENANCE_PREFIXES):
                # Self-contained row (monitor live evidence or sweep-found):
                # carries its own header hex and provenance in the committed
                # dataset. Verify and pass through. The provenance prefix is
                # the single recognition rule on BOTH paths: ingest
                # (_self_contained_row) fails closed on an unrecognized
                # prefix, so a freshly-merged --monitor-export / --extra-rows
                # row always carries a recognized one, and a committed row
                # re-read as a seed on plain rebuilds is recognized by the
                # same prefix (the underscore-prefixed ingest tag is not a
                # dataset column and does not survive the round trip). The
                # row therefore persists without re-supplying
                # --monitor-export / --extra-rows, and every committed
                # self-contained row stays rebuildable.
                rows.append(
                    assemble_row(
                        seed,
                        header_hex=seed["btc_header_hex"],
                        expected_nbits=seed["expected_nbits"],
                        coinbase_scriptsig_hex=seed["coinbase_scriptsig_hex"],
                        provenance=seed["provenance"],
                        first_observed_child_time=seed["first_observed_child_time"],
                    )
                )
                rows[-1]["_self_contained"] = "1"
                # Carry the export's MTP context through assembly so
                # validate_self_contained_rows can merge it into the
                # in-memory sidecar view (a NEW time-rule row's context is
                # not in the committed sidecar yet).
                if seed.get("_parent_median_time_past"):
                    rows[-1]["_parent_median_time_past"] = seed[
                        "_parent_median_time_past"
                    ]
                continue
            group = group_for_seed(key[0])
            if group == "A":
                chain = GROUP_A_CHAINS[key[0]]
                ev = evidence(chain).get(key)
                if ev is None:
                    raise ValueError(f"no {chain} full-evidence row for {label}")
                rows.append(
                    assemble_row(
                        seed,
                        header_hex=ev["btc_header_hex"],
                        expected_nbits=(ev.get("expected_nbits") or "").strip(),
                        coinbase_scriptsig_hex=ev["coinbase_scriptsig_hex"],
                        provenance=f"full-evidence:{chain}_evidence.csv",
                    )
                )
            elif group == "B":
                ev = evidence("rsk").get(key)
                if ev is None:
                    raise ValueError(f"no rsk full-evidence row for {label}")
                rows.append(
                    assemble_row(
                        seed,
                        header_hex=ev["btc_header_hex"],
                        expected_nbits=(ev.get("expected_nbits") or "").strip(),
                        # RSK does not expose the real parent coinbase; the
                        # committed dataset carries it from the namecoin
                        # observation.
                        coinbase_scriptsig_hex=seed["coinbase_scriptsig_hex"],
                        provenance="full-evidence:rsk_evidence.csv"
                        " (coinbase from committed error-blocks dataset)",
                    )
                )
            elif group == "C":
                if upstream is None:
                    upstream = load_upstream_headers(upstream_stale_blocks)
                header_hex = upstream.get(key)
                if header_hex is None:
                    raise ValueError(f"no upstream stale-blocks row for {label}")
                rows.append(
                    assemble_row(
                        seed,
                        header_hex=header_hex,
                        expected_nbits="",
                        coinbase_scriptsig_hex=seed["coinbase_scriptsig_hex"],
                        provenance="upstream-stale-blocks:stale-blocks.csv",
                    )
                )
            else:  # group D
                if recovered is None:
                    with recovered_headers.open() as f:
                        recovered = json.load(f)
                entry = recovered.get(f"{seed['height']}_{seed['hash']}")
                if entry is None:
                    raise ValueError(f"no recovered header for {label}")
                rows.append(
                    assemble_row(
                        seed,
                        header_hex=entry["btc_header_hex"],
                        expected_nbits="",
                        coinbase_scriptsig_hex=seed["coinbase_scriptsig_hex"],
                        provenance=entry["source"],
                    )
                )
        except (ValueError, KeyError, FileNotFoundError) as exc:
            errors.append(f"{label}: {exc}")

    rows.sort(key=lambda r: (int(r["height"]), r["hash"]))
    return rows, errors


def write_csv(rows: list[dict[str, str]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=COLUMNS,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def validate_self_contained_rows(rows: list[dict[str, str]]) -> list[str]:
    """Re-derive every self-contained (monitor/sweep) row via validate_row.

    The hash-equality check in assemble_row only proves the row is internally
    consistent; before a non-partial run may overwrite the committed dataset,
    each self-contained row must also pass the offline validator: own-target
    proof of work, expected_nbits against the canonical epoch table, and
    every claimed rules_violated token re-derived from the committed bytes.
    Returns one failure message per row problem (empty when all pass).

    The time-rule re-derivation reads the parent median-time-past from the
    committed sidecar, but a NEW monitor row's MTP context is only written to
    that sidecar by ``update_mtp_context`` AFTER this validation runs. So the
    rows are validated against an in-memory merge of the committed sidecar
    plus each self-contained row's own ``_parent_median_time_past``: a new
    ``time_below_mtp`` row re-derives against the context its export carries,
    without requiring the sidecar to already contain it (a row without MTP
    context still fails closed).
    """
    mtp_context = _load_mtp_context()
    for row in rows:
        mtp = row.get("_parent_median_time_past", "")
        if row.get("_self_contained") and mtp:
            mtp_context[(int(row["height"]), row["hash"])] = int(mtp)
    failures: list[str] = []
    for row in rows:
        if not row.get("_self_contained"):
            continue
        row_id = f"{row['height']}:{row['hash'][-12:]}"
        for failure in validate_row(row, mtp_context=mtp_context):
            failures.append(f"{row_id}: {failure}")
    return failures


def update_mtp_context(
    row: dict[str, str], path: Path = ERROR_BLOCKS_MTP_CONTEXT_CSV
) -> None:
    """Record a self-contained row's parent median-time-past in the sidecar.

    Covers any self-contained row (monitor export or extra-rows) carrying a
    ``_parent_median_time_past``. Keyed by (height, hash); an existing entry
    for the same key is replaced.
    """
    mtp = row.get("_parent_median_time_past", "")
    if not mtp:
        print(
            "warning: self-contained row has no parent_median_time_past; "
            f"MTP sidecar not updated for {row['height']}",
            file=sys.stderr,
        )
        return
    entries: dict[tuple[str, str], dict[str, str]] = {}
    if path.exists():
        with path.open(newline="") as f:
            for row_ in csv.DictReader(f):
                entries[(row_["height"], row_["hash"])] = row_
    entries[(row["height"], row["hash"])] = {
        "height": row["height"],
        "hash": row["hash"],
        "parent_median_time_past": mtp,
        "provenance": row["provenance"],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=MTP_CONTEXT_COLUMNS,
            lineterminator="\n",
        )
        writer.writeheader()
        for key in sorted(entries, key=lambda k: (int(k[0]), k[1])):
            writer.writerow(entries[key])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ERROR_BLOCKS_CSV)
    parser.add_argument(
        "--full-evidence-dir", type=Path, default=DEFAULT_FULL_EVIDENCE_DIR
    )
    parser.add_argument(
        "--upstream-stale-blocks", type=Path, default=DEFAULT_UPSTREAM_STALE_BLOCKS
    )
    parser.add_argument(
        "--recovered-headers", type=Path, default=DEFAULT_RECOVERED_HEADERS
    )
    parser.add_argument(
        "--monitor-export",
        type=Path,
        default=None,
        help="merge one merge-mining-monitor live evidence JSON export into "
        "the seed set (and record its MTP context in the committed sidecar)",
    )
    parser.add_argument(
        "--extra-rows",
        type=Path,
        default=None,
        help="merge classifier- or sweep-emitted rows (a JSON list of self-contained row "
        "objects) into the seed set; they persist in the committed CSV",
    )
    parser.add_argument(
        "--reconciled-error-blocks",
        type=Path,
        default=None,
        help="verify and consolidate a stale-descendant reconciliation error peer",
    )
    parser.add_argument(
        "--reconciled-child-identities",
        type=Path,
        default=DEFAULT_RECONCILED_CHILD_IDENTITIES,
        help="node-authenticated child identities for the reconciliation peer",
    )
    parser.add_argument(
        "--error-observation-ledger",
        type=Path,
        default=DEFAULT_ERROR_OBSERVATION_LEDGER,
        help="recovered child-witness ledger updated with reconciled observations",
    )
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument(
        "--seed",
        type=Path,
        default=ERROR_BLOCKS_CSV,
        help="seed rows CSV (default: the committed error-blocks dataset); "
        "tests point this at a compact fixture seed so the builder runs "
        "without the private evidence archives",
    )
    args = parser.parse_args(argv)

    if args.allow_partial:
        if args.output_dir is None:
            print("--allow-partial requires --output-dir", file=sys.stderr)
            return 2
    elif args.output_dir is not None:
        print("--output-dir is only valid with --allow-partial", file=sys.stderr)
        return 2

    def committed_cli_path(path: Path, expected: Path) -> bool:
        """Match a committed CLI path without resolving symlink aliases."""
        return Path(os.path.abspath(path)) == Path(os.path.abspath(expected))

    if args.reconciled_error_blocks is not None and (
        args.allow_partial
        or not committed_cli_path(args.output, ERROR_BLOCKS_CSV)
        or not committed_cli_path(args.seed, ERROR_BLOCKS_CSV)
        or not committed_cli_path(
            args.error_observation_ledger, DEFAULT_ERROR_OBSERVATION_LEDGER
        )
        or not committed_cli_path(
            args.reconciled_child_identities, DEFAULT_RECONCILED_CHILD_IDENTITIES
        )
    ):
        print(
            "--reconciled-error-blocks requires the non-partial committed "
            "catalogue output and seed, ledger, and child-identity manifest paths",
            file=sys.stderr,
        )
        return 2
    if args.reconciled_error_blocks is not None:
        # Keep every later read, temp-file placement, and replacement anchored
        # to the committed paths. The lexical guard above rejects symlink aliases;
        # these assignments make the write target explicit even if the guard is
        # refactored later.
        args.output = ERROR_BLOCKS_CSV
        args.seed = ERROR_BLOCKS_CSV
        args.error_observation_ledger = DEFAULT_ERROR_OBSERVATION_LEDGER
        args.reconciled_child_identities = DEFAULT_RECONCILED_CHILD_IDENTITIES

    try:
        seeds = load_seed_rows(args.seed)
    except ValueError as exc:
        print(f"error: invalid seed rows: {exc}", file=sys.stderr)
        return 1
    if not seeds:
        # Fail closed: an empty seed set (a header-only or empty CSV) yields an
        # empty gate, which is never valid for this committed dataset — the
        # default non-partial path would otherwise overwrite the committed
        # dataset with a header-only file, silently letting every known error
        # block re-enter publication loaders. This mirrors the gate loader's
        # fail-closed empty-dataset check in
        # ``stale_blocks_analysis.error_blocks``.
        print(
            f"error: no error block seed rows in {args.seed} "
            "(refusing to write an empty dataset)",
            file=sys.stderr,
        )
        return 1
    # Every self-contained row merged this run (monitor export + extra rows):
    # any of them may carry a ``_parent_median_time_past`` whose MTP context
    # must reach the committed sidecar when this run writes the committed
    # dataset, or the committed-dataset validator would fail the new
    # time-rule row for lacking committed MTP context.
    self_contained_rows: list[dict[str, str]] = []
    reconciled_ledger_rows: tuple[dict[str, str], ...] = ()
    monitor_row: dict[str, str] | None = None
    if args.monitor_export is not None:
        try:
            monitor_row = load_monitor_export(args.monitor_export)
        except (ValueError, KeyError, FileNotFoundError, json.JSONDecodeError) as exc:
            print(f"error: invalid monitor export: {exc}", file=sys.stderr)
            return 1
        seeds = merge_self_contained_row(seeds, monitor_row)
        self_contained_rows.append(monitor_row)
    if args.extra_rows is not None:
        try:
            extra_rows = load_extra_rows(args.extra_rows)
        except (ValueError, KeyError, FileNotFoundError, json.JSONDecodeError) as exc:
            print(f"error: invalid extra rows: {exc}", file=sys.stderr)
            return 1
        for extra_row in extra_rows:
            seeds = merge_self_contained_row(seeds, extra_row)
            self_contained_rows.append(extra_row)
    if args.reconciled_error_blocks is not None:
        try:
            reconciled = build_reconciled_import(
                peer_path=args.reconciled_error_blocks,
                identity_path=args.reconciled_child_identities,
                data_dir=ERROR_BLOCKS_CSV.parent.parent,
            )
            reconciled_rows = [
                _self_contained_row(row) for row in reconciled.catalogue_rows
            ]
        except (ValueError, KeyError, FileNotFoundError) as exc:
            print(f"error: invalid reconciled error blocks: {exc}", file=sys.stderr)
            return 1
        for reconciled_row in reconciled_rows:
            seeds = merge_self_contained_row(seeds, reconciled_row)
            self_contained_rows.append(reconciled_row)
        reconciled_ledger_rows = reconciled.ledger_rows
    rows, errors = build_rows(
        seeds,
        full_evidence_dir=args.full_evidence_dir,
        upstream_stale_blocks=args.upstream_stale_blocks,
        recovered_headers=args.recovered_headers,
    )

    if errors and not args.allow_partial:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(
            f"build failed: {len(errors)}/{len(seeds)} seed rows missing evidence "
            "(no output written)",
            file=sys.stderr,
        )
        return 1

    for error in errors:
        print(f"warning (partial build): {error}", file=sys.stderr)

    output = args.output
    if not args.allow_partial:
        # A non-partial scratch --output must never overwrite a committed
        # artifact other than the dataset itself. The committed-dataset write
        # (output == error_blocks.csv) is handled below; any OTHER path inside
        # the committed dataset directory (e.g. --output
        # data/error-blocks/mtp_context.csv) would replace a committed artifact
        # such as the MTP sidecar with an error-block CSV. Refuse it.
        resolved_output = output.resolve()
        committed_dir = ERROR_BLOCKS_CSV.parent.resolve()
        if (
            resolved_output != ERROR_BLOCKS_CSV.resolve()
            and resolved_output.is_relative_to(committed_dir)
        ):
            print(
                "refusing to write non-partial output to a committed artifact "
                f"path: {resolved_output} is inside the committed "
                f"{ERROR_BLOCKS_CSV.parent} (only {ERROR_BLOCKS_CSV.name} is a "
                "valid non-partial committed write); pass --allow-partial with "
                "a disposable --output-dir for a scratch build",
                file=sys.stderr,
            )
            return 2
    if args.allow_partial:
        # A partial build's --output-dir must be a genuinely disposable
        # location: pointing it at (or inside) the committed dataset directory
        # would let a partial build overwrite a DIFFERENT committed artifact
        # (e.g. --output mtp_context.csv would replace the committed MTP
        # sidecar with an error-block CSV).
        output_dir = args.output_dir.resolve()
        committed_dir = ERROR_BLOCKS_CSV.parent.resolve()
        if output_dir == committed_dir or output_dir.is_relative_to(committed_dir):
            print(
                "--allow-partial --output-dir must be a disposable directory "
                f"outside the committed dataset directory: {output_dir} is "
                f"(or is inside) the committed {ERROR_BLOCKS_CSV.parent}",
                file=sys.stderr,
            )
            return 2
        args.output_dir.mkdir(parents=True, exist_ok=True)
        output = (args.output_dir / output.name).resolve()
        if output == ERROR_BLOCKS_CSV.resolve():
            print(
                "refusing to write partial output to the committed path",
                file=sys.stderr,
            )
            return 2
    if not args.allow_partial and output.resolve() == ERROR_BLOCKS_CSV.resolve():
        # Writing the committed dataset: every self-contained monitor/sweep
        # row must re-derive through the offline validator (own-target PoW,
        # expected_nbits, and the claimed rules_violated), not just pass the
        # header-hash equality check. Fail closed on any validation failure.
        validation_failures = validate_self_contained_rows(rows)
        if validation_failures:
            for failure in validation_failures:
                print(
                    f"error: self-contained row failed validation: {failure}",
                    file=sys.stderr,
                )
            print(
                f"build failed: {len(validation_failures)} self-contained row "
                "validation failure(s) (no output written)",
                file=sys.stderr,
            )
            return 1
    if monitor_row is not None and not monitor_row.get("_parent_median_time_past"):
        # Surface an incomplete export regardless of output path: without a
        # parent MTP the time rule cannot be re-derived offline.
        print(
            "warning: monitor export has no parent_median_time_past; "
            f"MTP sidecar not updated for {monitor_row['height']}",
            file=sys.stderr,
        )
    # Only update the committed MTP sidecar when this run is actually writing
    # the committed dataset. A scratch --output (an isolated regeneration)
    # must not mutate tracked production context. EVERY self-contained row
    # carrying a parent median-time-past (monitor export OR extra-rows) gets
    # a sidecar entry: without it the committed-dataset validator would fail
    # the new time-rule row for lacking committed MTP context.
    writing_committed = (
        not args.allow_partial and output.resolve() == ERROR_BLOCKS_CSV.resolve()
    )
    if writing_committed:
        # Stage BOTH artifacts to temp files first, then replace the committed
        # files. Replace the staged MTP sidecar BEFORE the dataset: if the
        # dataset were committed first and the sidecar replace then failed (or
        # the process stopped between the two), error_blocks.csv would
        # reference required MTP context that was never committed, leaving the
        # published gate invalid. Sidecar-first means a failure instead leaves
        # the sidecar possibly-ahead — an extra MTP entry for a
        # not-yet-committed row, which is harmless because the sidecar is only
        # read for rows present in the dataset.
        sidecar_rows = [
            row for row in self_contained_rows if row.get("_parent_median_time_past")
        ]
        dataset_tmp = output.with_name(output.name + ".tmp")
        sidecar_tmp = ERROR_BLOCKS_MTP_CONTEXT_CSV.with_name(
            ERROR_BLOCKS_MTP_CONTEXT_CSV.name + ".tmp"
        )
        ledger_tmp = args.error_observation_ledger.with_name(
            args.error_observation_ledger.name + ".tmp"
        )
        write_csv(rows, dataset_tmp)
        if reconciled_ledger_rows:
            try:
                merged_ledger = merge_ledger_rows(
                    ledger_path=args.error_observation_ledger,
                    imported_rows=reconciled_ledger_rows,
                    catalogue_rows=rows,
                )
                write_ledger(merged_ledger, ledger_tmp)
                validate_error_observation_ledger(
                    catalogue_path=dataset_tmp,
                    ledger_path=ledger_tmp,
                )
            except (ValueError, KeyError, FileNotFoundError) as exc:
                dataset_tmp.unlink(missing_ok=True)
                ledger_tmp.unlink(missing_ok=True)
                print(
                    f"error: reconciled catalogue/ledger validation failed: {exc}",
                    file=sys.stderr,
                )
                return 1
        if sidecar_rows:
            # Seed the temp sidecar from the committed one so existing entries
            # are preserved; each update then reads and extends the temp file.
            if ERROR_BLOCKS_MTP_CONTEXT_CSV.exists():
                sidecar_tmp.write_bytes(ERROR_BLOCKS_MTP_CONTEXT_CSV.read_bytes())
            for row in sidecar_rows:
                update_mtp_context(row, path=sidecar_tmp)
        if sidecar_rows:
            os.replace(sidecar_tmp, ERROR_BLOCKS_MTP_CONTEXT_CSV)
        if reconciled_ledger_rows:
            # Ledger-first is fail closed if the process stops between the two
            # replacements: the aggregate validator sees unexpected witnesses
            # rather than silently publishing a parent with missing evidence.
            os.replace(ledger_tmp, args.error_observation_ledger)
        os.replace(dataset_tmp, output)
        print(f"wrote {len(rows)} rows to {output}")
        if reconciled_ledger_rows:
            print(f"updated error observation ledger {args.error_observation_ledger}")
        if sidecar_rows:
            print(f"updated MTP context sidecar {ERROR_BLOCKS_MTP_CONTEXT_CSV}")
        return 0
    write_csv(rows, output)
    print(f"wrote {len(rows)} rows to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
