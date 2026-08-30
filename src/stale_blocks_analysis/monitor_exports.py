"""Monitor-facing evidence export helpers.

This module projects normalized AuxPoW evidence into the final-category
artifacts consumed by the merge-mining monitor.
"""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .auxpow_parse import CHILD_HEADER_FIELDS, validate_child_header_fields
from .coinbase_output_claims import (
    merge_coinbase_output_claim_sets,
    parse_coinbase_output_claims,
    render_coinbase_output_claims,
)
from .config import (
    ACCEPTED_STALE_VALIDATION_STATUSES,
    BIP34_HEIGHT,
    CHAIN_SPECS,
    MONITOR_VALIDATION_CONTRACTS,
    RELEVANCE_STRICT_BTC_ORPHAN,
    RELEVANCE_WEAK_BTC_ORPHAN,
    RESULTS_DIR,
)
from .config import DATA_DIR
from .evidence_hydration import (
    RSK_SIDECAR_EXPORT_FIELDS,
    ChildIdentityStats,
    hydrate_child_identity,
    hydrate_namecoin_headers,
    load_child_identity,
    namecoin_header_candidate_paths,
)
from .evidence_normalization import (
    EVIDENCE_FIELDS,
    SourceStats,
    canonical_evidence_status,
    collect_source_rows,
    enforce_unknown_split_contract,
    int_or_none,
    is_hash,
    merge_stats,
    normalize_hash,
    note_child_height_availability,
    parse_header_fields,
    safe_path,
    write_csv,
)
from .evidence_sources import (
    EvidenceSource,
    discover_canonical_sources,
    discover_evidence_sources,
    discover_unknown_sources,
    stale_descendant_parent_verdict_source,
)
from .stale_descendants import (
    load_stale_descendant_observations,
    load_stale_descendant_parents,
)

MONITOR_OUTPUT_DIR = RESULTS_DIR / "monitor-evidence"
DEFAULT_RELEVANCE_INVENTORY = (
    RESULTS_DIR
    / "analysis"
    / "btc-stale-relevance"
    / "btc-stale-relevance-inventory.csv"
)
# Publication manifests use a stable logical external name so temporary
# staging basenames do not make otherwise identical builds non-reproducible.
# Diagnostic library calls still report the sanitized path they actually read.
REPORTED_RELEVANCE_INVENTORY = "<external>/btc-stale-relevance-inventory.csv"

# The full-evidence exports in ``full_evidence.py`` carry every evidence state,
# which makes them large (unknown/near rows dominate). This module keeps only
# the categories the merge-mining-monitor ingests as final —
# canonical rows, VALID direct stales, valid stale descendants, and
# strict/weak BTC orphans. Strict/weak verdicts are joined from the relevance
# inventory (scripts/analysis/classify_btc_stale_relevance.py) by header hash;
# the `btc_stale_relevance` / `relevance_reason` columns use the exact strings
# the monitor's importer parses.

MONITOR_EVIDENCE_FIELDS = EVIDENCE_FIELDS + [
    "btc_stale_relevance",
    "relevance_reason",
]

MONITOR_COUNT_FIELDS = [
    "chain",
    "source_kind",
    "artifact_scope",
    "artifact_path",
    "source_path",
    "canonical",
    "stale",
    "stale_descendant",
    "strict_btc_orphan",
    "weak_btc_orphan",
    "error_block",
    "monitor_rows",
    "source_rows",
    "canonical_evidence_status",
    "notes",
]

_STRICT_HEIGHT_SOURCES = frozenset({"coinbase_bip34_height", "btc_bip34_height"})
_ORPHAN_RELEVANCE_REASONS = {
    RELEVANCE_STRICT_BTC_ORPHAN: "strict_height_nbits_match",
    RELEVANCE_WEAK_BTC_ORPHAN: "timestamp_epoch_nbits_match",
}


@dataclass(frozen=True, slots=True)
class MonitorVerdict:
    """Final relevance verdict plus its authenticated strict Bitcoin height."""

    bucket: str
    reason: str
    btc_height: int | None = None
    strict_height_source: str = ""


def load_orphan_relevance_verdicts(path: Path | None) -> dict[str, MonitorVerdict]:
    """Map ``btc_header_hash`` to an authenticated strict/weak verdict.

    Reads the relevance inventory produced by
    ``scripts/analysis/classify_btc_stale_relevance.py``. Only the
    strict/weak orphan buckets are retained: excluded rows are dropped by
    the monitor, and ``pending`` rows have no final verdict yet.

    The verdict is per header: the same header observed by several chains
    can carry different per-row verdicts (evidence quality differs by
    source), and the strongest wins — a strict verdict from any observing
    chain beats a weak one, and the first row of the winning bucket is kept so
    regeneration is deterministic. Every strict verdict must carry the exact
    Bitcoin height and recognized height-evidence source authenticated by the
    relevance classifier. Conflicting strict heights for one parent fail
    closed. Weak verdicts retain their timestamp-only semantics and never
    project a height from this join.
    """
    if path is None or not path.exists():
        return {}
    verdicts: dict[str, MonitorVerdict] = {}
    with path.open(newline="") as f:
        for row_number, row in enumerate(csv.DictReader(f), start=2):
            raw_bucket = row.get("btc_stale_relevance") or ""
            bucket = raw_bucket.strip()
            if bucket not in (
                RELEVANCE_STRICT_BTC_ORPHAN,
                RELEVANCE_WEAK_BTC_ORPHAN,
            ):
                continue
            if raw_bucket != bucket:
                raise ValueError(f"{path}:{row_number}: relevance bucket is not exact")
            block_hash = normalize_hash(row.get("btc_header_hash"))
            if not is_hash(block_hash):
                continue
            raw_reason = row.get("relevance_reason") or ""
            reason = raw_reason.strip()
            if raw_reason != reason or reason != _ORPHAN_RELEVANCE_REASONS[bucket]:
                raise ValueError(
                    f"{path}:{row_number}: {bucket} relevance reason is not exact"
                )
            if bucket == RELEVANCE_STRICT_BTC_ORPHAN:
                raw_height = row.get("btc_height") or ""
                height = int_or_none(raw_height)
                raw_height_source = row.get("strict_height_source") or ""
                height_source = raw_height_source.strip()
                if (
                    raw_height != raw_height.strip()
                    or not raw_height.isascii()
                    or not raw_height.isdigit()
                    or height is None
                    or height < BIP34_HEIGHT
                    or str(height) != raw_height
                ):
                    raise ValueError(
                        f"{path}:{row_number}: strict relevance verdict lacks an "
                        "exact post-BIP34 Bitcoin height"
                    )
                if (
                    raw_height_source != height_source
                    or height_source not in _STRICT_HEIGHT_SOURCES
                ):
                    raise ValueError(
                        f"{path}:{row_number}: strict relevance verdict has an "
                        "unauthenticated height source"
                    )
                candidate = MonitorVerdict(
                    bucket=bucket,
                    reason=reason,
                    btc_height=height,
                    strict_height_source=height_source,
                )
            else:
                candidate = MonitorVerdict(bucket=bucket, reason=reason)
            existing = verdicts.get(block_hash)
            if existing is not None:
                if (
                    existing.bucket == RELEVANCE_STRICT_BTC_ORPHAN
                    and candidate.bucket == RELEVANCE_STRICT_BTC_ORPHAN
                    and existing.btc_height != candidate.btc_height
                ):
                    raise ValueError(
                        f"{path}:{row_number}: strict relevance verdict conflicts "
                        f"with the Bitcoin height already recorded for {block_hash}"
                    )
                if (
                    existing.bucket == RELEVANCE_STRICT_BTC_ORPHAN
                    or candidate.bucket == existing.bucket
                ):
                    continue
            verdicts[block_hash] = candidate
    return verdicts


def monitor_verdict(
    row: dict[str, str],
    orphan_verdicts: dict[str, MonitorVerdict],
) -> MonitorVerdict | None:
    """Final-category verdict for a normalized evidence row; None drops it.

    Canonical rows carry an empty relevance (the relevance layer refines
    stale candidacy, not canonical membership). Stales and descendants must
    pass their persisted validation gates, and carry an empty relevance too:
    a confirmed row already restates its VALID verdict on the primary
    `classification`/`validation_status` axes, so the derived axis is left
    empty and only the `relevance_reason` records the confirmation.
    Unknown-classified rows survive only with a strict/weak verdict from the
    relevance inventory. Accepted descendants already arrive as final rows from
    the canonical observation ledger.
    """
    classification = str(row.get("classification", ""))
    status = str(row.get("validation_status", "")).strip()
    if classification == "canonical":
        return MonitorVerdict("", "")
    if classification == "stale":
        # A stale row without a persisted VALID verdict (empty status in a
        # pre-gate archive inventory, or any REJECTED/UNKNOWN form) is not
        # admissible monitor evidence — the committed validated files are
        # the arbiter of which stales carry a gate verdict.
        if status not in ACCEPTED_STALE_VALIDATION_STATUSES:
            return None
        return MonitorVerdict("", "valid_direct_stale")
    if classification == "stale_descendant":
        if status != "VALID_STALE_DESCENDANT":
            return None
        return MonitorVerdict("", "valid_stale_descendant")
    if classification == "unknown":
        return orphan_verdicts.get(normalize_hash(row.get("btc_header_hash")))
    return None


def _monitor_rows_and_counts(
    rows: list[dict[str, str]],
    orphan_verdicts: dict[str, MonitorVerdict],
    *,
    include_canonical: bool = True,
) -> tuple[list[dict[str, str]], Counter[str]]:
    """Filter normalized rows to the monitor-facing set and tally categories.

    Keeps canonical rows (unless ``include_canonical`` is False), VALID
    stales and descendants (with an empty derived relevance and a
    ``valid_direct_stale``/``valid_stale_descendant`` reason), and unknown
    rows carrying a strict/weak verdict; everything else is dropped. Accepted
    descendant witnesses arrive as final rows from the canonical observation
    ledger. Each kept row gains the
    ``btc_stale_relevance`` / ``relevance_reason`` columns the monitor parses.
    The counter uses ``stale_descendant`` for admitted source observations,
    primary classification for canonical/stale rows, and bucket for
    strict/weak rows.
    """
    kept: list[dict[str, str]] = []
    counts: Counter[str] = Counter()
    for row in rows:
        verdict = monitor_verdict(row, orphan_verdicts)
        if verdict is None:
            continue
        classification = str(row.get("classification", ""))
        if not include_canonical and classification == "canonical":
            # Compact configuration: canonical rows (whether from companion
            # files or retained in-file) are sized and published separately.
            continue
        bucket = verdict.bucket
        reason = verdict.reason
        out = dict(row)
        if bucket == RELEVANCE_STRICT_BTC_ORPHAN:
            assert verdict.btc_height is not None
            raw_height = (out.get("btc_height") or "").strip()
            existing_height = int_or_none(raw_height)
            if raw_height and existing_height != verdict.btc_height:
                source_path = out.get("source_path") or "<unknown-source>"
                source_row = out.get("source_row_number") or "?"
                raise ValueError(
                    f"{source_path}:{source_row}: source Bitcoin height "
                    f"{raw_height!r} conflicts with authenticated strict relevance "
                    f"height {verdict.btc_height}"
                )
            if not raw_height:
                out["btc_height"] = str(verdict.btc_height)
        out["btc_stale_relevance"] = bucket
        out["relevance_reason"] = reason
        kept.append(out)
        if bucket in (RELEVANCE_STRICT_BTC_ORPHAN, RELEVANCE_WEAK_BTC_ORPHAN):
            counts[bucket] += 1
        else:
            counts[classification] += 1
    return kept, counts


def monitor_count_row(
    source: EvidenceSource,
    stats: SourceStats,
    counts: Counter[str],
    monitor_rows: int,
    artifact_path: Path | None,
    notes: str = "",
) -> dict[str, object]:
    """Render one per-chain row for the monitor-evidence counts CSV."""
    return {
        "chain": source.chain,
        "source_kind": source.source_kind,
        "artifact_scope": source.artifact_scope,
        "artifact_path": safe_path(artifact_path, chain=source.chain),
        "source_path": safe_path(source.path, chain=source.chain),
        "canonical": counts.get("canonical", 0),
        "stale": counts.get("stale", 0),
        "stale_descendant": counts.get("stale_descendant", 0),
        "strict_btc_orphan": counts.get(RELEVANCE_STRICT_BTC_ORPHAN, 0),
        "weak_btc_orphan": counts.get(RELEVANCE_WEAK_BTC_ORPHAN, 0),
        "error_block": 0,
        "monitor_rows": monitor_rows,
        "source_rows": stats.source_rows,
        "canonical_evidence_status": canonical_evidence_status(source, stats),
        "notes": notes,
    }


def _stale_descendant_evidence_rows(
    data_dir: Path,
) -> dict[str, list[dict[str, str]]]:
    """Project the accepted witness ledger into normalized evidence rows.

    The ledger is the sole witness/provenance interface. Source bucket names
    remain audit metadata there, while every projected row carries the final
    accepted stale-descendant verdict. A raw archive copy can collapse into a
    ledger row only after child-identity hydration proves the same event and
    semantic reconciliation preserves every evidence claim.
    """
    parents_path = data_dir / "stale_descendants.csv"
    observations_path = data_dir / "stale_descendant_observations.csv"
    parents = load_stale_descendant_parents(parents_path, data_dir=data_dir)
    observations = load_stale_descendant_observations(
        observations_path,
        parents_path=parents_path,
        data_dir=data_dir,
    )
    by_chain: dict[str, list[dict[str, str]]] = defaultdict(list)
    for observation in observations:
        parent = parents[(observation.parent_height, observation.parent_hash)]
        parent_row = parent.row
        parsed_parent = parse_header_fields(parent_row["btc_header_hex"])
        row = {field: "" for field in EVIDENCE_FIELDS}
        row.update(
            {
                "chain": observation.chain,
                "source_kind": "stale_descendant_observation_ledger",
                "source_path": observation.row["source_path"],
                "source_row_number": observation.row["source_row_number"],
                "artifact_scope": "accepted_stale_descendant_observation",
                "provenance": observation.row["provenance"],
                "child_height": str(observation.child_height),
                "child_block_hash": observation.child_hash,
                "child_header_hex": observation.row["child_header_hex"],
                "child_block_time": observation.row["child_block_time"],
                "child_nbits": observation.row["child_nbits"],
                "btc_height": str(parent.height),
                "btc_header_hash": parent.block_hash,
                "btc_prev_hash": parent_row.get("btc_prev_hash", ""),
                "btc_time": parent_row.get("btc_time", ""),
                "btc_bits": parent_row.get("btc_bits", ""),
                "btc_nonce": parsed_parent.get("nonce", ""),
                "btc_header_hex": parent_row["btc_header_hex"],
                "coinbase_scriptsig_hex": parent_row.get("coinbase_scriptsig_hex", ""),
                "coinbase_outputs": parent_row.get("coinbase_outputs", ""),
                "classification": "stale_descendant",
                "validation_status": "VALID_STALE_DESCENDANT",
                "expected_nbits": parent_row.get("expected_nbits", ""),
            }
        )
        by_chain[observation.chain].append(row)
    for rows in by_chain.values():
        rows.sort(
            key=lambda row: (
                int(row["btc_height"]),
                row["btc_header_hash"],
                int(row["child_height"]),
                row["child_block_hash"],
            )
        )
    return dict(by_chain)


_EVENT_SOURCE_FIELDS = frozenset(
    {
        "source_kind",
        "source_path",
        "source_row_number",
        "artifact_scope",
        "provenance",
    }
)
_EVENT_VERDICT_FIELDS = frozenset(
    {
        "classification",
        "validation_status",
        "rejection_reason",
        "btc_stale_relevance",
        "relevance_reason",
    }
)


def _decrement_stats_for_merged_row(stats: SourceStats, row: dict[str, str]) -> None:
    """Remove one redundant physical row from final source accounting."""
    stats.source_rows -= 1
    classification = row.get("classification", "")
    stats.classifications[classification] -= 1
    if (row.get("validation_status") or "").upper().startswith("REJECTED"):
        stats.rejected -= 1
    if classification == "malformed":
        stats.malformed -= 1
    if classification not in {
        "canonical",
        "stale",
        "unknown",
        "stale_descendant",
        "near",
    }:
        stats.other -= 1
    if not row.get("btc_header_hex"):
        stats.missing_btc_header_hex -= 1
    if not row.get("coinbase_scriptsig_hex"):
        stats.missing_coinbase_scriptsig_hex -= 1
    if not row.get("coinbase_outputs"):
        stats.missing_coinbase_outputs -= 1


def _publication_row_rank(
    row: dict[str, str],
    orphan_verdicts: dict[str, MonitorVerdict],
) -> int:
    """Rank one admissible final verdict for exact-event reconciliation."""
    verdict = monitor_verdict(row, orphan_verdicts)
    if verdict is None:
        return -1
    if verdict.bucket == RELEVANCE_WEAK_BTC_ORPHAN:
        return 0
    if verdict.bucket == RELEVANCE_STRICT_BTC_ORPHAN:
        return 1
    return {
        "canonical": 2,
        "stale": 3,
        "stale_descendant": 4,
    }.get(row.get("classification", ""), -1)


def _merge_authenticated_child_event_rows(
    rows: list[dict[str, str]],
    stats: SourceStats,
    orphan_verdicts: dict[str, MonitorVerdict],
) -> tuple[list[dict[str, str]], int]:
    """Collapse only semantically compatible copies of one child event.

    A validated 80-byte child header authenticates the chain-local event hash.
    Rows without that complete bundle stay distinct, so sparse source evidence
    can never be deleted by parent-hash matching. Duplicate hashes must agree
    on every populated child height and Bitcoin parent. The strongest final
    classification wins, while every populated evidence fact from every copy
    is retained or required to agree. Coinbase outputs use the shared semantic
    claim merger rather than raw-string equality.
    """

    def authenticates_event(row: dict[str, str]) -> bool:
        height = int_or_none(row.get("child_height"))
        if row.get("source_kind") in {
            "validated_stales",
            "stale_descendant_observation_ledger",
        }:
            return height is not None and height >= 0
        if not all((row.get(field) or "").strip() for field in CHILD_HEADER_FIELDS):
            return False
        chain_spec = CHAIN_SPECS.get(row.get("chain", ""))
        validate_child_header_fields(
            row,
            nbits_from_header=(
                chain_spec.child_nbits_from_header if chain_spec else True
            ),
        )
        return True

    authenticated_hashes = {
        normalize_hash(row.get("child_block_hash"))
        for row in rows
        if is_hash(normalize_hash(row.get("child_block_hash")))
        and authenticates_event(row)
    }
    merged_rows: list[dict[str, str]] = []
    index_by_child_hash: dict[str, int] = {}
    merged_count = 0
    evidence_fields = tuple(
        field
        for field in (*EVIDENCE_FIELDS, *RSK_SIDECAR_EXPORT_FIELDS)
        if field
        not in {
            *_EVENT_SOURCE_FIELDS,
            *_EVENT_VERDICT_FIELDS,
            "coinbase_outputs",
        }
    )
    for row in rows:
        chain = row.get("chain", "")
        child_hash = normalize_hash(row.get("child_block_hash"))
        child_height = int_or_none(row.get("child_height"))
        if child_hash not in authenticated_hashes:
            merged_rows.append(row)
            continue
        if child_height is not None and child_height < 0:
            raise ValueError(f"{chain}: child event {child_hash} has negative height")
        previous_index = index_by_child_hash.get(child_hash)
        if previous_index is None:
            index_by_child_hash[child_hash] = len(merged_rows)
            merged_rows.append(row)
            continue

        previous = merged_rows[previous_index]
        previous_height = int_or_none(previous.get("child_height"))
        if (
            previous_height is not None
            and child_height is not None
            and previous_height != child_height
        ):
            raise ValueError(
                f"{row.get('chain')}: child event {child_hash} has conflicting "
                f"heights {previous_height} and {child_height}"
            )
        previous_parent = normalize_hash(previous.get("btc_header_hash"))
        current_parent = normalize_hash(row.get("btc_header_hash"))
        if previous_parent != current_parent:
            raise ValueError(
                f"{row.get('chain')}: child event {child_hash} is attributed to "
                f"two Bitcoin parents ({previous_parent}, {current_parent})"
            )

        previous_rank = _publication_row_rank(previous, orphan_verdicts)
        current_rank = _publication_row_rank(row, orphan_verdicts)
        if current_rank > previous_rank:
            winner, loser = dict(row), previous
        else:
            winner, loser = dict(previous), row

        for field in evidence_fields:
            winner_value = (winner.get(field) or "").strip()
            loser_value = (loser.get(field) or "").strip()
            if winner_value and loser_value and winner_value != loser_value:
                raise ValueError(
                    f"{row.get('chain')}: child event {child_hash} has conflicting "
                    f"{field} evidence"
                )
            if not winner_value and loser_value:
                winner[field] = loser_value
        winner["coinbase_outputs"] = render_coinbase_output_claims(
            merge_coinbase_output_claim_sets(
                parse_coinbase_output_claims(
                    previous.get("coinbase_outputs") or "",
                    previous.get("full_coinbase_hex") or "",
                ),
                parse_coinbase_output_claims(
                    row.get("coinbase_outputs") or "",
                    row.get("full_coinbase_hex") or "",
                ),
            )
        )
        merged_rows[previous_index] = winner
        _decrement_stats_for_merged_row(stats, loser)
        merged_count += 1
    if merged_count:
        stats.notes.add(f"merged_duplicate_authenticated_child_events={merged_count}")
    return merged_rows, merged_count


def build_monitor_evidence_exports(
    *,
    data_dir: Path = DATA_DIR,
    output_dir: Path = MONITOR_OUTPUT_DIR,
    reported_output_dir: Path | None = None,
    chain_archive_dirs: Iterable[Path] = (),
    relevance_inventory: Path | None = DEFAULT_RELEVANCE_INVENTORY,
    reported_relevance_inventory: str | None = None,
    include_canonical: bool = True,
    fail_on_missing_child_identity: bool = False,
    include_error_observations: bool = False,
) -> dict[str, object]:
    """Write per-chain monitor-facing evidence CSVs plus a counts manifest.

    ``include_canonical=False`` skips canonical rows for every chain in an
    explicitly diagnostic build. ``fail_on_missing_child_identity`` makes an
    unhydrated live-chain row fatal: the monitor importer deliberately skips
    rows without exact child identity, so a publication build must fail closed
    rather than silently publish rows the importer will drop.
    ``reported_output_dir`` is the logical final directory recorded in counts
    and manifests when a caller writes to a temporary staging directory first.
    ``reported_relevance_inventory`` can supply a stable logical publication
    name while diagnostic callers retain the sanitized path they actually read.
    ``include_error_observations`` is enabled only by a complete publication
    build because the recovered witness ledger must agree with the catalogue;
    diagnostic exports deliberately leave the aggregate absent.
    """
    logical_output_dir = reported_output_dir or output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    sources = discover_evidence_sources(data_dir, chain_archive_dirs)
    canonical_sources = (
        discover_canonical_sources(data_dir, chain_archive_dirs)
        if include_canonical
        else {}
    )
    # Unknown companions are always discovered independently of include_canonical:
    # after the split the stale inventory has no unknown rows, so the strict/weak
    # orphan join depends on merging this companion.
    unknown_sources = discover_unknown_sources(data_dir, chain_archive_dirs)
    namecoin_paths = namecoin_header_candidate_paths(data_dir, chain_archive_dirs)
    child_identity = load_child_identity(data_dir)
    error_blocks_path = data_dir / "error-blocks" / "error_blocks.csv"
    excluded_error_rows: list[dict[str, str]] | None = (
        [] if include_error_observations else None
    )
    orphan_verdicts = load_orphan_relevance_verdicts(relevance_inventory)
    descendant_rows_by_chain = _stale_descendant_evidence_rows(data_dir)
    inventory_available = bool(orphan_verdicts) or (
        relevance_inventory is not None and relevance_inventory.exists()
    )

    count_rows: list[dict[str, object]] = []
    artifacts: dict[str, str] = {}
    identity_shortfalls: dict[str, ChildIdentityStats] = {}

    def export(
        source: EvidenceSource,
        artifact_name: str,
        companion: EvidenceSource | None = None,
        validated: EvidenceSource | None = None,
        unknown_companion: EvidenceSource | None = None,
    ) -> None:
        """Write one chain's monitor-evidence CSV and record its counts.

        ``validated`` replaces the full inventory's stale rows with the
        committed validated file (the arbiter of gate verdicts); ``companion``
        merges a canonical-parent companion file; ``unknown_companion`` merges
        the split-out ``_unknown_blocks.csv`` and is applied UNCONDITIONALLY --
        after the split the stale inventory has no unknown rows, so a
        conditional merge would silently drop every unknown monitor row and
        empty the strict/weak orphan join.
        """
        if validated is not None:
            # The committed validated file is the arbiter of which stales
            # carry a gate verdict. The full inventory contributes its
            # non-stale rows, including unknowns for the strict/weak join and
            # any canonical rows retained in-file. Other classifications stay
            # in source accounting but are omitted from monitor output.
            rows, stats = collect_source_rows(
                source,
                data_dir=data_dir,
                exclude_classifications=frozenset({"stale"}),
                error_blocks_path=error_blocks_path,
                excluded_error_rows=excluded_error_rows,
            )
            validated_rows, validated_stats = collect_source_rows(
                validated,
                data_dir=data_dir,
                error_blocks_path=error_blocks_path,
                excluded_error_rows=excluded_error_rows,
            )
            rows.extend(validated_rows)
            stats = merge_stats(stats, validated_stats)
        else:
            rows, stats = collect_source_rows(
                source,
                data_dir=data_dir,
                error_blocks_path=error_blocks_path,
                excluded_error_rows=excluded_error_rows,
            )
        if unknown_companion is not None:
            enforce_unknown_split_contract(source, stats, unknown_companion)
            unknown_rows, unknown_stats = collect_source_rows(
                unknown_companion,
                data_dir=data_dir,
                error_blocks_path=error_blocks_path,
                excluded_error_rows=excluded_error_rows,
            )
            rows.extend(unknown_rows)
            stats = merge_stats(stats, unknown_stats)
        if companion is not None:
            companion_rows, companion_stats = collect_source_rows(
                companion,
                data_dir=data_dir,
                error_blocks_path=error_blocks_path,
                excluded_error_rows=excluded_error_rows,
            )
            rows.extend(companion_rows)
            stats = merge_stats(stats, companion_stats)
        ledger_rows = descendant_rows_by_chain.get(source.chain, [])
        if ledger_rows:
            rows.extend(dict(row) for row in ledger_rows)
            ledger_stats = SourceStats(source_rows=len(ledger_rows))
            ledger_stats.classifications["stale_descendant"] = len(ledger_rows)
            stats = merge_stats(stats, ledger_stats)
        # Hydrate before exact-event reconciliation so legacy source rows that
        # carry only a parent hash can acquire their authenticated child event
        # and refine into a validated-stale or descendant-ledger row. The
        # identity stats used by the publication gate are recomputed below on
        # the final kept set, so unadmitted unknown rows do not create false
        # coverage failures.
        hydration = hydrate_namecoin_headers(rows, namecoin_paths)
        hydrate_child_identity(rows, child_identity)
        rows, _merged_events = _merge_authenticated_child_event_rows(
            rows,
            stats,
            orphan_verdicts,
        )
        kept, counts = _monitor_rows_and_counts(
            rows,
            orphan_verdicts,
            include_canonical=include_canonical,
        )
        identity_hydration = hydrate_child_identity(kept, child_identity)
        note_child_height_availability(stats, kept)
        if identity_hydration.missing_identity or identity_hydration.height_mismatch:
            identity_shortfalls[source.chain] = identity_hydration
        artifact_fields = MONITOR_EVIDENCE_FIELDS
        if source.chain == "rsk":
            artifact_fields = MONITOR_EVIDENCE_FIELDS + RSK_SIDECAR_EXPORT_FIELDS
        artifact_path: Path | None = None
        if (
            source.path is not None
            or companion is not None
            or unknown_companion is not None
            or ledger_rows
        ):
            artifact_path = output_dir / artifact_name
            write_csv(artifact_path, kept, artifact_fields)
            reported_artifact_path = logical_output_dir / artifact_name
            artifacts[source.chain] = safe_path(
                reported_artifact_path, chain=source.chain
            )
        notes_parts = sorted(stats.notes)
        if stats.classifications.get("unknown", 0) and not inventory_available:
            notes_parts.append("unknown_rows_present_no_relevance_inventory")
        if source.artifact_scope == "partial_canonical_subset":
            notes_parts.append("partial_canonical_subset_not_complete_coverage")
        if hydration.note():
            notes_parts.append(hydration.note())
        if identity_hydration.note():
            notes_parts.append(identity_hydration.note())
        if source.chain == "stale-descendants":
            notes_parts.append("parent_verdicts_only_witnesses_in_observation_ledger")
        notes = "; ".join(notes_parts)
        reported_artifact_path = (
            logical_output_dir / artifact_name if artifact_path is not None else None
        )
        count_rows.append(
            monitor_count_row(
                source,
                stats,
                counts,
                len(kept),
                reported_artifact_path,
                notes,
            )
        )

    for chain, spec in CHAIN_SPECS.items():
        main = sources[chain]
        validated: EvidenceSource | None = None
        validated_path = data_dir / "validated-stales" / spec.validated_csv.name
        if validated_path.exists():
            repo_validated = EvidenceSource(
                chain=chain,
                display_name=spec.display_name,
                path=validated_path,
                source_kind="validated_stales",
                artifact_scope="stale_only_publication",
                provenance="repo-data",
            )
            if main.source_kind == "validated_stales":
                # The committed file is the verdict arbiter; it replaces any
                # discovered (possibly older, verdict-less) validated copy.
                main = repo_validated
            else:
                validated = repo_validated
        export(
            main,
            f"{chain}_monitor_evidence.csv",
            companion=canonical_sources.get(chain),
            validated=validated,
            unknown_companion=unknown_sources.get(chain),
        )

    for chain, canonical_source in canonical_sources.items():
        if chain in CHAIN_SPECS:
            continue
        export(canonical_source, f"{chain}_monitor_evidence.csv")

    parent_verdicts = stale_descendant_parent_verdict_source(data_dir)
    if parent_verdicts is not None:
        export(parent_verdicts, "stale-descendants_monitor_evidence.csv")

    if include_error_observations:
        # Imported lazily to keep the ordinary final-category projection free
        # of the error aggregate's archive-only reconstruction dependency.
        from .error_observations import (
            error_observation_count_row,
            write_error_observation_artifact,
        )

        assert excluded_error_rows is not None
        hydrate_namecoin_headers(excluded_error_rows, namecoin_paths)
        hydrate_child_identity(excluded_error_rows, child_identity)
        error_artifact = write_error_observation_artifact(
            output_dir,
            data_dir=data_dir,
            source_evidence_rows=excluded_error_rows,
        )
        error_chain = str(error_artifact["artifact"])
        error_path = error_artifact["path"]
        assert isinstance(error_path, Path)
        reported_error_path = logical_output_dir / error_path.name
        artifacts[error_chain] = safe_path(reported_error_path)
        count_rows.append(
            error_observation_count_row(
                error_artifact,
                data_dir=data_dir,
                artifact_path=reported_error_path,
            )
        )

    if fail_on_missing_child_identity and identity_shortfalls:
        detail = "; ".join(
            f"{chain}: missing_identity={stats.missing_identity}, "
            f"height_mismatch={stats.height_mismatch}"
            for chain, stats in sorted(identity_shortfalls.items())
        )
        raise ValueError(
            "live-chain rows lack a verified child identity and the monitor "
            f"importer would silently drop them ({detail}); regenerate "
            "data/child-identity/ with scripts/extract/recover_child_identity.py "
            "or pass --allow-partial for a disposable diagnostic build"
        )
    counts_path = output_dir / "monitor-evidence-counts.csv"
    manifest_json_path = output_dir / "monitor-evidence-manifest.json"
    reported_counts_path = logical_output_dir / counts_path.name
    reported_manifest_path = logical_output_dir / manifest_json_path.name
    write_csv(counts_path, count_rows, MONITOR_COUNT_FIELDS)

    summary = {
        "output_dir": safe_path(logical_output_dir),
        "counts_csv": safe_path(reported_counts_path),
        "manifest_json": safe_path(reported_manifest_path),
        "validation_contracts": MONITOR_VALIDATION_CONTRACTS,
        "artifacts": artifacts,
        "relevance_inventory": (
            (
                reported_relevance_inventory
                or safe_path(relevance_inventory, chain="relevance")
            )
            if inventory_available
            else "missing"
        ),
        "strict_weak_verdicts_loaded": len(orphan_verdicts),
        "counts": count_rows,
    }
    manifest_json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary
