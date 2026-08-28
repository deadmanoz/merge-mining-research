"""Publication and report rendering for stale-ancestry reconciliation."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from stale_blocks_analysis.btc_classify import derive_split_paths
from stale_blocks_analysis.btc_stale_validation import (
    BIP34_HEIGHT_MISSING_PREFIX,
    VERSION_RULES,
    bip34_height_error,
    block_version_error,
    consensus_violations,
)
from stale_blocks_analysis.config import BIP34_HEIGHT, BIP34_VERSION_2_HEIGHT
from stale_blocks_analysis.full_evidence import (
    int_or_none,
    is_hash,
    load_namecoin_header_hexes,
    normalize_hash,
)
from stale_blocks_analysis.ancestry_walk import WalkResult
from stale_blocks_analysis.reconcile_observations import (
    StaleObservation,
    UnknownObservation,
    expected_bits_for_height,
    hash_meets_bits,
    header_hash,
    join_sorted,
    parse_header_fields,
    save_mainchain_cache,
    stale_sources,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = PROJECT_ROOT / "results" / "analysis" / "stale-ancestry"
PROMOTED_CSV = PROJECT_ROOT / "data" / "stale_descendants.csv"

OUTPUT_INVENTORY = "unknown-stale-reconciliation-inventory.csv"
OUTPUT_DIRECT = "unknown-stale-direct-matches.csv"
OUTPUT_PATHS = "unknown-stale-descendant-paths.csv"
OUTPUT_ROOTS = "unknown-stale-root-summary.csv"
OUTPUT_ANOMALIES = "unknown-stale-anomalies.csv"
OUTPUT_SUMMARY = "unknown-stale-reconciliation-summary.json"

# Column order of the promoted descendant sidecar. The consensus-invalid peer
# reuses it and appends the pipe-joined full rule set, the column name and
# format ``build_error_blocks.py`` honors verbatim on import.
PROMOTED_FIELDS = [
    "classification",
    "promotion_subclass",
    "validation_status",
    "btc_height",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "expected_nbits",
    "pow_valid",
    "header_hash_match",
    "bip34_height_status",
    "observed_btc_heights",
    "observed_btc_times",
    "observed_btc_bits",
    "root_stale_hash",
    "root_stale_height",
    "root_stale_sources",
    "root_stale_chains",
    "root_stale_btc_times",
    "root_stale_bits",
    "stale_fork_depth",
    "path_hashes",
    "path_chain_sets",
    "observed_chains",
    "unknown_rows",
    "source_rows",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "notes",
]
PROMOTED_ERROR_BLOCK_FIELDS = [*PROMOTED_FIELDS, "rules_violated"]


@dataclass(frozen=True, slots=True)
class PublicationBaseline:
    """Committed descendant rows and the private inventories they depend on."""

    statuses_by_hash: dict[str, str]
    observed_chains_by_hash: dict[str, frozenset[str]]
    unknown_rows_by_hash: dict[str, int]
    source_observation_counts_by_hash: dict[str, Counter[str]]
    notes_by_hash: dict[str, str]
    required_inventory_chains: frozenset[str]


def error_blocks_csv_for(promoted_csv: Path) -> Path:
    """Return the consensus-invalid sibling for a promoted-descendant path."""
    return Path(derive_split_paths(str(promoted_csv))[2])


DESCENDANT_UNJUDGEABLE_FAILURES = frozenset(
    {
        "missing_header_hex",
        "header_hash_mismatch",
        "prev_hash_path_mismatch",
        "pow_target_mismatch",
    }
)


def descendant_consensus_rules(
    header_hex: str,
    scriptsig_hex: str,
    inferred_height: int | None,
    validation_failures: list[str],
    *,
    header_bits: str,
    expected_nbits: str,
) -> list[str]:
    """Return the consensus rules a descendant candidate's bytes prove broken.

    A candidate with a non-empty result is not a rejected descendant, it is an
    error block: a Bitcoin block carrying full proof of work that breaks a
    rule. It uses the same shared derivation the classifier uses, so that a
    rejection means the same thing wherever it is produced.

    Two premises have to hold before any rule is derived, and the difficulty
    one is required as POSITIVE evidence rather than as a missing failure.

    First, every one of ``DESCENDANT_UNJUDGEABLE_FAILURES`` must be absent:

    - ``missing_header_hex`` / ``header_hash_mismatch``: the supplied bytes are
      not authenticated as this block's. Every rule below is read straight out
      of those bytes, so publishing a violation under the claimed hash would
      attribute another block's (or nobody's) header to it. Corroborating the
      published hash against the serialized header is the precondition for
      every downstream verdict in this repo, not an extra.
    - ``prev_hash_path_mismatch`` / ``pow_target_mismatch``: the height is not
      sound enough to judge against, and the digest is not known to meet the
      target its own bits encode. The height is the root's confirmed height
      plus the fork depth, walked along links this run already verified.
      Without them a coinbase-height mismatch would be equally consistent with
      a wrong height.

    Second, ``expected_nbits`` and ``header_bits`` must both be present and
    equal. The absence of an ``nbits_epoch_mismatch`` failure does NOT prove
    that: the caller derives ``expected_nbits`` from the committed epoch
    reference, which returns ``""`` for a height the table does not reach, and
    the comparison is then skipped rather than failed. Reading that silence as
    a match would let a foreign or easy-target header be published as an error
    block with its canonical difficulty never checked, so the match is required
    outright.

    Requiring it also settles the canonical proof of work without a second
    digest check, which is why none is made here. ``pow_target_mismatch`` being
    absent proves the digest meets the target ``header_bits`` encodes, and
    ``header_bits`` equalling ``expected_nbits`` makes that target the
    canonical one for this height. The classification-time twin
    (``btc_classify._meets_canonical_btc_difficulty``) does need its own digest
    check because it admits the unapplied-retarget rule, whose rows carry the
    PREVIOUS epoch's easier bits by definition; no such exception exists here.

    ``nbits_by_epoch`` is deliberately not supplied for the same reason: the
    bits are proven equal to the canonical value, so the unapplied-retarget
    rule cannot apply.
    """
    if inferred_height is None:
        return []
    if DESCENDANT_UNJUDGEABLE_FAILURES & set(validation_failures):
        return []
    canonical_bits = expected_nbits.strip().lower()
    observed_bits = header_bits.strip().lower()
    if not canonical_bits or not observed_bits or observed_bits != canonical_bits:
        return []
    rules = consensus_violations(
        {"btc_header_hex": header_hex, "coinbase_scriptsig_hex": scriptsig_hex},
        inferred_height,
    )
    # A version rule rests on a fixed-height cutover standing in for Core's
    # rolling IsSuperMajority vote, and Core counts that vote over the block's
    # OWN ancestors. For a direct stale those ancestors are the main chain, so
    # its window is the main chain's window and the cutover is exact. A
    # descendant's is not: its ancestry leaves the main chain at the fork root,
    # so a fork spanning an activation boundary can carry a different version
    # mix and a different verdict. Reconstructing the branch's own threshold
    # state is out of scope (GitHub issue #21), so a version rule cannot
    # promote a descendant to a block proven consensus-invalid. Rules that are
    # settled by the bytes alone are unaffected.
    return [rule for rule in rules if rule not in VERSION_RULES]


def bip34_height_absent(bip34_error: str) -> bool:
    """Report whether a BIP34 rejection is an absent height, not a wrong one.

    Two of the gate's verdicts mean the height is not there: no coinbase
    scriptSig to read at all, and a present, well-formed scriptSig carrying no
    decodable height push (``BIP34_HEIGHT_MISSING_PREFIX``, which the shared
    ``consensus_violations`` tokens as ``bip34_coinbase_height_missing``).
    Reporting the second as a mismatch would put ``rules_violated`` and
    ``validation_status`` in contradiction over the same committed bytes.
    """
    return "missing coinbase scriptSig" in bip34_error or bip34_error.startswith(
        BIP34_HEIGHT_MISSING_PREFIX
    )


def descendant_bip34_verdict(
    header_hex: str, scriptsig_hex: str, expected_height: int
) -> tuple[str, str | None]:
    """Return the descendant report status and validation-failure token.

    The shared consensus validator checks the raw header version and exact
    coinbase prefix. Source-reported height columns remain provenance only.
    """
    if expected_height < BIP34_VERSION_2_HEIGHT:
        return "not_applicable", None

    row = {
        "btc_header_hex": header_hex,
        "coinbase_scriptsig_hex": scriptsig_hex,
    }
    version_error = block_version_error(row, expected_height)
    bip34_error = bip34_height_error(row, expected_height)
    if bip34_error is None:
        parsed = parse_header_fields(header_hex)
        version = int_or_none(parsed.get("version", ""))
        if expected_height < BIP34_HEIGHT and version is not None and version < 2:
            return "not_applicable", None
        status = "match"
    elif bip34_error.startswith("UNKNOWN:"):
        status = "unknown"
    elif bip34_height_absent(bip34_error):
        status = "missing"
    else:
        status = "mismatch"

    if version_error is not None:
        if version_error.startswith("UNKNOWN:"):
            return status, "block_version_unknown"
        return status, "btc_block_version_below_minimum"
    if bip34_error is None:
        return status, None
    if bip34_error.startswith("UNKNOWN:"):
        return "unknown", "bip34_validation_unknown"
    if bip34_height_absent(bip34_error):
        return "missing", "bip34_height_missing"
    if "version below 2" in bip34_error:
        return "mismatch", "bip34_block_version"
    return "mismatch", "bip34_height_mismatch"


def source_observation_counts(
    source_rows: object, observed_chains: frozenset[str] | set[str]
) -> Counter[str]:
    """Count pipe-delimited source observations by their chain prefix.

    Paths and line numbers are deliberately excluded from the identity floor:
    complete inventories may move or be regenerated with different row
    numbers. Every nonempty token must still identify a chain represented in
    ``observed_chains``.
    """
    tokens = tuple(
        token.strip() for token in str(source_rows or "").split("|") if token.strip()
    )
    if not tokens:
        raise ValueError("source_rows has no observations")
    counts: Counter[str] = Counter()
    for token in tokens:
        chain = token.split(":", 1)[0].strip()
        if not chain:
            raise ValueError(f"source_rows token has an empty chain prefix: {token!r}")
        if chain not in observed_chains:
            raise ValueError(
                f"source_rows chain prefix {chain!r} is not present in observed_chains"
            )
        counts[chain] += 1
    return counts


def load_publication_baseline(path: Path = PROMOTED_CSV) -> PublicationBaseline:
    """Load the committed descendant floor used to reject degraded rebuilds."""
    if not path.is_file():
        raise ValueError(f"publication descendant baseline is missing: {path}")
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required_fields = {
            "classification",
            "validation_status",
            "btc_header_hash",
            "observed_chains",
            "unknown_rows",
            "source_rows",
        }
        missing_fields = required_fields - set(reader.fieldnames or [])
        if missing_fields:
            raise ValueError(
                f"publication descendant baseline lacks fields: {path}: "
                + ", ".join(sorted(missing_fields))
            )
        statuses: dict[str, str] = {}
        observed_chains_by_hash: dict[str, frozenset[str]] = {}
        unknown_rows_by_hash: dict[str, int] = {}
        source_observation_counts_by_hash: dict[str, Counter[str]] = {}
        notes_by_hash: dict[str, str] = {}
        required_chains: set[str] = set()
        for row_number, row in enumerate(reader, start=2):
            block_hash = normalize_hash(row.get("btc_header_hash"))
            status = (row.get("validation_status") or "").strip()
            classification = (row.get("classification") or "").strip()
            if not is_hash(block_hash):
                raise ValueError(
                    f"{path}:{row_number}: malformed publication descendant hash"
                )
            if classification != "stale_descendant" or not status:
                raise ValueError(
                    f"{path}:{row_number}: malformed publication descendant verdict"
                )
            if block_hash in statuses:
                raise ValueError(
                    f"{path}:{row_number}: duplicate publication descendant hash "
                    f"{block_hash}"
                )
            observed_chains = tuple(
                token.strip()
                for token in (row.get("observed_chains") or "").split("|")
                if token.strip()
            )
            try:
                unknown_rows = int((row.get("unknown_rows") or "").strip())
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{row_number}: invalid publication unknown_rows"
                ) from exc
            if unknown_rows < 1:
                raise ValueError(
                    f"{path}:{row_number}: publication unknown_rows must be positive"
                )
            if not observed_chains:
                raise ValueError(
                    f"{path}:{row_number}: publication descendant has no observed chains"
                )
            observed_chain_set = frozenset(observed_chains)
            try:
                source_counts = source_observation_counts(
                    row.get("source_rows"), observed_chain_set
                )
            except ValueError as exc:
                raise ValueError(f"{path}:{row_number}: {exc}") from exc
            if source_counts.total() != unknown_rows:
                raise ValueError(
                    f"{path}:{row_number}: publication source_rows count does not "
                    "match unknown_rows"
                )
            statuses[block_hash] = status
            observed_chains_by_hash[block_hash] = observed_chain_set
            unknown_rows_by_hash[block_hash] = unknown_rows
            source_observation_counts_by_hash[block_hash] = source_counts
            notes_by_hash[block_hash] = (row.get("notes") or "").strip()
            required_chains.update(observed_chains)
    if not statuses:
        raise ValueError(f"publication descendant baseline is empty: {path}")
    if not required_chains:
        raise ValueError(
            f"publication descendant baseline has no observed chains: {path}"
        )
    return PublicationBaseline(
        statuses_by_hash=statuses,
        observed_chains_by_hash=observed_chains_by_hash,
        unknown_rows_by_hash=unknown_rows_by_hash,
        source_observation_counts_by_hash=source_observation_counts_by_hash,
        notes_by_hash=notes_by_hash,
        required_inventory_chains=frozenset(required_chains),
    )


def descendant_notes(
    block_hash: str,
    validation_failures: list[str],
    baseline: PublicationBaseline | None,
) -> str:
    """Return current failures or immutable audit notes from the prior row."""
    if validation_failures:
        return ";".join(validation_failures)
    if baseline is not None:
        baseline_notes = baseline.notes_by_hash.get(block_hash, "")
        return ";".join(
            note
            for note in baseline_notes.split(";")
            if note == "reclassified_from_direct_stale"
            or note.startswith("branch_mtp=")
        )
    return ""


def validate_output_mode(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    results_dir_default: Path = RESULTS_DIR,
    promoted_csv_default: Path = PROMOTED_CSV,
) -> None:
    """Resolve the derived output path, then guard the publication defaults.

    ``--error-blocks-csv`` defaults to the sibling of whatever
    ``--promoted-csv`` names, so a disposable promoted path already yields a
    disposable error-block path; only an explicit committed one is refused.

    Every artifact this run generates must also resolve to a distinct file.
    They are written in sequence, so an aliased pair fails silently and
    destructively: the later write replaces one the run has just finished.
    Checking the error-block path against ``--promoted-csv`` alone would leave
    the six ``--results-dir`` artifacts open, and pointing it at, say,
    ``unknown-stale-root-summary.csv`` would have the error-block rows written
    and then immediately replaced by the root summary.
    """
    if args.error_blocks_csv is None:
        args.error_blocks_csv = error_blocks_csv_for(args.promoted_csv)
    labelled = {
        "reconciliation-inventory output": args.results_dir / OUTPUT_INVENTORY,
        "direct-matches output": args.results_dir / OUTPUT_DIRECT,
        "descendant-paths output": args.results_dir / OUTPUT_PATHS,
        "root-summary output": args.results_dir / OUTPUT_ROOTS,
        "anomalies output": args.results_dir / OUTPUT_ANOMALIES,
        "reconciliation-summary output": args.results_dir / OUTPUT_SUMMARY,
        "--promoted-csv": args.promoted_csv,
        "--error-blocks-csv": args.error_blocks_csv,
    }
    seen: dict[Path, str] = {}
    for label, path in labelled.items():
        resolved = path.resolve()
        previous = seen.get(resolved)
        if previous is not None:
            parser.error(f"{label} aliases {previous}: {resolved}")
        seen[resolved] = label
    if not args.allow_partial:
        return
    default_outputs: list[str] = []
    if args.results_dir.resolve() == results_dir_default.resolve():
        default_outputs.append("--results-dir")
    if args.promoted_csv.resolve() == promoted_csv_default.resolve():
        default_outputs.append("--promoted-csv")
    if (
        args.error_blocks_csv.resolve()
        == error_blocks_csv_for(promoted_csv_default).resolve()
    ):
        default_outputs.append("--error-blocks-csv")
    if default_outputs:
        parser.error(
            "--allow-partial requires explicit disposable output paths; refusing "
            "the publication defaults for " + ", ".join(default_outputs)
        )


def validate_publication_discovery(
    baseline: PublicationBaseline,
    full_files: dict[str, Path],
    unknown_files: dict[str, Path],
    parser: argparse.ArgumentParser,
) -> None:
    """Require source inventories for every chain represented in the baseline."""
    discovered = set(full_files) | set(unknown_files)
    missing = sorted(baseline.required_inventory_chains - discovered)
    if missing:
        parser.error(
            "refusing an incomplete publication reconciliation; missing full/unknown "
            "inventories for baseline chains: "
            + ", ".join(missing)
            + ". Use --allow-partial only with disposable output paths."
        )


def validate_publication_rows(
    rows: Iterable[dict[str, object]],
    baseline: PublicationBaseline,
    parser: argparse.ArgumentParser,
) -> None:
    """Reject a computed descendant set that regresses the committed baseline.

    ``rows`` is every computed row, including the ones routed to the
    error-block peer: moving artifact is not losing evidence. Proving a
    committed VALID descendant consensus-invalid is a separate regression,
    because that row does leave the published sidecar.
    """
    statuses: dict[str, str] = {}
    computed_rows_by_hash: dict[str, dict[str, object]] = {}
    duplicate_hashes: set[str] = set()
    for row in rows:
        block_hash = normalize_hash(str(row.get("btc_header_hash", "")))
        if block_hash in statuses:
            duplicate_hashes.add(block_hash)
        statuses[block_hash] = str(row.get("validation_status", ""))
        computed_rows_by_hash[block_hash] = row

    missing = sorted(set(baseline.statuses_by_hash) - set(statuses))
    validity_regressions = sorted(
        block_hash
        for block_hash, expected_status in baseline.statuses_by_hash.items()
        if expected_status == "VALID_STALE_DESCENDANT"
        and statuses.get(block_hash) != "VALID_STALE_DESCENDANT"
    )
    consensus_invalid_regressions = sorted(
        block_hash
        for block_hash, expected_status in baseline.statuses_by_hash.items()
        if expected_status == "VALID_STALE_DESCENDANT"
        and str(computed_rows_by_hash.get(block_hash, {}).get("classification", ""))
        == "error_block"
    )
    problems: list[str] = []
    if duplicate_hashes:
        problems.append(
            "duplicate computed descendant hashes: "
            + ", ".join(sorted(duplicate_hashes))
        )
    if missing:
        problems.append(
            f"missing {len(missing)} committed descendant hashes (first: {missing[0]})"
        )
    if validity_regressions:
        problems.append(
            f"{len(validity_regressions)} committed VALID descendants no longer VALID"
            f" (first: {validity_regressions[0]})"
        )
    if consensus_invalid_regressions:
        problems.append(
            f"{len(consensus_invalid_regressions)} committed VALID descendants are "
            "now consensus-invalid error blocks and would leave the sidecar "
            f"(first: {consensus_invalid_regressions[0]})"
        )
    if len(statuses) < len(baseline.statuses_by_hash):
        problems.append(
            "computed descendant coverage is below the publication baseline "
            f"({len(statuses)} < {len(baseline.statuses_by_hash)})"
        )

    chain_regressions: list[tuple[str, list[str]]] = []
    unknown_row_regressions: list[tuple[str, int | None, int]] = []
    source_row_regressions: list[tuple[str, str, int]] = []
    malformed_source_rows: list[tuple[str, str]] = []
    for block_hash in sorted(set(baseline.statuses_by_hash) & set(statuses)):
        computed_row = computed_rows_by_hash[block_hash]
        computed_chains = {
            token.strip()
            for token in str(computed_row.get("observed_chains", "")).split("|")
            if token.strip()
        }
        missing_chains = sorted(
            baseline.observed_chains_by_hash[block_hash] - computed_chains
        )
        if missing_chains:
            chain_regressions.append((block_hash, missing_chains))

        try:
            computed_unknown_rows: int | None = int(
                str(computed_row.get("unknown_rows", "")).strip()
            )
        except ValueError:
            computed_unknown_rows = None
        baseline_unknown_rows = baseline.unknown_rows_by_hash[block_hash]
        if (
            computed_unknown_rows is None
            or computed_unknown_rows < baseline_unknown_rows
        ):
            unknown_row_regressions.append(
                (block_hash, computed_unknown_rows, baseline_unknown_rows)
            )

        try:
            computed_source_counts = source_observation_counts(
                computed_row.get("source_rows", ""), computed_chains
            )
        except ValueError as exc:
            malformed_source_rows.append((block_hash, str(exc)))
            computed_source_counts = Counter()
        missing_source_counts = (
            baseline.source_observation_counts_by_hash[block_hash]
            - computed_source_counts
        )
        for chain, count in sorted(missing_source_counts.items()):
            source_row_regressions.append((block_hash, chain, count))

    if chain_regressions:
        block_hash, missing_chains = chain_regressions[0]
        problems.append(
            f"{len(chain_regressions)} committed descendants lost observed chains "
            f"(first: {block_hash} missing {','.join(missing_chains)})"
        )
    if unknown_row_regressions:
        block_hash, computed_count, baseline_count = unknown_row_regressions[0]
        problems.append(
            f"{len(unknown_row_regressions)} committed descendants lost unknown-row "
            f"observations (first: {block_hash} has {computed_count!s}, requires at "
            f"least {baseline_count})"
        )
    if malformed_source_rows:
        block_hash, detail = malformed_source_rows[0]
        problems.append(
            f"{len(malformed_source_rows)} computed descendants have malformed "
            f"source-row provenance (first: {block_hash}: {detail})"
        )
    if source_row_regressions:
        block_hash, chain, count = source_row_regressions[0]
        problems.append(
            f"{len(source_row_regressions)} committed per-chain source-observation "
            f"counts were lost (first: {block_hash} missing {chain!r} x{count})"
        )
    if problems:
        parser.error(
            "refusing a degraded publication reconciliation: "
            + "; ".join(problems)
            + ". Use --allow-partial only with disposable output paths."
        )


def write_csv(
    path: Path, rows: Iterable[dict[str, object]], fieldnames: list[str]
) -> None:
    """Write `rows` to `path` as a CSV with header `fieldnames`.

    Creates parent directories as needed. A row missing a field is written
    with `""` for that column.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def join_sorted(values: Iterable[str]) -> str:
    """Join the non-empty values of `values`, sorted, with `|` as the CSV-friendly delimiter."""
    return "|".join(sorted(v for v in values if v))


def select_promoted_evidence(
    observations: list[UnknownObservation], fallback_header_hex: str
) -> tuple[str, str, str, str, str, str]:
    """Select coherent header and coinbase evidence from ordered observations."""
    header_observation = next(
        (observation for observation in observations if observation.header_hex),
        observations[0],
    )
    coinbase_observation = next(
        (observation for observation in observations if observation.scriptsig_hex),
        None,
    ) or next(
        (observation for observation in observations if observation.outputs), None
    )
    return (
        header_observation.header_hex or fallback_header_hex,
        header_observation.prev_hash,
        header_observation.btc_time,
        header_observation.bits,
        coinbase_observation.scriptsig_hex if coinbase_observation else "",
        coinbase_observation.outputs if coinbase_observation else "",
    )


def render_and_publish(
    *,
    args: object,
    parser: object,
    data_dir: Path,
    results_dir: Path,
    cache_dir: Path,
    publication_baseline: PublicationBaseline | None,
    epoch_bits: dict[int, str],
    stale_by_hash: dict[str, list[StaleObservation]],
    known_stale_hashes: set[str],
    auxpow_stale_hashes: set[str],
    upstream_count: int,
    unknown_rows: list[UnknownObservation],
    unknown_row_counts_by_hash: Counter[str],
    unknown_chains_by_hash: dict[str, set[str]],
    unknown_example_by_hash: dict[str, UnknownObservation],
    unknown_observations_by_hash: dict[str, list[UnknownObservation]],
    inventory_rows: list[dict[str, object]],
    anomalies: list[dict[str, object]],
    walk_results: dict[str, WalkResult],
    path_for: Callable[[str], list[str]],
    mainchain_cache: dict[str, dict],
    mainchain_cache_dirty: bool,
    rel_fn: Callable[[Path], str],
    descendant_bip34_verdict_fn: Callable[[str, str, int], tuple[str, str | None]],
) -> dict[str, object]:
    """Build all reports, validate the baseline, then preserve write order."""
    direct_rows = []
    for obs in unknown_rows:
        if obs.prev_hash not in known_stale_hashes:
            continue
        sources, chains, heights, times, bits = stale_sources(
            stale_by_hash[obs.prev_hash]
        )
        direct_rows.append(
            {
                "unknown_chain": obs.chain,
                "unknown_source_path": obs.source_path,
                "unknown_row_number": obs.row_number,
                "unknown_child_height": obs.child_height,
                "unknown_btc_height": obs.btc_height,
                "unknown_btc_header_hash": obs.block_hash,
                "unknown_btc_prev_hash": obs.prev_hash,
                "matched_stale_hash": obs.prev_hash,
                "matched_stale_sources": sources,
                "matched_stale_chains": chains,
                "matched_stale_btc_heights": heights,
                "unknown_btc_time": obs.btc_time,
                "matched_stale_btc_times": times,
                "unknown_bits": obs.bits,
                "matched_stale_bits": bits,
            }
        )

    descendant_path_rows = []
    for block_hash, result in sorted(walk_results.items()):
        if result.category not in {"direct_stale_child", "stale_descendant"}:
            continue
        path = path_for(block_hash)
        stale_hash = result.terminal_hash
        sources, chains, heights, times, bits = stale_sources(stale_by_hash[stale_hash])
        example = unknown_example_by_hash[block_hash]
        descendant_path_rows.append(
            {
                "unknown_btc_header_hash": block_hash,
                "terminal_category": result.category,
                "depth": result.depth,
                "unknown_rows": unknown_row_counts_by_hash[block_hash],
                "unknown_chains": join_sorted(unknown_chains_by_hash[block_hash]),
                "example_source_path": example.source_path,
                "example_row_number": example.row_number,
                "example_child_height": example.child_height,
                "example_btc_height": example.btc_height,
                "path_hashes": ">".join(path),
                "path_chain_sets": ">".join(
                    join_sorted(unknown_chains_by_hash.get(h, set()))
                    for h in path
                    if h in unknown_chains_by_hash
                ),
                "terminal_stale_hash": stale_hash,
                "terminal_stale_sources": sources,
                "terminal_stale_chains": chains,
                "terminal_stale_btc_heights": heights,
                "terminal_stale_btc_times": times,
                "terminal_stale_bits": bits,
            }
        )

    promoted_hashes = {
        h
        for h, result in walk_results.items()
        if result.category in {"direct_stale_child", "stale_descendant"}
    }
    missing_header_hashes = {
        h
        for h in promoted_hashes
        if not any(obs.header_hex for obs in unknown_observations_by_hash[h])
    }
    namecoin_header_hexes = load_namecoin_header_hexes(
        missing_header_hashes,
        [
            data_dir / "prototype" / "namecoin_blkdat_classified.csv",
            data_dir / "prototype" / "namecoin_blkdat_candidates.csv",
        ],
    )

    promoted_rows = []
    for block_hash in sorted(promoted_hashes):
        result = walk_results[block_hash]
        path = path_for(block_hash)
        stale_hash = result.terminal_hash
        root_heights = sorted(
            {
                int(obs.btc_height)
                for obs in stale_by_hash[stale_hash]
                if int_or_none(obs.btc_height) is not None
            }
        )
        root_height = root_heights[0] if root_heights else None
        inferred_height = (
            root_height + result.depth if root_height is not None else None
        )

        observations = sorted(
            unknown_observations_by_hash[block_hash],
            key=lambda obs: (
                not bool(obs.header_hex),
                obs.chain,
                obs.source_path,
                obs.row_number,
            ),
        )
        (
            header_hex,
            observed_prev,
            observed_time,
            observed_bits,
            scriptsig_hex,
            coinbase_outputs,
        ) = select_promoted_evidence(
            observations, namecoin_header_hexes.get(block_hash, "")
        )
        parsed = parse_header_fields(header_hex)
        path_prev = path[1] if len(path) > 1 else ""
        row_prev = parsed.get("prev_hash") or observed_prev
        row_time = parsed.get("time") or observed_time
        row_bits = parsed.get("bits") or observed_bits
        observed_heights = sorted(
            {obs.btc_height for obs in observations if obs.btc_height}
        )
        observed_times = sorted({obs.btc_time for obs in observations if obs.btc_time})
        observed_bits = sorted({obs.bits for obs in observations if obs.bits})
        expected_nbits = (
            expected_bits_for_height(str(inferred_height), epoch_bits)
            if inferred_height is not None
            else ""
        )

        validation_failures: list[str] = []
        if not header_hex:
            validation_failures.append("missing_header_hex")
        elif header_hash(header_hex) != block_hash:
            validation_failures.append("header_hash_mismatch")
        if path_prev and row_prev != path_prev:
            validation_failures.append("prev_hash_path_mismatch")
        if not row_bits or not hash_meets_bits(block_hash, row_bits):
            validation_failures.append("pow_target_mismatch")
        if expected_nbits and row_bits and row_bits.lower() != expected_nbits:
            validation_failures.append("nbits_epoch_mismatch")
        if inferred_height is None:
            validation_failures.append("missing_root_height")

        if inferred_height is None:
            bip34_height_status = "not_applicable"
        else:
            bip34_height_status, bip34_failure = descendant_bip34_verdict_fn(
                header_hex,
                scriptsig_hex,
                inferred_height,
            )
            if bip34_failure is not None:
                validation_failures.append(bip34_failure)

        consensus_rules = descendant_consensus_rules(
            header_hex,
            scriptsig_hex,
            inferred_height,
            validation_failures,
            header_bits=row_bits,
            expected_nbits=expected_nbits,
        )
        # The descendant verdict and the classification are the same judgement
        # on one row, so they must not disagree. The BIP34 verdict above passes
        # a scriptSig that is over-long but correctly prefixed, and never looks
        # at the length at all, so without this a row would be emitted to the
        # error-block peer still carrying VALID_STALE_DESCENDANT. Rows that
        # already carry a failure are already rejections and keep their primary
        # reason; the derived rules travel in ``rules_violated`` either way.
        if consensus_rules and not validation_failures:
            validation_failures.extend(consensus_rules)
        validation_status = (
            "VALID_STALE_DESCENDANT"
            if not validation_failures
            else "REJECTED_" + "|".join(validation_failures)
        )
        sources, chains, heights, times, bits = stale_sources(stale_by_hash[stale_hash])

        promoted_rows.append(
            {
                "classification": (
                    "error_block" if consensus_rules else "stale_descendant"
                ),
                "rules_violated": "|".join(consensus_rules),
                "promotion_subclass": result.category,
                "validation_status": validation_status,
                "btc_height": "" if inferred_height is None else inferred_height,
                "btc_header_hash": block_hash,
                "btc_prev_hash": row_prev,
                "btc_time": row_time,
                "btc_bits": row_bits,
                "expected_nbits": expected_nbits,
                "pow_valid": "true"
                if row_bits and hash_meets_bits(block_hash, row_bits)
                else "false",
                "header_hash_match": "true"
                if header_hex and header_hash(header_hex) == block_hash
                else "false",
                "bip34_height_status": bip34_height_status,
                "observed_btc_heights": join_sorted(observed_heights),
                "observed_btc_times": join_sorted(observed_times),
                "observed_btc_bits": join_sorted(observed_bits),
                "root_stale_hash": stale_hash,
                "root_stale_height": "" if root_height is None else root_height,
                "root_stale_sources": sources,
                "root_stale_chains": chains,
                "root_stale_btc_times": times,
                "root_stale_bits": bits,
                "stale_fork_depth": result.depth,
                "path_hashes": ">".join(path),
                "path_chain_sets": ">".join(
                    join_sorted(unknown_chains_by_hash.get(h, set()))
                    for h in path
                    if h in unknown_chains_by_hash
                ),
                "observed_chains": join_sorted(unknown_chains_by_hash[block_hash]),
                "unknown_rows": unknown_row_counts_by_hash[block_hash],
                "source_rows": join_sorted(
                    f"{obs.chain}:{obs.source_path}:{obs.row_number}"
                    for obs in observations
                ),
                "coinbase_scriptsig_hex": scriptsig_hex,
                "coinbase_outputs": coinbase_outputs,
                "btc_header_hex": header_hex,
                "notes": descendant_notes(
                    block_hash, validation_failures, publication_baseline
                ),
            }
        )

    # A candidate whose own bytes prove a consensus rule broken is not a stale
    # descendant, so it leaves the sidecar entirely for the error-block peer.
    # Publishing it here instead would put a second classification into a file
    # whose reader accepts exactly one, and would hand nothing the derived rules.
    descendant_rows = [
        row for row in promoted_rows if row["classification"] == "stale_descendant"
    ]
    error_block_rows = [
        row for row in promoted_rows if row["classification"] == "error_block"
    ]

    # The baseline is an evidence-coverage floor, so it is checked against every
    # computed row rather than the published subset: a committed hash that moved
    # to the error-block peer is still recovered, not lost. Losing one from both
    # artifacts, or proving a committed VALID descendant consensus-invalid, is
    # still a regression and still fails the run.
    if publication_baseline is not None:
        validate_publication_rows(promoted_rows, publication_baseline, parser)
    if mainchain_cache_dirty:
        save_mainchain_cache(cache_dir, mainchain_cache)

    root_summary: dict[tuple[str, str], dict[str, object]] = {}
    for block_hash, result in walk_results.items():
        key = (result.category, result.terminal_hash)
        item = root_summary.setdefault(
            key,
            {
                "terminal_category": result.category,
                "terminal_hash": result.terminal_hash,
                "unique_unknown_hashes": 0,
                "unknown_rows": 0,
                "chains": set(),
                "max_depth": 0,
                "example_unknown_hash": block_hash,
                "example_path": "",
            },
        )
        item["unique_unknown_hashes"] = int(item["unique_unknown_hashes"]) + 1
        item["unknown_rows"] = (
            int(item["unknown_rows"]) + unknown_row_counts_by_hash[block_hash]
        )
        item["chains"].update(unknown_chains_by_hash[block_hash])
        item["max_depth"] = max(int(item["max_depth"]), result.depth)

    compact_roots: dict[tuple[str, str], dict[str, object]] = {}
    for item in root_summary.values():
        category = str(item["terminal_category"])
        terminal_hash = str(item["terminal_hash"])
        compact_key = (
            category,
            terminal_hash
            if category in {"direct_stale_child", "stale_descendant"}
            else "(multiple)",
        )
        compact = compact_roots.setdefault(
            compact_key,
            {
                "terminal_category": category,
                "terminal_hash": compact_key[1],
                "terminal_root_count": 0,
                "unique_unknown_hashes": 0,
                "unknown_rows": 0,
                "chains": set(),
                "max_depth": 0,
                "sample_terminal_hashes": [],
                "sample_unknown_hashes": [],
                "example_path": "",
            },
        )
        compact["terminal_root_count"] = int(compact["terminal_root_count"]) + 1
        compact["unique_unknown_hashes"] = int(compact["unique_unknown_hashes"]) + int(
            item["unique_unknown_hashes"]
        )
        compact["unknown_rows"] = int(compact["unknown_rows"]) + int(
            item["unknown_rows"]
        )
        compact["chains"].update(item["chains"])
        compact["max_depth"] = max(int(compact["max_depth"]), int(item["max_depth"]))
        if len(compact["sample_terminal_hashes"]) < 25:
            compact["sample_terminal_hashes"].append(terminal_hash)
        if len(compact["sample_unknown_hashes"]) < 25:
            compact["sample_unknown_hashes"].append(str(item["example_unknown_hash"]))
        if not compact["example_path"]:
            compact["example_path"] = ">".join(
                path_for(str(item["example_unknown_hash"]))
            )

    root_rows = [
        {
            "terminal_category": item["terminal_category"],
            "terminal_hash": item["terminal_hash"],
            "terminal_root_count": item["terminal_root_count"],
            "unique_unknown_hashes": item["unique_unknown_hashes"],
            "unknown_rows": item["unknown_rows"],
            "chains": join_sorted(item["chains"]),
            "max_depth": item["max_depth"],
            "sample_terminal_hashes": join_sorted(item["sample_terminal_hashes"]),
            "sample_unknown_hashes": join_sorted(item["sample_unknown_hashes"]),
            "example_path": item["example_path"],
        }
        for item in compact_roots.values()
    ]
    root_rows.sort(
        key=lambda row: (
            str(row["terminal_category"]),
            -int(row["unknown_rows"]),
            str(row["terminal_hash"]),
        )
    )

    category_unique_counts = Counter(
        result.category for result in walk_results.values()
    )
    category_row_counts: Counter[str] = Counter()
    for block_hash, result in walk_results.items():
        category_row_counts[result.category] += unknown_row_counts_by_hash[block_hash]

    stale_descendant_hashes = {
        h for h, result in walk_results.items() if result.category == "stale_descendant"
    }
    direct_hashes = {
        h
        for h, result in walk_results.items()
        if result.category == "direct_stale_child"
    }
    stale_child_rollup = defaultdict(
        lambda: {"direct": 0, "descendants": 0, "chains": set()}
    )
    for block_hash, result in walk_results.items():
        if result.category not in {"direct_stale_child", "stale_descendant"}:
            continue
        rollup = stale_child_rollup[result.terminal_hash]
        if result.category == "direct_stale_child":
            rollup["direct"] += unknown_row_counts_by_hash[block_hash]
        else:
            rollup["descendants"] += unknown_row_counts_by_hash[block_hash]
        rollup["chains"].update(unknown_chains_by_hash[block_hash])

    valid_promoted_hashes = {
        row["btc_header_hash"]
        for row in descendant_rows
        if row["validation_status"] == "VALID_STALE_DESCENDANT"
    }
    rejected_promoted_hashes = {
        row["btc_header_hash"]
        for row in descendant_rows
        if row["validation_status"] != "VALID_STALE_DESCENDANT"
    }
    error_block_hashes = {row["btc_header_hash"] for row in error_block_rows}

    summary = {
        "known_stale_hashes": len(known_stale_hashes),
        "upstream_stale_hashes": upstream_count,
        "auxpow_stale_hashes": len(auxpow_stale_hashes),
        "total_unknown_rows": len(unknown_rows),
        "unique_unknown_hashes": len(unknown_row_counts_by_hash),
        "direct_stale_child_unknown_rows": sum(
            unknown_row_counts_by_hash[h] for h in direct_hashes
        ),
        "unique_direct_stale_child_unknown_hashes": len(direct_hashes),
        "stale_descendant_unknown_rows": sum(
            unknown_row_counts_by_hash[h] for h in stale_descendant_hashes
        ),
        "unique_stale_descendant_unknown_hashes": len(stale_descendant_hashes),
        "promoted_stale_descendant_hashes": len(valid_promoted_hashes),
        "rejected_stale_descendant_hashes": len(rejected_promoted_hashes),
        "error_block_descendant_hashes": len(error_block_hashes),
        "promoted_csv": rel_fn(args.promoted_csv),
        "error_blocks_csv": rel_fn(args.error_blocks_csv),
        "dangling_unknown_roots": sum(
            1 for category, _terminal in root_summary if category == "dangling_unknown"
        ),
        "unknown_root_seen_elsewhere_roots": sum(
            1
            for category, _terminal in root_summary
            if category == "unknown_root_seen_elsewhere"
        ),
        "mainchain_descendant_anomalies": category_row_counts.get(
            "mainchain_descendant", 0
        ),
        "cycle_or_bad_data_rows": category_row_counts.get("cycle_or_bad_data", 0),
        "category_counts_by_unique_unknown_hash": dict(
            sorted(category_unique_counts.items())
        ),
        "category_counts_by_unknown_row": dict(sorted(category_row_counts.items())),
        "chains_included": [
            row["chain"] for row in inventory_rows if int(row["total_rows"]) > 0
        ],
        "chains_excluded": {
            row["chain"]: row["notes"]
            for row in inventory_rows
            if int(row["total_rows"]) == 0
        },
        "stale_hash_rollups": {
            h: {
                "direct_unknown_rows": data["direct"],
                "descendant_unknown_rows": data["descendants"],
                "chains_with_descendants": join_sorted(data["chains"]),
            }
            for h, data in sorted(stale_child_rollup.items())
        },
        "mainchain_check": {
            "used_existing_cache_entries": len(mainchain_cache),
            "queried_bitcoin_core": bool(args.check_mainchain),
            "rpc_url": args.rpc_url if args.check_mainchain else "",
        },
    }

    write_csv(
        results_dir / OUTPUT_INVENTORY,
        inventory_rows,
        [
            "chain",
            "full_inventory_path",
            "validated_stale_path",
            "header_hash_column_used",
            "prev_hash_column_used",
            "total_rows",
            "stale_rows",
            "unknown_rows",
            "rows_missing_header_hash",
            "rows_missing_prev_hash",
            "notes",
        ],
    )
    write_csv(
        results_dir / OUTPUT_DIRECT,
        direct_rows,
        [
            "unknown_chain",
            "unknown_source_path",
            "unknown_row_number",
            "unknown_child_height",
            "unknown_btc_height",
            "unknown_btc_header_hash",
            "unknown_btc_prev_hash",
            "matched_stale_hash",
            "matched_stale_sources",
            "matched_stale_chains",
            "matched_stale_btc_heights",
            "unknown_btc_time",
            "matched_stale_btc_times",
            "unknown_bits",
            "matched_stale_bits",
        ],
    )
    write_csv(
        results_dir / OUTPUT_PATHS,
        descendant_path_rows,
        [
            "unknown_btc_header_hash",
            "terminal_category",
            "depth",
            "unknown_rows",
            "unknown_chains",
            "example_source_path",
            "example_row_number",
            "example_child_height",
            "example_btc_height",
            "path_hashes",
            "path_chain_sets",
            "terminal_stale_hash",
            "terminal_stale_sources",
            "terminal_stale_chains",
            "terminal_stale_btc_heights",
            "terminal_stale_btc_times",
            "terminal_stale_bits",
        ],
    )
    write_csv(args.promoted_csv, descendant_rows, PROMOTED_FIELDS)
    write_csv(args.error_blocks_csv, error_block_rows, PROMOTED_ERROR_BLOCK_FIELDS)
    write_csv(
        results_dir / OUTPUT_ROOTS,
        root_rows,
        [
            "terminal_category",
            "terminal_hash",
            "terminal_root_count",
            "unique_unknown_hashes",
            "unknown_rows",
            "chains",
            "max_depth",
            "sample_terminal_hashes",
            "sample_unknown_hashes",
            "example_path",
        ],
    )
    write_csv(
        results_dir / OUTPUT_ANOMALIES,
        anomalies,
        [
            "issue_type",
            "severity",
            "count",
            "chain",
            "source_path",
            "row_number",
            "btc_header_hash",
            "btc_prev_hash",
            "details",
        ],
    )
    (results_dir / OUTPUT_SUMMARY).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )

    return summary
