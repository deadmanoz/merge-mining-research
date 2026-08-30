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

from stale_blocks_analysis.bitcoin_binary import parse_coinbase_tx
from stale_blocks_analysis.btc_stale_validation import (
    BIP34_HEIGHT_MISSING_PREFIX,
    VERSION_RULES,
    bip34_height_error,
    block_version_error,
    consensus_violations,
)
from stale_blocks_analysis.auxpow_parse import (
    ChildHeaderValidationError,
    validate_available_child_header_fields,
)
from stale_blocks_analysis.config import (
    BIP34_HEIGHT,
    BIP34_VERSION_2_HEIGHT,
    CHAIN_SPECS,
    DATA_DIR,
)
from stale_blocks_analysis.coinbase_output_claims import (
    merge_coinbase_output_claim_sets,
    parse_coinbase_output_claims,
    render_coinbase_output_claims,
)
from stale_blocks_analysis.full_evidence import (
    int_or_none,
    is_hash,
    normalize_hash,
)
from stale_blocks_analysis.evidence_hydration import (
    child_identity_candidates,
    load_child_identity,
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
from stale_blocks_analysis.stale_descendants import (
    OBSERVATIONS_PATH,
    OBSERVATION_FIELDS,
    PARENT_VERDICT_FIELDS,
    load_stale_descendant_observations,
    load_stale_descendant_parents,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = PROJECT_ROOT / "results" / "analysis" / "stale-ancestry"
PARENT_VERDICTS_CSV = PROJECT_ROOT / "data" / "stale_descendants.csv"

OUTPUT_INVENTORY = "unknown-stale-reconciliation-inventory.csv"
OUTPUT_DIRECT = "unknown-stale-direct-matches.csv"
OUTPUT_PATHS = "unknown-stale-descendant-paths.csv"
OUTPUT_ROOTS = "unknown-stale-root-summary.csv"
OUTPUT_ANOMALIES = "unknown-stale-anomalies.csv"
OUTPUT_SUMMARY = "unknown-stale-reconciliation-summary.json"

ERROR_CANDIDATE_FIELDS = [*PARENT_VERDICT_FIELDS, "source_rows", "rules_violated"]


@dataclass(frozen=True, slots=True)
class PublicationBaseline:
    """Committed descendant rows and the private inventories they depend on."""

    statuses_by_hash: dict[str, str]
    heights_by_hash: dict[str, int]
    root_hashes_by_hash: dict[str, str]
    mainchain_statuses_by_hash: dict[str, str]
    active_hashes_by_hash: dict[str, str]
    root_mainchain_statuses_by_hash: dict[str, str]
    root_active_hashes_by_hash: dict[str, str]
    mainchain_sources_by_hash: dict[str, str]
    observed_chains_by_hash: dict[str, frozenset[str]]
    source_observation_counts_by_hash: dict[str, Counter[str]]
    required_inventory_chains: frozenset[str]
    observation_identities: frozenset[tuple[str, int, str, str]] = frozenset()


DESCENDANT_UNJUDGEABLE_FAILURES = frozenset(
    {
        "missing_header_hex",
        "header_hash_mismatch",
        "prev_hash_path_mismatch",
        "pow_target_mismatch",
        "missing_expected_nbits",
    }
)

CONSENSUS_INVALID_PARENT_RULE = "consensus_invalid_parent"


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
    - ``missing_expected_nbits``: the committed epoch reference cannot identify
      Bitcoin's canonical target at the inferred height. The candidate must
      fail closed rather than treating an unperformed comparison as a match.

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


def load_publication_baseline(
    path: Path = PARENT_VERDICTS_CSV,
    *,
    data_dir: Path = DATA_DIR,
) -> PublicationBaseline:
    """Load the committed parent verdicts and canonical witness ledger."""
    parents = load_stale_descendant_parents(path, data_dir=data_dir)
    observations = load_stale_descendant_observations(
        path.parent / "stale_descendant_observations.csv",
        parents_path=path,
        data_dir=data_dir,
    )
    statuses: dict[str, str] = {}
    heights: dict[str, int] = {}
    root_hashes: dict[str, str] = {}
    mainchain_statuses: dict[str, str] = {}
    active_hashes: dict[str, str] = {}
    root_mainchain_statuses: dict[str, str] = {}
    root_active_hashes: dict[str, str] = {}
    mainchain_sources: dict[str, str] = {}
    observed_chains_by_hash: dict[str, set[str]] = defaultdict(set)
    source_observation_counts_by_hash: dict[str, Counter[str]] = defaultdict(Counter)
    required_chains: set[str] = set()
    for parent in parents.values():
        row = parent.row
        statuses[parent.block_hash] = row["validation_status"]
        heights[parent.block_hash] = parent.height
        root_hashes[parent.block_hash] = normalize_hash(row.get("root_stale_hash"))
        mainchain_statuses[parent.block_hash] = row["active_mainchain_status"]
        active_hashes[parent.block_hash] = row["active_mainchain_hash_at_height"]
        root_mainchain_statuses[parent.block_hash] = row["root_active_mainchain_status"]
        root_active_hashes[parent.block_hash] = row[
            "root_active_mainchain_hash_at_height"
        ]
        mainchain_sources[parent.block_hash] = row[
            "active_mainchain_verification_source"
        ]
    for observation in observations:
        observed_chains_by_hash[observation.parent_hash].add(observation.chain)
        source_observation_counts_by_hash[observation.parent_hash][
            observation.chain
        ] += 1
        required_chains.add(observation.chain)
    return PublicationBaseline(
        statuses_by_hash=statuses,
        heights_by_hash=heights,
        root_hashes_by_hash=root_hashes,
        mainchain_statuses_by_hash=mainchain_statuses,
        active_hashes_by_hash=active_hashes,
        root_mainchain_statuses_by_hash=root_mainchain_statuses,
        root_active_hashes_by_hash=root_active_hashes,
        mainchain_sources_by_hash=mainchain_sources,
        observed_chains_by_hash={
            block_hash: frozenset(chains)
            for block_hash, chains in observed_chains_by_hash.items()
        },
        source_observation_counts_by_hash=dict(source_observation_counts_by_hash),
        required_inventory_chains=frozenset(required_chains),
        observation_identities=frozenset(
            observation.logical_identity for observation in observations
        ),
    )


def descendant_notes(validation_failures: list[str]) -> str:
    """Render notes proved by the current reconciliation run."""
    return ";".join(validation_failures)


def partition_ancestry_rows(
    ancestry_rows: list[dict[str, object]],
) -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    """Select accepted parents, unpublishable rows, and blocking diagnostics.

    The returned diagnostic list is intentionally not a disjoint partition.
    Every walk into a catalogued consensus-invalid terminal blocks publication
    and belongs in the disposable error-candidate report, even when incomplete
    evidence leaves that row correctly classified as ``unpublishable``. Only a
    fully authenticated full-PoW row may carry ``classification=error_block``.
    """
    accepted: list[dict[str, object]] = []
    unpublishable: list[dict[str, object]] = []
    error_candidates: list[dict[str, object]] = []
    for row in ancestry_rows:
        classification = row["classification"]
        if classification == "error_block" or (
            row.get("ancestry_relation") == "consensus_invalid_descendant"
        ):
            error_candidates.append(row)
        if classification == "error_block":
            continue
        if classification == "stale_descendant" and (
            row["validation_status"] == "VALID_STALE_DESCENDANT"
        ):
            accepted.append(row)
        else:
            unpublishable.append(row)
    return accepted, unpublishable, error_candidates


def validate_output_mode(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    results_dir_default: Path = RESULTS_DIR,
    parent_verdicts_csv_default: Path = PARENT_VERDICTS_CSV,
    observations_csv_default: Path = OBSERVATIONS_PATH,
) -> None:
    """Require distinct diagnostic outputs outside the committed interfaces."""
    labelled = {
        "reconciliation-inventory output": args.results_dir / OUTPUT_INVENTORY,
        "direct-matches output": args.results_dir / OUTPUT_DIRECT,
        "descendant-paths output": args.results_dir / OUTPUT_PATHS,
        "root-summary output": args.results_dir / OUTPUT_ROOTS,
        "anomalies output": args.results_dir / OUTPUT_ANOMALIES,
        "reconciliation-summary output": args.results_dir / OUTPUT_SUMMARY,
        "--parent-verdicts-csv": args.parent_verdicts_csv,
        "--observations-csv": args.observations_csv,
        "--error-candidates-csv": args.error_candidates_csv,
    }
    seen: dict[Path, str] = {}
    for label, path in labelled.items():
        resolved = path.resolve()
        previous = seen.get(resolved)
        if previous is not None:
            parser.error(f"{label} aliases {previous}: {resolved}")
        seen[resolved] = label
    committed_outputs = {
        parent_verdicts_csv_default.resolve(): "stale-descendant parent verdicts",
        observations_csv_default.resolve(): "stale-descendant observation ledger",
    }
    for path, artifact in committed_outputs.items():
        offending_label = seen.get(path)
        if offending_label is not None:
            parser.error(
                f"{offending_label} is diagnostic/staging-only and cannot target "
                f"the committed {artifact}; use the publication workflow"
            )

    # The low-level command writes every labelled path directly. Keep all such
    # outputs away from the repository's canonical data tree and committed
    # result publications, regardless of which of the three CSV options names
    # the target. The dedicated, gitignored stale-ancestry results namespace is
    # the sole in-repository diagnostic exception.
    data_publication_root = (PROJECT_ROOT / "data").resolve()
    results_publication_root = (PROJECT_ROOT / "results").resolve()
    diagnostic_results_root = results_dir_default.resolve()
    for label, path in labelled.items():
        resolved = path.resolve()
        protected_data = resolved.is_relative_to(data_publication_root)
        protected_results = resolved.is_relative_to(
            results_publication_root
        ) and not resolved.is_relative_to(diagnostic_results_root)
        if protected_data or protected_results:
            parser.error(
                f"{label} is diagnostic/staging-only and cannot target a protected "
                f"publication surface: {resolved}"
            )
    if not args.allow_partial:
        return
    if args.results_dir.resolve() == results_dir_default.resolve():
        parser.error("--allow-partial requires an explicit disposable --results-dir")


def validate_publication_discovery(
    baseline: PublicationBaseline,
    full_files: dict[str, Path],
    unknown_files: dict[str, Path],
    canonical_files: dict[str, Path],
    parser: argparse.ArgumentParser,
) -> None:
    """Require source inventories for every chain represented in the baseline."""
    discovered = set(full_files) | set(unknown_files) | set(canonical_files)
    missing = sorted(baseline.required_inventory_chains - discovered)
    if missing:
        parser.error(
            "refusing an incomplete publication reconciliation; missing full, "
            "unknown, or canonical inventories for baseline chains: "
            + ", ".join(missing)
            + ". Use --allow-partial only with disposable output paths."
        )


def validate_publication_rows(
    rows: Iterable[dict[str, object]],
    observation_rows: Iterable[dict[str, object]],
    baseline: PublicationBaseline,
    parser: argparse.ArgumentParser,
) -> None:
    """Reject loss of a committed parent or logical witness identity."""
    statuses: dict[str, str] = {}
    parent_identities: set[tuple[int, str]] = set()
    computed_rows_by_hash: dict[str, dict[str, object]] = {}
    duplicate_hashes: set[str] = set()
    for row in rows:
        block_hash = normalize_hash(str(row.get("btc_header_hash", "")))
        if block_hash in statuses:
            duplicate_hashes.add(block_hash)
        statuses[block_hash] = str(row.get("validation_status", ""))
        computed_rows_by_hash[block_hash] = row
        height = int_or_none(str(row.get("btc_height", "")))
        if height is not None:
            parent_identities.add((height, block_hash))

    baseline_parent_identities = {
        (height, block_hash) for block_hash, height in baseline.heights_by_hash.items()
    }
    missing = sorted(baseline_parent_identities - parent_identities)
    problems: list[str] = []
    if duplicate_hashes:
        problems.append(
            "duplicate computed descendant hashes: "
            + ", ".join(sorted(duplicate_hashes))
        )
    if missing:
        problems.append(
            f"missing {len(missing)} committed descendant identities (first: {missing[0]})"
        )
    validity_regressions = sorted(
        block_hash
        for block_hash in baseline.statuses_by_hash
        if statuses.get(block_hash) != "VALID_STALE_DESCENDANT"
        or str(computed_rows_by_hash.get(block_hash, {}).get("classification", ""))
        != "stale_descendant"
    )
    if validity_regressions:
        problems.append(
            f"{len(validity_regressions)} committed VALID descendants no longer VALID"
            f" (first: {validity_regressions[0]})"
        )
    computed_observation_identities: set[tuple[str, int, str, str]] = set()
    for row in observation_rows:
        child_height = int_or_none(str(row.get("child_height", "")))
        identity = (
            str(row.get("chain", "")),
            -1 if child_height is None else child_height,
            normalize_hash(str(row.get("child_block_hash", ""))),
            normalize_hash(str(row.get("btc_header_hash", ""))),
        )
        if identity in computed_observation_identities:
            problems.append(f"duplicate computed witness identity: {identity}")
            break
        computed_observation_identities.add(identity)
    missing_observations = sorted(
        baseline.observation_identities - computed_observation_identities
    )
    if missing_observations:
        problems.append(
            f"missing {len(missing_observations)} committed logical witness "
            f"identities (first: {missing_observations[0]})"
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
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def join_sorted(values: Iterable[str]) -> str:
    """Join the non-empty values of `values`, sorted, with `|` as the CSV-friendly delimiter."""
    return "|".join(sorted(v for v in values if v))


def select_parent_evidence(
    observations: list[UnknownObservation],
) -> tuple[str, str, str, str, str, str]:
    """Reconcile every compatible source into one maximal evidence bundle."""
    if not observations:
        raise ValueError("cannot select parent evidence without observations")

    def consistent(label: str, values: Iterable[str]) -> str:
        present = {value.strip().lower() for value in values if value.strip()}
        if len(present) > 1:
            raise ValueError(f"conflicting {label} evidence across source observations")
        return next(iter(present), "")

    header_hex = consistent(
        "Bitcoin header", (observation.header_hex for observation in observations)
    )
    prev_hash = consistent(
        "Bitcoin previous hash", (observation.prev_hash for observation in observations)
    )
    btc_time = consistent(
        "Bitcoin header time", (observation.btc_time for observation in observations)
    )
    bits = consistent(
        "Bitcoin compact target", (observation.bits for observation in observations)
    )

    scriptsigs = [
        observation.scriptsig_hex.strip().lower()
        for observation in observations
        if observation.scriptsig_hex.strip()
    ]
    claim_sets = []
    for observation in observations:
        claim_sets.append(
            parse_coinbase_output_claims(
                observation.outputs, observation.full_coinbase_hex
            )
        )
        if observation.full_coinbase_hex:
            try:
                parsed_coinbase = parse_coinbase_tx(
                    bytes.fromhex(observation.full_coinbase_hex)
                )
            except ValueError as exc:
                raise ValueError("full coinbase transaction is not valid hex") from exc
            if parsed_coinbase is None:
                raise ValueError("full coinbase transaction could not be parsed")
            scriptsigs.append(parsed_coinbase["scriptsig"].hex())
    scriptsig_hex = consistent("coinbase scriptSig", scriptsigs)
    if scriptsig_hex:
        try:
            bytes.fromhex(scriptsig_hex)
        except ValueError as exc:
            raise ValueError("coinbase scriptSig is not valid hex") from exc
    coinbase_outputs = render_coinbase_output_claims(
        merge_coinbase_output_claim_sets(*claim_sets)
    )
    return (
        header_hex,
        prev_hash,
        btc_time,
        bits,
        scriptsig_hex,
        coinbase_outputs,
    )


def build_descendant_observation_rows(
    descendant_rows: list[dict[str, object]],
    observations_by_hash: dict[str, list[UnknownObservation]],
    *,
    data_dir: Path,
    parser: argparse.ArgumentParser,
) -> list[dict[str, object]]:
    """Derive the canonical witness ledger from this run's source observations."""
    child_identities = load_child_identity(data_dir)
    ledger_rows: list[dict[str, object]] = []
    logical_seen: set[tuple[str, int, str, str]] = set()
    logical_observations: dict[tuple[str, int, str, str], list[UnknownObservation]] = {}
    source_seen: set[tuple[str, str, int, str]] = set()
    for parent_row_number, parent in enumerate(descendant_rows, start=2):
        parent_hash = normalize_hash(str(parent["btc_header_hash"]))
        parent_height = int_or_none(str(parent["btc_height"]))
        source_observations = observations_by_hash.get(parent_hash, [])
        if parent_height is None or not source_observations:
            parser.error(
                f"accepted descendant {parent_hash} has no reproducible source observations"
            )
        observed_chains: set[str] = set()
        parent_count = 0
        for observation in sorted(
            source_observations,
            key=lambda item: (
                item.chain,
                item.source_path,
                item.row_number,
                item.source_sha256,
                item.source_kind,
                item.source_classification,
            ),
        ):
            identity_candidates = child_identity_candidates(
                child_identities, observation.chain, parent_hash
            )
            if not identity_candidates:
                parser.error(
                    f"accepted descendant witness {observation.chain}:{parent_hash} "
                    "lacks an authenticated child identity"
                )
            source_child_height = int_or_none(observation.child_height)
            source_child_hash = normalize_hash(observation.source_child_hash)
            if observation.source_child_hash.strip() and not is_hash(source_child_hash):
                parser.error(
                    "source observation carries a malformed child block hash "
                    f"for {observation.chain}:{parent_hash}:"
                    f"{observation.source_child_hash}"
                )
            if observation.child_height.strip():
                matching_identities = tuple(
                    identity
                    for identity in identity_candidates
                    if source_child_height is not None
                    and source_child_height >= 0
                    and int_or_none(identity.get("child_height")) == source_child_height
                )
            else:
                matching_identities = identity_candidates
            if source_child_hash:
                matching_identities = tuple(
                    identity
                    for identity in matching_identities
                    if normalize_hash(identity.get("child_block_hash"))
                    == source_child_hash
                )
            if not matching_identities:
                parser.error(
                    "authenticated child identity disagrees with source observation "
                    f"{observation.chain}:{parent_hash}:"
                    f"{observation.child_height or '<identity-height>'}:"
                    f"{source_child_hash or '<identity-hash>'}"
                )
            if len(matching_identities) > 1:
                parser.error(
                    "ambiguous authenticated child identities for source observation "
                    f"{observation.chain}:{parent_hash}:"
                    f"{observation.child_height or '<missing-child-height>'}:"
                    f"{source_child_hash or '<missing-child-hash>'}; "
                    "the source row does not identify one exact child event"
                )
            identity = matching_identities[0]
            identity_height = int_or_none(identity.get("child_height"))
            child_hash = normalize_hash(identity.get("child_block_hash"))
            child_time = (identity.get("child_block_time") or "").strip()
            if (
                identity_height is None
                or identity_height < 0
                or (
                    source_child_height is not None
                    and source_child_height != identity_height
                )
                or (source_child_hash and source_child_hash != child_hash)
                or not is_hash(child_hash)
                or not child_time.isdigit()
                or int(child_time) <= 0
            ):
                parser.error(
                    f"authenticated child identity disagrees with source observation "
                    f"{observation.chain}:{parent_hash}:"
                    f"{observation.child_height or '<identity-height>'}"
                )
            child_height = identity_height
            logical_identity = (
                observation.chain,
                child_height,
                child_hash,
                parent_hash,
            )
            source_identity = (
                observation.chain,
                observation.source_path,
                observation.row_number,
                observation.source_sha256,
            )
            if source_identity in source_seen:
                parser.error(
                    f"duplicate descendant source coordinate: {source_identity}"
                )
            source_seen.add(source_identity)
            if logical_identity in logical_seen:
                # A never-split inventory can retain the same physical event
                # that its canonical companion publishes. The authenticated
                # child identity proves publication multiplicity, while the
                # source rows still have to reconcile semantically. Keep the
                # lexicographically first source coordinate from the stable
                # ordering above; contradictory copies fail closed.
                try:
                    select_parent_evidence(
                        [*logical_observations[logical_identity], observation]
                    )
                except ValueError as exc:
                    parser.error(
                        "conflicting evidence for authenticated descendant "
                        f"event {logical_identity}: {exc}"
                    )
                logical_observations[logical_identity].append(observation)
                continue
            logical_seen.add(logical_identity)
            logical_observations[logical_identity] = [observation]
            observed_chains.add(observation.chain)
            parent_count += 1
            verification = (identity.get("verification") or "").strip()
            child_header = (identity.get("child_header_hex") or "").strip().lower()
            child_nbits = (identity.get("child_nbits") or "").strip().lower()
            try:
                validate_available_child_header_fields(
                    {
                        "child_block_hash": child_hash,
                        "child_header_hex": child_header,
                        "child_block_time": child_time,
                        "child_nbits": child_nbits,
                    },
                    nbits_from_header=CHAIN_SPECS[
                        observation.chain
                    ].child_nbits_from_header,
                )
            except (ChildHeaderValidationError, KeyError) as exc:
                parser.error(
                    f"invalid authenticated child identity for "
                    f"{observation.chain}:{parent_hash}: {exc}"
                )
            ledger_rows.append(
                {
                    "btc_height": str(parent_height),
                    "btc_header_hash": parent_hash,
                    "chain": observation.chain,
                    "child_height": str(child_height),
                    "child_block_hash": child_hash,
                    "child_block_hash_order": "internal",
                    "child_header_hex": child_header,
                    "child_block_time": child_time,
                    "child_nbits": child_nbits,
                    "source_btc_height": observation.btc_height,
                    "source_kind": observation.source_kind,
                    "source_path": observation.source_path,
                    "source_row_number": str(observation.row_number),
                    "source_sha256": observation.source_sha256,
                    "source_classification": observation.source_classification,
                    "btc_height_provenance": "ancestry-root-plus-depth",
                    "child_height_provenance": (
                        "source-row"
                        if source_child_height is not None
                        else f"child-identity:{verification}"
                    ),
                    "identity_provenance": f"child-identity:{verification}",
                    "parent_row_number": str(parent_row_number),
                    "provenance": "catalogue:stale-descendant-observations",
                }
            )
        parent["observed_chains"] = join_sorted(observed_chains)
        parent["source_observation_count"] = parent_count
    ledger_rows.sort(
        key=lambda row: (
            int(str(row["btc_height"])),
            str(row["btc_header_hash"]),
            str(row["chain"]),
            int(str(row["child_height"])),
            str(row["child_block_hash"]),
        )
    )
    return ledger_rows


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
    consensus_invalid_heights_by_hash: dict[str, int],
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

    candidate_hashes = {
        h
        for h, result in walk_results.items()
        if result.category
        in {
            "direct_stale_child",
            "stale_descendant",
            "consensus_invalid_descendant",
        }
    }
    ancestry_rows = []
    for block_hash in sorted(candidate_hashes):
        result = walk_results[block_hash]
        path = path_for(block_hash)
        terminal_hash = result.terminal_hash
        inherited_invalid_parent = result.category == "consensus_invalid_descendant"
        if inherited_invalid_parent:
            root_height = consensus_invalid_heights_by_hash.get(terminal_hash)
            if root_height is None:
                parser.error(
                    "consensus-invalid ancestry terminal lacks a canonical height: "
                    f"{terminal_hash}"
                )
        else:
            root_heights = sorted(
                {
                    int(obs.btc_height)
                    for obs in stale_by_hash[terminal_hash]
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
        ) = select_parent_evidence(observations)
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
        if inferred_height is not None and not expected_nbits:
            validation_failures.append("missing_expected_nbits")
        elif expected_nbits and row_bits and row_bits.lower() != expected_nbits:
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

        inherited_parent_rule_proven = bool(
            inherited_invalid_parent
            and inferred_height is not None
            and not (DESCENDANT_UNJUDGEABLE_FAILURES & set(validation_failures))
            and expected_nbits
            and row_bits
            and row_bits.lower() == expected_nbits
        )
        derived_consensus_rules = descendant_consensus_rules(
            header_hex,
            scriptsig_hex,
            inferred_height,
            validation_failures,
            header_bits=row_bits,
            expected_nbits=expected_nbits,
        )
        consensus_rules = [
            *([CONSENSUS_INVALID_PARENT_RULE] if inherited_parent_rule_proven else []),
            *derived_consensus_rules,
        ]
        # The descendant verdict and the classification are the same judgement
        # on one row, so they must not disagree. The BIP34 verdict above passes
        # a scriptSig that is over-long but correctly prefixed, and never looks
        # at the length at all, so without this the error-candidate diagnostic
        # would carry VALID_STALE_DESCENDANT. Rows that
        # already carry a failure are already rejections and keep their primary
        # reason; the derived rules travel in ``rules_violated`` either way.
        if consensus_rules and not validation_failures:
            validation_failures.extend(consensus_rules)
        validation_status = (
            "VALID_STALE_DESCENDANT"
            if not validation_failures
            else "REJECTED_" + "|".join(validation_failures)
        )
        if inherited_invalid_parent:
            sources, chains, heights, times, bits = (
                "",
                "",
                str(root_height),
                "",
                "",
            )
        else:
            sources, chains, heights, times, bits = stale_sources(
                stale_by_hash[terminal_hash]
            )
        final_observed_chains = join_sorted(unknown_chains_by_hash[block_hash])
        source_observation_count = unknown_row_counts_by_hash[block_hash]
        candidate_cache = (
            {} if inherited_invalid_parent else mainchain_cache.get(block_hash, {})
        )
        root_cache = (
            {} if inherited_invalid_parent else mainchain_cache.get(terminal_hash, {})
        )
        candidate_cache_verified = bool(
            inferred_height is not None
            and int_or_none(str(candidate_cache.get("height"))) == inferred_height
            and str(candidate_cache.get("verification_source") or "").startswith(
                "bitcoin-core-rpc:"
            )
            and is_hash(
                normalize_hash(str(candidate_cache.get("active_hash_at_height") or ""))
            )
            and normalize_hash(str(candidate_cache.get("active_hash_at_height") or ""))
            != block_hash
        )
        root_cache_verified = bool(
            root_height is not None
            and int_or_none(str(root_cache.get("height"))) == root_height
            and str(root_cache.get("verification_source") or "").startswith(
                "bitcoin-core-rpc:"
            )
            and is_hash(
                normalize_hash(str(root_cache.get("active_hash_at_height") or ""))
            )
            and normalize_hash(str(root_cache.get("active_hash_at_height") or ""))
            != terminal_hash
        )
        # Publication always refreshes these exact height comparisons in the
        # current run. The committed fields are an offline audit trail and do
        # not substitute for querying Bitcoin Core again.
        candidate_status = (
            "verified_not_active" if candidate_cache_verified else "not_checked"
        )
        root_status = "verified_not_active" if root_cache_verified else "not_checked"
        candidate_active_hash = str(candidate_cache.get("active_hash_at_height") or "")
        root_active_hash = str(root_cache.get("active_hash_at_height") or "")
        mainchain_source = str(candidate_cache.get("verification_source") or "")

        ancestry_rows.append(
            {
                "classification": (
                    "error_block"
                    if consensus_rules
                    else "unpublishable"
                    if validation_failures
                    else "stale_descendant"
                ),
                "rules_violated": "|".join(consensus_rules),
                "ancestry_relation": result.category,
                "validation_status": validation_status,
                "active_mainchain_status": candidate_status,
                "active_mainchain_hash_at_height": candidate_active_hash,
                "root_active_mainchain_status": root_status,
                "root_active_mainchain_hash_at_height": root_active_hash,
                "active_mainchain_verification_source": mainchain_source,
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
                "root_stale_hash": terminal_hash,
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
                "observed_chains": final_observed_chains,
                "source_observation_count": source_observation_count,
                "source_rows": join_sorted(
                    f"{obs.chain}:{obs.source_path}:{obs.row_number}"
                    for obs in observations
                ),
                "coinbase_scriptsig_hex": scriptsig_hex,
                "coinbase_outputs": coinbase_outputs,
                "btc_header_hex": header_hex,
                "notes": descendant_notes(validation_failures),
            }
        )

    # No consensus-invalid candidate can become an accepted stale descendant.
    # The disposable diagnostic carries both authenticated full-PoW violations
    # ready for canonical error-module review and inherited-invalid rows whose
    # incomplete or low-work evidence must be corrected first. Either blocks
    # the descendant transaction.
    descendant_rows, unpublishable_rows, error_block_rows = partition_ancestry_rows(
        ancestry_rows
    )
    for row in unpublishable_rows:
        block_hash = str(row["btc_header_hash"])
        example = unknown_example_by_hash[block_hash]
        anomalies.append(
            {
                "issue_type": "candidate_validation_failed",
                "severity": "error",
                "count": row["source_observation_count"],
                "chain": row["observed_chains"],
                "source_path": example.source_path,
                "row_number": example.row_number,
                "btc_header_hash": block_hash,
                "btc_prev_hash": row["btc_prev_hash"],
                "details": row["notes"],
            }
        )
    descendant_observation_rows = build_descendant_observation_rows(
        descendant_rows,
        unknown_observations_by_hash,
        data_dir=data_dir,
        parser=parser,
    )

    # The baseline is an evidence-coverage floor, so it is checked against every
    # computed row rather than the accepted subset: a committed hash that is now
    # an error candidate is still recovered, not lost. Losing it entirely, or
    # proving a committed VALID descendant consensus-invalid, remains a
    # regression and fails the run.
    if publication_baseline is not None:
        validate_publication_rows(
            ancestry_rows,
            descendant_observation_rows,
            publication_baseline,
            parser,
        )
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

    accepted_descendant_hashes = {
        row["btc_header_hash"]
        for row in descendant_rows
        if row["validation_status"] == "VALID_STALE_DESCENDANT"
    }
    error_candidate_hashes = {row["btc_header_hash"] for row in error_block_rows}

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
        "accepted_stale_descendant_hashes": len(accepted_descendant_hashes),
        "unpublishable_candidate_hashes": len(unpublishable_rows),
        "error_candidate_hashes": len(error_candidate_hashes),
        "parent_verdicts_csv": rel_fn(args.parent_verdicts_csv),
        "observations_csv": rel_fn(args.observations_csv),
        "error_candidates_csv": rel_fn(args.error_candidates_csv),
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
            "canonical_inventory_path",
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
    write_csv(args.parent_verdicts_csv, descendant_rows, PARENT_VERDICT_FIELDS)
    write_csv(
        args.observations_csv,
        descendant_observation_rows,
        list(OBSERVATION_FIELDS),
    )
    write_csv(
        args.error_candidates_csv,
        error_block_rows,
        ERROR_CANDIDATE_FIELDS,
    )
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
