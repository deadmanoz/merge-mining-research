"""Header and child-identity hydration for normalized evidence rows."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .auxpow_chainid import hash_from_header_bytes
from .auxpow_parse import ChildHeaderValidationError, validate_child_header_fields
from .config import CHAIN_SPECS
from .evidence_normalization import (
    int_or_none,
    is_hash,
    normalize_hash,
    reconcile_parent_header_fields,
)
from .evidence_sources import normalize_chain_archive_dirs

NAMECOIN_CHAIN = "namecoin"


def load_namecoin_header_hexes(
    targets: set[str],
    candidate_paths: Iterable[Path],
) -> dict[str, str]:
    """Map ``btc_hash`` -> ``btc_header_hex`` for ``targets`` from prototype extracts.

    Reads the ``candidate_paths`` CSVs in order (by convention the namecoin
    ``*_blkdat_classified.csv`` then ``*_blkdat_candidates.csv`` extracts,
    which carry full 80-byte headers), recording each row's header hex keyed
    by its own ``btc_hash`` column and restricted to ``targets``. Missing
    files are skipped, and scanning stops early once every target hash is
    resolved, so an earlier path in the list wins when it covers the targets.
    Returns ``{block_hash: header_hex}`` for the resolved subset of ``targets``.

    This is a pure loader keyed by the source CSV's own ``btc_hash`` column;
    it does NOT check that a header hex actually hashes to that hash (the
    reconcile loader this was lifted from did not either). Callers that need a
    verified header must check it -- ``hydrate_namecoin_headers`` does.
    """
    if not targets:
        return {}
    out: dict[str, str] = {}
    for path in candidate_paths:
        if not path.exists():
            continue
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                h = normalize_hash(row.get("btc_hash", ""))
                header_hex = row.get("btc_header_hex", "").strip()
                if h in targets and header_hex:
                    out[h] = header_hex
        if len(out) == len(targets):
            break
    return out


def namecoin_header_candidate_paths(
    data_dir: Path,
    chain_archive_dirs: Iterable[Path] = (),
) -> list[Path]:
    """Ordered ``btc_header_hex`` recovery sources for namecoin, repo-local first.

    The repo-local ``data/prototype/`` pair takes precedence, then each
    normalized chain-archive root's ``namecoin/classified`` +
    ``namecoin/raw-extraction`` extract pair. ``load_namecoin_header_hexes``
    reads these in order and stops once every target is resolved, so the
    repo-local extracts win when they cover the targets.
    """
    paths = [
        data_dir / "prototype" / "namecoin_blkdat_classified.csv",
        data_dir / "prototype" / "namecoin_blkdat_candidates.csv",
    ]
    for root in normalize_chain_archive_dirs(chain_archive_dirs):
        paths.append(
            root / NAMECOIN_CHAIN / "classified" / "namecoin_blkdat_classified.csv"
        )
        paths.append(
            root / NAMECOIN_CHAIN / "raw-extraction" / "namecoin_blkdat_candidates.csv"
        )
    return paths


def verified_header_hex(header_hex: str, expected_display_hash: str) -> bool:
    """True if ``header_hex``'s 80-byte double-SHA256, reversed, is ``expected_display_hash``.

    ``expected_display_hash`` is a display-order (RPC-order) lowercase hex
    hash. A malformed hex string, a header shorter than 80 bytes, or any hash
    disagreement returns False, so a bad candidate header is never written.
    """
    try:
        raw = bytes.fromhex(header_hex)
    except ValueError:
        return False
    if len(raw) < 80:
        return False
    return hash_from_header_bytes(raw[:80])[::-1].hex() == expected_display_hash


@dataclass(slots=True)
class HydrationStats:
    """Per-run namecoin ``btc_header_hex`` hydration coverage.

    ``targets`` is the number of headerless namecoin rows considered;
    ``hydrated`` gained a verified header; ``hash_mismatch_rejected`` is the
    subset of ``still_missing`` whose candidate header was present but failed
    verification. ``sources_available`` records whether any candidate extract
    file existed at all, so a zero-source run is never silent.
    """

    targets: int = 0
    hydrated: int = 0
    still_missing: int = 0
    hash_mismatch_rejected: int = 0
    sources_available: bool = False

    def note(self) -> str:
        """One coverage line for a manifest/counts notes field; '' when no targets."""
        if not self.targets:
            return ""
        line = (
            "namecoin_header_hydration="
            f"hydrated:{self.hydrated}"
            f"/still_missing:{self.still_missing}"
            f"/hash_mismatch_rejected:{self.hash_mismatch_rejected}"
        )
        if not self.sources_available:
            line += "; no_namecoin_header_hydration_sources_found"
        return line


def hydrate_namecoin_headers(
    rows: list[dict[str, str]],
    candidate_paths: list[Path],
) -> HydrationStats:
    """Fill empty ``btc_header_hex`` on namecoin rows from recovered extracts, in place.

    Targets the namecoin rows whose ``btc_header_hex`` is empty but whose
    ``btc_header_hash`` is a well-formed hash, loads their headers via
    ``load_namecoin_header_hexes`` (lazily -- no files are read when there are
    no targets), and writes a header ONLY when it verifies against the row's
    hash (``verified_header_hex``). A candidate that is missing, malformed, or
    hashes to the wrong value is never written and is counted. The ``rows``
    list is mutated in place; returns the coverage stats.
    """
    stats = HydrationStats()
    target_rows = [
        row
        for row in rows
        if row.get("chain") == NAMECOIN_CHAIN
        and not row.get("btc_header_hex")
        and is_hash(normalize_hash(row.get("btc_header_hash", "")))
    ]
    if not target_rows:
        return stats
    stats.targets = len(target_rows)
    stats.sources_available = any(path.exists() for path in candidate_paths)
    target_hashes = {
        normalize_hash(row.get("btc_header_hash", "")) for row in target_rows
    }
    header_map = load_namecoin_header_hexes(target_hashes, candidate_paths)
    for row in target_rows:
        display_hash = normalize_hash(row.get("btc_header_hash", ""))
        candidate = header_map.get(display_hash)
        if candidate and verified_header_hex(candidate, display_hash):
            row["btc_header_hex"] = candidate
            reconcile_parent_header_fields(
                row,
                context=(
                    f"{row.get('chain') or NAMECOIN_CHAIN} evidence row "
                    f"{row.get('source_row_number') or '?'}"
                ),
            )
            stats.hydrated += 1
        else:
            if candidate:
                stats.hash_mismatch_rejected += 1
            stats.still_missing += 1
    return stats


# ── Child identity hydration ──────────────────────────────────────
#
# Generic per-chain ledgers under data/child-identity/ authenticate exact child
# events. They are grouped here by (chain, btc_header_hash), then resolved by
# authenticated child height/hash when one parent has multiple witnesses. The
# five active hydration chains (namecoin, rsk, syscoin, elastos, fractal) use
# identities recovered from their reachable nodes. Historical Devcoin and
# Ixcoin rows pin complete child headers authenticated from archive source rows;
# selected error witnesses also record independent RPC verification. Hathor
# retains source-authenticated identity directly in its acquisition artifact
# and needs no separate ledger.
# merge-mining-monitor keys events by
# (source, child_height, child_block_hash), so imported rows need the exact
# identity to deduplicate against live capture. RSK rows additionally carry the
# fields the monitor's rsk_merge_mining_evidence sidecar requires; they are
# attached to the row and published only in the RSK export's extra columns.

CHILD_IDENTITY_DIR_NAME = "child-identity"

CHILD_IDENTITY_CORE_FIELDS = [
    "chain",
    "btc_header_hash",
    "child_height",
    "child_block_hash",
    "child_block_time",
    "verification",
    "note",
    "child_header_hex",
    "child_nbits",
]

# The five active child chains whose evidence rows REQUIRE a separate recovered
# child identity: merge-mining-monitor keys their live-captured events by
# (source, child_height, child_block_hash), and its importer skips rows
# without exact identity. Hydration targets these chains unconditionally --
# a missing or empty identity file must surface as missing_identity, never
# silently narrow the target set.
CHILD_IDENTITY_HYDRATION_CHAINS = frozenset(
    {"namecoin", "rsk", "syscoin", "elastos", "fractal"}
)

# Hathor is also an active child chain and its published rows must carry the
# same complete identity before publication. Its acquisition already provides
# that identity, so it is checked here but is not a sidecar-hydration target.
CHILD_IDENTITY_REQUIRED_CHAINS = frozenset({*CHILD_IDENTITY_HYDRATION_CHAINS, "hathor"})

RSK_SIDECAR_EXPORT_FIELDS = [
    "rsk_miner",
    "merge_mining_hash",
    "is_uncle",
    "uncle_index",
    "uncle_parent_height",
    "rsk_merkle_proof",
    "rsk_coinbase_tail",
]


ChildIdentityParentKey = tuple[str, str]
ChildIdentityRow = dict[str, str]


class ChildIdentityIndex:
    """Authenticated child-event tuples grouped by their Bitcoin parent."""

    def __init__(self) -> None:
        self._by_parent: dict[ChildIdentityParentKey, list[ChildIdentityRow]] = {}
        self._by_event: dict[tuple[str, str, int, str], ChildIdentityRow] = {}

    def add(self, key: ChildIdentityParentKey, row: ChildIdentityRow) -> None:
        """Append one already-validated child event under ``key``."""
        self._by_parent.setdefault(key, []).append(row)
        child_height = int_or_none(row.get("child_height"))
        child_hash = normalize_hash(row.get("child_block_hash"))
        if child_height is not None and is_hash(child_hash):
            self._by_event[(key[0], key[1], child_height, child_hash)] = row

    def candidates(self, key: ChildIdentityParentKey) -> tuple[ChildIdentityRow, ...]:
        """Return every authenticated child event for one parent."""
        return tuple(self._by_parent.get(key, ()))

    def parent_keys(self) -> tuple[ChildIdentityParentKey, ...]:
        """Return the parent keys represented by this exact-event index."""
        return tuple(self._by_parent)

    def exact_event(
        self,
        chain: str,
        parent_hash: str,
        child_height: int,
        child_hash: str,
    ) -> ChildIdentityRow | None:
        """Return one validated exact child event, if present."""
        return self._by_event.get(
            (
                chain,
                normalize_hash(parent_hash),
                child_height,
                normalize_hash(child_hash),
            )
        )


def child_identity_candidates(
    identity: ChildIdentityIndex,
    chain: str,
    parent_hash: str,
) -> tuple[ChildIdentityRow, ...]:
    """Return every authenticated candidate for one chain and Bitcoin parent."""
    key = (chain, normalize_hash(parent_hash))
    return identity.candidates(key)


def load_child_identity(data_dir: Path) -> ChildIdentityIndex:
    """Index authenticated child events under ``(chain, btc_header_hash)``.

    Reads every ``data/child-identity/*_child_identity.csv``; a row is usable
    only when its ``verification`` names a non-empty authentication method, its
    ``child_height`` is a nonnegative integer, its ``child_block_hash`` is a
    well-formed 32-byte hex value, and its ``child_block_time`` is a positive
    integer. An authenticated-but-incomplete row (malformed or manually truncated
    sidecar) is dropped here, so the affected evidence rows surface as
    ``missing_identity`` downstream instead of hydrating blanks that defeat
    the publication gate.
    """
    identity = ChildIdentityIndex()
    identity_dir = data_dir / CHILD_IDENTITY_DIR_NAME
    if not identity_dir.is_dir():
        return identity
    event_parents: dict[tuple[str, int, str], tuple[str, Path, int]] = {}
    for path in sorted(identity_dir.glob("*_child_identity.csv")):
        with path.open(newline="") as f:
            for row_number, row in enumerate(csv.DictReader(f), start=2):
                chain = (row.get("chain") or "").strip()
                child_header = (row.get("child_header_hex") or "").strip()
                child_nbits = (row.get("child_nbits") or "").strip()
                if child_header or child_nbits:
                    try:
                        spec = CHAIN_SPECS.get(chain)
                        validate_child_header_fields(
                            row,
                            nbits_from_header=(
                                spec.child_nbits_from_header if spec else True
                            ),
                        )
                    except ChildHeaderValidationError as exc:
                        relationship = {
                            "child_header_hex does not match child_block_hash": (
                                "child_header_hex disagrees with child_block_hash; "
                                "child_block_hash disagrees with child_header_hex"
                            ),
                            "child_header_hex does not match child_block_time": (
                                "child_header_hex disagrees with child_block_time; "
                                "child_block_time disagrees with child_header_hex"
                            ),
                            "child header does not match child_nbits": (
                                "child_header_hex disagrees with child_nbits; "
                                "child_nbits disagrees with child_header_hex"
                            ),
                        }.get(str(exc), str(exc))
                        raise ChildHeaderValidationError(
                            f"{path}:{row_number}: {relationship}"
                        ) from exc
                if not (row.get("verification") or "").strip():
                    continue
                child_hash = (row.get("child_block_hash") or "").strip().lower()
                child_height = int_or_none(row.get("child_height"))
                child_time = (row.get("child_block_time") or "").strip()
                if (
                    child_height is None
                    or child_height < 0
                    or not is_hash(child_hash)
                    or not child_time.isdigit()
                ):
                    continue
                block_hash = normalize_hash(row.get("btc_header_hash"))
                if chain and is_hash(block_hash):
                    key = (chain, block_hash)
                    event = (chain, child_height, child_hash)
                    previous = event_parents.get(event)
                    if previous is not None:
                        previous_parent, previous_path, previous_row = previous
                        if previous_parent != block_hash:
                            raise ValueError(
                                f"{path}:{row_number}: child identity {event} is "
                                "assigned to multiple Bitcoin parents: "
                                f"{previous_parent} at {previous_path}:{previous_row} "
                                f"and {block_hash}"
                            )
                        raise ValueError(
                            f"{path}:{row_number}: duplicate child identity event "
                            f"{event} for {chain}:{block_hash}"
                        )
                    event_parents[event] = (block_hash, path, row_number)
                    identity.add(key, row)
    return identity


@dataclass(slots=True)
class ChildIdentityStats:
    """Per-chain child-identity hydration coverage.

    ``targets`` is the number of rows considered for a verified identity;
    ``hydrated`` gained or confirmed one. ``missing_identity`` and
    ``height_mismatch`` count NON-canonical rows that remain incomplete or
    retain an unmatched source event (fatal to a publication build: the
    monitor importer requires an exact identity for these categories).
    ``canonical_unhydrated`` counts canonical rows left empty. These rows are
    still emitted because canonical evidence is part of the publication set;
    the count records the source's child-identity limit without treating an
    absent optional identity join as contradictory evidence.
    """

    targets: int = 0
    hydrated: int = 0
    missing_identity: int = 0
    height_mismatch: int = 0
    canonical_unhydrated: int = 0

    def note(self) -> str:
        """One coverage line for a counts notes field; '' when no targets."""
        if not self.targets:
            return ""
        line = f"child_identity_hydration=hydrated:{self.hydrated}"
        if self.missing_identity:
            line += f"/missing_identity:{self.missing_identity}"
        if self.height_mismatch:
            line += f"/height_mismatch:{self.height_mismatch}"
        if self.canonical_unhydrated:
            line += f"/canonical_unhydrated:{self.canonical_unhydrated}"
        return line


def hydrate_child_identity(
    rows: list[dict[str, str]],
    identity: ChildIdentityIndex,
) -> ChildIdentityStats:
    """Fill empty child identity fields from verified recovery rows, in place.

    Targets every row for a chain in the separate hydration set
    (``CHILD_IDENTITY_HYDRATION_CHAINS``) regardless of whether the source
    prepopulated ``child_block_hash``. A populated normalized source hash is
    an exact-event selector and must match the node-verified sidecar (internal
    wire order for Bitcoin-family chains, forward order for RSK); a missing
    identity still counts as a shortfall. Other chains are targeted when their
    source hash is empty and identity data was loaded for them. The hydration
    set is targeted unconditionally so a missing, empty, or verification-less
    identity file surfaces as
    ``missing_identity`` instead of silently narrowing the target set. The
    identity row fills an explicitly unavailable source ``child_height`` but
    must agree with every populated source height. Multiple identities for one
    parent are selected only by a matching source child height or hash; an
    unresolved choice fails rather than substituting an arbitrary event. A
    disagreement leaves the row untouched and is counted, so a stale identity
    file can never mislabel authenticated evidence. RSK sidecar fields ride
    along on the row dict and only reach output when the caller includes them
    in the export's field list.
    """
    stats = ChildIdentityStats()
    chains_with_identity = {chain for chain, _ in identity.parent_keys()}
    for row in rows:
        chain = row.get("chain", "")
        if chain not in CHILD_IDENTITY_HYDRATION_CHAINS:
            if chain in CHILD_IDENTITY_REQUIRED_CHAINS:
                # Hathor's API acquisition is the authoritative identity
                # source. Do not replace it from a sidecar, but count an
                # incomplete non-canonical source row as a publication
                # shortfall so the monitor gate cannot silently drop it.
                if (row.get("classification") or "") != "canonical":
                    child_height = int_or_none(row.get("child_height"))
                    child_hash = normalize_hash(row.get("child_block_hash"))
                    child_time = (row.get("child_block_time") or "").strip()
                    identity_complete = (
                        child_height is not None
                        and child_height >= 0
                        and is_hash(child_hash)
                        and child_time.isdigit()
                        and int(child_time) > 0
                    )
                    if not identity_complete:
                        stats.targets += 1
                        stats.missing_identity += 1
                continue
            if row.get("child_block_hash"):
                # Chains outside the separate hydration set keep their
                # source-supplied identity untouched (the explicit-recovery
                # artifacts are authoritative for it).
                continue
            if chain not in chains_with_identity:
                continue
        block_hash = normalize_hash(row.get("btc_header_hash", ""))
        if not is_hash(block_hash):
            continue
        stats.targets += 1
        is_canonical_row = (row.get("classification") or "") == "canonical"
        candidates = child_identity_candidates(identity, chain, block_hash)
        if not candidates:
            if is_canonical_row:
                stats.canonical_unhydrated += 1
            else:
                stats.missing_identity += 1
            continue
        row_height_text = (row.get("child_height") or "").strip()
        row_height = int_or_none(row_height_text)
        matching_candidates = candidates
        if row_height_text:
            matching_candidates = tuple(
                candidate
                for candidate in matching_candidates
                if row_height is not None
                and row_height >= 0
                and int_or_none(candidate.get("child_height")) == row_height
            )
        source_child_hash_text = (row.get("child_block_hash") or "").strip()
        source_child_header_text = (row.get("child_header_hex") or "").strip()
        if source_child_hash_text:
            source_child_hash = normalize_hash(source_child_hash_text)
            matching_candidates = tuple(
                candidate
                for candidate in matching_candidates
                if normalize_hash(candidate.get("child_block_hash"))
                == source_child_hash
            )
        if not matching_candidates:
            if source_child_header_text:
                raise ChildHeaderValidationError(
                    f"{chain} child identity disagrees with the "
                    f"source-authenticated bundle for BTC header {block_hash}"
                )
            if is_canonical_row:
                stats.canonical_unhydrated += 1
            else:
                stats.height_mismatch += 1
            continue
        if len(matching_candidates) > 1:
            raise ValueError(
                "ambiguous authenticated child identity for "
                f"{chain}:{block_hash}; source row must identify the child "
                "event by height or hash"
            )
        candidate = matching_candidates[0]
        candidate_height = int_or_none(candidate.get("child_height"))
        candidate_height_valid = candidate_height is not None and candidate_height >= 0
        heights_agree = candidate_height_valid and (
            not row_height_text
            or (
                row_height is not None
                and row_height >= 0
                and candidate_height == row_height
            )
        )
        if not heights_agree:
            if is_canonical_row:
                stats.canonical_unhydrated += 1
            else:
                stats.height_mismatch += 1
            continue
        if not row_height_text:
            row["child_height"] = str(candidate_height)
        row_child_header = (row.get("child_header_hex") or "").strip()
        if row_child_header:
            row_child_hash = normalize_hash(row.get("child_block_hash"))
            candidate_hash = normalize_hash(candidate.get("child_block_hash"))
            row_child_time = (row.get("child_block_time") or "").strip()
            candidate_time = (candidate.get("child_block_time") or "").strip()
            if row_child_hash != candidate_hash or (
                row_child_time and row_child_time != candidate_time
            ):
                raise ChildHeaderValidationError(
                    f"{chain} child identity disagrees with the "
                    f"source-authenticated bundle for BTC header {block_hash}"
                )
            for field in ("child_header_hex", "child_nbits"):
                row_value = (row.get(field) or "").strip()
                candidate_value = (candidate.get(field) or "").strip()
                if row_value and candidate_value and row_value != candidate_value:
                    raise ChildHeaderValidationError(
                        f"{chain} child identity {field} disagrees with the "
                        f"source-authenticated bundle for BTC header {block_hash}"
                    )
        # The node-verified identity is authoritative for live chains. Its hash
        # fills a blank or repeats the exact source selector established above;
        # its timestamp replaces the source value. An authenticated source
        # header is retained when the identity source genuinely has no
        # Bitcoin-shaped header (for example RSK).
        row["child_block_hash"] = (candidate.get("child_block_hash") or "").strip()
        row["child_block_time"] = (candidate.get("child_block_time") or "").strip()
        for field in ("child_header_hex", "child_nbits"):
            candidate_value = (candidate.get(field) or "").strip()
            if candidate_value:
                row[field] = candidate_value
        if chain == "rsk":
            # Sidecar fields are an RSK-only extension; the explicit gate keeps
            # a stray sidecar-named column in another chain's identity file
            # from ever leaking into a non-RSK row.
            for field in RSK_SIDECAR_EXPORT_FIELDS:
                value = (candidate.get(field) or "").strip()
                if value:
                    row[field] = value
        stats.hydrated += 1
    return stats
