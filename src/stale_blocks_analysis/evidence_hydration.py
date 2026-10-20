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
from .rsk_sidecar import (
    RSK_SIDECAR_EXPORT_FIELDS,
    RSK_SOURCE_BUNDLE_MARKER,
    validate_rsk_sidecar_cells,
)

NAMECOIN_CHAIN = "namecoin"


def load_namecoin_header_hexes(
    targets: set[str],
    candidate_paths: Iterable[Path],
) -> dict[str, str]:
    """Earlier paths win. Does not check that the header hashes to ``btc_hash``.

    ``hydrate_namecoin_headers`` verifies before writing.
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
    """Repo-local ``data/prototype/`` first, then each archive's classified and raw pair."""
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
    """Display-order SHA256d of the first 80 bytes. A bad candidate is False, never written."""
    try:
        raw = bytes.fromhex(header_hex)
    except ValueError:
        return False
    if len(raw) < 80:
        return False
    return hash_from_header_bytes(raw[:80])[::-1].hex() == expected_display_hash


@dataclass(slots=True)
class HydrationStats:
    """``hash_mismatch_rejected`` is a present header that failed verification.

    ``sources_available`` keeps a zero-source run from looking like a clean miss.
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
    """Write a header only when it verifies. A mismatch is counted and not written."""
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


# Grouped by (chain, btc_header_hash), then by child height/hash.
# Monitor dedup is (source, child_height, child_block_hash). RSK sidecar
# fields publish only in the RSK export. Hathor keeps its acquisition identity.

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

# Monitor ``UNIQUE (source_id, child_block_hash)`` skips rows without identity.
# A missing file is ``missing_identity``, not a smaller target set.
CHILD_IDENTITY_HYDRATION_CHAINS = frozenset(
    {"namecoin", "rsk", "syscoin", "elastos", "fractal"}
)

# Hathor is required at publication but is not a sidecar-hydration target.
CHILD_IDENTITY_REQUIRED_CHAINS = frozenset({*CHILD_IDENTITY_HYDRATION_CHAINS, "hathor"})


def _validate_rsk_sidecar_bundle(row: dict[str, str], *, row_id: str) -> None:
    """Require one complete, monitor-importable RSK sidecar bundle."""
    try:
        validate_rsk_sidecar_cells(row, row_id=row_id)
    except ValueError as exc:
        raise ChildHeaderValidationError(str(exc)) from exc


def _apply_rsk_sidecar_bundle(
    row: dict[str, str], candidate: dict[str, str], block_hash: str
) -> None:
    """Check agreement before replacing an exact RSK event's whole bundle."""
    _validate_rsk_sidecar_bundle(
        candidate, row_id=f"rsk child-identity BTC header {block_hash}"
    )
    for field in RSK_SIDECAR_EXPORT_FIELDS:
        source_value = (row.get(field) or "").strip()
        candidate_value = (candidate.get(field) or "").strip()
        if source_value and source_value != candidate_value:
            raise ChildHeaderValidationError(
                f"rsk {field} disagrees with source bundle for BTC header {block_hash}"
            )
    for field in (
        "child_height",
        "child_block_hash",
        "child_block_time",
        *RSK_SIDECAR_EXPORT_FIELDS,
    ):
        row[field] = (candidate.get(field) or "").strip()


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
    """Usable rows have a verification method, nonnegative height, 32-byte hash, and positive time.

    An authenticated but incomplete row is dropped so it surfaces as ``missing_identity``.
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
                    or not child_time.isascii()
                    or not child_time.isdigit()
                    or int(child_time) <= 0
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
    """``missing_identity`` and ``height_mismatch`` are fatal for non-canonical rows.

    Empty canonical rows are still emitted. That count is not a contradiction.
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
    """Hydrate ``CHILD_IDENTITY_HYDRATION_CHAINS`` in place. A missing file is a shortfall.

    A source hash is an exact selector: internal/wire order for Bitcoin-family
    chains, forward order for RSK. An ambiguous parent fails rather than
    picking an event. Bitcoin-family disagreements leave the row untouched.
    RSK disagreements raise ``ChildHeaderValidationError``. A complete fresh
    RSK bundle is not a target unless a matching sidecar exists.
    """
    stats = ChildIdentityStats()
    chains_with_identity = {chain for chain, _ in identity.parent_keys()}
    for row in rows:
        chain = row.get("chain", "")
        if chain not in CHILD_IDENTITY_HYDRATION_CHAINS:
            if chain in CHILD_IDENTITY_REQUIRED_CHAINS:
                # Hathor's acquisition identity is not replaced. An incomplete
                # non-canonical row is still a publication shortfall.
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
                # Explicit-recovery artifacts stay authoritative outside the hydration set.
                continue
            if chain not in chains_with_identity:
                continue
        block_hash = normalize_hash(row.get("btc_header_hash", ""))
        if not is_hash(block_hash):
            continue
        is_canonical_row = (row.get("classification") or "") == "canonical"
        candidates = child_identity_candidates(identity, chain, block_hash)
        source_child_height = int_or_none(row.get("child_height"))
        source_rsk_bundle = chain == "rsk" and row.get(RSK_SOURCE_BUNDLE_MARKER) == "1"
        source_rsk_identity_complete = (
            source_rsk_bundle
            and source_child_height is not None
            and source_child_height >= 0
            and is_hash(normalize_hash(row.get("child_block_hash")))
            and (row.get("child_block_time") or "").strip().isascii()
            and (row.get("child_block_time") or "").strip().isdigit()
            and int((row.get("child_block_time") or "0").strip()) > 0
        )
        if source_rsk_bundle:
            if not source_rsk_identity_complete:
                raise ChildHeaderValidationError(
                    f"rsk source bundle lacks complete child identity for "
                    f"BTC header {block_hash}"
                )
            _validate_rsk_sidecar_bundle(
                row, row_id=f"rsk source bundle BTC header {block_hash}"
            )
            exact_candidates = tuple(
                candidate
                for candidate in candidates
                if int_or_none(candidate.get("child_height")) == source_child_height
                and normalize_hash(candidate.get("child_block_hash"))
                == normalize_hash(row.get("child_block_hash"))
            )
            if not exact_candidates:
                continue
            candidate = exact_candidates[0]
            candidate_time = (candidate.get("child_block_time") or "").strip()
            source_time = (row.get("child_block_time") or "").strip()
            # Same height and hash with a different timestamp is a conflict.
            if candidate_time != source_time:
                raise ChildHeaderValidationError(
                    f"rsk child time disagrees with source bundle for BTC header {block_hash}"
                )
            _apply_rsk_sidecar_bundle(row, candidate, block_hash)
            stats.targets += 1
            stats.hydrated += 1
            continue

        stats.targets += 1
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
        if chain == "rsk":
            candidate_hash = normalize_hash(candidate.get("child_block_hash"))
            source_hash = normalize_hash(row.get("child_block_hash"))
            candidate_time = (candidate.get("child_block_time") or "").strip()
            source_time = (row.get("child_block_time") or "").strip()
            if (
                not heights_agree
                or not is_hash(candidate_hash)
                or not candidate_time.isascii()
                or not candidate_time.isdigit()
                or int(candidate_time) <= 0
                or (source_hash and candidate_hash != source_hash)
                or (source_time and candidate_time != source_time)
            ):
                raise ChildHeaderValidationError(
                    f"rsk child identity disagrees with source bundle "
                    f"for BTC header {block_hash}"
                )
            _apply_rsk_sidecar_bundle(row, candidate, block_hash)
            stats.hydrated += 1
            continue
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
        # Node-verified hash fills a blank or repeats the source selector.
        # Its timestamp replaces the source value. A source header stays when
        # the identity row has none.
        row["child_block_hash"] = (candidate.get("child_block_hash") or "").strip()
        row["child_block_time"] = (candidate.get("child_block_time") or "").strip()
        for field in ("child_header_hex", "child_nbits"):
            candidate_value = (candidate.get(field) or "").strip()
            if candidate_value:
                row[field] = candidate_value
        stats.hydrated += 1
    return stats
