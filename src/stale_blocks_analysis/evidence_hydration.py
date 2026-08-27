"""Header and child-identity hydration for normalized evidence rows."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .auxpow_chainid import hash_from_header_bytes
from .auxpow_parse import ChildHeaderValidationError
from .evidence_normalization import int_or_none, is_hash, normalize_hash
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
            stats.hydrated += 1
        else:
            if candidate:
                stats.hash_mismatch_rejected += 1
            stats.still_missing += 1
    return stats


# ── Live-chain child identity hydration ─────────────────────────────────
#
# Five active child chains (namecoin, rsk, syscoin, elastos, fractal) were
# recovered without child block identity: their artifacts carry the child
# HEIGHT but no child block hash or timestamp. Hathor is active too, but its
# API acquisition retains the source-authenticated child identity directly, so
# it does not need this separate sidecar. merge-mining-monitor
# keys live-captured events by (source, child_height, child_block_hash), so
# imported rows need the exact identity to deduplicate against live capture.
# scripts/extract/recover_child_identity.py recovers and node-verifies the
# identity per parent header from the still-reachable child nodes; the
# committed per-chain CSVs under data/child-identity/ are joined here by
# (chain, btc_header_hash). RSK rows additionally carry the fields the
# monitor's rsk_merge_mining_evidence sidecar requires; they are attached to
# the row and published only in the RSK export's extra columns.

CHILD_IDENTITY_DIR_NAME = "child-identity"

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


def load_child_identity(data_dir: Path) -> dict[tuple[str, str], dict[str, str]]:
    """Map ``(chain, btc_header_hash)`` -> verified child-identity row.

    Reads every ``data/child-identity/*_child_identity.csv``; a row is usable
    only when its ``verification`` is non-empty (node-verified), its
    ``child_height`` is a nonnegative integer, its ``child_block_hash`` is a
    well-formed 32-byte hex value, and its ``child_block_time`` is a positive
    integer. A verified-but-incomplete row (malformed or manually truncated
    sidecar) is dropped here, so the affected evidence rows surface as
    ``missing_identity`` downstream instead of hydrating blanks that defeat
    the publication gate.
    """
    identity_dir = data_dir / CHILD_IDENTITY_DIR_NAME
    if not identity_dir.is_dir():
        return {}
    identity: dict[tuple[str, str], dict[str, str]] = {}
    for path in sorted(identity_dir.glob("*_child_identity.csv")):
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
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
                chain = (row.get("chain") or "").strip()
                block_hash = normalize_hash(row.get("btc_header_hash"))
                if chain and is_hash(block_hash):
                    identity[(chain, block_hash)] = row
    return identity


@dataclass(slots=True)
class ChildIdentityStats:
    """Per-chain child-identity hydration coverage.

    ``targets`` is the number of rows considered (child hash empty, header
    hash well-formed); ``hydrated`` gained a verified identity;
    ``missing_identity`` / ``height_mismatch`` count NON-canonical rows left
    empty (fatal to a publication build: the monitor importer consumes these
    categories and skips rows without exact identity).
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
    identity: dict[tuple[str, str], dict[str, str]],
) -> ChildIdentityStats:
    """Fill empty child identity fields from verified recovery rows, in place.

    Targets every row for a chain in the separate hydration set
    (``CHILD_IDENTITY_HYDRATION_CHAINS``) regardless of whether the source
    prepopulated ``child_block_hash`` -- the
    node-verified sidecar is authoritative there, so a raw inventory's
    display-order hash is replaced and a missing identity still counts as a
    shortfall -- plus any other chain's empty-hash rows when identity data
    was loaded for it. The hydration set is targeted unconditionally so a
    missing, empty, or verification-less identity file surfaces as
    ``missing_identity`` instead of silently narrowing the target set. The
    identity row must agree on ``child_height``; a disagreement leaves the
    row untouched and is counted, so a stale identity file can never
    mislabel evidence. RSK sidecar fields ride along on the row dict and
    only reach output when the caller includes them in the export's field
    list.
    """
    stats = ChildIdentityStats()
    chains_with_identity = {chain for chain, _ in identity}
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
        candidate = identity.get((chain, block_hash))
        if candidate is None:
            if is_canonical_row:
                stats.canonical_unhydrated += 1
            else:
                stats.missing_identity += 1
            continue
        candidate_height = int_or_none(candidate.get("child_height"))
        row_height = int_or_none(row.get("child_height"))
        heights_agree = (
            candidate_height is not None
            and candidate_height >= 0
            and row_height is not None
            and row_height >= 0
            and candidate_height == row_height
        )
        if not heights_agree:
            if is_canonical_row:
                stats.canonical_unhydrated += 1
            else:
                stats.height_mismatch += 1
            continue
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
        # The node-verified identity is authoritative for live chains, so a
        # source-prepopulated hash is replaced with the verified value.
        row["child_block_hash"] = (candidate.get("child_block_hash") or "").strip()
        if not row.get("child_block_time"):
            row["child_block_time"] = (candidate.get("child_block_time") or "").strip()
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
