"""Evidence-source discovery contracts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .config import CHAIN_SPECS, DATA_DIR


@dataclass(frozen=True, slots=True)
class EvidenceSource:
    chain: str
    display_name: str
    path: Path | None
    source_kind: str
    artifact_scope: str
    provenance: str


def normalize_chain_archive_dirs(chain_archive_dirs: Iterable[Path] = ()) -> list[Path]:
    """Normalize archive roots to their `chains/` directory when present."""
    roots: list[Path] = []
    for root in chain_archive_dirs:
        if not root:
            continue
        expanded = root.expanduser()
        chains_root = expanded / "chains"
        roots.append(chains_root if chains_root.is_dir() else expanded)
    return roots


def archive_candidates(root: Path, chain: str, suffix: str, family: str) -> list[Path]:
    """Candidate paths for ``<chain>_<suffix>.csv`` under an archive root.

    Checks the per-chain ``family`` subdirectory (``classified/`` or
    ``validated/``), the chain directory itself, then the root.
    """
    return [
        root / chain / family / f"{chain}_{suffix}.csv",
        root / chain / f"{chain}_{suffix}.csv",
        root / f"{chain}_{suffix}.csv",
    ]


_ARCHIVE_FULL_INVENTORY_OVERRIDES: dict[str, tuple[Path, ...]] = {
    # Doichain's authoritative full inventory has a nonstandard archive
    # location. The file in ``classified/`` is the intentionally header-only
    # publication output, while this dated artifact contains all 50,621 rows.
    "doichain": (Path("2026-06-24-redo/doichain_stale_blocks.csv"),),
}


def archive_full_inventory_candidates(root: Path, chain: str) -> list[Path]:
    """Return full-inventory candidates, honoring explicit archive layouts."""
    overrides = [
        root / chain / relative
        for relative in _ARCHIVE_FULL_INVENTORY_OVERRIDES.get(chain, ())
    ]
    return overrides + archive_candidates(root, chain, "stale_blocks", "classified")


def first_existing(paths: Iterable[Path]) -> Path | None:
    """Return the first path that exists, else None."""
    for path in paths:
        if path.exists():
            return path
    return None


def discover_evidence_sources(
    data_dir: Path = DATA_DIR,
    chain_archive_dirs: Iterable[Path] = (),
) -> dict[str, EvidenceSource]:
    """Discover the best available evidence source for every integrated chain."""
    archive_dirs = normalize_chain_archive_dirs(chain_archive_dirs)
    sources: dict[str, EvidenceSource] = {}
    for chain, spec in CHAIN_SPECS.items():
        archive_full: list[Path] = []
        archive_validated: list[Path] = []
        for root in archive_dirs:
            archive_full.extend(archive_full_inventory_candidates(root, chain))
            archive_validated.extend(
                archive_candidates(root, chain, "validated_stales", "validated")
            )

        full_path = first_existing(archive_full)
        if full_path is None:
            full_path = data_dir / f"{chain}_stale_blocks.csv"
            if not full_path.exists():
                full_path = None
        if full_path is not None:
            sources[chain] = EvidenceSource(
                chain=chain,
                display_name=spec.display_name,
                path=full_path,
                source_kind="full_inventory",
                artifact_scope="full_classifier_inventory",
                provenance="archive" if full_path in archive_full else "repo-data",
            )
            continue

        validated_path = first_existing(archive_validated)
        if validated_path is None:
            validated_path = (
                data_dir / "validated-stales" / f"{chain}_validated_stales.csv"
            )
            if not validated_path.exists():
                validated_path = None
        if validated_path is not None:
            sources[chain] = EvidenceSource(
                chain=chain,
                display_name=spec.display_name,
                path=validated_path,
                source_kind="validated_stales",
                artifact_scope="stale_only_publication",
                provenance="archive"
                if validated_path in archive_validated
                else "repo-data",
            )
        else:
            sources[chain] = EvidenceSource(
                chain=chain,
                display_name=spec.display_name,
                path=None,
                source_kind="missing",
                artifact_scope="missing",
                provenance="",
            )
    return sources


def discover_canonical_sources(
    data_dir: Path = DATA_DIR,
    chain_archive_dirs: Iterable[Path] = (),
) -> dict[str, EvidenceSource]:
    """Discover per-chain canonical-parent companions where they exist.

    Canonical parents are kept in a separate
    ``<chain>_canonical_blocks.csv`` artifact (written by ``run_classifier``;
    the same convention the private archive uses), so they are discovered
    independently of the stale/unknown inventory and merged into the exports.
    Only chains with an existing companion appear in the result. A
    never-split chain's inventory can already carry the same canonical rows
    as its companion (see i0coin), so callers merging this companion dedupe
    with ``dedupe_canonical_companion_rows``.
    """
    archive_dirs = normalize_chain_archive_dirs(chain_archive_dirs)
    sources: dict[str, EvidenceSource] = {}
    source_profiles = [
        (
            chain,
            spec.display_name,
            "canonical_blocks",
            "canonical_blocks",
            "",
        )
        for chain, spec in CHAIN_SPECS.items()
    ]
    source_profiles.append(
        (
            "vcash",
            "VCash",
            "wayback_canonical_hydration",
            "partial_canonical_subset",
            "wayback:vcash.tech/block + bitcoin-core:canonical",
        )
    )
    for chain, display_name, source_kind, artifact_scope, provenance in source_profiles:
        candidates: list[Path] = []
        for root in archive_dirs:
            candidates.extend(
                archive_candidates(root, chain, "canonical_blocks", "classified")
            )
        candidates.append(data_dir / f"{chain}_canonical_blocks.csv")
        path = first_existing(candidates)
        if path is None:
            continue
        sources[chain] = EvidenceSource(
            chain=chain,
            display_name=display_name,
            path=path,
            source_kind=source_kind,
            artifact_scope=artifact_scope,
            provenance=(
                provenance or ("repo-data" if path.parent == data_dir else "archive")
            ),
        )
    return sources


def discover_unknown_sources(
    data_dir: Path = DATA_DIR,
    chain_archive_dirs: Iterable[Path] = (),
) -> dict[str, EvidenceSource]:
    """Discover per-chain unknown companions where they exist.

    Unknown rows are split into a separate ``<chain>_unknown_blocks.csv``
    artifact (the classifier's shared writer), so they are discovered
    independently of the stale-only inventory and merged into the exports. A
    never-split chain has no unknown companion -- its unknowns stay in the
    commingled ``<chain>_stale_blocks.csv`` -- so only chains with an existing
    companion appear here. Rows carry ``source_kind="full_inventory"`` so
    ``collect_source_rows`` processes them exactly like the inventory's unknowns.
    """
    archive_dirs = normalize_chain_archive_dirs(chain_archive_dirs)
    sources: dict[str, EvidenceSource] = {}
    for chain, spec in CHAIN_SPECS.items():
        candidates: list[Path] = []
        for root in archive_dirs:
            candidates.extend(
                archive_candidates(root, chain, "unknown_blocks", "classified")
            )
        candidates.append(data_dir / f"{chain}_unknown_blocks.csv")
        path = first_existing(candidates)
        if path is None:
            continue
        sources[chain] = EvidenceSource(
            chain=chain,
            display_name=spec.display_name,
            path=path,
            source_kind="full_inventory",
            artifact_scope="full_classifier_inventory",
            provenance="repo-data" if path.parent == data_dir else "archive",
        )
    return sources


def stale_descendant_source(data_dir: Path) -> EvidenceSource | None:
    """Build the pseudo-chain source for ``data/stale_descendants.csv``.

    Returns None when the sidecar is absent. The descendants export uses
    the reserved chain key ``stale-descendants``.
    """
    path = data_dir / "stale_descendants.csv"
    if not path.exists():
        return None
    return EvidenceSource(
        chain="stale-descendants",
        display_name="Stale descendants",
        path=path,
        source_kind="stale_descendant_sidecar",
        artifact_scope="stale_descendant_sidecar",
        provenance="repo-data",
    )


# ── Namecoin header-hex hydration ───────────────────────────────────────
#
# Namecoin's committed validated input carries most, but not all, of the
# recovered 80-byte parent headers. Its strict/weak-orphan archive rows may
# also be headerless. The merge-mining-monitor refuses headerless rows at
# import because it PoW-validates every header, so hydrate only the missing
# `btc_header_hex` values from the Namecoin block.dat prototype extracts or
# private archive sources. A recovered header is written only when it verifies
# against the row's own `btc_header_hash`.
