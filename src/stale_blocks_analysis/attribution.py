"""Pool attribution over this repo's recovered evidence. The census is not merged here.

Passes, in order: ``coinbase`` where identification produced a label, else
``unattributed``; then historical RSK ``pool_label`` on ``(height, hash)``,
never displacing coinbase (``rsk_historical`` is not a current result); then
``template_producer``, folded only for coinbase-derived labels. Export columns
are ``height,hash,source,pool,template_producer,attribution_basis,has_bin``.
``min_height`` is a plain floor; 0 means everything available.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from . import stale_blocks as _stale_loaders
from .data_source_provenance import clone_state, read_pinned_ref
from .config import (
    CANONICAL_ONLY_CHAINS,
    ACCEPTED_STALE_VALIDATION_STATUSES,
    BLOCKS_DIR,
    CHAIN_SPECS,
    CHAINS_BY_AUXPOW_ACTIVATION,
    ERROR_BLOCKS_CSV,
    ERROR_BLOCKS_MTP_CONTEXT_CSV,
    LOCAL_MINING_POOLS_DIR,
    PROJECT_ROOT,
    RESULTS_DIR,
    RSK_CSV,
    STALE_DESCENDANT_OBSERVATIONS_CSV,
    STALE_DESCENDANTS_CSV,
    STALE_DIR,
    VALIDATED_STALES_DIR,
)
from .pool_identification import pool_dataset_fingerprint, reset_runtime_pool_tables
from .stale_blocks import _LOADER_SPECS, load_stale_descendants
from .stale_merge import merge_stale_sources, tag_stale_blocks
from .template_producers import fold_template_producer

# Gitignored regenerable run product; see docs/pool-attribution.md.
ATTRIBUTIONS_CSV = (
    RESULTS_DIR / "analysis" / "pool-attribution" / "stale-block-attributions.csv"
)
ATTRIBUTIONS_CSV.parent.mkdir(parents=True, exist_ok=True)

# Consumers group on this vocabulary. A value outside it would split groups.
ATTRIBUTION_BASES = ("coinbase", "rsk_historical", "unattributed")

ATTRIBUTION_COLUMNS = [
    "height",
    "hash",
    "source",
    "pool",
    "template_producer",
    "attribution_basis",
    "has_bin",
]


def auxpow_loader_roster() -> list[tuple[str, Callable]]:
    """``CHAINS_BY_AUXPOW_ACTIVATION`` order. A new loader joins by name."""
    return [
        (key, getattr(_stale_loaders, f"load_{key.replace('-', '_')}_stales"))
        for key, _date in CHAINS_BY_AUXPOW_ACTIVATION
    ]


def apply_attribution_basis(stale: list[dict]) -> None:
    """``coinbase`` only when ``_pool_match`` produced the label.

    A caller-supplied label must already carry an ``attribution_basis``.
    """
    for s in stale:
        supplied = s.get("attribution_basis")
        if supplied:
            if supplied not in ATTRIBUTION_BASES:
                raise ValueError(
                    f"record ({s.get('height')}, {s.get('hash')}) carries "
                    f"attribution_basis {supplied!r}, which is not one of "
                    f"{', '.join(ATTRIBUTION_BASES)}"
                )
            labelled = bool(s.get("pool")) and s["pool"] != "Unknown"
            if labelled != (supplied != "unattributed"):
                raise ValueError(
                    f"record ({s.get('height')}, {s.get('hash')}) has "
                    f"pool={s.get('pool')!r} with "
                    f"attribution_basis={supplied!r}; an unattributed row "
                    "carries no pool label and a labelled row is never "
                    "unattributed"
                )
            continue
        match = s.get("_pool_match")
        if s.get("pool") and s["pool"] != "Unknown" and match is None:
            raise ValueError(
                f"pre-tagged record ({s.get('height')}, {s.get('hash')}) has "
                "no attribution_basis; callers that label records before "
                "tagging must also say what kind of evidence the label "
                "rests on"
            )
        identified = match in ("tag", "op_return", "address")
        s["attribution_basis"] = (
            "coinbase"
            if s.get("pool") and s["pool"] != "Unknown" and identified
            else "unattributed"
        )


def apply_rsk_historical_labels(stale: list[dict]) -> None:
    """Apply RSK ``pool_label`` as ``rsk_historical``, not a coinbase result.

    RSK does not expose the parent coinbase. The key is ``(height, hash)``,
    not the merged row's retained ``source``.
    """
    if not RSK_CSV.exists():
        return

    labels: dict[tuple[int, str], str] = {}
    with open(RSK_CSV, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("classification") != "stale":
                continue
            if (
                row.get("validation_status") or ""
            ) not in ACCEPTED_STALE_VALIDATION_STATUSES:
                continue
            label = (row.get("pool_label") or "").strip()
            # Registry sentinel "Unknown" stays unattributed.
            if not label or label == "Unknown":
                continue
            labels[(int(row["btc_height"]), row["btc_header_hash"])] = label

    n = 0
    for s in stale:
        # Coinbase evidence outranks the historical registry.
        if s.get("attribution_basis") == "coinbase":
            continue
        label = labels.get((s["height"], s["hash"]))
        if not label:
            continue
        s["pool"] = label
        s["attribution_basis"] = "rsk_historical"
        n += 1

    if n:
        print(
            f"  RSK historical miner-registry labels applied to {n} rows "
            "(historical evidence, not current attribution)"
        )


def apply_template_producers(stale: list[dict]) -> None:
    """Fold only ``attribution_basis=coinbase``. Historical and unattributed labels stay unfolded."""
    for s in stale:
        tag = s.get("pool") or "Unknown"
        # Address-only coinbase evidence names the tag owner and has no tag
        # to fold. Only scriptSig and OP_RETURN matches fold.
        if s.get("attribution_basis") == "coinbase" and s.get("_pool_match") in (
            "tag",
            "op_return",
        ):
            s["template_producer"] = fold_template_producer(tag, s["height"])
        else:
            s["template_producer"] = tag


def load_attributed_stales(
    min_height: int = 0, allow_partial: bool = False
) -> list[dict]:
    """This repo's loaders, descendants, and RSK observations. The census is not merged.

    ``min_height`` is a plain floor; 0 admits everything available.
    """
    require_committed_inputs()
    require_blocks_archive(allow_partial=allow_partial)
    # Rebuild pool tables so labels match the sidecar, even after a registry edit.
    reset_runtime_pool_tables()

    print("Loading merge-mining-recovered stale records ...")
    stale: list[dict] = []
    for key, loader in auxpow_loader_roster():
        rows = loader(min_height=min_height)
        if rows:
            print(f"  {len(rows)} {CHAIN_SPECS[key].display_name} stale blocks loaded")
            stale = merge_stale_sources(stale, rows)

    descendants = load_stale_descendants(min_height=min_height)
    if descendants:
        print(
            f"  {len(descendants)} stale descendants loaded (derived from unknown rows)"
        )
        stale = merge_stale_sources(stale, descendants)

    print("Parsing stale block binaries ...")
    stale = tag_stale_blocks(
        stale, allow_partial=allow_partial, archive_blobs=archive_blob_map()
    )
    rejected = sum(1 for s in stale if s.pop("_bin_rejected", False))
    n_bin = sum(1 for s in stale if s["has_bin"])
    print(f"  {n_bin} binaries parsed, {len(stale) - n_bin} without binary")

    apply_attribution_basis(stale)
    apply_rsk_historical_labels(stale)
    apply_template_producers(stale)

    # Provenance is this batch's inputs, not the state at a later write.
    batch = AttributedStales(stale)
    batch.min_height = min_height
    batch.provenance = _capture_provenance(allow_partial, rejected)
    return batch


def dump_attributions_csv(stale: list[dict], path: Path = ATTRIBUTIONS_CSV) -> None:
    """Project onto ``ATTRIBUTION_COLUMNS``. Working keys are not part of the export."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ATTRIBUTION_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for r in stale:
            writer.writerow({c: r.get(c) for c in ATTRIBUTION_COLUMNS})


def _repository_input_files() -> list[Path]:
    """Loader CSVs, descendant and error-block inputs, and every module here.

    Local edits change labels, so the sidecar hashes content, not just the commit.
    """
    files = sorted(VALIDATED_STALES_DIR.glob("*.csv"))
    files += [
        STALE_DESCENDANTS_CSV,
        STALE_DESCENDANT_OBSERVATIONS_CSV,
        ERROR_BLOCKS_CSV,
        ERROR_BLOCKS_MTP_CONTEXT_CSV,
    ]
    # Every module: a hand-listed subset goes stale as imports change.
    files += sorted(Path(__file__).resolve().parent.glob("*.py"))
    return files


def _repository_inputs_fingerprint(files: list[Path] | None = None) -> str:
    """SHA-256 of the export inputs. A missing file fails instead of leaving the digest."""
    h = hashlib.sha256()
    for f in files if files is not None else _repository_input_files():
        h.update(f.name.encode())
        h.update(f.read_bytes())
    return h.hexdigest()


def archive_blob_map() -> dict[str, str]:
    """Tracked blob name for each archived binary at the checkout's HEAD."""
    proc = subprocess.run(
        ["git", "-C", str(STALE_DIR), "ls-tree", "-r", "HEAD", "blocks/"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return {}
    blobs: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        meta, _, name = line.partition("\t")
        if name.endswith(".bin"):
            blobs[name.rsplit("/", 1)[-1]] = meta.split()[2]
    return blobs


def archive_inventory() -> tuple[set[str] | None, set[str]]:
    """HEAD names, not the index, so a staged deletion cannot shrink the manifest.

    Compared by name. ``None`` when the clone is not a git checkout.
    """
    present = {p.name for p in BLOCKS_DIR.glob("*.bin")}
    proc = subprocess.run(
        [
            "git",
            "-C",
            str(STALE_DIR),
            "ls-tree",
            "-r",
            "--name-only",
            "HEAD",
            "blocks/",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None, present
    expected = {
        line.rsplit("/", 1)[-1]
        for line in proc.stdout.splitlines()
        if line.endswith(".bin")
    }
    return expected, present


class AttributedStales(list):
    """A list plus the floor and input snapshot that produced it.

    Bound to the batch, so a second load cannot overwrite the first CSV's provenance.
    """

    # None means "not bound by a load": a batch a caller assembled itself
    # has no floor of its own, and zero is a real floor, not an absence.
    min_height: int | None = None
    provenance: dict | None = None


def _capture_provenance(allow_partial: bool, rejected: int = 0) -> dict:
    """Snapshot the state of every input this run reads."""
    expected_names, present_names = archive_inventory()
    missing = (
        sorted(expected_names - present_names) if expected_names is not None else []
    )
    return {
        "mining_pools": {
            "pinned_ref": read_pinned_ref(
                PROJECT_ROOT / "data-sources.tsv", "mining-pools"
            ),
            "state": clone_state(LOCAL_MINING_POOLS_DIR),
            "dataset_fingerprint": pool_dataset_fingerprint(),
        },
        "repository": {
            "state": clone_state(PROJECT_ROOT),
            "input_fingerprint": _repository_inputs_fingerprint(),
        },
        "stale_blocks": {
            "pinned_ref": read_pinned_ref(
                PROJECT_ROOT / "data-sources.tsv", "stale-blocks"
            ),
            "state": clone_state(STALE_DIR),
            "input_fingerprint": _stale_inputs_fingerprint(),
            "archive": {
                # An empty tracked inventory is not a verified archive.
                "verifiable": bool(expected_names),
                "expected": (
                    len(expected_names) if expected_names is not None else None
                ),
                "present": len(present_names),
                "missing": len(missing),
                # A rejected binary, or no manifest, is still a partial run.
                "rejected": rejected,
                "partial": bool(missing) or bool(rejected) or not expected_names,
                "allow_partial": allow_partial,
            },
        },
    }


def require_committed_inputs() -> None:
    """A missing CSV is indistinguishable from a real zero-row chain.

    ``CANONICAL_ONLY_CHAINS`` have no direct-stale artifact on purpose.
    """
    missing = [
        VALIDATED_STALES_DIR / f"{key}_validated_stales.csv"
        for key, _date in CHAINS_BY_AUXPOW_ACTIVATION
        if key not in CANONICAL_ONLY_CHAINS
        and not (VALIDATED_STALES_DIR / f"{key}_validated_stales.csv").exists()
    ]
    if not STALE_DESCENDANTS_CSV.exists():
        missing.append(STALE_DESCENDANTS_CSV)
    if not STALE_DESCENDANT_OBSERVATIONS_CSV.exists():
        missing.append(STALE_DESCENDANT_OBSERVATIONS_CSV)
    if not missing:
        # A truncated CSV also looks like a genuine zero-row chain.
        unreadable = []
        for key, _date in CHAINS_BY_AUXPOW_ACTIVATION:
            path = VALIDATED_STALES_DIR / f"{key}_validated_stales.csv"
            if key in CANONICAL_ONLY_CHAINS and not path.exists():
                continue
            # RSK has no spec; bitcoin-vault's key uses an underscore.
            spec = _LOADER_SPECS.get(key) or _LOADER_SPECS.get(key.replace("-", "_"))
            # Coinbase columns too: identity alone would still emit Unknown rows.
            required = {
                "classification",
                "validation_status",
                "coinbase_scriptsig_hex",
                "coinbase_outputs",
            }
            # Every chain is identified the same way; the spec only says
            # so explicitly where one exists.
            required |= (
                {spec.height_col, spec.hash_col}
                if spec is not None
                else {"btc_height", "btc_header_hash"}
            )
            if key == "rsk":
                required.add("pool_label")
            with open(path, newline="") as f:
                header = next(csv.reader(f), [])
            absent = sorted(required - set(header))
            if absent:
                unreadable.append(f"{path.name} (no {', '.join(absent)})")
        with open(STALE_DESCENDANTS_CSV, newline="") as f:
            descendant_header = set(next(csv.reader(f), []))
        descendant_absent = sorted(
            {
                "classification",
                "validation_status",
                "btc_height",
                "btc_header_hash",
                "coinbase_scriptsig_hex",
                "coinbase_outputs",
            }
            - descendant_header
        )
        if descendant_absent:
            unreadable.append(
                f"{STALE_DESCENDANTS_CSV.name} (no {', '.join(descendant_absent)})"
            )
        if unreadable:
            raise FileNotFoundError(
                f"{len(unreadable)} committed loader input(s) are present but "
                f"unreadable: {'; '.join(unreadable[:3])}. A truncated input "
                "silently shrinks the export instead of failing. Restore the "
                "file(s) from the checkout."
            )
    if missing:
        shown = ", ".join(p.name for p in missing[:3])
        raise FileNotFoundError(
            f"{len(missing)} committed attribution input(s) missing "
            f"(e.g. {shown}). A missing loader input is silently identical "
            "to a chain with no recovered stales, so it stops the run "
            "rather than shrinking the export. Restore the file(s) from the "
            "checkout."
        )


def require_blocks_archive(allow_partial: bool = False) -> None:
    """A missing binary silently downgrades that row to AuxPoW-only evidence.

    ``allow_partial`` continues and the sidecar records it.
    """
    expected, present = archive_inventory()
    if not present:
        raise FileNotFoundError(
            f"No block binaries under {BLOCKS_DIR} — run "
            "./scripts/fetch-data.sh to clone the pinned "
            "bitcoin-data/stale-blocks dataset. Its blocks/ binaries are a "
            "coinbase source for recovered headers; an empty or missing "
            "archive would silently produce weaker labels."
        )
    # No tracked binaries means there is no manifest to compare.
    if not expected and not allow_partial:
        raise FileNotFoundError(
            f"Cannot verify the block archive at {STALE_DIR}: it tracks no "
            "block binaries at HEAD, so there is no manifest to compare "
            "against and missing binaries would silently fall back to "
            "AuxPoW-only evidence. Run ./scripts/fetch-data.sh to fetch the "
            "pinned clone, or pass --allow-partial to attribute from an "
            "unverifiable archive (recorded in the meta sidecar)."
        )
    missing = sorted(expected - present) if expected is not None else []
    if missing and not allow_partial:
        shown = ", ".join(missing[:3])
        raise FileNotFoundError(
            f"Incomplete block archive: {len(missing)} of {len(expected)} "
            f"binaries tracked at the {STALE_DIR} checkout are absent "
            f"(e.g. {shown}). The missing ones would silently fall back to "
            "AuxPoW-only evidence. Run ./scripts/fetch-data.sh, or pass "
            "--allow-partial to attribute from what is present (recorded "
            "in the meta sidecar)."
        )


def _stale_inputs_fingerprint() -> str:
    """SHA-256 of the blocks/ binaries. Commit and dirty flag do not distinguish edits."""
    h = hashlib.sha256()
    if BLOCKS_DIR.is_dir():
        for f in sorted(BLOCKS_DIR.glob("*.bin")):
            h.update(f.name.encode())
            try:
                h.update(f.read_bytes())
            except OSError:
                # Distinct from an absent file and from an empty one.
                h.update(b"<unreadable>")
    return h.hexdigest()


def write_attribution_meta(
    stale: list[dict],
    csv_path: Path,
    min_height: int = 0,
    allow_partial: bool = False,
) -> Path:
    """Pin, commit, dirty flag, and content fingerprints for the working-tree inputs."""
    # The batch knows what produced it; the arguments are the fallback for
    # a caller that assembled records itself.
    provenance = getattr(stale, "provenance", None) or _capture_provenance(
        allow_partial
    )
    batch_floor = getattr(stale, "min_height", None)
    if batch_floor is not None:
        min_height = batch_floor
    # The sidecar hashes this CSV so a mixed pair is detectable.
    meta = {
        "artifact": {
            "csv_name": csv_path.name,
            "csv_sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
        },
        "min_height": min_height,
        "rows": len(stale),
        "attribution_basis_counts": dict(
            sorted(Counter(s.get("attribution_basis") for s in stale).items())
        ),
        **provenance,
    }
    meta_path = csv_path.with_suffix(".meta.json")
    with open(meta_path, "w", newline="") as f:
        json.dump(meta, f, indent=2, sort_keys=True)
        f.write("\n")
    return meta_path


def _warn_on_unpinned_registry(meta_path: Path) -> None:
    """Surface a registry that is not the clean committed pin on stderr."""
    meta = json.loads(meta_path.read_text())
    pools = meta["mining_pools"]
    state = pools.get("state")
    pin = pools.get("pinned_ref")
    if state is None:
        print(
            "WARNING: mining-pools clone absent or Git metadata unavailable; "
            "labels are not traceable to the committed pin.",
            file=sys.stderr,
        )
        return
    if state.get("dirty") or (pin and state.get("commit") != pin):
        print(
            "WARNING: mining-pools clone is not the clean committed pin "
            f"(pin {pin}, actual {state.get('commit')}, "
            f"dirty={state.get('dirty')}); labels reflect the working tree "
            "recorded in the .meta.json sidecar, not the pin.",
            file=sys.stderr,
        )


def publish_attribution_artifacts(
    stale: list[dict],
    csv_path: Path,
    min_height: int = 0,
    allow_partial: bool = False,
) -> tuple[Path, Path]:
    """Stage both files and replace them only after both succeed.

    The sidecar's CSV hash makes an interrupted mixed pair detectable.
    """
    batch_floor = getattr(stale, "min_height", None)
    if batch_floor is not None:
        min_height = batch_floor
    meta_path = csv_path.with_suffix(".meta.json")
    staging = csv_path.parent / f".{csv_path.stem}.staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    try:
        staged_csv = staging / csv_path.name
        dump_attributions_csv(stale, staged_csv)
        staged_meta = write_attribution_meta(
            stale, staged_csv, min_height, allow_partial
        )
        staged_csv.replace(csv_path)
        staged_meta.replace(meta_path)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return csv_path, meta_path


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=(
            "Build the per-stale-block pool-attribution export "
            "(see docs/pool-attribution.md for the column contract)."
        )
    )
    ap.add_argument(
        "--min-height",
        type=int,
        default=0,
        help=(
            "height floor passed to every loader; the default of 0 admits "
            "everything available, and analysis-side callers supply their own"
        ),
    )
    ap.add_argument(
        "--allow-partial",
        action="store_true",
        help=(
            "attribute from an incomplete block archive; missing binaries "
            "fall back to AuxPoW-only evidence and the sidecar records it"
        ),
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=ATTRIBUTIONS_CSV,
        help=f"output CSV path (default: {ATTRIBUTIONS_CSV})",
    )
    return ap


def main() -> None:
    args = _build_arg_parser().parse_args()

    try:
        stale = load_attributed_stales(
            min_height=args.min_height, allow_partial=args.allow_partial
        )
    except (FileNotFoundError, ValueError) as exc:
        sys.exit(str(exc))
    csv_path, meta_path = publish_attribution_artifacts(
        stale, args.output, args.min_height, args.allow_partial
    )
    print(f"CSV  -> {csv_path}")
    print(f"Meta -> {meta_path}")
    _warn_on_unpinned_registry(meta_path)

    pools = {s.get("pool") or "Unknown" for s in stale}
    n_rsk = sum(1 for s in stale if s.get("attribution_basis") == "rsk_historical")
    print(
        f"  {len(stale)} rows, {len(pools)} distinct pools, "
        f"{n_rsk} RSK historical labels"
    )


if __name__ == "__main__":
    main()
