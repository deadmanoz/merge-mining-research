"""Per-stale-block pool attribution: assembly, evidence basis, and export.

This is the attribution layer's driver. It merges every per-chain
AuxPoW-recovered loader in `stale_blocks.py` plus the stale descendants,
tags each record with a mining pool, and records what kind of evidence
produced each label.

The scope is deliberately this repo's own recovered evidence. The upstream
census is not merged or labelled here: the combined census-plus-recovered
set is the stale-rate analysis's input, and the companion repo assembles it
from these same functions.

Acquisition and recovery stay free of pool attribution; this module is the
separate pass over already-loaded records described in
`docs/pool-attribution.md`.

Three passes run over the merged, tagged records, in order:

1. `attribution_basis` is set to `coinbase` where coinbase identification
   produced a real label, and `unattributed` otherwise.
2. Rows whose `(height, hash)` matches an accepted RSK stale observation
   are joined against the `pool_label` column of the committed
   `rsk_validated_stales.csv`, whose labels come from a historical
   miner-address registry rather than the BTC parent coinbase (RSK's proof
   does not expose it). The join key is `(height, hash)`, regardless of
   which source's row survived the merge, and never displaces a coinbase
   attribution. Labelled rows carry `attribution_basis=rsk_historical`
   so a consumer can always tell them apart: they are historical evidence,
   never a current attribution result.
3. `template_producer` is folded from the tag-owner label for
   coinbase-attributed rows, so every record carries both the tag owner and,
   where the measurement evidence supports it, the entity that actually
   built the template. Rows whose label is not coinbase-derived
   (`rsk_historical`, `unattributed`) carry their label unfolded: the fold
   table's evidence is coinbase-tag measurement and does not apply to them.

Export contract (`results/analysis/pool-attribution/stale-block-attributions.csv`,
a gitignored regenerable run product):

    height,hash,source,pool,template_producer,attribution_basis,has_bin

`attribution_basis` is one of `coinbase`, `rsk_historical`, or
`unattributed`.

`min_height` is a plain caller-supplied floor passed through to every loader.
It carries no windowing semantics of its own: the default of 0 means
"everything available", and analysis-side callers that need a narrower
population supply their own floor.

Depends on: config (CHAIN_SPECS, CHAINS_BY_AUXPOW_ACTIVATION, RESULTS_DIR,
RSK_CSV, BLOCKS_DIR), stale_blocks (per-chain loaders), stale_merge
(merge_stale_sources, tag_stale_blocks), template_producers
(fold_template_producer).
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
from .config import (
    BLOCKS_DIR,
    CHAIN_SPECS,
    CHAINS_BY_AUXPOW_ACTIVATION,
    ERROR_BLOCKS_CSV,
    ERROR_BLOCKS_MTP_CONTEXT_CSV,
    LOCAL_MINING_POOLS_DIR,
    PROJECT_ROOT,
    RESULTS_DIR,
    RSK_CSV,
    STALE_DESCENDANT_CORRECTIONS_CSV,
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

# The declared vocabulary of the attribution_basis column. Consumers group
# by it, so a caller-supplied value outside this set would silently break
# their grouping.
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
    """Per-chain stale loaders in CHAINS_BY_AUXPOW_ACTIVATION order.

    Derived from the public CHAIN_SPECS registry — new chains join the
    attribution export automatically when their loader lands in
    stale_blocks.py.
    """
    return [
        (key, getattr(_stale_loaders, f"load_{key.replace('-', '_')}_stales"))
        for key, _date in CHAINS_BY_AUXPOW_ACTIVATION
    ]


def apply_attribution_basis(stale: list[dict]) -> None:
    """Record whether coinbase identification produced a real pool label.

    Only labels that identification actually produced (the record carries a
    `_pool_match` from `tag_stale_blocks`) can become `coinbase`. A record
    labelled by the caller before tagging must also carry its own
    `attribution_basis`, which is preserved; without one there is no way to
    know what kind of evidence the label rests on, so that is an error
    rather than a guess.
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
    """Join the historical miner-registry `pool_label` onto RSK observations.

    RSK's merge-mining proof does not expose the BTC parent coinbase, so
    `load_rsk_stales` deliberately returns header identity only. The labels
    live in the committed loader input's `pool_label` column and are applied
    here, flagged as `rsk_historical` so they are never mistaken for a
    coinbase-derived attribution result.

    The join key is `(height, hash)`, the identity of the observed header,
    not the merged row's retained `source`: when an RSK-observed header also
    appears in the census or an earlier-activation chain, that primary
    row's source survives the merge, but the header was still accepted as
    an RSK stale observation and its historical label still applies.
    """
    if not RSK_CSV.exists():
        return

    labels: dict[tuple[int, str], str] = {}
    with open(RSK_CSV, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("classification") != "stale":
                continue
            if not (row.get("validation_status") or "").startswith("VALID"):
                continue
            label = (row.get("pool_label") or "").strip()
            # The registry column uses the literal sentinel "Unknown" for
            # rows its historical analysis could not attribute; treat it
            # like an empty label so those rows stay `unattributed`.
            if not label or label == "Unknown":
                continue
            labels[(int(row["btc_height"]), row["btc_header_hash"])] = label

    n = 0
    for s in stale:
        # A row can carry real coinbase evidence (its own binary, or a
        # coinbase grafted from another chain's observation of the same
        # header). Coinbase attribution outranks the historical registry,
        # so never overwrite it.
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
    """Fold coinbase-derived tag-owner labels into template-producer labels.

    The fold table's evidence is stratum-job and coinbase-tag measurement, so
    it applies only to rows whose label came from the coinbase
    (`attribution_basis=coinbase`). An `rsk_historical` label is a
    miner-address attribution with no coinbase behind it, so it is carried
    into `template_producer` unfolded rather than upgraded to a
    template-producer claim; unattributed rows carry "Unknown".
    """
    for s in stale:
        tag = s.get("pool") or "Unknown"
        # The fold's evidence is coinbase-TAG measurement, so it applies
        # only when the label came from an actual tag observation (scriptSig
        # or OP_RETURN); a payout-address-only identification is coinbase
        # evidence for the tag OWNER but observes no tag, so it is carried
        # unfolded.
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
    """Load, merge, tag, and attribute the merge-mining-recovered stales.

    The record set is this repo's own evidence: AuxPoW-recovered direct
    stales from every chain loader, the stale descendants, and RSK
    observations. The upstream census is NOT merged here; labelling the
    combined census-plus-recovered set is the stale-rate analysis's job,
    and the companion repo assembles it from these same functions.

    *min_height* is passed verbatim to every loader as a plain height floor;
    the default of 0 admits everything available.
    """
    require_committed_inputs()
    require_blocks_archive(allow_partial=allow_partial)
    # Rebuild the identification tables from disk so this run's labels match
    # the dataset state the meta sidecar records, even in a long-lived
    # process that edited the registry clone since the previous run.
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
    stale = tag_stale_blocks(stale, allow_partial=allow_partial)
    n_bin = sum(1 for s in stale if s["has_bin"])
    print(f"  {n_bin} binaries parsed, {len(stale) - n_bin} without binary")

    apply_attribution_basis(stale)
    apply_rsk_historical_labels(stale)
    apply_template_producers(stale)

    # Bind provenance to this batch. Publication can happen much later in a
    # library caller, by which time the registry or the archive may have
    # moved; the sidecar must describe the state that produced these
    # labels, not the state at write time.
    batch = AttributedStales(stale)
    batch.min_height = min_height
    batch.provenance = _capture_provenance(allow_partial)
    return batch


def dump_attributions_csv(stale: list[dict], path: Path = ATTRIBUTIONS_CSV) -> None:
    """Write the per-stale-block attribution export to *path*.

    Records carry working keys beyond the export contract (`_scriptsig_hex`
    and `_outputs_str` survive both the .bin tagging path and the duplicate
    graft in `merge_stale_sources`), so every row is projected onto the
    declared columns rather than handed to DictWriter as-is.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ATTRIBUTION_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for r in stale:
            writer.writerow({c: r.get(c) for c in ATTRIBUTION_COLUMNS})


def _repository_input_files() -> list[Path]:
    """The repository files whose content shapes the export.

    Data side: every committed loader CSV, the stale descendants and their
    correction overlay, and the error-blocks exclusion inputs. Code side:
    every module in this package. Two runs with the same commit but
    different local edits to any of these can produce different labels, so
    the sidecar fingerprints their content rather than relying on the
    commit-plus-dirty flag alone.
    """
    files = sorted(VALIDATED_STALES_DIR.glob("*.csv"))
    files += [
        STALE_DESCENDANTS_CSV,
        STALE_DESCENDANT_CORRECTIONS_CSV,
        ERROR_BLOCKS_CSV,
        ERROR_BLOCKS_MTP_CONTEXT_CSV,
    ]
    # Every module in the package, not a hand-listed subset: the loaders
    # reach helpers transitively (error_blocks, bitcoin_binary, ...), and a
    # curated list silently goes stale as those imports change.
    files += sorted(Path(__file__).resolve().parent.glob("*.py"))
    return files


def _repository_inputs_fingerprint(files: list[Path] | None = None) -> str:
    """SHA-256 over the repository files the export consumes."""
    h = hashlib.sha256()
    for f in files if files is not None else _repository_input_files():
        if f.exists():
            h.update(f.name.encode())
            h.update(f.read_bytes())
    return h.hexdigest()


def archive_inventory() -> tuple[set[str] | None, set[str]]:
    """Block-binary filenames tracked at HEAD, and those on disk.

    The tracked set is the only manifest of what a complete archive looks
    like. It is read from HEAD rather than the index so a staged deletion
    cannot shrink it, and compared by name rather than by count so an
    untracked stray cannot mask a missing binary. It is None when the clone
    is not a git checkout, where no manifest exists to compare against.
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
    """The attributed records, carrying what produced them.

    A plain list to every consumer, but it also remembers the height floor
    that bounded it and a snapshot of the inputs that were read. Binding
    those to the batch rather than to module state means a caller can load
    twice and publish either one without the second load's provenance
    landing on the first one's CSV.
    """

    # None means "not bound by a load": a batch a caller assembled itself
    # has no floor of its own, and zero is a real floor, not an absence.
    min_height: int | None = None
    provenance: dict | None = None


def _capture_provenance(allow_partial: bool) -> dict:
    """Snapshot the state of every input this run reads."""
    expected_names, present_names = archive_inventory()
    missing = (
        sorted(expected_names - present_names) if expected_names is not None else []
    )
    return {
        "mining_pools": {
            "pinned_ref": _pinned_ref("mining-pools"),
            "state": _clone_state(LOCAL_MINING_POOLS_DIR),
            "dataset_fingerprint": pool_dataset_fingerprint(),
        },
        "repository": {
            "state": _clone_state(PROJECT_ROOT),
            "input_fingerprint": _repository_inputs_fingerprint(),
        },
        "stale_blocks": {
            "pinned_ref": _pinned_ref("stale-blocks"),
            "state": _clone_state(STALE_DIR),
            "input_fingerprint": _stale_inputs_fingerprint(),
            "archive": {
                # An empty tracked inventory proves nothing about what
                # should be present, so it is not a verified archive.
                "verifiable": bool(expected_names),
                "expected": (
                    len(expected_names) if expected_names is not None else None
                ),
                "present": len(present_names),
                "missing": len(missing),
                "partial": bool(missing),
                "allow_partial": allow_partial,
            },
        },
    }


def require_committed_inputs() -> None:
    """Stop when a committed loader input is absent.

    A missing CSV makes its loader return no rows, which is
    indistinguishable in the export from a chain that genuinely recovered
    no stales (several chains legitimately have zero-row inputs). Presence
    is therefore checked before loading rather than inferred from counts.
    """
    missing = [
        VALIDATED_STALES_DIR / f"{key}_validated_stales.csv"
        for key, _date in CHAINS_BY_AUXPOW_ACTIVATION
        if not (VALIDATED_STALES_DIR / f"{key}_validated_stales.csv").exists()
    ]
    if not STALE_DESCENDANTS_CSV.exists():
        missing.append(STALE_DESCENDANTS_CSV)
    if not missing:
        # Presence is not enough: a zero-byte or header-truncated CSV
        # yields no rows and is indistinguishable in the export from a
        # chain that genuinely recovered none.
        unreadable = []
        for key, _date in CHAINS_BY_AUXPOW_ACTIVATION:
            path = VALIDATED_STALES_DIR / f"{key}_validated_stales.csv"
            spec = _LOADER_SPECS.get(key)
            # Every column an attribution path actually consumes, not just
            # the identity ones: a CSV that keeps its identity columns but
            # loses the coinbase evidence still yields rows, silently
            # weakened to Unknown.
            required = {
                "classification",
                "validation_status",
                "coinbase_scriptsig_hex",
                "coinbase_outputs",
            }
            if spec is not None:
                required |= {spec.height_col, spec.hash_col}
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
    """Stop when the fetched blocks/ archive is missing or incomplete.

    The census clone's raw blocks are a coinbase source for recovered
    headers, and a binary that is merely absent downgrades that row to
    AuxPoW-only evidence without any visible failure. Both the CLI and
    library callers (the companion analysis repo) check this before
    assembling a record set. *allow_partial* attributes from whatever is
    present, which the meta sidecar then records.
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
    # An empty tracked inventory is not a complete archive: a checkout that
    # tracks no binaries tells us nothing about what should be present.
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
    """SHA-256 over the consumed stale-blocks input (the blocks/ binaries).

    The raw blocks are the only part of the stale-blocks clone this export
    reads (as a coinbase source for recovered headers the census also
    archived). The clone is as editable as the registry clone, and the
    commit + dirty flag alone cannot distinguish two different working-tree
    edits. The run already reads every matching binary, so hashing them
    costs comparably to the export itself.
    """
    h = hashlib.sha256()
    if BLOCKS_DIR.is_dir():
        for f in sorted(BLOCKS_DIR.glob("*.bin")):
            h.update(f.name.encode())
            h.update(f.read_bytes())
    return h.hexdigest()


def _clone_state(path: Path) -> dict | None:
    """Commit and dirty state of a fetched clone; None when absent/not git."""
    if not (path / ".git").exists():
        return None

    def _git(*args: str) -> str | None:
        proc = subprocess.run(
            ["git", "-C", str(path), *args], capture_output=True, text=True
        )
        return proc.stdout.strip() if proc.returncode == 0 else None

    commit = _git("rev-parse", "HEAD")
    status = _git("status", "--porcelain")
    return {"commit": commit, "dirty": bool(status)}


def _pinned_ref(key: str) -> str | None:
    """The commit pinned for *key* in the committed data-sources.tsv."""
    manifest = PROJECT_ROOT / "data-sources.tsv"
    if not manifest.exists():
        return None
    for line in manifest.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) == 4 and fields[0] == key:
            return fields[2]
    return None


def write_attribution_meta(
    stale: list[dict],
    csv_path: Path,
    min_height: int = 0,
    allow_partial: bool = False,
) -> Path:
    """Record the dataset state the export was produced from.

    The registry is read from its working tree on every run (a local fork is
    a supported workflow), so an export is reproducible only together with
    the registry state that produced it. The sidecar records the pinned and
    actual commits, the dirty flag, and the content fingerprint of the pool
    dataset, plus the same for the stale-blocks clone and the per-basis row
    counts.
    """
    # The batch knows what produced it; the arguments are the fallback for
    # a caller that assembled records itself.
    provenance = getattr(stale, "provenance", None) or _capture_provenance(
        allow_partial
    )
    batch_floor = getattr(stale, "min_height", None)
    if batch_floor is not None:
        min_height = batch_floor
    # The sidecar describes a specific CSV, so it carries that CSV's own
    # hash. Publishing two files can never be one atomic act, but this
    # makes a mismatched pair detectable by any consumer rather than
    # silently believable.
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
            "WARNING: mining-pools clone not found or not a git checkout; "
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
    """Write the export and its sidecar, replacing the previous pair together.

    Both files are built in a staging directory and moved into place only
    once both succeed, so a failed run cannot leave a half-written pair.
    This mirrors the staged-artifact rule the monitor-evidence build
    already follows.

    Two files cannot be swapped in one atomic act, so the sidecar also
    carries the CSV's own hash: a reader that finds a mismatch knows it is
    looking at a mixed pair from an interrupted rerun, rather than
    trusting provenance that describes different labels.
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
