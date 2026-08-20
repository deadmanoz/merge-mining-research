"""Per-stale-block pool attribution: assembly, evidence basis, and export.

This is the attribution layer's driver. It loads the upstream
bitcoin-data/stale-blocks baseline, merges every per-chain AuxPoW-recovered
loader in `stale_blocks.py` plus the stale descendants over it, tags each
record with a mining pool, and records which evidence path produced each
label. Acquisition and recovery stay free of pool attribution; this module is
the separate pass over already-loaded records described in
`docs/pool-attribution.md`.

Three passes run over the merged, tagged records, in order:

1. `attribution_basis` is set to `coinbase` where coinbase identification
   produced a real label, and `unattributed` otherwise.
2. RSK rows are re-joined against the `pool_label` column of the committed
   `rsk_validated_stales.csv`, whose labels come from a historical
   miner-address registry rather than the BTC parent coinbase (RSK's proof
   does not expose it). Those rows carry `attribution_basis=rsk_historical`
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
RSK_CSV, STALE_CSV), stale_blocks (per-chain loaders), stale_merge
(merge_stale_sources, tag_stale_blocks), template_producers
(fold_template_producer).
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections.abc import Callable
from pathlib import Path

from . import stale_blocks as _stale_loaders
from .config import (
    CHAIN_SPECS,
    CHAINS_BY_AUXPOW_ACTIVATION,
    RESULTS_DIR,
    RSK_CSV,
    STALE_CSV,
)
from .stale_blocks import load_stale_csv, load_stale_descendants
from .stale_merge import merge_stale_sources, tag_stale_blocks
from .template_producers import fold_template_producer

# Gitignored regenerable run product; see docs/pool-attribution.md.
ATTRIBUTIONS_CSV = (
    RESULTS_DIR / "analysis" / "pool-attribution" / "stale-block-attributions.csv"
)
ATTRIBUTIONS_CSV.parent.mkdir(parents=True, exist_ok=True)

ATTRIBUTION_COLUMNS = [
    "height",
    "hash",
    "source",
    "pool",
    "template_producer",
    "attribution_basis",
    "has_bin",
]


def _auxpow_loader_roster() -> list[tuple[str, Callable]]:
    """Per-chain stale loaders in CHAINS_BY_AUXPOW_ACTIVATION order.

    Derived from the public CHAIN_SPECS registry — new chains join the
    attribution export automatically when their loader lands in
    stale_blocks.py.
    """
    return [
        (key, getattr(_stale_loaders, f"load_{key.replace('-', '_')}_stales"))
        for key, _date in CHAINS_BY_AUXPOW_ACTIVATION
    ]


def _apply_attribution_basis(stale: list[dict]) -> None:
    """Record whether coinbase identification produced a real pool label."""
    for s in stale:
        s["attribution_basis"] = (
            "coinbase" if s.get("pool") and s["pool"] != "Unknown" else "unattributed"
        )


def _apply_rsk_historical_labels(stale: list[dict]) -> None:
    """Re-join RSK rows against the historical miner-registry `pool_label`.

    RSK's merge-mining proof does not expose the BTC parent coinbase, so
    `load_rsk_stales` deliberately returns header identity only. The labels
    live in the committed loader input's `pool_label` column and are applied
    here, flagged as `rsk_historical` so they are never mistaken for a
    coinbase-derived attribution result.
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
        if s.get("source") != "rsk":
            continue
        # An RSK-sourced row can still gain real coinbase evidence when a
        # later-activating chain witnessed the same header and the merge
        # grafted its coinbase. Coinbase attribution outranks the historical
        # registry, so never overwrite it.
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


def _apply_template_producers(stale: list[dict]) -> None:
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
        if s.get("attribution_basis") == "coinbase":
            s["template_producer"] = fold_template_producer(tag, s["height"])
        else:
            s["template_producer"] = tag


def load_attributed_stales(min_height: int = 0) -> list[dict]:
    """Load, merge, tag, and attribute every available stale-block record.

    *min_height* is passed verbatim to every loader as a plain height floor;
    the default of 0 admits everything available.
    """
    print("Loading stale block records ...")
    stale = load_stale_csv(min_height=min_height)
    print(f"  {len(stale)} stale blocks at height >= {min_height:,}")

    for key, loader in _auxpow_loader_roster():
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
    stale = tag_stale_blocks(stale)
    n_bin = sum(1 for s in stale if s["has_bin"])
    print(f"  {n_bin} binaries parsed, {len(stale) - n_bin} without binary")

    _apply_attribution_basis(stale)
    _apply_rsk_historical_labels(stale)
    _apply_template_producers(stale)
    return stale


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
    print(f"CSV -> {path}")


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
        "--output",
        type=Path,
        default=ATTRIBUTIONS_CSV,
        help=f"output CSV path (default: {ATTRIBUTIONS_CSV})",
    )
    return ap


def main() -> None:
    args = _build_arg_parser().parse_args()

    if not STALE_CSV.exists():
        sys.exit(
            f"Missing {STALE_CSV} — run ./scripts/fetch-data.sh to clone the "
            "pinned bitcoin-data/stale-blocks dataset."
        )

    stale = load_attributed_stales(min_height=args.min_height)
    dump_attributions_csv(stale, args.output)

    pools = {s.get("pool") or "Unknown" for s in stale}
    n_rsk = sum(1 for s in stale if s.get("attribution_basis") == "rsk_historical")
    print(
        f"  {len(stale)} rows, {len(pools)} distinct pools, "
        f"{n_rsk} RSK historical labels"
    )


if __name__ == "__main__":
    main()
