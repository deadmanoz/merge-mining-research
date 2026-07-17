#!/usr/bin/env python3
"""Compute novelty splits for a single merge-mined chain.

Produces two views of the chain's validated stale set, used by per-chain
documentation in docs/chains/<chain>.md:

  1. Isolated vs upstream stale-blocks: of the chain's stales, how many are
     also in the upstream bitcoin-data/stale-blocks dataset?
  2. Chronological cumulative: replaying the merge in chronological order
     (CHAINS_BY_AUXPOW_ACTIVATION), how many of this chain's stales are
     novel at this point in chronological time — vs. already-claimed by an
     earlier-born chain?

Writes one row per validated stale to results/per-chain-novelty/<chain>.csv
with columns: btc_height, btc_hash, in_upstream, first_seen_chain.
Prints a summary the doc author pastes into the chain's doc.

Novelty precedence rule: earlier-born chain wins. This is a simplifying
convention, not a claim about real-world block-observation ordering.
"""

from __future__ import annotations

import argparse
import csv

from stale_blocks_analysis.config import (
    CHAINS_BY_AUXPOW_ACTIVATION,
    PROJECT_ROOT,
)
from stale_blocks_analysis.stale_blocks import (
    load_argentum_stales,
    load_bitmark_stales,
    load_bitcoin_vault_stales,
    load_coiledcoin_stales,
    load_crown_stales,
    load_devcoin_stales,
    load_doichain_stales,
    load_elastos_stales,
    load_elcash_stales,
    load_emercoin_stales,
    load_fractal_stales,
    load_geistgeld_stales,
    load_groupcoin_stales,
    load_hathor_stales,
    load_huntercoin_stales,
    load_i0coin_stales,
    load_ixcoin_stales,
    load_myriadcoin_stales,
    load_namecoin_stales,
    load_rsk_stales,
    load_stale_csv,
    load_syscoin_stales,
    load_terracoin_stales,
    load_unobtanium_stales,
    load_xaya_stales,
)


LOADERS = {
    "namecoin": load_namecoin_stales,
    "geistgeld": load_geistgeld_stales,
    "i0coin": load_i0coin_stales,
    "coiledcoin": load_coiledcoin_stales,
    "ixcoin": load_ixcoin_stales,
    "devcoin": load_devcoin_stales,
    "groupcoin": load_groupcoin_stales,
    "huntercoin": load_huntercoin_stales,
    "syscoin": load_syscoin_stales,
    "elastos": load_elastos_stales,
    "unobtanium": load_unobtanium_stales,
    "crown": load_crown_stales,
    "xaya": load_xaya_stales,
    "myriadcoin": load_myriadcoin_stales,
    "argentum": load_argentum_stales,
    "emercoin": load_emercoin_stales,
    "terracoin": load_terracoin_stales,
    "rsk": load_rsk_stales,
    "doichain": load_doichain_stales,
    "bitmark": load_bitmark_stales,
    "bitcoin-vault": load_bitcoin_vault_stales,
    "elcash": load_elcash_stales,
    "fractal": load_fractal_stales,
    "hathor": load_hathor_stales,
}

PENDING_INPUTS = {
    # Keep this hook for future wired-before-data chains so a missing input
    # cannot publish a header-only novelty CSV that looks like a zero-yield
    # result.
}

OUTPUT_DIR = PROJECT_ROOT / "results" / "per-chain-novelty"


def chain_key(record: dict) -> tuple[int, str]:
    """Normalise a stale record to (height, hash). Loaders use 'height'/'hash';
    upstream load_stale_csv uses the same keys."""
    return (record["height"], record["hash"])


def load_chain(name: str) -> list[dict]:
    """Load ``name``'s validated stale records via its registered loader.

    Raises ``SystemExit`` if ``name`` has no entry in ``LOADERS``.
    """
    if name not in LOADERS:
        raise SystemExit(
            f"No integrated loader for '{name}'. "
            f"Available: {sorted(LOADERS)}. "
            "Chains without a main-pipeline loader require an explicit "
            "per-chain integration before novelty can be computed."
        )
    return LOADERS[name](min_height=0)


def compute_views(chain: str, write_csv: bool) -> dict:
    """Compute the isolated and chronological-cumulative novelty splits for ``chain``.

    The isolated view compares ``chain``'s validated stales against the
    upstream ``bitcoin-data/stale-blocks`` dataset. The chronological
    cumulative view additionally attributes each stale to the earliest-born
    chain (per ``CHAINS_BY_AUXPOW_ACTIVATION``) that also claims it, so
    "novel at this position" means novel against upstream and every
    chronologically earlier wired chain.

    When ``write_csv`` is true, writes one row per validated stale to
    ``results/per-chain-novelty/<chain>.csv`` (columns: ``btc_height``,
    ``btc_hash``, ``in_upstream``, ``first_seen_chain``), unless ``chain`` has
    a still-missing entry in ``PENDING_INPUTS`` and produced zero stales, in
    which case any stale existing CSV is removed and the summary carries
    ``csv_skipped_reason`` instead. Returns the summary dict consumed by
    ``print_summary``. Raises ``SystemExit`` if ``chain`` is not in
    ``CHAINS_BY_AUXPOW_ACTIVATION``.
    """
    chain_stales = load_chain(chain)
    chain_keys = {chain_key(r): r for r in chain_stales}

    # 1. Isolated view: upstream stale-blocks vs this chain.
    upstream = load_stale_csv(min_height=0)
    upstream_keys = {chain_key(r) for r in upstream}
    in_upstream = chain_keys.keys() & upstream_keys
    isolated_novel = chain_keys.keys() - upstream_keys

    # 2. Chronological cumulative: chains chronologically earlier than this one.
    chrono_names = [c for c, _ in CHAINS_BY_AUXPOW_ACTIVATION]
    if chain not in chrono_names:
        raise SystemExit(
            f"Chain '{chain}' not in CHAINS_BY_AUXPOW_ACTIVATION. "
            f"Add it to config.py before running this helper."
        )
    chain_pos = chrono_names.index(chain)
    earlier_chains = chrono_names[:chain_pos]
    # Per-key attribution: which earlier-born chain first claims this hash?
    first_seen: dict[tuple[int, str], str] = {}
    for earlier in earlier_chains:
        if earlier not in LOADERS:
            continue  # unwired chain, not in main pipeline
        for r in LOADERS[earlier](min_height=0):
            k = chain_key(r)
            if k in chain_keys and k not in first_seen:
                first_seen[k] = earlier
    cumulative_novel = chain_keys.keys() - upstream_keys - first_seen.keys()

    summary = {
        "chain": chain,
        "total_validated": len(chain_keys),
        "isolated": {
            "also_in_upstream": len(in_upstream),
            "novel_vs_upstream": len(isolated_novel),
        },
        "cumulative": {
            "also_in_upstream": len(in_upstream),
            "also_in_earlier_chain": len(first_seen),
            "novel_at_this_position": len(cumulative_novel),
            "earlier_chain_breakdown": _tally(first_seen.values()),
        },
        "earlier_chains_consulted": [c for c in earlier_chains if c in LOADERS],
        "earlier_chains_skipped_unwired": [
            c for c in earlier_chains if c not in LOADERS
        ],
    }

    if write_csv:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        out = OUTPUT_DIR / f"{chain}.csv"
        pending_input = PENDING_INPUTS.get(chain)
        if pending_input is not None and not pending_input.exists() and not chain_keys:
            if out.exists():
                out.unlink()
            summary["csv_skipped_reason"] = (
                f"not written because {pending_input.relative_to(PROJECT_ROOT)} "
                "does not exist yet"
            )
            return summary
        with open(out, "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(
                [
                    "btc_height",
                    "btc_hash",
                    "in_upstream",
                    "first_seen_chain",
                ]
            )
            for k in sorted(chain_keys):
                w.writerow(
                    [
                        k[0],
                        k[1],
                        "yes" if k in upstream_keys else "no",
                        first_seen.get(k, ""),
                    ]
                )
        summary["csv_path"] = str(out.relative_to(PROJECT_ROOT))

    return summary


def _tally(values) -> dict[str, int]:
    """Count occurrences of each value, returning a ``{value: count}`` dict."""
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


def print_summary(s: dict) -> None:
    """Print the isolated and cumulative novelty splits from a ``compute_views`` summary."""
    c = s["chain"]
    print(f"\n=== {c} novelty splits (total validated: {s['total_validated']}) ===\n")

    iso = s["isolated"]
    print("Isolated vs upstream stale-blocks:")
    print(f"  also in upstream:         {iso['also_in_upstream']}")
    print(f"  novel vs upstream:        {iso['novel_vs_upstream']}")

    cum = s["cumulative"]
    print(
        "\nChronological cumulative (this chain layered on upstream + earlier-born chains):"
    )
    print(f"  also in upstream:         {cum['also_in_upstream']}")
    print(f"  also in earlier chain:    {cum['also_in_earlier_chain']}")
    print(f"  novel at this position:   {cum['novel_at_this_position']}")
    if cum["earlier_chain_breakdown"]:
        print("  earlier-chain attribution:")
        for ch, n in sorted(
            cum["earlier_chain_breakdown"].items(), key=lambda x: -x[1]
        ):
            print(f"    {ch:<11} {n}")
    if s["earlier_chains_skipped_unwired"]:
        print(
            f"  (skipped unwired earlier chains: "
            f"{', '.join(s['earlier_chains_skipped_unwired'])})"
        )

    if "csv_path" in s:
        print(f"\nPer-stale CSV: {s['csv_path']}")
    elif "csv_skipped_reason" in s:
        print(f"\nPer-stale CSV: {s['csv_skipped_reason']}")


def main() -> None:
    """Parse CLI args, compute the novelty views for the chosen chain, and print the summary."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "chain",
        choices=sorted(LOADERS),
        help="Integrated chain to compute novelty for.",
    )
    p.add_argument(
        "--no-csv",
        action="store_true",
        help="Skip writing the per-stale CSV (print summary only).",
    )
    args = p.parse_args()
    summary = compute_views(args.chain, write_csv=not args.no_csv)
    print_summary(summary)


if __name__ == "__main__":
    main()
