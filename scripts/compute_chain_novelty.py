#!/usr/bin/env python3
"""Generate the complete direct-stale novelty report from compact inputs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from stale_blocks_analysis import stale_blocks
from stale_blocks_analysis.config import (
    CANONICAL_ONLY_CHAINS,
    CHAINS_BY_AUXPOW_ACTIVATION,
    CHAIN_SPECS,
    ERROR_BLOCKS_CSV,
    PROJECT_ROOT,
    STALE_CSV,
    STALE_DIR,
)
from stale_blocks_analysis.data_source_provenance import clone_state, read_pinned_ref

OUTPUT = PROJECT_ROOT / "results" / "novelty.md"
MANIFEST = PROJECT_ROOT / "data-sources.tsv"


def require_csv(path: Path, columns: set[str]) -> None:
    """Even a genuine zero-row input must carry its required schema."""
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, strict=True)
        header = reader.fieldnames or []
        if not columns <= set(header) or len(header) != len(set(header)):
            raise ValueError(f"Missing or duplicate required CSV columns in {path}")
        for number, row in enumerate(reader, 2):
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Malformed CSV row {number} in {path}")


def verified_upstream_pin() -> str:
    """Require the selected clone and its actual CSV bytes at the declared pin."""
    pin = read_pinned_ref(MANIFEST, "stale-blocks")
    state = clone_state(STALE_DIR)
    if not pin or state is None or state["commit"] != pin or state["dirty"]:
        raise ValueError(
            "Upstream must be an inspectable, clean clone at the stale-blocks pin"
        )
    # Checking bytes also catches ignored replacements and assume-unchanged files.
    try:
        committed = subprocess.run(
            ["git", "-C", str(STALE_DIR), "show", f"{pin}:stale-blocks.csv"],
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("Cannot read pinned upstream CSV from Git") from exc
    if STALE_CSV.read_bytes() != committed:
        raise ValueError("Upstream CSV differs from the pinned content")
    return pin


def input_fingerprint() -> str:
    """Bind input bytes and ordered chronology without machine-specific paths."""
    inputs = {"stale-blocks.csv": STALE_CSV, "error-blocks.csv": ERROR_BLOCKS_CSV}
    inputs.update(
        {
            f"validated-stales/{key}.csv": CHAIN_SPECS[key].validated_csv
            for key, _ in CHAINS_BY_AUXPOW_ACTIVATION
            if key not in CANONICAL_ONLY_CHAINS
        }
    )
    manifest = {
        "chronology": CHAINS_BY_AUXPOW_ACTIVATION,
        "canonical_only": sorted(CANONICAL_ONLY_CHAINS),
        "inputs": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in inputs.items()
        },
    }
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


def calculate(upstream: set[tuple[int, str]], chains: dict[str, set]) -> dict:
    """Allocate exact parent identities in the supplied chronology order."""
    recovered: set[tuple[int, str]] = set()
    rows = []
    for key, parents in chains.items():
        rows.append(
            {
                "chain": key,
                "accepted": len(parents),
                "overlap": len(parents & upstream),
                "absent": len(parents - upstream),
                "chronological": len(parents - upstream - recovered),
            }
        )
        recovered.update(parents)
    return {
        "rows": rows,
        "upstream": len(upstream),
        "recovered": len(recovered),
        "overlap": len(recovered & upstream),
        "absent": len(recovered - upstream),
    }


def build_report() -> str:
    names = [key for key, _ in CHAINS_BY_AUXPOW_ACTIVATION]
    if (
        len(names) != len(set(names))
        or set(names) != set(CHAIN_SPECS)
        or not CANONICAL_ONLY_CHAINS <= set(names)
    ):
        raise ValueError("Chain chronology and registry disagree")
    loaders = {}
    for key in names:
        loader = getattr(stale_blocks, f"load_{key.replace('-', '_')}_stales", None)
        if not callable(loader):
            raise ValueError(f"Missing integrated loader for {key}")
        loaders[key] = loader
        path = CHAIN_SPECS[key].validated_csv
        if key in CANONICAL_ONLY_CHAINS:
            if path.exists():
                raise ValueError(
                    f"Canonical-only chain {key} has an unexpected validated CSV"
                )
        else:
            require_csv(
                path,
                {
                    "btc_height",
                    "btc_header_hash",
                    "classification",
                    "validation_status",
                },
            )
    require_csv(STALE_CSV, {"height", "hash"})
    require_csv(ERROR_BLOCKS_CSV, {"height", "hash", "classification"})
    pin = verified_upstream_pin()
    fingerprint = input_fingerprint()
    upstream = {
        (row["height"], row["hash"])
        for row in stale_blocks.load_stale_csv(min_height=0)
    }
    chains = {
        key: set()
        if key in CANONICAL_ONLY_CHAINS
        else {(row["height"], row["hash"]) for row in loaders[key](min_height=0)}
        for key in names
    }
    result = calculate(upstream, chains)
    if input_fingerprint() != fingerprint or verified_upstream_pin() != pin:
        raise ValueError(
            "Novelty inputs changed during generation; rerun with stable inputs"
        )
    return render_report(result, pin, fingerprint)


def render_report(result: dict, pin: str, fingerprint: str) -> str:
    lines = [
        "# Direct-stale novelty",
        "",
        "Generated by `scripts/compute_chain_novelty.py`. Do not edit counts by hand.",
        "Run `just novelty` to regenerate or `just novelty-check` to verify.",
        "",
        f"Upstream commit: `{pin}`.",
        f"Input SHA-256: `{fingerprint}`.",
        "",
        "The fingerprint binds every required validated-stales CSV, the upstream CSV,",
        "the error-block catalogue, the ordered chain chronology and canonical-only roster.",
        "It contains no timestamp or local path.",
        "",
        "## Method",
        "",
        "Counts use distinct `(height, hash)` direct-stale parents at all heights, after",
        "the existing loaders apply accepted-status and exact error-catalogue gates to",
        "chain inputs and the error-catalogue gate to upstream. These are accepted header",
        "candidates under the available-evidence profile, not proof of full-block validity.",
        "",
        "For chain C, effective upstream U and the union E of earlier chains, overlap is",
        "C intersect U, absent from upstream is C minus U, and chronological novelty is",
        "C minus (U union E). Order follows `CHAINS_BY_AUXPOW_ACTIVATION`, including its",
        "explicit same-date ordering. This allocation convention establishes neither first",
        "observation nor scientific value. Cross-chain witnesses remain useful corroboration.",
        "",
        "## Per-chain counts",
        "",
        "| Chain | Accepted parents | Upstream overlap | Absent from upstream | Chronological novelty |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in result["rows"]:
        key = row["chain"]
        name = CHAIN_SPECS[key].display_name
        label = f"[{name}](../docs/chains/{key}.md)"
        if key in CANONICAL_ONLY_CHAINS:
            label += " (canonical-only; no validated-stales CSV)"
        lines.append(
            f"| {label} | {row['accepted']:,} | {row['overlap']:,} | {row['absent']:,} | {row['chronological']:,} |"
        )
    lines += [
        "",
        "Canonical-only rows have no accepted direct-stale input. A zero in other rows",
        "comes from a present, schema-checked input; it is not a claim about the chain's",
        "entire lifetime or an unsearched interval.",
        "",
        "## Deduplicated totals",
        "",
        "| Set | Distinct parents |",
        "|---|---:|",
        f"| Effective upstream | {result['upstream']:,} |",
        f"| Recovered union across chains | {result['recovered']:,} |",
        f"| Recovered union also in upstream | {result['overlap']:,} |",
        f"| Recovered union absent from upstream | {result['absent']:,} |",
        "",
        "The last row equals the sum of chronological novelty. Accepted-parent and",
        "upstream-absent columns count a shared parent once per witnessing chain, so their",
        "sums are not deduplicated union totals. Stale descendants are excluded here; the",
        "[contribution sidecar](../docs/upstreaming.md) also admits descendants and need",
        "not have the same count.",
        "",
        "Row-level evidence: [validated inputs](../data/validated-stales/) and the",
        "[error catalogue](../data/error-blocks/error_blocks.csv). See the",
        "[recovery methodology](../docs/auxpow-recovery.md) and",
        "[data validity contract](../docs/data-validity.md) for evidence limitations.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true", help="Compare without writing")
    args = parser.parse_args(argv)
    try:
        content = build_report().encode("utf-8")
        if args.check:
            if not args.output.is_file() or args.output.read_bytes() != content:
                raise ValueError(
                    f"Novelty report is stale or absent: {args.output}; run just novelty"
                )
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(
                    dir=args.output.parent, delete=False
                ) as stream:
                    temporary = Path(stream.name)
                    stream.write(content)
                os.replace(temporary, args.output)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
    except (OSError, ValueError, KeyError, csv.Error) as exc:
        print(f"Novelty: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
