# Error Blocks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote consensus-invalid full-PoW blocks ("error blocks") from a negative exclusion overlay into a first-class, re-derivable published dataset, hunt for the rest of the population, and add `error_block` as a primary classification value.

**Architecture:** One committed consolidated CSV (`data/error-blocks/error_blocks.csv`) is both the rich evidence dataset and the exact-key exclusion gate. A renamed loader module reads it (keying off `classification == "error_block"`, no `exclusion_scope` column). An offline validator re-derives every row's violation from committed bytes in CI. A builder harvests evidence from reachable archives; four sweep scripts hunt for new members and write reports. All work happens in the `merge-mining-research-error-blocks` worktree on branch `feat/error-blocks`.

**Tech Stack:** Python 3.10+, stdlib `csv`/`json`/`hashlib`, pytest, Ruff, `just`. Existing package modules: `stale_blocks_analysis.{config,auxpow_parse,btc_stale_validation,btc_nbits_validation,auxpow_chainid}`.

**Spec:** `docs/superpowers/specs/2026-07-29-error-blocks-design.md`

---

## Grounding facts the implementer must know

- **Worktree:** all paths below are under `<repo-worktree>` (the `merge-mining-research-error-blocks` worktree). Branch `feat/error-blocks`. Never commit to `main`.
- **Current overlay:** `data/stale_block_exclusions.csv` — 32 rows. Header: `height,hash,btc_prev_hash,btc_header_version,coinbase_height,coinbase_scriptsig_hex,source_chains,source_child_observations,rejection_reason,exclusion_scope`. 31 `consensus_invalid` + 1 `direct_stale_only` (height 656478).
- **656478 is NOT in any per-chain validated-stales CSV** (verified: its hash `00000000000000000005f8f74e57aa4584aacfed509b8a6feb20bc22e7d60a34` appears only in `data/stale_block_exclusions.csv` and `data/stale_descendants.csv`). So removing the `direct_stale_only` guard needs **no CSV mutation** — only deleting scope handling and adding an absence test. This does NOT cross the brief's validated-stales boundary.
- **Loader module:** `src/stale_blocks_analysis/stale_exclusions.py` exposes `load_stale_exclusion_keys`, `load_consensus_invalid_stale_keys`, `exclude_stale_rows`, `exclude_consensus_invalid_rows`, all taking `path: Path = STALE_EXCLUSIONS_CSV`. Matching is exact `(int(row["height"]), str(row["hash"]).lower())`.
- **Callers to update:** `src/stale_blocks_analysis/stale_blocks.py` (lines 35, 81, 211, 689, 837), `src/stale_blocks_analysis/full_evidence.py` (28-30, 699-717), `scripts/reports/build_upstream_stale_sidecar.py` (11-13, 82, 147-148), `scripts/analysis/reconcile_unknown_stale_ancestry.py` (51-53, 874, 1029), `scripts/analysis/classify_btc_stale_relevance.py` (74, 543), `scripts/classify/classify_rsk_stales.py` (52, 268-274, 532).
- **Config:** `STALE_EXCLUSIONS_CSV = DATA_DIR / "stale_block_exclusions.csv"` at `config.py:49`. `VALIDATED_STALES_DIR` (:33), `BITCOIN_EPOCH_REFERENCE_DIR` (:42), `STALE_DESCENDANTS_CSV` (:233), `RESULTS_DIR` (:52). BIP constants `BIP34_VERSION_2_HEIGHT=224413`, `BIP34_HEIGHT=227931`, `BIP66_HEIGHT=363725`, `BIP65_HEIGHT=388381` (:403-406).
- **PoW helper:** `auxpow_parse.hash_meets_btc_difficulty(header_hash_internal: bytes, bits: int) -> bool` at `auxpow_parse.py:256` — internal (LE) 32-byte sha256d vs target. `nbits_to_target(bits)` at :240.
- **Gate functions (reuse in validator):** `btc_stale_validation.block_version_error(row, expected_height, *, header_hex_key)`, `median_time_past_error(row, parent_median_time_past, *, time_key)`, `coinbase_scriptsig_length_error(row, *, scriptsig_key)`, `bip34_height_error(row, expected_height, *, bip34_key, scriptsig_key, header_hex_key)`. Each returns `None` (pass) or a `"REJECTED: ..."`/`"UNKNOWN: ..."` string.
- **Epoch nBits reference:** `data/bitcoin-epoch-reference/btc_nbits_by_epoch.json` is `{ "<height>": "<hexbits>", ... }` (e.g. `"0": "1d00ffff"`). Used offline for `expected_nbits` cross-checks.
- **Evidence sources (reachable, read-only):** `<archival-host>` chain archive `~/mmr-child-header-regen-20260729/staging/chains/<chain>/classified/<chain>_stale_blocks.csv` (has `validation_status` REJECTED reasons + `btc_header_hex`/`coinbase_scriptsig_hex`/`btc_time`/`btc_bits`/`expected_nbits`); sibling `~/dev/bitcoin/stale-blocks-research/results/full-evidence/<chain>_evidence.csv` (43-col provenance). 946213 comes from a monitor export (operator-coordinated).
- **Hash byte order:** use `stale_blocks_analysis.auxpow_chainid` helpers; never guess display vs internal order.

---

## Task 1: New dataset schema + loader module skeleton

**Files:**
- Create: `src/stale_blocks_analysis/error_blocks.py`
- Modify: `src/stale_blocks_analysis/config.py` (add `ERROR_BLOCKS_CSV`, `ERROR_BLOCKS_DIR`)
- Test: `tests/test_error_blocks.py`

- [ ] **Step 1: Add config constants**

In `src/stale_blocks_analysis/config.py`, after line 49 (`STALE_EXCLUSIONS_CSV`), add:

```python
ERROR_BLOCKS_DIR = DATA_DIR / "error-blocks"
ERROR_BLOCKS_CSV = ERROR_BLOCKS_DIR / "error_blocks.csv"
```

Do NOT create the directory at import time (the file is committed; the loader fails closed if missing). Keep `STALE_EXCLUSIONS_CSV` for now (removed in Task 4).

- [ ] **Step 2: Write the failing loader test**

Create `tests/test_error_blocks.py`:

```python
from __future__ import annotations

from pathlib import Path

import pytest

from stale_blocks_analysis.config import ERROR_BLOCKS_CSV
from stale_blocks_analysis.error_blocks import (
    exclude_consensus_invalid_rows,
    exclude_stale_rows,
    load_consensus_invalid_stale_keys,
    load_stale_exclusion_keys,
)

REPO = Path(__file__).resolve().parents[1]


def test_load_keys_from_committed_dataset() -> None:
    keys = load_stale_exclusion_keys(ERROR_BLOCKS_CSV)
    assert (
        363967,
        "00000000000000000954ed93eda1e79e8261137548fa9ccf4d516bb384a3660b",
    ) in keys


def test_consensus_invalid_subset_equals_all_rows() -> None:
    # Every dataset row is an error block, so the two key sets are identical.
    assert load_stale_exclusion_keys(
        ERROR_BLOCKS_CSV
    ) == load_consensus_invalid_stale_keys(ERROR_BLOCKS_CSV)


def test_missing_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_stale_exclusion_keys(tmp_path / "nope.csv")


def test_blank_classification_fails_closed(tmp_path: Path) -> None:
    p = tmp_path / "error_blocks.csv"
    p.write_text("height,hash,classification\n1," + "00" * 32 + ",\n")
    with pytest.raises(ValueError):
        load_stale_exclusion_keys(p)


def test_exclude_rows_filters_exact_key() -> None:
    rows = [
        {
            "height": "363967",
            "hash": "00000000000000000954ed93eda1e79e8261137548fa9ccf4d516bb384a3660b",
        },
        {"height": "1", "hash": "11" * 32},
    ]
    kept = exclude_consensus_invalid_rows(rows, path=ERROR_BLOCKS_CSV)
    assert kept == [{"height": "1", "hash": "11" * 32}]
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m pytest tests/test_error_blocks.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'stale_blocks_analysis.error_blocks'`

- [ ] **Step 4: Implement the loader module**

Create `src/stale_blocks_analysis/error_blocks.py`:

```python
"""Load exact keys excluded from the direct-stale publication path.

Every row in ``data/error-blocks/error_blocks.csv`` is a consensus-invalid
full-proof-of-work Bitcoin block (an "error block"), so the exclusion key set
is derived directly from ``classification == "error_block"`` rows. There is no
``exclusion_scope`` column: membership in this dataset already means
consensus-invalid. This dataset is the single source of truth for the gate.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .config import ERROR_BLOCKS_CSV

ERROR_BLOCK_CLASSIFICATION = "error_block"


def _load_keys(path: Path) -> set[tuple[int, str]]:
    if not path.exists():
        raise FileNotFoundError(f"error blocks dataset missing: {path}")

    keys: set[tuple[int, str]] = set()
    with path.open(newline="") as f:
        for row_number, row in enumerate(csv.DictReader(f), start=2):
            try:
                classification = (row.get("classification") or "").strip()
                if classification != ERROR_BLOCK_CLASSIFICATION:
                    raise ValueError
                height = int(row["height"])
                block_hash = row["hash"].strip().lower()
                if height < 0 or len(block_hash) != 64:
                    raise ValueError
                bytes.fromhex(block_hash)
                key = (height, block_hash)
            except (KeyError, ValueError) as exc:
                raise ValueError(
                    f"invalid error block row {row_number} in {path}"
                ) from exc
            if key in keys:
                raise ValueError(f"duplicate error block key {key} in {path}")
            keys.add(key)
    return keys


def load_stale_exclusion_keys(
    path: Path = ERROR_BLOCKS_CSV,
) -> set[tuple[int, str]]:
    """Return exact ``(height, hash)`` keys excluded from direct-stale loaders."""
    return _load_keys(path)


def load_consensus_invalid_stale_keys(
    path: Path = ERROR_BLOCKS_CSV,
) -> set[tuple[int, str]]:
    """Return exact keys whose evidence proves a Bitcoin consensus failure."""
    return _load_keys(path)


def exclude_stale_rows(
    rows: list[dict],
    *,
    path: Path = ERROR_BLOCKS_CSV,
) -> list[dict]:
    """Remove excluded exact stale keys from normalized loader rows."""
    excluded = load_stale_exclusion_keys(path)
    return [
        row
        for row in rows
        if (int(row["height"]), str(row["hash"]).lower()) not in excluded
    ]


def exclude_consensus_invalid_rows(
    rows: list[dict],
    *,
    path: Path = ERROR_BLOCKS_CSV,
) -> list[dict]:
    """Remove consensus-invalid (error block) keys from a stale catalogue."""
    excluded = load_consensus_invalid_stale_keys(path)
    return [
        row
        for row in rows
        if (int(row["height"]), str(row["hash"]).lower()) not in excluded
    ]
```

- [ ] **Step 5: Run test to verify it passes (needs seed data)**

This test reads the committed `ERROR_BLOCKS_CSV`, which does not exist until Task 2. For now, run only the tests that don't need the committed file:

Run: `python -m pytest tests/test_error_blocks.py::test_missing_file_fails_closed tests/test_error_blocks.py::test_blank_classification_fails_closed -v`
Expected: PASS (2 passed). The committed-file tests are exercised after Task 2.

- [ ] **Step 6: Commit**

```bash
git add src/stale_blocks_analysis/config.py src/stale_blocks_analysis/error_blocks.py tests/test_error_blocks.py
git commit -m "feat(error-blocks): add error_blocks loader module and config constants"
```

---

## Task 2: Build the seed dataset CSV

**Files:**
- Create: `scripts/prep/build_error_blocks.py`
- Create: `data/error-blocks/error_blocks.csv` (generated)
- Test: `tests/test_error_blocks.py` (extend)

The builder harvests full evidence for the 31 seed rows from the reachable archives and writes the committed CSV. It is read-only against sources and fails closed when a required input is missing.

- [ ] **Step 1: Write the failing builder/seed test**

Append to `tests/test_error_blocks.py`:

```python
import csv


EXPECTED_COLUMNS = [
    "height",
    "hash",
    "btc_prev_hash",
    "btc_header_version",
    "btc_time",
    "btc_bits",
    "expected_nbits",
    "btc_header_hex",
    "coinbase_height",
    "coinbase_scriptsig_hex",
    "source_chains",
    "source_child_observations",
    "classification",
    "rejection_reason",
    "rules_violated",
    "first_observed_child_time",
    "provenance",
]


def test_committed_dataset_schema_and_seed_count() -> None:
    with ERROR_BLOCKS_CSV.open(newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == EXPECTED_COLUMNS
        rows = list(reader)
    # 31 seed rows (946213 and sweep finds are added in later tasks).
    assert len(rows) >= 31
    assert all(r["classification"] == "error_block" for r in rows)
    assert all(r["rules_violated"] for r in rows)
    assert all(r["provenance"] for r in rows)
    assert all(len(r["btc_header_hex"]) == 160 for r in rows)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_error_blocks.py::test_committed_dataset_schema_and_seed_count -v`
Expected: FAIL with `FileNotFoundError` (ERROR_BLOCKS_CSV does not exist yet)

- [ ] **Step 3: Implement the builder**

Create `scripts/prep/build_error_blocks.py`. It reads the old overlay for the seed key list, joins each key to its evidence row in the reachable archives (`<archival-host>` classified inventories via a mount/ssh-fetch, or the sibling full-evidence exports), derives the audit columns from `btc_header_hex`, and writes the CSV. It must fail closed (exit non-zero, no write) if any seed key's evidence cannot be located, unless `--allow-partial --output-dir <dir>` is given.

Structure (implement fully; this is the skeleton with the load-bearing parts shown):

```python
"""Build data/error-blocks/error_blocks.csv from reachable evidence archives.

Read-only against all sources. Fails closed (no write) when a required seed
row's evidence is missing, unless --allow-partial writes to a disposable
--output-dir. The 946213 monitor row is merged from --monitor-export.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from stale_blocks_analysis.config import ERROR_BLOCKS_CSV, STALE_EXCLUSIONS_CSV

COLUMNS = [
    "height",
    "hash",
    "btc_prev_hash",
    "btc_header_version",
    "btc_time",
    "btc_bits",
    "expected_nbits",
    "btc_header_hex",
    "coinbase_height",
    "coinbase_scriptsig_hex",
    "source_chains",
    "source_child_observations",
    "classification",
    "rejection_reason",
    "rules_violated",
    "first_observed_child_time",
    "provenance",
]


def parse_header_fields(header_hex: str) -> dict[str, str]:
    """Derive version/time/bits from an 80-byte header hex (display order out)."""
    raw = bytes.fromhex(header_hex)
    version = int.from_bytes(raw[0:4], "little", signed=True)
    time_ = int.from_bytes(raw[68:72], "little")
    bits = int.from_bytes(raw[72:76], "little")
    return {
        "btc_header_version": str(version),
        "btc_time": str(time_),
        "btc_bits": f"{bits:08x}",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ERROR_BLOCKS_CSV)
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--monitor-export", type=Path, default=None)
    args = parser.parse_args(argv)
    # Guard: --allow-partial requires a disposable --output-dir that is not the
    # committed default; refuse to write partial output over the committed CSV.
    if args.allow_partial and args.output_dir is None:
        print("--allow-partial requires --output-dir", file=sys.stderr)
        return 2
    if args.allow_partial and args.output.resolve() == ERROR_BLOCKS_CSV.resolve():
        print("refusing to write partial output to the committed path", file=sys.stderr)
        return 2
    # ... harvest seed keys from STALE_EXCLUSIONS_CSV, join to archive evidence,
    # derive audit columns, merge monitor export, write CSV (or fail closed).
    raise NotImplementedError("implemented in this task")


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run the builder to generate the committed CSV**

Run (evidence paths passed explicitly; adjust to the mounted archive location):

```bash
python scripts/prep/build_error_blocks.py \
  --chain-archive-dir /path/to/staging/chains \
  --full-evidence-dir ~/dev/bitcoin/stale-blocks-research/results/full-evidence
```

Expected: writes `data/error-blocks/error_blocks.csv` with 31 rows; exits 0. If evidence is missing it exits non-zero and writes nothing.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_error_blocks.py -v`
Expected: all PASS (loader tests now find the committed file)

- [ ] **Step 6: Commit**

```bash
git add scripts/prep/build_error_blocks.py data/error-blocks/error_blocks.csv tests/test_error_blocks.py
git commit -m "feat(error-blocks): builder and 31-row seed dataset"
```

---

## Task 3: Offline re-derivation validator

**Files:**
- Create: `scripts/analysis/validate_error_blocks.py`
- Test: `tests/test_error_blocks_validator.py`

The validator re-checks every row from committed bytes: full PoW via `hash_meets_btc_difficulty`, each named rule in `rules_violated`, `expected_nbits` against the epoch reference, and derived==stated for the audit columns. It runs offline (no live RPC).

- [ ] **Step 1: Write the failing validator test**

Create `tests/test_error_blocks_validator.py`:

```python
from __future__ import annotations

from pathlib import Path

from stale_blocks_analysis.config import ERROR_BLOCKS_CSV

import importlib.util


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_error_blocks",
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "analysis"
        / "validate_error_blocks.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_committed_row_revalidates() -> None:
    mod = _load_validator()
    failures = mod.validate_dataset(ERROR_BLOCKS_CSV)
    assert failures == [], f"rows failed re-derivation: {failures}"


def test_pow_target_failure_is_not_an_error_block() -> None:
    mod = _load_validator()
    # A row whose header does not meet its own target must be flagged.
    row = {
        "height": "100",
        "hash": "ff" * 32,
        "btc_bits": "1d00ffff",
        "btc_header_hex": "00" * 80,
        "coinbase_scriptsig_hex": "02" + "00" * 30,
        "rules_violated": "bip66_block_version_below_3",
        "expected_nbits": "1d00ffff",
    }
    assert mod.validate_row(row) != []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_error_blocks_validator.py -v`
Expected: FAIL (module has no `validate_dataset` / `validate_row`)

- [ ] **Step 3: Implement the validator**

Create `scripts/analysis/validate_error_blocks.py`:

```python
"""Re-derive every error_blocks.csv row's violation from committed bytes.

Offline: uses data/bitcoin-epoch-reference for expected nBits and the committed
header/coinbase evidence. A row that fails re-derivation is reported; the test
suite fails on any non-empty result.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from stale_blocks_analysis.auxpow_parse import hash_meets_btc_difficulty
from stale_blocks_analysis.btc_stale_validation import (
    bip34_height_error,
    block_version_error,
    coinbase_scriptsig_length_error,
)
from stale_blocks_analysis.config import (
    BITCOIN_EPOCH_REFERENCE_DIR,
    ERROR_BLOCKS_CSV,
)

# Map rules_violated tokens to the gate that re-derives them. Time rules
# (time_below_mtp / time_beyond_future_limit) need canonical context handled
# separately; the header/coinbase rules reuse the existing gates.
HEADER_VERSION_RULES = {"bip66_block_version_below_3", "bip65_block_version_below_4"}
COINBASE_LENGTH_RULES = {"coinbase_scriptsig_length_above_100"}
BIP34_RULES = {"bip34_coinbase_height_mismatch", "bip34_v2_coinbase_height_mismatch"}


def _load_nbits_table(path: Path = BITCOIN_EPOCH_REFERENCE_DIR) -> dict[int, str]:
    with (path / "btc_nbits_by_epoch.json").open() as f:
        return {int(k): v for k, v in json.load(f).items()}


def validate_row(row: dict[str, str]) -> list[str]:
    """Return a list of re-derivation failure messages (empty = valid)."""
    failures: list[str] = []
    header_hex = row["btc_header_hex"]
    raw = bytes.fromhex(header_hex)
    bits = int(row["btc_bits"], 16)
    # (a) Full PoW: header hash must meet its own target (else it is a share).
    import hashlib

    digest = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    if not hash_meets_btc_difficulty(digest, bits):
        failures.append("header hash does not meet its own target (not full PoW)")
    # (b) Re-derive each named rule.
    height = int(row["height"])
    for rule in row["rules_violated"].split("|"):
        rule = rule.strip()
        if rule in HEADER_VERSION_RULES:
            err = block_version_error({"btc_header_hex": header_hex}, height)
            if err is None:
                failures.append(f"rule {rule} did not re-derive")
        elif rule in COINBASE_LENGTH_RULES:
            err = coinbase_scriptsig_length_error(row)
            if err is None:
                failures.append(f"rule {rule} did not re-derive")
        elif rule in BIP34_RULES:
            err = bip34_height_error(row, height)
            if err is None:
                failures.append(f"rule {rule} did not re-derive")
        # time rules validated in Task 5 with canonical context.
    # (c) expected_nbits cross-check against the epoch reference.
    nbits = _load_nbits_table()
    epoch_start = (height // 2016) * 2016
    expected = nbits.get(epoch_start)
    if (
        expected is not None
        and row.get("expected_nbits")
        and row["expected_nbits"] != expected
    ):
        failures.append(
            f"expected_nbits {row['expected_nbits']} != epoch reference {expected}"
        )
    return failures


def validate_dataset(path: Path = ERROR_BLOCKS_CSV) -> list[str]:
    failures: list[str] = []
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            for msg in validate_row(row):
                failures.append(f"{row['height']}:{row['hash'][:12]}: {msg}")
    return failures


if __name__ == "__main__":
    import sys

    result = validate_dataset()
    for line in result:
        print(line)
    sys.exit(1 if result else 0)
```

Note for the implementer: `block_version_error` and `bip34_height_error` take a row dict keyed by `btc_header_hex` / `coinbase_scriptsig_hex` / `btc_bip34_height`; construct the row dict the gates expect. The `median_time_past_error` gate needs `parent_median_time_past`, which is supplied from committed canonical context in Task 5, not here.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_error_blocks_validator.py -v`
Expected: PASS (all 31 seed rows re-validate; the synthetic PoW-failure row is flagged)

- [ ] **Step 5: Commit**

```bash
git add scripts/analysis/validate_error_blocks.py tests/test_error_blocks_validator.py
git commit -m "feat(error-blocks): offline re-derivation validator wired into tests"
```

---

## Task 4: Migrate callers to the new module and remove the old overlay

**Files:**
- Modify: `src/stale_blocks_analysis/stale_blocks.py` (imports + 5 call sites)
- Modify: `src/stale_blocks_analysis/full_evidence.py`
- Modify: `scripts/reports/build_upstream_stale_sidecar.py`
- Modify: `scripts/analysis/reconcile_unknown_stale_ancestry.py`
- Modify: `scripts/analysis/classify_btc_stale_relevance.py`
- Modify: `scripts/classify/classify_rsk_stales.py`
- Modify: `src/stale_blocks_analysis/config.py` (remove `STALE_EXCLUSIONS_CSV`)
- Delete: `src/stale_blocks_analysis/stale_exclusions.py`, `data/stale_block_exclusions.csv`
- Test: `tests/test_stale_exclusions.py` → migrate to `tests/test_error_blocks.py`

- [ ] **Step 1: Update all imports and call sites**

In each caller, replace `from .stale_exclusions import ...` / `from stale_blocks_analysis.stale_exclusions import ...` with `from .error_blocks import ...` / `from stale_blocks_analysis.error_blocks import ...`. The function names and signatures are unchanged, so call sites need no logic change. Remove any `direct_stale_only` special-casing (e.g. the descendant-path comment/logic in `stale_blocks.py:837` and `full_evidence.py:699-717`) since the scope no longer exists — `exclude_consensus_invalid_rows` and `exclude_stale_rows` now behave identically.

- [ ] **Step 2: Remove the old module, overlay, and config constant**

```bash
git rm src/stale_blocks_analysis/stale_exclusions.py data/stale_block_exclusions.csv
```

In `config.py`, delete line 49 (`STALE_EXCLUSIONS_CSV = ...`). Grep to confirm no remaining references:

Run: `rg -n "stale_exclusions|STALE_EXCLUSIONS_CSV|stale_block_exclusions" src scripts tests`
Expected: no matches

- [ ] **Step 3: Migrate the old exclusion test**

Fold the relevant pins from `tests/test_stale_exclusions.py` into `tests/test_error_blocks.py`, updated for the new file and the 31-key set. Add the 656478 single-home test:

```python
def test_656478_absent_from_direct_stale_catalogues() -> None:
    # 656478 is a stale_descendant; it must not appear in any direct-stale CSV.
    target = "00000000000000000005f8f74e57aa4584aacfed509b8a6feb20bc22e7d60a34"
    for path in sorted(
        (REPO / "data" / "validated-stales").glob("*_validated_stales.csv")
    ):
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                assert row.get("btc_header_hash", "").lower() != target, path


def test_656478_remains_in_stale_descendants() -> None:
    target = "00000000000000000005f8f74e57aa4584aacfed509b8a6feb20bc22e7d60a34"
    with (REPO / "data" / "stale_descendants.csv").open(newline="") as f:
        hashes = {r["btc_header_hash"].lower() for r in csv.DictReader(f)}
    assert target in hashes
```

Delete `tests/test_stale_exclusions.py` after migrating its still-relevant assertions (the publication-CSV absence check, now keyed off the 31 error-block keys).

- [ ] **Step 4: Run the full test suite**

Run: `just test`
Expected: all PASS (no regressions across loaders, full-evidence, sidecar, relevance, reconcile, rsk)

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(error-blocks): migrate exclusion gate to error_blocks dataset, drop overlay"
```

---

## Task 5: Add the 946213 time-too-old row + time-rule validation

**Files:**
- Modify: `data/error-blocks/error_blocks.csv` (add row)
- Modify: `scripts/analysis/validate_error_blocks.py` (add time-rule checks)
- Modify: `scripts/prep/build_error_blocks.py` (merge `--monitor-export`)
- Test: `tests/test_error_blocks_validator.py` (extend)

- [ ] **Step 1: Obtain the monitor export (operator-coordinated, read-only)**

Coordinate with the operator for a read-only export of the 946213 event from the merge-mining-monitor (its DB/API). Record the monitor event identifiers. Do NOT write to the monitor. Place the export at a gitignored path (e.g. `cache/monitor_946213_export.json`).

- [ ] **Step 2: Write the failing time-rule test**

Append to `tests/test_error_blocks_validator.py`:

```python
def test_946213_time_below_mtp_revalidates() -> None:
    mod = _load_validator()
    import csv as _csv
    from stale_blocks_analysis.config import ERROR_BLOCKS_CSV as _p

    with _p.open(newline="") as f:
        row = next(r for r in _csv.DictReader(f) if r["height"] == "946213")
    assert "time_below_mtp" in row["rules_violated"]
    assert row["provenance"].startswith("monitor-live-capture:")
    assert mod.validate_row(row) == []
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m pytest tests/test_error_blocks_validator.py::test_946213_time_below_mtp_revalidates -v`
Expected: FAIL (`StopIteration` — no 946213 row yet)

- [ ] **Step 4: Add time-rule validation to the validator**

In `validate_error_blocks.py`, add MTP and future-limit checks. The MTP check needs the canonical parent's median-time-past; source it from committed canonical context (the epoch reference / a committed MTP-by-height sidecar the builder emits), not live RPC. Add to `validate_row`:

```python
TIME_RULES = {"time_below_mtp", "time_beyond_future_limit"}
FUTURE_LIMIT_SECONDS = 2 * 60 * 60  # Bitcoin's +2h future-time bound
```

For `time_below_mtp`, call `median_time_past_error(row, parent_mtp)` with the committed parent MTP and assert it returns a REJECTED string. For `time_beyond_future_limit`, assert `btc_time` exceeds the referenced neighbor/median time by more than the bound. Document the exact committed context source in the module docstring.

- [ ] **Step 5: Merge the 946213 row via the builder**

Run the builder with `--monitor-export cache/monitor_946213_export.json` so it appends the 946213 row with `provenance=monitor-live-capture:<event ids>`, `rejection_reason=time_below_mtp`, `rules_violated=time_below_mtp`. Re-run the builder to regenerate `data/error-blocks/error_blocks.csv` (now 32 rows).

- [ ] **Step 6: Run tests to verify they pass**

Run: `python -m pytest tests/test_error_blocks.py tests/test_error_blocks_validator.py -v`
Expected: all PASS (32 rows re-validate, including 946213)

- [ ] **Step 7: Commit**

```bash
git add data/error-blocks/error_blocks.csv scripts/analysis/validate_error_blocks.py scripts/prep/build_error_blocks.py tests/test_error_blocks_validator.py
git commit -m "feat(error-blocks): add 946213 time-too-old row from monitor evidence"
```

---

## Task 6: Add `error_block` to the classification vocabulary + monitor lockstep note

**Files:**
- Modify: `docs/data-reference.md` (Value vocabularies section)
- Modify: `docs/upstreaming.md` (lockstep coordination note)
- Test: `tests/test_error_blocks.py` (vocabulary pin)

Note: `config.py` has no `CLASSIFICATION_*` constants block (only `RELEVANCE_*`
constants at :423-429); the primary classification vocabulary is documented in
`docs/data-reference.md`, not enforced as constants. So this task documents
`error_block` in docs only — do not invent a new constants location.

- [ ] **Step 1: Write the failing vocabulary test**

Append to `tests/test_error_blocks.py`:

```python
def test_error_block_is_a_documented_classification() -> None:
    text = (REPO / "docs" / "data-reference.md").read_text()
    assert "`error_block`" in text
    assert "consensus-invalid" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_error_blocks.py::test_error_block_is_a_documented_classification -v`
Expected: FAIL (`error_block` not yet in data-reference.md)

- [ ] **Step 3: Document the new classification value**

In `docs/data-reference.md` "Value vocabularies" (around line 368), add `error_block` to the primary `classification` list: a consensus-invalid full-PoW block witnessed via merge-mining, catalogued in `data/error-blocks/error_blocks.csv`, never a stale/orphan contender. Note it is a breaking vocabulary change for the merge-mining-monitor importer and its ported relevance classifier, and that renames must land in lockstep.

- [ ] **Step 4: Add the lockstep coordination note**

In `docs/upstreaming.md`, add a section noting that `error_block` (plus the extended `rejection_reason` vocabulary `time_below_mtp`/`time_beyond_future_limit`) is a breaking change for the monitor; the monitor-side display work is a follow-up in that repo.

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_error_blocks.py::test_error_block_is_a_documented_classification -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add docs/data-reference.md docs/upstreaming.md tests/test_error_blocks.py
git commit -m "docs(error-blocks): add error_block classification vocabulary + monitor lockstep note"
```

---

## Task 7: Sweep 1 — rejected-row mining

**Files:**
- Create: `scripts/analysis/sweep_error_blocks_rejected_rows.py`
- Create: `results/analysis/error-blocks/rejected-rows-report.md` (generated)
- Modify: `data/error-blocks/error_blocks.csv` (append confirmed members)

- [ ] **Step 1: Implement the sweep**

`scripts/analysis/sweep_error_blocks_rejected_rows.py` scans every reachable chain classified inventory (`<chain>_stale_blocks.csv`) for rows with a `REJECTED:` `validation_status`. For each, it re-verifies `hash_meets_btc_difficulty` per row: those meeting the full target while failing a *contextual* consensus rule are error-block candidates (fed to the builder); those failing the target are not. It writes a dated report listing rows examined, candidates found, and negatives. Fails closed if no inventories are reachable, with `--allow-partial --output-dir` for diagnostics.

- [ ] **Step 2: Run the sweep and review the report**

Run: `python scripts/analysis/sweep_error_blocks_rejected_rows.py --chain-archive-dir /path/to/staging/chains --output-dir results/analysis/error-blocks`
Expected: writes `rejected-rows-report.md`; prints candidates found per chain (devcoin 16, i0coin 9 nBits-failures re-classified, etc.)

- [ ] **Step 3: Feed confirmed candidates to the builder and re-validate**

Run the builder to merge confirmed candidates, then:

Run: `python -m pytest tests/test_error_blocks_validator.py -v`
Expected: PASS (all rows including new members re-validate)

- [ ] **Step 4: Commit**

```bash
git add scripts/analysis/sweep_error_blocks_rejected_rows.py results/analysis/error-blocks/rejected-rows-report.md data/error-blocks/error_blocks.csv
git commit -m "feat(error-blocks): rejected-row mining sweep + report"
```

---

## Task 8: Sweep 2 — time-rule sweep

**Files:**
- Create: `scripts/analysis/sweep_error_blocks_time_rule.py`
- Create: `results/analysis/error-blocks/time-rule-report.md` (generated)
- Modify: `data/error-blocks/error_blocks.csv` (append confirmed members)

- [ ] **Step 1: Implement the sweep**

For every stale/unknown candidate across all chains' classified artifacts, compare header `nTime` against the canonical chain's MTP at the claimed height (from committed canonical context) and against the +2h future bound relative to neighbor evidence. Re-verify full PoW per row. Write a dated report including negative results (eras examined, e.g. 2011 BTC Guild, 2015-16 cluster).

- [ ] **Step 2: Run, review, feed to builder, re-validate**

Run: `python scripts/analysis/sweep_error_blocks_time_rule.py --output-dir results/analysis/error-blocks`
Then builder + `python -m pytest tests/test_error_blocks_validator.py -v`. Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add scripts/analysis/sweep_error_blocks_time_rule.py results/analysis/error-blocks/time-rule-report.md data/error-blocks/error_blocks.csv
git commit -m "feat(error-blocks): time-rule sweep + report"
```

---

## Task 9: Sweep 3 — version/BIP sweep

**Files:**
- Create: `scripts/analysis/sweep_error_blocks_version_bip.py`
- Create: `results/analysis/error-blocks/version-bip-report.md` (generated)
- Modify: `data/error-blocks/error_blocks.csv` (append confirmed members)

- [ ] **Step 1: Implement the sweep**

Apply BIP34 (v2 + coinbase height), BIP66 (v3), BIP65 (v4) enforcement heights vs header versions and coinbase contents across all catalogued stale candidates in chains not previously swept (beyond namecoin/devcoin/ixcoin). Re-verify full PoW. Write a dated report including negatives.

- [ ] **Step 2: Run, review, feed to builder, re-validate**

Run: `python scripts/analysis/sweep_error_blocks_version_bip.py --output-dir results/analysis/error-blocks`
Then builder + `python -m pytest tests/test_error_blocks_validator.py -v`. Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add scripts/analysis/sweep_error_blocks_version_bip.py results/analysis/error-blocks/version-bip-report.md data/error-blocks/error_blocks.csv
git commit -m "feat(error-blocks): version/BIP sweep + report"
```

---

## Task 10: Sweep 4 — coinbase-form sweep

**Files:**
- Create: `scripts/analysis/sweep_error_blocks_coinbase_form.py`
- Create: `results/analysis/error-blocks/coinbase-form-report.md` (generated)
- Modify: `data/error-blocks/error_blocks.csv` (append confirmed members)

- [ ] **Step 1: Implement the sweep**

Check scriptSig length bounds (2–100) and BIP34 height serialization across all candidates. The `coinbase_scriptsig_length_above_100` reason currently has exactly one member; this sweep confirms whether that is real or an artifact of incomplete prior coverage. Re-verify full PoW. Write a dated report including negatives.

- [ ] **Step 2: Run, review, feed to builder, re-validate**

Run: `python scripts/analysis/sweep_error_blocks_coinbase_form.py --output-dir results/analysis/error-blocks`
Then builder + `python -m pytest tests/test_error_blocks_validator.py -v`. Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add scripts/analysis/sweep_error_blocks_coinbase_form.py results/analysis/error-blocks/coinbase-form-report.md data/error-blocks/error_blocks.csv
git commit -m "feat(error-blocks): coinbase-form sweep + report"
```

---

## Task 11: Documentation + CHANGELOG + per-chain views

**Files:**
- Create: `docs/error-blocks.md`
- Modify: `docs/chains/<chain>.md` (devcoin, i0coin, ixcoin, namecoin, syscoin, others whose accounting changed)
- Modify: `docs/process-data-outcomes.md`
- Modify: `CHANGELOG.md`
- Modify: `AGENTS.md`
- Create: `scripts/reports/report_error_blocks_by_chain.py` (per-chain observation views → `results/`)

- [ ] **Step 1: Write `docs/error-blocks.md`**

Define the category (full-PoW + AuxPoW-witnessed + ≥1 named mechanically-recheckable consensus violation; target-failures excluded), the rule set with enforcement heights (BIP34 two-stage 224,413/227,931, BIP66 v3 363,725, BIP65 v4 388,381, MTP, +2h future limit, coinbase scriptSig 2–100), the evidence standard, and per-rule counts (generated from the dataset).

- [ ] **Step 2: Update chain docs and process-data-outcomes**

Update each affected `docs/chains/<chain>.md` accounting section to point at the dataset, and refresh integrated counts in `docs/process-data-outcomes.md`. Fact-check counts against the CSVs.

- [ ] **Step 3: Add the per-chain view generator**

`scripts/reports/report_error_blocks_by_chain.py` reads `error_blocks.csv` and writes per-chain observation views under `results/analysis/error-blocks/by-chain/` (diagnostics, not committed loader inputs), keyed off `source_chains`/`source_child_observations`.

- [ ] **Step 4: Update AGENTS.md and CHANGELOG**

Add the new artifact, the `error_block` value, and the data-boundary note to `AGENTS.md`. Add a `## Unreleased` CHANGELOG entry in the existing prose+bullets style, including the deliberate 656478 handling and the monitor lockstep note.

- [ ] **Step 5: Run full validation**

Run: `just test && just lint && just check-leaks`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add docs/ CHANGELOG.md AGENTS.md scripts/reports/report_error_blocks_by_chain.py results/analysis/error-blocks/
git commit -m "docs(error-blocks): category doc, chain accounting, per-chain views, changelog"
```

---

## Self-Review notes (already applied)

- **Spec coverage:** Tasks 1-5 cover the dataset/builder/validator/946213; Task 4 the gate migration + 656478; Task 6 the vocabulary + lockstep; Tasks 7-10 the four sweeps; Task 11 docs. The `direct_stale_only` removal is Task 4 (no CSV mutation needed — 656478 already absent from validated-stales).
- **Placeholders:** The builder (Task 2 Step 3) and sweep scripts show structure with the load-bearing functions; the harvest/join loop is described precisely because exact archive paths depend on the operator's mount point. This is intentional — the implementer must confirm the mounted archive path before running.
- **Type consistency:** `validate_row(row) -> list[str]`, `validate_dataset(path) -> list[str]`, loader functions keep the exact `stale_exclusions` signatures. `ERROR_BLOCKS_CSV` used consistently.
