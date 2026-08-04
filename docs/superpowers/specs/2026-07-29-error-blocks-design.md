# Error Blocks — a first-class consensus-invalid dataset

**Date:** 2026-07-29
**Status:** Approved (design), pending implementation plan
**Source brief:** `~/Downloads/merge-mining-research-error-blocks-brief.md`

## 1. Concept & taxonomy

An **error block** is a full-proof-of-work Bitcoin block, witnessed via
merge-mining evidence, that *would have been* a stale/orphan contender except
that the block itself violates a consensus rule. It lost no race; it was never
eligible to race. The proof of work is real (the header hash meets the Bitcoin
target in force at the claimed position), the AuxPoW commitments are real, but
the block is consensus-invalid for a specific, mechanically re-checkable reason.

Representation decisions (confirmed with the operator):

- **Formal class:** `consensus_invalid` — matches the existing
  `exclusion_scope` value and the semantics already documented in
  `docs/data-validity.md`.
- **Informal / public name:** "error blocks" — used in filenames, the module
  name, and docs.
- **`error_block` becomes a new primary `classification` value**, alongside
  `canonical` / `stale` / `unknown` / `stale_descendant` / `near`. This is a
  taxonomy change that **must land in lockstep with merge-mining-monitor** (its
  importer and its ported BTC-orphan relevance classifier read the
  classification strings verbatim; see `docs/data-reference.md` "Value
  vocabularies"). This change carries the repo-side vocabulary change plus an
  explicit, documented monitor-coordination note. The monitor-side display work
  remains a separate follow-up in that repository.
- **Subcategory = the `rejection_reason` vocabulary**, extended with
  `time_below_mtp` and `time_beyond_future_limit`. A row may violate several
  rules: `rules_violated` (pipe-joined) captures the full set, while
  `rejection_reason` remains the primary / first failure.
- **Explicitly NOT error blocks:** blocks that merely fail the PoW *target*
  (shares / `near` / weak candidates). The distinction is re-verified per row
  via `hash_meets_btc_difficulty`, never inherited from an old rejection label.

## 2. The artifact & its schema

One committed file — **`data/error-blocks/error_blocks.csv`** — is
simultaneously the rich evidence dataset *and* the exact-key exclusion gate. It
is the single source of truth; the old `data/stale_block_exclusions.csv` is
removed.

Layout decision (confirmed): **consolidated global file + per-chain views.**
Error blocks are chain-independent (one invalid BTC block is witnessed by many
sibling chains, and the exclusion gate is global), so the source of truth is a
single consolidated CSV. Per-chain observation views are generated as
diagnostics under `results/` (not committed loader inputs) for readability.

Columns (ordered for the loader). The schema keeps human-auditable convenience
columns alongside the raw evidence hex; the validator cross-checks that every
derived column matches what it re-parses from the hex:

```
height, hash, btc_prev_hash, btc_header_version, btc_time, btc_bits,
expected_nbits, btc_header_hex, coinbase_height, coinbase_scriptsig_hex,
source_chains, source_child_observations, classification, rejection_reason,
rules_violated, first_observed_child_time, provenance
```

Load-bearing field notes:

- `hash` in **display order** (matching the existing overlay and all loaders);
  byte order handled via `stale_blocks_analysis.auxpow_chainid` helpers, never
  guessed.
- `classification` = `error_block` for every data row (the new primary value).
  The exclusion gate keys off this value directly — there is **no
  `exclusion_scope` column** (it is redundant: every row in this dataset is
  `consensus_invalid` by construction).
- `rejection_reason` = primary failure (existing vocabulary plus the new
  `time_below_mtp` / `time_beyond_future_limit`); `rules_violated` =
  pipe-joined full set. "Primary" follows the ordered gate composition already
  used by `stale_header_context_error` (median-time-past → minimum version →
  coinbase scriptSig length → BIP34 coinbase height): the first failure in that
  order.
- `btc_header_version`, `btc_time`, `btc_bits`, `coinbase_height` are
  convenience/audit columns derivable from `btc_header_hex` and
  `coinbase_scriptsig_hex`; they are kept so the CSV is human-auditable without
  re-parsing, and the validator asserts derived == stated on every row.
- `first_observed_child_time` = earliest child-chain observation timestamp where
  known.
- `provenance` = the artifact each row's facts came from (e.g.
  `chain-archive:devcoin classified/devcoin_stale_blocks.csv`, or
  `monitor-live-capture:<event ids>` for the 946213 row).

Seeding:

- The 31 `consensus_invalid` overlay rows seed the dataset. Each is re-validated
  by the offline validator before entry — no row is grandfathered on its old
  label.
- The BTC height **946213** `time-too-old` row (F2Pool-attributed, April 2026,
  witnessed by namecoin 821553 / syscoin 2226227 / elastos 2196610) is added
  from the merge-mining-monitor live evidence with explicit
  `provenance=monitor-live-capture:<event ids>`. The export is pulled read-only,
  coordinated with the operator; this change includes that row (not deferred).

The 32nd overlay row — height **656478**, `exclusion_scope=direct_stale_only`,
`rejection_reason=reclassified_stale_descendant` — is **not** an error block and
is **not** carried into this dataset. It is a valid `stale_descendant` that was
double-catalogued: present both in `data/stale_descendants.csv` (its correct
home) and in a per-chain direct-stale validated CSV (its original, pre-
reclassification home). The old overlay row existed only to subtract it from the
direct-stale view. This change instead **removes 656478 from its per-chain
validated-stales CSV**, so a `stale_descendant` lives in exactly one place and
no `direct_stale_only` exclusion guard is needed at all. (This is a deliberate,
documented expansion beyond the brief's "do not change validated-stales
baselines" boundary — see §5.)

## 3. Components & data flow

Four pieces, each with one job:

- **`src/stale_blocks_analysis/error_blocks.py`** (renamed from
  `stale_exclusions.py`) — the gate/loader. Keeps the exact public API
  (`load_stale_exclusion_keys`, `load_consensus_invalid_stale_keys`,
  `exclude_stale_rows`, `exclude_consensus_invalid_rows`) so all existing
  callers behave identically, but reads `error_blocks.csv` and derives the
  exclusion key set from `classification == "error_block"` rows (no
  `exclusion_scope` column). Adds new-signature aliases under error-blocks
  naming. The module docstring documents the dataset as the single source of
  truth. All callers — `stale_blocks.py`,
  `full_evidence.py`, `scripts/reports/build_upstream_stale_sidecar.py`,
  `scripts/analysis/reconcile_unknown_stale_ancestry.py`,
  `scripts/analysis/classify_btc_stale_relevance.py`,
  `scripts/classify/classify_rsk_stales.py` — are updated to the new import.
  Because 656478 is removed from its validated-stales CSV at the source, the
  `direct_stale_only` scope and its special-casing in the descendant loader path
  are deleted; the gate no longer distinguishes scopes.

- **`scripts/prep/build_error_blocks.py`** — the builder. Harvests evidence for
  seed rows and sweep candidates from the reachable sources (the chain archive
  on `<archival-host>` `staging/chains/<chain>/classified/`, the sibling
  `stale-blocks-research/results/full-evidence/`, and the monitor export for
  946213), assembles rows, and writes `error_blocks.csv`. Read-only against all
  sources; fails closed with a clear message when a required private input is
  absent (mirroring the ancestry-reconciliation guard), with an `--allow-partial`
  diagnostic mode writing to a disposable `--output-dir`.

- **`scripts/analysis/validate_error_blocks.py`** — the offline re-derivation
  validator, wired into `tests/` so it runs in CI like the existing gates. For
  every row it re-checks from committed bytes:
  (a) `hash_meets_btc_difficulty` (full PoW — separates error blocks from
      shares);
  (b) the named consensus violation(s) in `rules_violated` — BIP34
      coinbase-height (two-stage), min-version (BIP34/BIP66/BIP65 heights),
      coinbase scriptSig 2–100 length, median-time-past, and the +2h future-time
      limit;
  (c) `expected_nbits` against the committed `data/bitcoin-epoch-reference/`
      nBits table;
  (d) MTP / active-parent context from committed canonical reference data, not
      live RPC.
  A row that fails re-derivation fails the test suite.

- **Sweep scripts** under `scripts/analysis/` (one per sweep, each emitting a
  report): `sweep_error_blocks_time_rule.py`,
  `sweep_error_blocks_rejected_rows.py`, `sweep_error_blocks_version_bip.py`,
  `sweep_error_blocks_coinbase_form.py`. Each examines the reachable classified
  inventories, re-verifies `hash_meets_btc_difficulty` per row, proposes new
  error-block rows (fed to the builder), and writes a dated report to
  `results/analysis/error-blocks/` including **negative results** (rows
  examined, nothing found).

## 4. Error handling, evidence standard & validation

Evidence-first rules (the brief's hard constraint):

- **No row enters on an old label.** Every violation is re-derived from
  committed bytes by the validator. A seed row whose evidence cannot be
  recovered is flagged, and the build fails closed until its evidence is staged.
- **Fail closed on missing private inputs.** The builder and sweeps refuse to
  write committed artifacts when a required archive/export is absent, and
  require `--allow-partial` plus a disposable `--output-dir` for any diagnostic
  run — the same contract as `reconcile_unknown_stale_ancestry.py` and
  `just monitor-evidence`. ("Fail closed" = error out rather than silently
  emit a partial/empty/guessed result.)
- **PoW/target distinction is re-verified, never inherited.**
  `hash_meets_btc_difficulty` runs per row; target-failures are excluded from
  the error-block set (they are `near` / shares, a different category).
- **Hash byte order explicit** via `auxpow_chainid` helpers.
- **Gate parity test:** a test asserts the new `error_blocks.csv` yields exactly
  the 31 historical `consensus_invalid` exclusion keys (the error-block set is
  unchanged by the migration). Separately, a test asserts that height 656478 no
  longer appears in any per-chain direct-stale validated CSV and still appears
  in `data/stale_descendants.csv`, so the net loader output is provably
  equivalent to the old overlay's behavior — with the `direct_stale_only`
  band-aid removed at the source rather than via an exclusion row.

Testing:

- New `tests/test_error_blocks.py` covering: schema/column order, the offline
  validator against pinned fixtures (one per rule, including the new time
  rules), gate parity with the historical overlay key set, fail-closed behavior
  on malformed/blank scope, and the loader API.
- Existing `tests/test_stale_exclusions.py` is migrated to point at the new
  file/module (its inventory pins become the seed-parity assertions over the 31
  error-block keys, plus the 656478 removal/single-home checks).
- Validation commands: `just test`, `just lint`, `just check-leaks`, plus
  focused runs of the new validator and each sweep's report.

## 5. Documentation, monitor lockstep & scope boundaries

Docs:

- **`docs/error-blocks.md`** (new) — defines the category, the precise
  definition (full-PoW + AuxPoW-witnessed + ≥1 named mechanically-recheckable
  consensus violation; target-failures excluded), the rule set with enforcement
  heights (BIP34 two-stage at 224,413/227,931, BIP66 v3 at 363,725, BIP65 v4 at
  388,381, median-time-past, the +2h future limit, coinbase scriptSig 2–100),
  the evidence standard, and per-rule counts.
- **`docs/data-reference.md`** — add `error_block` to the primary
  `classification` vocabulary and document the new dataset + the removed overlay.
- **`docs/chains/<chain>.md`** — update the accounting sections for every chain
  whose exclusion accounting changed (devcoin 484→16, i0coin 176→9, ixcoin,
  namecoin, syscoin, etc.) to point at the dataset.
- **`docs/process-data-outcomes.md`** — updated integrated counts.
- **`CHANGELOG.md`** — `## Unreleased` entry in the existing prose+bullets style.
- **`AGENTS.md`** — update the data-boundary and taxonomy notes to name the new
  artifact and the `error_block` value.

Monitor lockstep (carried in this change):

- The repo-side vocabulary change (`error_block` classification, extended
  `rejection_reason`) is documented as a **breaking change for the
  merge-mining-monitor importer** and its ported relevance classifier. Flag it
  explicitly in `docs/upstreaming.md` / a coordination note; the actual
  monitor-side display work stays in that repo as a follow-up, but the
  vocabulary contract change is called out so it does not land silently.

Scope boundaries (what this change does NOT do):

- No changes to `stale_descendants.csv` semantics, or the in-flight
  `codex/child-header-hydration` branch's files.
- **Deliberate scope expansion (operator-approved):** this change removes height
  656478 from its per-chain validated-stales CSV so a `stale_descendant` lives
  in exactly one place. This crosses the brief's original "do not change
  validated-stales baselines" boundary and is called out explicitly here and in
  the CHANGELOG. No other validated-stales baseline is touched.
- Error blocks are **not** proposed upstream to `bitcoin-data/stale-blocks`
  (they are not valid blocks).
- No writes to the merge-mining-monitor — the 946213 evidence is pulled
  read-only via an operator-coordinated export.
- No refactors beyond what the dataset, gate migration, and sweeps require.

## Evidence sources (confirmed reachable)

- **Chain archive (`<archival-host>`):**
  `~/mmr-child-header-regen-20260729/staging/chains/<chain>/classified/<chain>_stale_blocks.csv`
  — full classifier inventories carrying `validation_status` (`REJECTED: ...`
  reasons), `expected_nbits`, `btc_header_hex`, `coinbase_scriptsig_hex`,
  `btc_time`, `btc_bits`. Verified for devcoin (468 VALID + 16 REJECTED = 484).
- **Sibling repo:** `~/dev/bitcoin/stale-blocks-research/results/full-evidence/<chain>_evidence.csv`
  — 43-column evidence exports with provenance / observation metadata.
- **Monitor live evidence:** the 946213 row, via operator-coordinated read-only
  export (event IDs recorded as provenance).

## Acceptance

- `data/error-blocks/error_blocks.csv` exists with the 31 `consensus_invalid`
  seed rows re-validated plus whatever the sweeps find and the 946213 row, each
  row passing the offline re-derivation validator in CI. No `exclusion_scope`
  column; the gate keys off `classification == "error_block"`.
- Height 656478 is removed from its per-chain validated-stales CSV and remains
  in `data/stale_descendants.csv`; the `direct_stale_only` guard is gone.
- Every sweep has a written report (members found, rows examined, negative
  results included).
- One source of truth between the dataset and the exclusion gate; net loader
  output provably equivalent to the old overlay's behavior (parity test).
- `error_block` added to the classification vocabulary with the monitor lockstep
  documented.
- Docs and CHANGELOG updated; `just test`, `just lint`, `just check-leaks` pass.
