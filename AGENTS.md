# AGENTS.md

Instructions for AI agents working in this repository. These rules apply to the
whole repo unless a more specific `AGENTS.md` is added in a subdirectory.

## Project Purpose

This is a Bitcoin merge-mining research repo. When a sibling chain merge-mines
Bitcoin, it records on an independent ledger what a Bitcoin miner was building
on: the Bitcoin block it extended (usually canonical, sometimes stale), that
block's coinbase where exposed, and the time. Pool identity is a later
inference, not a field recorded directly by every sibling chain. This repo
mines that evidence for questions about Bitcoin mining generally: mining pools,
propagation, and the canonical-versus-stale record. The remit is broad. The most
developed strand is stale-block recovery; a tested marker registry supports
future canonical-chain census work.
See `docs/research-directions.md` for the strands and further directions.

The stale-block-recovery strand combines the upstream
`bitcoin-data/stale-blocks` dataset with AuxPoW and merge-mining evidence from
other chains, validates recovered stale events, preserves coinbase and miner
evidence for later attribution research, and publishes compact recovery
evidence and diagnostics.

Treat this as a research pipeline, not a normal app. The important outputs are
claims, datasets, recovery diagnostics, and methodology docs. When code changes
affect those claims, update the corresponding data and docs in the same change
or call out what still needs regeneration.

## First Read

Before non-trivial edits, read the relevant local docs:

- `README.md` for setup, main commands, and the layout.
- `docs/research-directions.md` for the repo's scope and direction framing.
- `docs/auxpow-recovery.md` for the cross-chain recovery model.
- `docs/process-data-outcomes.md` for current integrated counts and caveats.
- `docs/upstreaming.md` for contribution rules to `bitcoin-data`.
- `docs/chains/<chain>.md` before changing a chain-specific extractor,
  classifier, loader, or CSV.

## Setup

Use Python 3.10 or newer.

```bash
git lfs install --local
git lfs pull --include="results/monitor-evidence/*_monitor_evidence.csv"
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
./scripts/fetch-data.sh
```

The full test suite reads the committed monitor-evidence baseline, so CI and
local clean checkouts must materialize the Git LFS payloads before running it.

The development install includes pytest and Ruff. The core install
(`pip install -e .`) covers the acquisition/recovery pipeline when development
checks are not needed.

`scripts/fetch-data.sh` clones or updates the upstream datasets declared in
`data-sources.tsv` (`bitcoin-data/stale-blocks` under `data/stale-blocks/`) and
checks each out at its pinned commit, so recovery inputs are reproducible. Use
`just upstream-check` to compare the pin with upstream, `just upstream-update`
to update the pin, and `just upstream-sidecar` to build the contribution
sidecar. Override the location with `STALE_BLOCKS_DIR`. The script leaves a
clone that is on a branch or has local edits untouched.

## Common Commands

Prefer the `justfile` recipes when they cover the task:

```bash
just test
just test-markers
just full-evidence
just child-header-coverage
just strict-weak-orphans
just monitor-evidence
just upstream-check
just upstream-update
just upstream-sidecar
just lint
just check-leaks
```

`just monitor-evidence` is a publication build and fails closed unless the
private archive, relevance, and supplemental inputs are complete. Diagnostic
builds must pass `--allow-partial` with an explicit disposable `--output-dir`;
`--skip-canonical` is diagnostic-only, and normal publication includes every
available canonical row for every chain. Never point a partial build at the
committed monitor-evidence directory. Both modes stage the complete generated
artifact set before replacing prior files; unrelated files already in the
output directory are preserved.

Useful direct commands:

```bash
python -m pytest tests/
python scripts/analysis/reconcile_unknown_stale_ancestry.py
```

The ancestry command is a publication rebuild. It fails before writing unless
the private full/unknown inventories needed to reproduce every committed
descendant are staged under `data/`. Incomplete diagnostics must pass
`--allow-partial` together with explicit disposable `--results-dir` and
`--promoted-csv` paths; neither path may be a committed default.

## Repository Map

- `src/stale_blocks_analysis/`: importable recovery package for the
  stale-block-recovery direction. Shared core modules back the chain scripts:
  `auxpow_parse` (CAuxPow deserializer plus nBits/difficulty helpers), `btc_rpc`
  (batched JSON-RPC client), `btc_classify` (`classify_candidates` and the
  `run_classifier` driver), `btc_nbits_validation` (the contamination gate),
  `btc_stale_validation` (the combined expected-`nBits`, active-parent,
  median-time-past, historical minimum-version, coinbase scriptSig-length, and
  BIP34 coinbase-height gates),
  `stale_exclusions` (the exact-key consensus-invalid overlay), and the
  `CHAIN_SPECS` registry in `config.py`. The extraction, classification, loaders
  in `stale_blocks.py`, and evidence exports form the public recovery pipeline.
  Prefer adding shared logic here over re-inlining it in a script. Future
  research directions get their own packages.
- `scripts/`: extraction, classification, analysis, and utility scripts,
  organized into family subdirectories: `extract/`, `classify/`, `analysis/`,
  `reports/`, `prep/`. `compute_chain_novelty.py` and `fetch-data.sh` stay at
  the `scripts/` root. Unknown-ancestry reconciliation lives at
  `scripts/analysis/reconcile_unknown_stale_ancestry.py`. Scripts import the
  installed package and many default to `data/` paths for operator convenience.
- `data/`: committed compact loader inputs plus gitignored fetched/scratch data.
- `results/`: committed reference CSVs and recovery diagnostics.
- `docs/`: research directions, methodology, and per-chain provenance.
- `node-infra/`: Dockerized legacy chain nodes and operational notes.
- `cache/`: runtime cache, never committed.

## Data Boundaries

Be strict about what belongs in git:

- Commit canonical compact loader inputs such as
  `data/validated-stales/*_validated_stales.csv` (RSK included: `rsk_validated_stales.csv`)
  and `data/stale_descendants.csv`. Commit
  `data/stale_block_exclusions.csv`, the compact exact-key overlay that prevents
  corrected upstream or archived candidates from re-entering public outputs.
- Do not commit fetched upstream data under `data/stale-blocks/`.
- Do not commit raw extracts, PoW-passing intermediates, full classifier
  outputs (including `data/*_canonical_blocks.csv`), rejection scratch files,
  marker SQLite/Parquet outputs, or node data directories unless a doc
  explicitly says that exact artifact is public.
- Commit the complete final-category projection under
  `results/monitor-evidence/`: every available canonical row, accepted direct
  stale and descendant, and strict/weak unknown-row observation. Do not
  introduce per-chain publication allowlists. The per-chain
  `*_monitor_evidence.csv` payloads are tracked uniformly through Git LFS;
  `monitor-evidence-counts.csv` and `monitor-evidence-manifest.json` remain
  ordinary Git files. Run `git lfs pull` before consuming or regenerating the
  committed payloads.
- The largest consolidated datasets (full per-chain evidence exports,
  unknown-origin inventories over ~100 MB) are intended for future external
  publication and are not tracked in git. Private or bulky per-chain artifacts
  belong in the private archive, not in this repo.
- `results/` contains reference snapshots. Do not casually regenerate broad
  output sets as part of an unrelated code change.

If a script writes ignored scratch data to `data/`, leave it ignored. If a new
workflow needs a committed artifact, document why it is canonical and consumed
by the public pipeline.

## Research Semantics

Preserve these distinctions:

- A direct stale is a recovered BTC parent header whose `btc_prev_hash` is a
  canonical Bitcoin block. Per-chain loader CSVs represent these.
- A stale descendant is a BTC stale-fork continuation whose ancestry walks back
  to a known stale root. These live only in `data/stale_descendants.csv`
  and are loaded only with `classification=stale_descendant` and
  `validation_status=VALID_STALE_DESCENDANT`.
- Raw classifier rows labelled `unknown` remain unknown rows. Do not relabel
  them as direct stales just because a separate sidecar promotes a descendant.
- The word "orphan" is reserved for the strict/weak relevance buckets
  (`strict_btc_orphan`/`weak_btc_orphan`), matching the merge-mining-monitor's
  vocabulary. The broad evidence state is `unknown`. Legacy artifacts (the
  private archive, pre-rename inventories) wrote `orphan` in the
  `classification` column; writers emit `unknown` and readers accept both.
- The taxonomy has two axes and they must not be conflated: the primary
  `classification` (`canonical`/`stale`/`unknown`/`stale_descendant`/`near`)
  is the evidence state, and the derived `btc_stale_relevance` refines unknown
  rows into `strict_btc_orphan`/`weak_btc_orphan`/`excluded`/`pending`
  (constants in `config.py`). `stale`/`stale_descendant` rows already carry
  their confirmation on the primary axis (a VALID `validation_status`), so
  they carry an EMPTY `btc_stale_relevance` and a `relevance_reason` of
  `valid_direct_stale`/`valid_stale_descendant`; the derived axis holds only
  the unknown-row refinement values. The merge-mining-monitor's BTC-orphan
  classifier is a port of `scripts/analysis/classify_btc_stale_relevance.py`
  and its importer reads the `btc_stale_relevance`/`relevance_reason` columns
  verbatim, so renames of those columns, the bucket strings, or the
  `classification` vocabulary must land in lockstep with the monitor, and
  strict/weak never fold into the primary `classification` column. See
  `docs/data-reference.md` "Value vocabularies".
- Deduplicate stale events by `(height, hash)`, not by height alone. Competing
  same-height stale hashes are real data.
- Preserve upstream rows on exact duplicates while carrying AuxPoW coinbase
  evidence for later attribution research.
- RSK is special: its proof does not expose the real parent coinbase. Preserve
  `rsk_miner` as evidence, but do not treat historical `pool_label` values as a
  current attribution result.
- Post-2017 contamination from BCH/BSV-like parent headers is filtered with
  self-target PoW and expected-`nBits` checks. Before classification, the shared
  driver corroborates the published hash, previous hash, time, and `nBits`
  against the serialized 80-byte header and checks its self-target proof of
  work. Direct stale candidates also apply Bitcoin's contemporaneous minimum
  block versions (2 from BIP34 height
  227,931, 3 from BIP66 height 363,725, and 4 from BIP65 height 388,381) and
  BIP34's two-stage coinbase-height rule: version 2 or newer from height
  224,413, then every valid block from height 227,931. Do not weaken these
  gates, plus active-parent placement, median-time-past, and the coinbase
  scriptSig's 2-to-100-byte limit where the real parent coinbase is available.
  The necessary available-evidence profile runs once at classification time
  and its verdict is persisted per row in the committed
  `*_validated_stales.csv` as `validation_status` / `expected_nbits`. `VALID`
  means that this declared publication profile passed; it is not proof that a
  complete Bitcoin block was consensus-valid. The committed file is
  VALID-only; loaders read/filter the verdict but never recompute the gate.
  RSK does not expose the real parent coinbase and therefore cannot apply the
  two coinbase-dependent checks independently. The exact-key exclusion overlay
  protects sources that have not yet incorporated a correction.
- Hash byte order must be explicit. Use the helpers in
  `stale_blocks_analysis.auxpow_chainid` instead of guessing display vs
  internal order.
- Chronological novelty follows `CHAINS_BY_AUXPOW_ACTIVATION` in `config.py`.
  This is a reproducible attribution convention, not a real-time observation
  claim.

## Code Conventions

- Keep shared paths, protocol constants, the relevance vocabulary, and chain
  chronology in `src/stale_blocks_analysis/config.py`. `config.py`
  intentionally creates output directories at import time.
- Loader functions in `stale_blocks.py` should return the established row shape:
  `height`, `hash`, `source`, and when available `_scriptsig_hex` and
  `_outputs_str`. The current recovery pipeline does not return pool labels.
- Use `csv.DictReader` and `csv.DictWriter` for CSV work. Preserve stable column
  names and deterministic row ordering. Evidence writers emit LF explicitly so
  LFS-backed CSVs remain byte-reproducible without Git text normalization.
- Use binary parsers and existing helpers for Bitcoin wire data. Avoid ad hoc
  slicing unless the surrounding code already uses that exact convention.
- For coinbase marker additions, prefer adding data entries in
  `coinbase_markers.py` over changing parser logic. Add or update tests with
  pinned fixtures.
- Keep dependencies modest. Core analysis is intentionally mostly stdlib plus
  the runtime dependencies in `pyproject.toml`; development checks use the
  optional `dev` extra.
- Do not perform broad formatting or doc reflow in research docs. Their counts,
  caveats, and wording are often audit evidence.

## Validation

Run the narrowest meaningful checks for the files you touched, then broaden
when behavior crosses module boundaries.

- Parser, loader, or helper change: run the relevant `python -m pytest ...`
  target under `tests/`.
- Coinbase marker registry change: run `just test-markers`.
- Chain classifier or extraction change: run focused script-level checks and
  any chain-specific tests. If committed loader inputs change, regenerate the
  dependent novelty or recovery outputs that the docs cite.
- Docs-only changes usually do not need tests, but fact-check counts against
  the CSVs or JSON summaries they cite.

Always state which commands were run and which were skipped.

## Node Infrastructure

Each `node-infra/<chain>/` directory is its own operational workspace with a
README and usually a local `justfile`. Read the chain README before building or
starting a node.

Keep generated node datadirs, RPC credentials, logs, block indexes, and
chainstate files out of git. Some chain directories already have local
`.gitignore` files for `data/`; if you introduce a new generated datadir, add
an ignore rule before running long-lived node commands.

## Issue Tracking

Use GitHub issues and pull requests for bug reports and contributions; see
`CONTRIBUTING.md`. (In-progress research tasks are additionally tracked in a
local issue database that is not part of this repository.)

## Shell and Git Safety

- The working tree may contain user edits. Inspect `git status --short` before
  editing and do not revert unrelated changes.
- Never run `git push`, post to GitHub, or publish externally without explicit
  user permission.
- Keep credentials and private hostnames out of committed files and logs.
  Redact private infrastructure to angle-bracket placeholders (for example
  `<archival-host>`, `<chain-data-dir>`) rather than naming real hosts, LAN IPs,
  or `/mnt` paths. `just check-leaks` greps tracked files for a built-in LAN-IP
  baseline plus any operator tokens listed in the gitignored `.leak-tokens`
  file (see `.leak-tokens.example`), and fails if any reappear.
- Prefer `rg` and `rg --files` for search.
- Use non-interactive command forms where aliases might prompt:

```bash
cp -f source dest
mv -f source dest
rm -f file
ssh -o BatchMode=yes host command
```

## Pre-Handoff Checklist

Before handing back:

- Confirm the changed files are limited to the task.
- Run appropriate validation or explain why it was not run.
- Re-check `git status --short`.
- Summarize data/result/doc regeneration separately from code edits.
- Call out unresolved research caveats, missing private inputs, or cache/RPC
  limitations that affect the result.
