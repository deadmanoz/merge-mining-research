# AGENTS.md

This repository extracts Bitcoin merge-mining evidence from sibling chains for
research. Its outputs are claims, datasets and methodology, so code changes
must keep the affected data and documentation consistent. `AGENTS.md` is the
canonical entry point; `CLAUDE.md` links to it.

## Architecture

`src/stale_blocks_analysis/` owns shared extraction, classification, evidence
normalization and publication logic. `scripts/` contains thin CLI wrappers.
Pool attribution is a separate pass over recovered evidence; acquisition and
classification never import it. Extend existing owners before adding a new
script, package or abstraction. Pipeline details are in
[docs/pipeline-reference.md](docs/pipeline-reference.md).

The Kraft native dumps are the foundation sources for Huntercoin and Xaya.
Their former Arweave and CDN recoveries are historical provenance, not fallback
inputs or parallel workflows. Keep originals privately; do not maintain legacy
acquisition or scan-position compatibility for these chains.

## Build & Test

Use Python 3.10+ and activate the project `.venv` before every Python command.
Install with `python -m pip install -e ".[dev]"` after activation. Prefer the
root or workspace `justfile` when it covers the task.

```bash
source .venv/bin/activate
git lfs install --local
git lfs pull --include="results/monitor-evidence/*_monitor_evidence.csv"
./scripts/fetch-data.sh
just format-check
just lint
just test
just validate-error-blocks
just validate-coinbase-outputs
just novelty-check
just check-leaks
```

The complete suite includes the materialized LFS dataset tests and Docker
Compose policy tests. Compose tests only render configuration; the CLI is
required, and tests never start nodes. Use focused tests first, then the full
suite when behavior crosses boundaries. State checks run and skipped.

Run `just novelty` after compact inputs or the upstream pin change. Current
novelty counts belong only in the generated `results/novelty.md`. Do not
regenerate unrelated reference outputs.

## Conventions

- Shared paths, protocol constants, chain chronology and relevance vocabulary
  belong in `config.py`. Imports must not create output directories.
- Use existing binary parsers and explicit hash byte-order helpers. Do not
  infer display/internal order or use ad hoc wire slicing.
- Use `csv.DictReader`/`DictWriter`, stable schemas and deterministic ordering.
  Evidence writers emit LF explicitly for reproducible LFS bytes.
- Standard AuxPoW extractors use `standard_auxpow_extraction_columns()`.
  Source-specific acquisition fields normalize into the shared evidence schema.
- Keep dependencies modest. Change normal producers to perform the final
  workflow; remove obsolete repair paths and test-only seams.
- Update the changelog and affected methodology with code/data changes. Avoid
  broad documentation reflow; counts and caveats may be audit evidence.

## Research Safeguards

Read [docs/research-contracts.md](docs/research-contracts.md) before
changing evidence or publication behavior. In particular:

- Distinguish canonical, direct stale, stale descendant, unknown, near and
  consensus-invalid error evidence. Source bucket labels are not verdicts.
- Keep unknown relevance on its separate `btc_stale_relevance` axis; never
  fold strict/weak orphan buckets into primary `classification`.
- Deduplicate Bitcoin events by `(height, hash)`, not height alone. Preserve
  distinct child witnesses. Do not turn missing evidence into an empty dataset.
- Keep all publication validation gates and exact error-catalogue exclusions.
  Accepted stale verdicts prove the declared available-evidence profile, not
  complete Bitcoin body or UTXO consensus validity.
- Authenticate every stale/invalid predecessor path and endpoint. Admit
  catalogue entries only with genuine full-work violations and child witnesses;
  keep the catalogue, evidence sidecars and observation ledger together.
- Stored native ancestry and AuxPoW commitments do not establish native
  active-chain membership or full child consensus.
- Pool identity is a later inference. RSK lacks the real parent coinbase; its
  historical labels are not a current attribution result.
- Schema and classification vocabulary changes must coordinate with Monitor.
  Research supplies read-only artifacts; Monitor deployment is separately owned.

## Publication & Data Boundaries

Commit compact accepted inputs, canonical error/ancestry modules and the
complete Monitor projection, with payload CSVs in Git LFS. Keep raw extracts,
full classifier inventories, node datadirs, credentials and bulky research
exports in the private archive. Fetched upstream dependencies stay ignored.
See the reference for exact public surfaces and retained-input contracts.

`just monitor-evidence` fails closed on incomplete private inputs and publishes
all available canonical rows. Its staging is atomic and unrelated output files
are preserved. Never put diagnostic partial output in committed results.
`--allow-partial` and `--skip-canonical` require explicit disposable destinations.

Use `just reconcile-stale-ancestry` for complete ancestry publication; validate
the error module first. Do not hand-edit accepted ancestry CSVs or replace them
with a partial run. Use a stable non-secret RPC source label such as
`core-reference`, never credentials, a private hostname or a transient tunnel.

RSK classifier families bind exact dependency bytes and require a completed
checkpoint from a clean checkout. Staged publication can select new inputs
with `--data-dir` while retaining those runtime-bound dependencies. Read the
pipeline reference before regenerating either family.

## Operational Safety

Read [docs/node-operations.md](docs/node-operations.md) before node
or archive work, then the workspace README. Read the ignored
`docs/private/infra-access.md` in the operator's primary checkout for private
locations; keep those details out of tracked files and logs.

- Treat archive payloads as immutable. Historical paths may be hardlinked.
  Work on separate copies; never write preserved inputs in place.
- Adopt populated historical datadirs with retained verified images and
  documented offline profiles. Do not initialize, reindex or upgrade them.
- Require noncreating data/config binds. Keep RPC scoped privately, restart
  disabled until acceptance, and startup ordered after mounts/interfaces.
- Research-owned images and variants live in `node-infra/<workspace>/`.
  The archive dashboard and Monitor each have separate owning repositories.
- Use `docker compose` v2. Do not build, start or synchronize nodes as an
  incidental consequence of a research or publication command.

## Repository Etiquette

Inspect `git status --short` before edits and preserve unrelated user changes.
Commit only when requested. Never push, post to GitHub or publish externally
without explicit authorization. Follow `CONTRIBUTING.md` and
`docs/upstreaming.md`; in-progress research additionally uses local Beads.

Redact infrastructure with placeholders such as `<archival-host>` and
`<chain-data-dir>`. Run `just check-leaks` before committing. Keep credentials
and node database files outside Git.

Before handoff, recheck status, explain code changes separately from regenerated
data/docs, report validation and state research caveats or missing inputs.

## Documentation

- [Pipeline reference](docs/pipeline-reference.md): producer and package contracts.
- [Research contracts](docs/research-contracts.md): evidence and publication semantics.
- [Node operations](docs/node-operations.md): archive and legacy-node runbooks.
- `README.md`: setup, supported commands and layout.
- `docs/research-directions.md`: research scope.
- `docs/auxpow-recovery.md`: cross-chain model.
- `docs/process-data-outcomes.md`: current integrated results and caveats.
- `docs/chains/<chain>.md`: read before changing a chain-specific workflow.
- `docs/data-reference.md`, `docs/data-validity.md`, `docs/error-blocks.md`:
  schemas and evidence methodology.

Update the relevant documentation alongside code changes. Keep detailed
references and runbooks in `docs/`; keep only agent instructions and links here.
