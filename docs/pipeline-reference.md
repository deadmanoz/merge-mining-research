# Pipeline implementation reference

This reference describes package ownership and producer lifecycles. Read it
before changing producers, source discovery, classification or publication.
All paths and commands are relative to the repository root.

## Contents

- [Setup](#setup)
- [Common Commands](#common-commands)
- [Shared AuxPoW commitment checks](#shared-auxpow-commitment-checks)
- [Repository Map](#repository-map)
- [Code Conventions](#code-conventions)

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

The `dataset`-marked tests read the committed monitor-evidence baseline, so a
full local test run must materialize the Git LFS payloads first. CI runs the
remaining tests across the Python matrix without LFS and runs the publication
dataset checks once with the payloads materialized.

The node-infra Compose policy tests (`tests/test_node_infra_compose.py`, part
of the default pytest suite) require the Docker Compose CLI. They only render
the committed Terracoin/Fractal profiles with `docker compose config`. They never
start containers, build or pull images, or contact a node, and
fail loudly when the renderer is unavailable. Run them alone with
`just test-node-infra`; CI verifies the renderer explicitly before the suite.

The development install includes pytest and Ruff. The core install
(`pip install -e .`) covers the acquisition/recovery pipeline when development
checks are not needed.

`scripts/fetch-data.sh` clones or updates the upstream datasets declared in
`data-sources.tsv`: `bitcoin-data/stale-blocks`, `bitcoin-data/mining-pools`,
and `bitcoin-data/invalid-blocks`, each under its corresponding `data/` directory. It
checks each out at its pinned commit, so recovery inputs are reproducible. Use
`just upstream-check` to compare the pin with upstream, `just upstream-update`
to update the pin, and `just upstream-sidecar` to build the contribution
sidecar. Override the locations with `STALE_BLOCKS_DIR`,
`LOCAL_MINING_POOLS_DIR`, and `INVALID_BLOCKS_DIR`. The pinned
`data/invalid-blocks/` dependency supplies authenticated bodies for external
body-invalid verdicts; it is fetched by the same script and remains ignored.
The script leaves a clone that is on a branch or has local edits untouched.

## Common Commands

RSK extraction accepts `RSK_RPC_URL` for a remote archive endpoint; the default
is loopback port 4444. Long runs pin a settled endpoint as documented in
`docs/chains/rsk.md`.

Staged regeneration keeps Monitor's preservation baseline in the runtime
checkout's materialised
`results/monitor-evidence/`; install the complete prior generation there
before a staged rebuild. `--data-dir` can select the new publication inputs
while the runtime retains original dependency bytes bound by a classifier
manifest. See `docs/data-reference.md` for the source-family contract.

Repeated `--chain-archive-dir` arguments are searched in command-line order.
Put the refreshed source view before older archive roots and keep its full,
canonical and unknown inventories together; later roots can otherwise supply
a superseded companion. Required historical child-header checks run before
publication filtering, including for rows that will not be published.

Prefer the `justfile` recipes when they cover the task:

```bash
just test
just test-unit
just test-dataset
just test-markers
just test-node-infra
just extract-huntercoin --blocks-dir <working-blocks-dir> --output <private-output.csv>
just extract-xaya --blocks-dir <working-blocks-dir> --output <private-output.csv> --all-headers
just validate-coinbase-outputs
just full-evidence
just child-header-coverage
just strict-weak-orphans
just monitor-evidence
just validate-error-blocks
just reconcile-stale-ancestry --rpc-source-label core-reference
just attribute
just upstream-check
just upstream-update
just upstream-sidecar
just novelty
just novelty-check
just lint
just check-leaks
```

`just monitor-evidence` is a publication build and fails closed unless the
private archive and relevance inputs are complete. Diagnostic
builds must pass `--allow-partial` with an explicit disposable `--output-dir`;
`--skip-canonical` is diagnostic-only, and normal publication includes every
available canonical row for every chain. Never point a partial build at the
committed monitor-evidence directory. Both modes stage the complete generated
artifact set before replacing the publication; unrelated files already in the
output directory are preserved. Complete exports may use an external final
destination. When output is staged for later installation elsewhere, pass
`--reported-output-dir` with that final destination; otherwise the output
directory itself is the reported destination. Completeness gates do not
require installation into the repository's default results directory.

Useful direct commands:

```bash
python -m pytest tests/
```

The low-level ancestry CLI is diagnostic and staging-only. Incomplete runs
must pass `--allow-partial` together with explicit disposable
`--results-dir`, `--parent-verdicts-csv`, `--observations-csv`, and
`--error-candidates-csv` paths. No generated output may resolve under the
canonical `data/` tree or a committed `results/` surface; the dedicated ignored
`results/analysis/stale-ancestry/` namespace is the only in-repository
diagnostic destination.

`just validate-error-blocks` validates the reviewed canonical error catalogue,
MTP sidecar, and exact child-observation ledger. `just reconcile-stale-ancestry`
is the complete stale-ancestry publication workflow. It validates that error
module first, then rebuilds the accepted parent verdicts in
`data/stale_descendants.csv` and their authenticated witnesses in
`data/stale_descendant_observations.csv`. Any uncatalogued consensus-invalid
candidate aborts before installation. Do not substitute a partial ancestry
run or hand-edit either published stale-ancestry CSV.
Source coordinates beneath the selected `--data-dir` retain their logical
`data/` paths before archive symlinks are resolved. Moving a staging directory
does not change witness provenance; genuinely external paths use the shared
archive redaction convention. Reads and source digests still use the actual files.
Publication requires a stable, non-secret `--rpc-source-label`; use the
configured Bitcoin Core node's durable inventory name (for example,
`core-reference`), not a hostname containing credentials or a transient tunnel
address. The parent verdict persists it as `bitcoin-core-rpc:<label>`.

## Shared AuxPoW commitment checks

`auxpow_commitment.parent_merkle_matches` takes internal-order transaction,
branch and parent-root hashes. `child_commitment_failure` takes an internal-order
child hash and branch, index, script bytes and chain ID. It checks the first
display-order root occurrence, marker uniqueness and adjacency (or legacy root
offset at most 20), the size/nonce footer, tree size and LCG slot. Its neutral
failure and mismatch values let adapters retain their existing diagnostics.
These helpers authenticate commitments, not full child or Bitcoin body consensus.

The live Huntercoin/Xaya dict adapter retains transaction parsing/completeness
and index guards. Qbit retains its bounded non-witness coinbase envelope and
early chain-index range check. Lyncoin retains its parent chain-ID rejection,
pre-Flex child identity, late slot check and height-specific errors. Each owner
keeps its original validation order and target rules. Wire-parser ownership is
unchanged. Huntercoin can retain authenticated non-coinbase controls; Xaya
rejects those parents.

The common rules were checked against pinned native `src/auxpow.cpp` in
Huntercoin `6aa3da0bbe4a7d16352c02f07369a00ae78fcf59`,
Xaya `7537e1d25a28f30b66f006a6cd2afdda8d343c9e` and
Lyncoin `c289540da7ea3bb78f6e9eb661ad72b90476cc40`, and Qbit's
`src/auxpow_validation.cpp` and `src/auxpow.cpp` at
`70fea84f5becfb57463247af09790df5ddd424f8`. This is a comparison of the shared
rules, not native consensus replay: Huntercoin's historical fork-dependent
marker requirement remains outside this evidence profile, and Research's
existing first-failure order need not match native order. Qbit mainnet's
`nAuxpowDisplayCommitmentHeight` is zero in `src/kernel/chainparams.cpp`.

## Repository Map

- `src/stale_blocks_analysis/`: importable recovery package for the
  stale-block-recovery direction. Shared core modules back the chain scripts:
  `auxpow_parse` (CAuxPow deserializer plus nBits/difficulty helpers), `btc_rpc`
  (batched JSON-RPC client),   `btc_classify` (`classify_candidates` and the
  `run_classifier` driver), `classifier_cli` (the thin-chain classify
  command: `scripts/classify/classify_stales.py --chain <key>`),
  `native_headers` (exact block-file framing, optional XOR decoding and
  genesis-linked stored ancestry), `auxpow_commitment` (parent transaction
  coinbase identity, Merkle inclusion and child commitment/chain-slot
  authentication),
  `huntercoin_extraction` (foundational native Huntercoin acquisition),
  `xaya_extraction` (native Xaya acquisition and body-authenticated child
  heights, using the shared `block_body` owner at the PowData transaction
  offset and canonical height encoding from `bitcoin_binary`),
  `extract_driver` (batched raw-hex extraction plus the thin-adopter CLI
  lifecycle; wrappers keep child-RPC construction and the version gate),
  `btc_nbits_validation` (the contamination gate),
  `btc_stale_validation` (the combined expected-`nBits`, active-parent,
  median-time-past, historical minimum-version, coinbase scriptSig-length, and
  BIP34 coinbase-height gates),
  `error_ancestry` (authenticated predecessor paths to reviewed invalid roots,
  delegated to by `error_block_validation` for `consensus_invalid_parent`),
  `error_blocks` (the exact-key consensus-invalid exclusion gate, reading
  `data/error-blocks/error_blocks.csv`), `block_body` (shared body/merkle/witness
  authentication) and `body_evidence` (commit-pinned external verdict references
  and body authentication, without re-deriving body-rule invalidity), and the
  `CHAIN_SPECS` registry in `config.py`. The extraction, classification, loaders
  in `stale_blocks.py`, and evidence exports form the public recovery pipeline.
  `evidence_sources.py` owns source discovery, `evidence_normalization.py`
  owns the shared row contract, and `evidence_hydration.py` owns Namecoin
  and child-identity hydration. `rsk_extraction.py` owns RSK's durable raw
  CSV, fallback-ledger, checkpoint, digest, and classifier-input contract;
  `rsk_fallback.py` recognizes the variable-width RLP fallback signature
  representation without independently verifying the recovered signing key.
  `rsk_classifier_artifacts.py` stages and verifies the private classifier
  family, binding repository dependencies by checkout-relative path and digest;
  custom external dependencies remain manifest-relative. `rsk_sidecar.py` owns
  its Monitor-sidecar cell contract.
  `full_evidence.py` assembles full-evidence
  generation and re-exports the established helper surface.
  `monitor_exports.py` owns the final-category monitor projection and its
  publication constants; `monitor_publication.py` owns fail-closed
  publication validation and staged writes.
  The pool-attribution layer (`pool_identification`, `stale_merge`,
  `template_producers`, `attribution`; see `docs/pool-attribution.md`) is a
  separate pass over already-loaded records; the acquisition/recovery side
  never imports it.
  Prefer adding shared logic here over re-inlining it in a script. Future
  research directions get their own packages.
- `scripts/`: extraction, classification, analysis, and utility scripts,
  organized into family subdirectories: `extract/`, `classify/`, `analysis/`,
  `reports/`, `prep/`. `compute_chain_novelty.py` and `fetch-data.sh` stay at
  the `scripts/` root. Unknown-ancestry reconciliation is coordinated by
  `scripts/analysis/reconcile_unknown_stale_ancestry.py`; observation loading,
  ancestry traversal, and report publication live in
  `reconcile_observations.py`, `ancestry_walk.py`, and
  `reconcile_publication.py` in the installed package. The supported publisher
  is `scripts/prep/publish_stale_ancestry.py`. Error blocks are a reviewed,
  canonical data module validated by
  `scripts/analysis/validate_error_blocks.py` and CI. Four population sweeps under `scripts/analysis/`
  sharing `scripts/analysis/_sweep_common.py`, and
  `scripts/reports/report_error_blocks_by_chain.py` (per-chain diagnostic
  views). Thin AuxPoW classification is `scripts/classify/classify_stales.py
  --chain <key>` (a `CHAIN_SPECS` row, not a new sibling script). Thin
  raw-hex AuxPoW extractors that already use `run_extraction` keep a short
  wrapper for child-RPC construction and the version gate; CLI lifecycle
  and row construction live in `extract_driver`. A new thin raw-hex chain
  adds a `CHAIN_SPECS` row, a `_gate`, and that wrapper; not a copied
  `main()`. Hathor uses
  a range-neutral metadata ledger plus one sealed acquisition dataset, which
  `scripts/classify/classify_hathor.py` classifies directly without persisted
  classifier phases. RSK uses an explicit half-open extraction range, a
  coupled private fallback ledger, and an atomic checkpoint that content-binds
  each committed byte segment and both pinned chain endpoints. Its classifier
  accepts only a completed content-addressed checkpoint from a clean Git
  worktree, records that exact HEAD and the original dependency fingerprints,
  rechecks them immediately before promotion, stages the complete output
  family, emits a hash manifest last, and keeps the private
  `rsk_canonical_blocks.csv` companion alongside the stale/unknown inventory.
  ROD's publication input is a canonical-only companion built by
  `scripts/prep/build_rod_canonical.py`. The producer requires the complete
  private extraction audit and independently reviewed child and Bitcoin bodies,
  plus the audit-bound complete classification summary supplied with
  `--classification-summary`. It verifies the selected chunk and receipt
  against that summary's input manifest, validates the whole special-candidate
  inventory, and executes only verified frozen parser source bytes. It
  validates the pinned body digests and PowData proof, and writes to a fresh
  private output directory. Do not create an empty `rod_validated_stales.csv`.
  Scripts import the installed package and many default to
  `data/` paths for operator convenience.
- `data/`: committed compact loader inputs plus gitignored fetched/scratch data.
- `results/`: committed reference CSVs and recovery diagnostics.
- `docs/`: research directions, methodology, and per-chain provenance.
- `node-infra/`: Dockerized legacy chain nodes and operational notes.
- `cache/`: runtime cache, never committed.

## Code Conventions

`AGENTS.md` owns the common conventions. Additional owner contracts:

- Loader functions in `stale_blocks.py` return `height`, `hash`, `source`, and
  when available `_scriptsig_hex` and `_outputs_str`. Recovery does not return
  pool labels; attribution is a later pass.
- The blkdat classifier requires complete exact output scripts and emits the
  canonical rendering in every split, including P2PK and nulldata. Monitor
  baseline comparisons use the same chain-aware normalization as ingestion;
  retained projections cannot establish exact output positions.
- For coinbase marker additions, prefer data entries in `coinbase_markers.py`
  over parser changes, with pinned-fixture checks.
