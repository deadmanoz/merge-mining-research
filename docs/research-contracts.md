# Research evidence contracts

Read before changing parsers, classifiers, loaders, datasets or publication. These contracts prevent stronger research claims from being inferred from weaker evidence.
All paths and commands are relative to the repository root.

## Contents

- [Data Boundaries](#data-boundaries)
- [Research Semantics](#research-semantics)

## Data Boundaries

Be strict about what belongs in git:

- Commit canonical compact loader inputs such as
  `data/validated-stales/*_validated_stales.csv` (RSK included: `rsk_validated_stales.csv`)
  and the stale-descendant module:
  `data/stale_descendants.csv` for accepted parent verdicts and
  `data/stale_descendant_observations.csv` for authenticated child-chain
  witnesses. Commit
  `data/error-blocks/error_blocks.csv`, the consensus-invalid error-blocks
  dataset that is also the exact-key exclusion gate preventing invalid
  upstream or archived candidates from entering public outputs, along
  with its `data/error-blocks/mtp_context.csv` sidecar. Commit the recovered
  witness ledger `data/error-blocks/error_block_observations.csv`. Ancestry
  reconciliation may emit disposable error-candidate diagnostics, but those
  reports are never publication inputs or committed datasets. Do not commit
  private source inventories.
- Do not commit fetched upstream data under `data/stale-blocks/` or
  `data/mining-pools/`.
- Do not commit attribution run outputs. `just attribute` labels the
  merge-mining-recovered stales and writes
  `results/analysis/pool-attribution/*`, covered by the existing
  `results/analysis/*/` ignore; the export is a regenerable run product
  (see `docs/pool-attribution.md`).
- Do not commit raw extracts, PoW-passing intermediates, full classifier
  outputs (including `data/*_canonical_blocks.csv`), rejection scratch files,
  marker SQLite/Parquet outputs, or node data directories unless a doc
  explicitly says that exact artifact is public.
- RSK raw checkpoints, fallback ledgers, classifier-family manifests, and
  staged temporary files are private run artifacts. Keep the checkpoint and
  its two content-bound CSVs together; the classifier intentionally refuses a
  raw CSV without its complete matching checkpoint.
- VCash's partial explorer recovery follows the same canonical-companion
  contract: `scripts/prep/hydrate_vcash_canonical.py` writes the gitignored
  `data/vcash_canonical_blocks.csv` by default, and monitor publication
  discovers that filename under `data/` or a supplied chain archive.
- Commit the complete final-category projection under
  `results/monitor-evidence/`: every available canonical row, accepted direct
  stale and descendant, and strict/weak unknown-row observation. Do not
  introduce per-chain publication allowlists. The per-chain
  `*_monitor_evidence.csv` payloads are tracked uniformly through Git LFS;
  `monitor-evidence-counts.csv` and `monitor-evidence-manifest.json` remain
  ordinary Git files. The JSON manifest owns the per-chain inventories for the
  canonical error-block and stale-descendant observation ledgers consumed by
  downstream importers; consumers must not reconstruct them from the lower-level
  ledgers. Run `git lfs pull` before consuming or regenerating the committed
  payloads.
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
  to a trusted stale root. `data/stale_descendants.csv` is the parent-verdict
  table and contains only `classification=stale_descendant`,
  `validation_status=VALID_STALE_DESCENDANT` rows.
- `data/stale_descendant_observations.csv` is the authenticated witness ledger.
  Its source classification records which archive bucket held the observation;
  that value is audit evidence, not the parent verdict. Parent classification
  comes only from the ancestry and consensus gates.
- Reconciliation considers every authenticated candidate, starts only from the
  declared trusted-root set, and verifies the complete predecessor path. The
  canonical parent loader requires the stored root height and fork depth to
  agree, authenticates both path endpoints, and checks every path edge against
  its parent-verdict header or an exact height/hash-bound 80-byte header from
  the selected pinned upstream census. Upstream-only intermediate nodes supply
  path evidence without invented child witnesses or accepted parent rows.
  The loader also
  requires the exact parent schema, matching `expected_nbits`, true PoW/header
  flags, and an accepting BIP34 verdict. It requires the terminal identity to
  occur in the selected data tree's accepted per-chain or pinned upstream
  direct-stale inputs, after that tree's canonical error-block exclusion. A
  purported root is direct stale only when its predecessor is on Bitcoin's
  active main chain. The witness ledger assigns each authenticated child event
  to exactly one Bitcoin parent while preserving distinct same-chain events
  that witness the same parent. Consensus-invalid candidates route to
  `error_block` before stale-descendant publication. A catalogued error block is
  an explicit invalid ancestry terminal: every child or deeper descendant
  inherits that invalid verdict and blocks publication through the ancestry
  diagnostic. Correct
  incomplete or low-work source evidence; admit only an authenticated full-PoW
  violation to the canonical error module. Never promote a row from its source
  bucket label alone.
- Raw classifier rows retain their source classification in source artifacts.
  Monitor publication joins exact authenticated witnesses to the accepted
  parent verdict and emits `classification=stale_descendant`,
  `validation_status=VALID_STALE_DESCENDANT`, and
  `relevance_reason=valid_stale_descendant`. It does not turn unrelated unknown
  or canonical rows into descendants.
- The word "orphan" is reserved for the strict/weak relevance buckets
  (`strict_btc_orphan`/`weak_btc_orphan`), matching the merge-mining-monitor's
  vocabulary. The broad evidence state is `unknown`. Historical private
  inventories may use `orphan` in the
  `classification` column; writers emit `unknown` and readers accept both.
- The taxonomy has two axes and they must not be conflated: the primary
  `classification` (`canonical`/`stale`/`unknown`/`stale_descendant`/`near`/`error_block`)
  is the evidence state, and the derived `btc_stale_relevance` refines unknown
  rows into `strict_btc_orphan`/`weak_btc_orphan`/`excluded`/`pending`
  (constants in `config.py`). `error_block` is a consensus-invalid
  full-proof-of-work Bitcoin block witnessed via merge mining (catalogued in
  `data/error-blocks/error_blocks.csv`); it was never a stale/orphan contender,
  and blocks that merely fail the PoW target stay `near`. `stale`/`stale_descendant` rows already carry
  their confirmation on the primary axis (a VALID `validation_status`), so
  they carry an EMPTY `btc_stale_relevance` and a `relevance_reason` of
  `valid_direct_stale`/`valid_stale_descendant`; the derived axis holds only
  the unknown-row refinement values. The merge-mining-monitor's BTC-orphan
  classifier is a port of `scripts/analysis/classify_btc_stale_relevance.py`
  and its importer reads the `btc_stale_relevance`/`relevance_reason` columns
  verbatim, so renames of those columns, the bucket strings, or the
  `classification` vocabulary (including adding `error_block`) must land in
  lockstep with the monitor, and
  strict/weak never fold into the primary `classification` column. See
  `docs/data-reference.md` "Value vocabularies".
- Deduplicate stale events by `(height, hash)`, not by height alone. Competing
  same-height stale hashes are real data.
- Preserve upstream rows on exact duplicates while carrying AuxPoW coinbase
  evidence for later attribution research.
- RSK is special: its proof does not expose the real parent coinbase. Preserve
  `rsk_miner` as evidence, but do not treat historical `pool_label` values as a
  current attribution result. The attribution layer may surface those labels
  only with `attribution_basis=rsk_historical`.
- Pool attribution is dual: every attributed record carries `pool` (tag owner)
  plus `template_producer` (the dated proxy-cluster fold in
  `template_producers.py`). The attribution export covers only the
  merge-mining-recovered stales; labelling the combined
  census-plus-recovered set, the observed-vs-expected analysis, and
  the propagation-era scheme live in the companion `stale_rate_analysis` repo;
  this repo deliberately carries no era constants or era vocabulary, and the
  attribution API takes `min_height` as a caller-supplied parameter.
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
  `*_validated_stales.csv` as `validation_status` / `expected_nbits`. The only
  accepted direct-stale statuses are exactly `VALID` and
  `VALID (post-BCH, difficulty matches BTC)`. Either means that this declared
  publication profile passed; neither proves that a complete Bitcoin block was
  consensus-valid. Externally verified body-invalid parents belong in the
  error-block catalogue with a commit-pinned `body_evidence.csv` reference.
  The catalogue excludes them from accepted stale outputs; raw source verdicts
  remain audit evidence. A descendant whose inferred height has no committed
  canonical `nBits` reference is unpublishable. Loaders read and filter the
  verdict but never recompute the gate.
  RSK does not expose the real parent coinbase and therefore cannot apply the
  two coinbase-dependent checks independently. The exact-key error-blocks
  exclusion gate (`data/error-blocks/error_blocks.csv`)
  protects every publication surface from consensus-invalid candidates.
- Hash byte order must be explicit. Use the helpers in
  `stale_blocks_analysis.auxpow_chainid` instead of guessing display vs
  internal order.
- Current novelty counts belong only in generated `results/novelty.md`. Run
  `just novelty` after changing compact inputs or the upstream pin, and
  `just novelty-check` to verify freshness. Other docs link to the report.
  The generator requires complete inputs and verified upstream Git metadata;
  canonical-only chains deliberately have no validated-stales CSV.
  `data_source_provenance.py` shares pin and clone-state inspection with
  attribution; failed Git inspection returns unknown state, never clean.
- Chronological novelty follows `CHAINS_BY_AUXPOW_ACTIVATION` in `config.py`.
  This is a reproducible attribution convention, not a real-time observation
  claim.
