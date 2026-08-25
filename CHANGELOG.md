# Changelog

## Unreleased

Keep error-observation publication updates fail-closed when an ordinary monitor
artifact is missing or the regenerated aggregate falls below its existing
floor. Require every recovered witness to carry an authenticated child hash,
deriving it from the supplied child header when available.

Harden add-only error-observation updates by validating ordinary payload
contents, preserving published parent and witness identities, rejecting
duplicate child identities, and publishing separate validation contracts for
ordinary evidence and consensus-invalid error observations.

Require add-only ordinary artifacts to retain the complete monitor schema and
the exact relevance axes emitted for each supported classification.

Reject add-only rows without a Bitcoin parent hash, crossed orphan verdict
tuples, manifest count drift, or error-observation validation tokens in stale
rows.

Also verify serialized parent headers, live-chain child identities, exact raw
relevance tokens, and the ordinary status contract across every row type.

Corroborate all published parent-header fields and any serialized live-chain
child header during add-only preflight.

Add the pool-attribution layer. The repo has always retained coinbase
evidence for a later attribution phase; this lands that phase. A pinned
clone of bitcoin-data/mining-pools joins the fetched datasets, and
`just attribute` turns the retained evidence into an export of pool labels
for the merge-mining-recovered stales.

Identification matches each coinbase against the registry: scriptSig tags
longest-first, then coinbase OP_RETURN outputs, then payout addresses.

The record set is this repo's own recovered evidence: every AuxPoW loader
plus the stale descendants. The upstream census is not labelled here; the
combined census-plus-recovered set belongs to the stale-rate analysis,
which the companion repo assembles from the same functions.

Every row carries three attribution fields: the tag-owner `pool`, a
`template_producer` that folds modern proxy-pooled tags into the entity that
actually built the template, and an `attribution_basis` naming the kind of
evidence (`coinbase`, `rsk_historical`, or `unattributed`). RSK's labels
come from a historical miner registry and only ever appear under their own
basis, never as current attribution.

The export is a gitignored run product, not a committed dataset. The
observed-vs-expected analysis and the propagation-era scheme live in a
companion analysis repo, so this repo carries no era constants;
`docs/pool-attribution.md` states the boundary and the export contract.

Label error blocks during classification instead of discovering them by hand
afterwards. A shared routing step now sorts every gate-rejected stale
candidate by what the rejection means, re-deriving the broken consensus rules
from the row's own bytes. The three meanings are ranked rather than tested in
any convenient order, because one row can satisfy several of them: a placement
rejection makes the row `unknown` first (with no active-chain parent its height
was never established, so no height-dependent rule is trustworthy); a
difficulty that is not Bitcoin's at that height also makes it `unknown` and
outranks a broken rule, since a foreign SHA-256 chain's header is not an
invalid Bitcoin block, the sole exception being
`nbits_retarget_not_applied`, whose bits are the previous epoch's by
definition; only then does a proven violation become
`classification=error_block` in its own bucket file; and a rejection whose
evidence proves nothing stays a rejected stale, as does one whose canonical
`nBits` was never recorded. Contamination is decided from the persisted
`expected_nbits` rather than the verdict string, which the later header-context
gate can overwrite.

The routing runs uniformly across the shared driver, the four direct-gate
classifiers, the namecoin/i0coin classifier, RSK (version, median-time-past,
and retarget rules only, as its proof exposes no coinbase), Hathor Phase C, and
the stale-descendant reconciliation. Hathor Phase B now writes the shared
`VALID`/`REJECTED:`/`UNKNOWN:` verdict vocabulary, with Phase C accepting the
pre-rename tokens archived intermediates still carry; Phase C also loads the
committed retarget-epoch table, so an epoch-start candidate carrying the
previous epoch's bits becomes an error block there rather than being dropped,
and its re-routed unknowns get an `_unknown_blocks` peer instead of vanishing
from both the inventory and the unknown-ancestry walk. The ancestry
reconciliation derives rules only from header bytes that authenticate against
the claimed hash, and routes the candidates it does judge out of
`data/stale_descendants.csv` into a new `--error-blocks-csv` peer, so the
descendant sidecar keeps a single `classification`. The classifier output
writer fails loudly on an unrecognised classification instead of silently
dropping the row, and its `rejected` count spans every bucket the routing
produced (with a `rejected_stale`/`rejected_error_block`/`rejected_unknown`
breakdown) so a fully re-routed run cannot report zero rejections.
`nbits_retarget_not_applied` and the two `bip34_*_coinbase_height_missing`
rules join the shared derivation, the rejected-rows sweep gains namecoin
coverage, and the RSK classifier refuses aliased output paths before it opens
any of them. All 33 committed error blocks re-derive unchanged under the shared
decision.

Preserve LF line endings in both error-block CSV writers and make the offline
error-block validator reject every row whose `classification` is not exactly
`error_block`. Project a source row originally labelled `stale` to
`stale_descendant` only when its accepted sidecar observation matches both the
source chain identity and the compact exact-key direct-stale correction
overlay; ordinary unknown-row descendant observations continue to preserve
their original source classification.

Project the accepted stale-descendant sidecar's `VALID_STALE_DESCENDANT`
verdict onto every corresponding monitor source observation while preserving
its original source classification as provenance. Regenerate the complete
monitor-evidence publication from the authenticated source estate so every
committed payload follows the same current builder contract, including an
empty stale-gate axis for canonical and unresolved-unknown rows, plus blank
child heights where the offline source cannot authenticate consensus height.
Publish the exact BIP34 child height for 19,610 Xaya canonical observations
that still carried legacy block-file positions in the prior monitor
projection.

Require a stale-descendant projection to match the source chain, Bitcoin
height, and header hash, so a mistyped source height cannot enter monitor
evidence or satisfy its publication preflight. Make the error-block builder
reject duplicate witnessing-chain declarations, make its offline validator
reject duplicate canonical keys, and require every committed error-block
sweep inventory to meet its recorded minimum row baseline before replacing a
publication report. Add Elastos to the rejected-row sweep coverage map.

Reclassify the preserved Elastos and Syscoin raw extracts against Bitcoin Core
and correct 44 side-chain headers previously retained as canonical into valid
direct stales. Add the shared Elastos/Syscoin stale descendant, recover child
identity for all newly retained monitor rows, and rebuild the monitor evidence,
novelty outputs, and ancestry sidecar. Make normalized evidence inputs
idempotent, remove Elastos-only classifier columns and status semantics, and
exclude the mixed upstream-contribution sidecar from the direct-stale root set
so descendant publication cannot rewrite its own ancestry on a later run.

Stop persisting block-file scan order as child-chain data. Generic `blk*.dat`
extracts now omit scan sequence and leave unresolved height blank; the RPC
normalizer fills only an authenticated consensus height resolved by child hash.
Remove the old synthetic i0coin `child_height`, CoiledCoin `clc_height`, and
archived Doichain height values while retaining uniform blank height columns
and their other evidence. Normalize every committed validated CSV to the same
16-column core schema, with source-specific research columns trailing. Exports
with one or more rows lacking an exact child height disclose
`child_height=unavailable`.

Derive Xaya's exact consensus child height from its BIP34 child coinbase after
the `PowData`/`CAuxPow` wrapper and fail the output transaction if any
merge-mined record lacks that enforced height. Validate every populated field
in incomplete coverage bundles, require the stale-descendant coverage input,
and align canonical-companion `source_rows` accounting with the deduplicated
publication projection.

Require Huntercoin classification to start from its refreshed raw extraction,
refuse empty live child-identity recovery work lists, and accept a recovered
identity only when both source and sidecar heights are nonnegative integers.

Integrate VCash's partial canonical recovery through the standard discovered
`vcash_canonical_blocks.csv` source and normal evidence validation path. Remove
the generic pre-normalized supplemental-evidence escape hatch and its separate
publication guard, preserving the actual child timestamps already carried by
the VCash recovery source.

Define the standard Bitcoin-family AuxPoW extraction column order once and use
it across all 12 ordinary RPC extractors. Reject pre-hydration schemas across
every custom appender, require live identity sidecars to agree with complete
source-authenticated bundles, reject Git LFS pointers and malformed evidence
schemas in child-header coverage, and document the shared 16-column validated
stale layout.

Publish all 30 accepted stale-descendant source observations through their
exact per-chain monitor rows. The 28 observations sourced from unknown rows
retain `classification=unknown` and record
`relevance_reason=valid_stale_descendant`; the Namecoin and RSK observations
corrected from direct stales are projected as
`classification=stale_descendant` with
`validation_status=VALID_STALE_DESCENDANT`. Publication now fails closed if
any accepted `(chain, btc_header_hash)` observation is absent, and provenance
redaction resolves relative paths before deciding whether they are
repository-local.

Consolidate complete and partial child-header authentication in the shared
parser, separate Huntercoin source-index and acquisition-coverage validation
from its scan driver, remove redundant contract tests, and enforce unused-name
checks. CI now runs lint, formatting, and leak checks once; exercises the unit
suite across supported Python versions without downloading LFS payloads; and
runs the `dataset`-marked publication invariants once with Git LFS. Child
identity recovery now skips optional canonical rows, keeping uniform canonical
publication from expanding a bounded non-canonical recovery into a full-chain
scan.

Store every per-chain monitor-evidence publication payload in Git LFS while
keeping its counts CSV and JSON manifest in ordinary Git, and emit generated
evidence and child-identity CSV line endings as LF directly so regenerated
artifacts remain byte-reproducible.

Teach every historical Namecoin-family extraction path to emit authenticated
child-chain evidence directly from its original block source. Raw RPC blocks,
decoded JSON dumps, offline `blk*.dat` scans, Huntercoin block binaries,
Blockbook responses, and Xaya's `PowData` wrapper now produce
`child_block_hash`, `child_header_hex`, `child_block_time`, and `child_nbits`;
the classifier and evidence exporters preserve and validate the same bundle.
`just child-header-coverage` reports per-chain hydration coverage and fails on
header/hash, header/time, or header/`nBits` contradictions. The completed
source-authenticated regeneration covers 2,933,154 of 2,933,154 historical
rows with zero unrecoverable rows, plus all 6 accepted stale-descendant source
observations. The generic snapshot classifier's primary accepted and rejected
publication outputs now use the established normalized `btc_height` /
`btc_header_hash` / `btc_bits` schema. Its full `--classified-output` inventory
retains the source-specific `btc_stale_height` / `btc_hash` / `btc_bits_hex`
fields and validation annotations. The normalized rejected rows no longer carry
standalone `nbits_match` or `post_bch_fork` columns; those diagnostics remain
represented by `validation_status` and `expected_nbits` and are preserved as
standalone fields in the full classifier inventory.

Promote consensus-invalid full-proof-of-work Bitcoin blocks ("error blocks")
from a negative exclusion overlay into a first-class, re-derivable published
dataset, hunt for the rest of the population, and add `error_block` as a
primary classification value.

- New `data/error-blocks/error_blocks.csv` is simultaneously the rich evidence
  dataset and the exact-key exclusion gate: one committed consolidated file
  (33 rows) supersedes and removes the former `data/stale_block_exclusions.csv`
  overlay. Every row carries `classification=error_block` and a named,
  mechanically re-checkable `rejection_reason`; the gate keys off that value
  directly (no `exclusion_scope` column) via the renamed
  `src/stale_blocks_analysis/error_blocks.py` loader. A committed
  `data/error-blocks/mtp_context.csv` sidecar carries the canonical parent's
  median-time-past for the `time_below_mtp` row.
- `error_block` is added to the primary `classification` vocabulary alongside
  `canonical`/`stale`/`unknown`/`stale_descendant`/`near`: a consensus-invalid
  full-PoW block witnessed via merge mining that was never a stale/orphan
  contender. This is a **breaking vocabulary change for the
  merge-mining-monitor importer** and its ported relevance classifier; renames
  and additions must land in lockstep with the monitor (documented in
  `docs/data-reference.md` and `docs/upstreaming.md`). Blocks that merely fail
  the PoW target are not error blocks; they remain `near`.
- New builder `scripts/prep/build_error_blocks.py` assembles the dataset from
  reachable archives, and new offline validator
  `scripts/analysis/validate_error_blocks.py` re-derives every row's full PoW
  and named violation from committed bytes in CI (fail-closed; no row enters on
  an old label).
- Four sweeps under `scripts/analysis/` sharing `scripts/analysis/_sweep_common.py`
  hunted for new members, each with a dated report under
  `results/analysis/error-blocks/`. The rejected-row sweep found and promoted
  height 717,696 (`nbits_retarget_not_applied`, witnessed by emercoin and
  syscoin); height 946,213 (`time_below_mtp`) was added from merge-mining-monitor
  live evidence. The time-rule sweep found 0 `time_below_mtp` violations and
  resolved all 15 `time_beyond_future_limit` flags as late-mined (0 violations),
  establishing that the future-limit rule is not mechanically re-checkable
  offline. The version/BIP and coinbase-form sweeps found 0 new error blocks
  (no accepted VALID stale is an error block; the single
  `coinbase_scriptsig_length_above_100` member is real).
- Deliberate scope expansion (operator-approved): the former overlay's
  `direct_stale_only` row at height 656,478 is removed from the overlay-guard
  model entirely. It is a valid `stale_descendant` that was double-catalogued
  and now lives in exactly one place (`data/stale_descendants.csv`) with no
  exclusion guard. No other validated-stales baseline is touched.
- New `scripts/reports/report_error_blocks_by_chain.py` generates per-chain
  observation views under `results/analysis/error-blocks/by-chain/` as
  diagnostics (not committed loader inputs), via `just error-blocks-report`.

Recover node-verified child block identity for the six live-lifecycle chains
(Namecoin, RSK, Syscoin, Hathor, Elastos, Fractal) and publish it through the
monitor-evidence exports, so merge-mining-monitor's dataset importer can key
imported rows exactly like live capture and deduplicate against it.

- New `scripts/extract/recover_child_identity.py` recovers each row's child
  block hash and timestamp by height -> hash -> block RPC against the live
  child nodes (public API for Hathor), verifying the Bitcoin parent linkage
  re-derives from every fetched child block. All 2,287 chain/header
  observations across the six chains verified (1,919 distinct Bitcoin
  parent headers; 232 parents were observed by more than one chain);
  results are committed under `data/child-identity/`.
- The evidence schema gains `child_block_time` (after `child_block_hash`),
  and both the monitor and full-evidence exports hydrate the child identity
  columns from `data/child-identity/` at build time, refusing identities
  recorded at a different child height. A publication monitor build
  (without `--allow-partial`) now fails closed when a live-chain row lacks a
  verified identity, because the monitor importer deliberately skips such
  rows; `recover_child_identity.py --limit` requires a disposable
  `--output-dir` so a smoke run can never truncate the committed identity
  files.
  Hydrated child hashes use the pipeline's internal (wire) byte order
  (forward for RSK), matching monitor storage. Coverage lands in the counts
  `notes` as `child_identity_hydration=hydrated:N`, and the six live chains
  are targeted unconditionally: a missing, empty, or verification-less
  identity file surfaces as `missing_identity` (fatal to a publication
  build) instead of silently narrowing the target set.
- The RSK monitor export appends the seven columns the monitor's
  `rsk_merge_mining_evidence` sidecar requires (`rsk_miner`,
  `merge_mining_hash`, `is_uncle`, `uncle_index`, `uncle_parent_height`,
  `rsk_merkle_proof`, `rsk_coinbase_tail`), sourced from the live RSK node
  and cross-checked against the classified recovery metadata.
- The stale-descendants export is deliberately outside the exact
  child-identity contract: its rows aggregate observations from several
  chains into chain-less rows and merge-mining-monitor's import surface has
  no stale-descendants entry, so its child identity columns stay empty. The
  counts row records `child_identity=represented_by_source_chain_observations`;
  all 28 corresponding source-chain observations are published through their
  exact per-chain rows with source-authenticated child evidence. Six of those
  observations have complete historical child headers and belong to the 17
  refresh chains reported by `results/child-header-coverage.csv`; the live-chain
  observations use the independently node-verified child identities under
  `data/child-identity/`.
- Because the strict/weak orphan projections mirror the monitor export's
  schema, the regenerated RSK projection also carries the seven sidecar
  columns; the other chains' projections gain only `child_block_time`.
- Regenerate all 30 monitor publication artifacts from the same complete
  inputs. Normal publication now includes every available canonical row for
  every chain, with no per-chain allowlist, together with accepted direct
  stales, accepted descendants, and strict/weak unknown-row observations.
  `--skip-canonical` remains available only for explicit disposable
  diagnostics. The strict/weak projection contains 24 strict and 10 weak
  observations across 7 chains.
- Retain complete dated external refreshes for all 17 canonical classifier
  inventories and the 30-artifact normalized full-evidence set. Regenerate
  all 17 historical committed validated inputs and
  `results/child-header-coverage.csv` from the normal source paths. The
  Electric Cash rerun now carries parent output scripts; Terracoin carries
  source-native parent output addresses; Bitcoin Vault classifies 2,566
  canonical and 9 accepted stale rows from 169,939 ordered acquisitions.
- Make publication preflight source-aware without weakening coverage floors:
  accept canonical rows already present in an authoritative full inventory,
  merge split unknown companions for relevance coverage, and avoid inspecting
  unrelated sources when a chain has no strict/weak baseline rows. Resolve
  repository-relative CLI paths before provenance redaction so regenerated
  rows keep reproducible in-repo source paths. Doichain's authoritative
  50,621-row inventory remains an explicit archive-layout declaration rather
  than a smaller substitute.
- Harden the final provenance and validation contract: redact private archive
  staging roots, union disjoint canonical companions by exact header identity,
  preserve original input row numbers in evidence diagnostics, and fail closed
  on malformed Terracoin RPC child-header fields.

The scheduled Bitcoin epoch-reference refresh now merges its own pull request
once CI passes, instead of leaving it for a manual merge. Opening the pull
request with an `AUTOMATION_PAT` repository secret is what makes this possible:
a pull request opened with the default `GITHUB_TOKEN` never triggers a workflow
run, so there was no CI result to gate on. Without the secret the refresh
degrades to the previous open-and-wait behaviour.

## 0.1.0 - 2026-07-22

Initial public release of the merge-mining research pipeline, documentation,
reproducible node infrastructure, and compact datasets.
