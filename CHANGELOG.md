# Changelog

## Unreleased

Add the body-invalid stales overlay
(`data/error-blocks/body_invalid_stales.csv`): annotations for accepted VALID
direct stales whose complete block body is known consensus-invalid from an
externally observed full block, starting with the two F2Pool `bad-blk-sigops`
blocks at heights 783,426 and 784,121. The overlay is not part of the
error-block catalogue or its exclusion gate — the sigop excess is provably not
derivable from the committed bytes (the embedded legacy sigops scale to below
the 80,000 limit; the remainder needs spent-prevout context), so the rows keep
their accepted statuses and the catalogue keeps its offline re-derivation
standard. A fail-closed validator (`just validate-body-invalid-stales`,
`stale_blocks_analysis.body_invalid_overlay`) enforces validated-stales
membership, catalogue disjointness, the rule-vocabulary boundary, and — when
the pinned stale-blocks clone is fetched — the archived block files' SHA-256,
header hashes, and legacy sigop counts.

Publish the error-block and stale-descendant observation inventories by chain
directly in the monitor manifest so downstream consumers can validate the
canonical ledgers without reconstructing their metadata.

Require the exact stale-descendant parent-verdict, stale-descendant witness-ledger,
and error-observation witness-ledger schemas, including complete CSV row widths,
and require every persisted parent gate cell to carry its accepting verdict. Make
monitor publication authenticate every error-observation row against ordinary
evidence rules and the canonical ledger, and reject duplicate `(height, hash)`
keys in the MTP context sidecar.

Remove every ancestry recovery copy after a fully successful in-process
rollback, preserve all copies when rollback is incomplete, and block a new
publication when any adjacent recovery file from any process remains.

Preserve multiple distinct authenticated child events from one chain when they
witness the same accepted stale-descendant parent. Resolve hydration, recovery,
ancestry, and error-observation joins by exact child event, reject ambiguous or
cross-parent reuse, authenticate headerless descendant witnesses through the
selected child-identity index, require canonical POSIX source paths, and validate
Xaya identities with its external `PowData` `nBits` contract.

Require the canonical stale-descendant witness ledger before attribution can
admit any parent verdict, and fail provenance fingerprinting if an expected
publication input disappears.

Require every stored ancestry terminal to exist in the selected data tree's
accepted per-chain or pinned upstream direct-stale inputs, excluding that
tree's canonical error blocks. Reject an authenticated child event that is
assigned to more than one Bitcoin parent.

Preserve address-derived payout recipients through canonical coinbase-output
reconciliation so legacy bare-address and `address:value` evidence still
supports pool attribution. Match refined P2PK outputs by their recipient
HASH160 without treating P2SH or witness programs as the same target.

Fail closed when stale-ancestry reconciliation lacks Bitcoin's canonical
`nBits` for an inferred height. Treat catalogue error blocks as explicit
invalid ancestry terminals so every child and deeper descendant is emitted
only as an uncatalogued-error diagnostic. Collapse compatible physical archive
copies only after they resolve to the same authenticated child event, reject
conflicting copies, and normalize Bitcoin-family display-order child hashes
before storing their logical witness identity while keeping RSK hashes forward.
Keep RPC credentials out of the `just` launcher output when operators supply
them explicitly.

Treat split unknown inventories as the same source family as their complete
classifier inventories so scan-order child heights cannot become authenticated
publication facts. Reject every low-level ancestry output that resolves under a
canonical data or results publication surface. Authenticate each committed
parent's stale-root height, fork depth, path endpoints, and every serialized
predecessor link before accepting its ancestry verdict.

Keep the authored future-limit follow-up in `docs/error-blocks.md` and make the
time-rule sweep report fully regenerable without copying prose from the report
it replaces.

Route every stale-descendant consumer through the canonical parent loader,
cross-check parent chain/count summaries against the witness ledger, and emit
reconciliation notes only from the current run. Require each reconciled parent
header to come from the selected authenticated observations, and keep
unjudgeable candidates in diagnostics instead of the canonical parent table.
Rebuild the pending-upstream sidecar solely from current validated inputs,
without using its prior output as a header cache.

Publish the complete stale-ancestry result as two committed tables: 21 accepted
parent verdicts in `data/stale_descendants.csv` and 32 authenticated
child-chain witnesses in `data/stale_descendant_observations.csv`. Reconciliation
evaluates the full candidate population from declared trusted roots, requires
active-mainchain placement for direct roots, gives consensus-invalid candidates
error-block precedence, and treats source bucket labels as audit evidence only.
Require publication to name the Bitcoin Core verification source explicitly and
persist that non-secret label with each exact active-hash-at-height verdict.

Publish 39 consensus-invalid full-proof-of-work Bitcoin parents and 86 recovered
child observations. Four ancestry-derived parents re-derive
`bip34_coinbase_height_mismatch`; their eight Namecoin, Devcoin, and Ixcoin
witnesses are authenticated by source coordinate, archive SHA-256, source
coinbase and available Bitcoin header evidence, and node-verified 80-byte child
headers.

Refresh Namecoin and Fractal Bitcoin against the same Bitcoin Core generation.
Publish 1,649 accepted Namecoin direct-stale observations and 40 Fractal
observations, retain 456,660 and 58,970 canonical rows respectively, and project
the recovered Namecoin witness at Bitcoin height 941,882 as a stale descendant.

Publish monitor evidence as one coherent transaction. Regenerate every ordinary
artifact, the error-observation aggregate, counts, and manifest from the same
authenticated source population. Project a strict orphan's Bitcoin height only
from the relevance classifier's authenticated BIP34 verdict, rejecting missing
or conflicting strict heights while leaving weak verdicts timestamp-only.

Publish error-block observations on the 34-column monitor union schema,
hydrate RSK sidecar cells from committed child-identity, and keep RSK keccak
child hashes in forward node order. Ordinary publication excludes those
five RSK error parents; identity recovery includes them in the RSK work list
and tries canonical `eth_getBlockByNumber` when classified uncle metadata is
absent.

Catalogue Bitcoin height 957780 (`time_below_mtp`) from merge-mining-monitor
live capture, with recovered Namecoin, Syscoin, Fractal, and Elastos witnesses.

Split monitor-facing evidence projection from full-evidence source
normalization without changing schemas, publication contracts, or output data.

Unify Hathor acquisition and classification around one range-neutral dataset.
Record terminal metadata for the caller-declared height range, retain every
version-3 proof and its funds-and-graph bytes in one sealed acquisition row,
and classify that dataset directly into the standard terminal categories in a
single atomic run. Remove the separate raw/supplement acquisition path and the
persisted classifier phases. Historical private artifacts require a disposable
operator transform outside the publication path.

Publish the authenticated Hathor result from height 0 through 6,593,796 as one
corpus:
3,658 canonical observations, 6 accepted direct stales, 248,760 unknowns,
6,279,947 near rows, and 1 classifier-emitted error block. Record the zero
strict/weak result and retain source-authenticated child identity on the six
compact stale rows.

Keep Hathor in the active-child publication identity gate while leaving it out
of the separate sidecar-hydration set, and include its reconstructed Bitcoin
coinbase scriptSig in strict-height relevance classification. The complete
rerun assessed all 248,760 unknown rows and retained the zero strict/weak
result.

Require relevance inventories to account for every non-excluded unknown row in
a private full-inventory source before publishing monitor evidence, normalizing
blank classifications and matching source identities while authenticating
Hathor child hashes against reconstructed headers.

Validate every monitor publication against one manifest root and one complete
set of ordinary artifacts. Require exact schemas, classifications, hashes,
heights, serialized parent and child headers, source provenance, stable row
ordering, numeric counts, and matching artifact paths across the counts CSV and
manifest. Preserve accepted identities and reject duplicates, undeclared
chains, category overlap, malformed encodings, and incomplete publication sets.

Treat physical rows that share one authenticated
`(chain, btc_header_hash, child_block_hash)` event as a single semantic-floor
claim only when the retained row refines every committed category and evidence
field. Preserve injective multiplicity for distinct child hashes and for sparse
rows without authenticated child identity.

Authenticate stale-descendant witnesses against the committed observation
ledger and validate strict and weak orphan verdicts against the committed
Bitcoin epoch references. Preserve direct-stale verdicts, expected `nBits`, RSK
sidecar fields, coinbase evidence, relevance metadata, and child-observation
multiplicity across the transaction.

Require every error witness to carry an authenticated child identity and keep
ordinary and consensus-invalid validation contracts separate within the same
complete publication transaction.

Add the pool-attribution layer. The repo has always retained coinbase
evidence for a later attribution phase; this lands that phase. A pinned
clone of bitcoin-data/mining-pools joins the fetched datasets, and
`just attribute` turns the retained evidence into an export of pool labels
for the merge-mining-recovered stales.

Identification matches each coinbase against the registry: scriptSig tags
longest-first, then coinbase OP_RETURN outputs, then payout addresses.

The record set is this repo's own recovered evidence: every merge-mining
recovery loader plus the stale descendants. The upstream census is not labelled
here; the
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

Label error blocks during classification. A shared routing step sorts every gate-rejected stale
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
and retarget rules only, as its proof exposes no coinbase), the unified Hathor
classifier, and the stale-descendant reconciliation. Hathor loads the committed
retarget-epoch table, so an epoch-start candidate carrying the previous epoch's
bits becomes an error block rather than being dropped, and its re-routed
unknowns remain in the unknown inventory. The ancestry
reconciliation derives rules only from header bytes that authenticate against
the claimed hash, routes consensus-invalid candidates before writing the
accepted parent and witness tables, and uses internal error-row staging only as
build mechanics. The classifier output
writer fails loudly on an unrecognised classification instead of silently
dropping the row, and its `rejected` count spans every bucket the routing
produced (with a `rejected_stale`/`rejected_error_block`/`rejected_unknown`
breakdown) so a fully re-routed run cannot report zero rejections.
`nbits_retarget_not_applied` and the two `bip34_*_coinbase_height_missing`
rules join the shared derivation, the rejected-rows sweep gains namecoin
coverage, and the RSK classifier refuses aliased output paths before it opens
any of them. Every committed error block re-derives under the shared decision.

Preserve LF line endings in both error-block CSV writers and make the offline
error-block validator reject every row whose `classification` is not exactly
`error_block`. Publish stale-descendant parent verdicts only when the accepted
parent row and an exact authenticated witness agree on chain, Bitcoin identity,
and source coordinates. Preserve source classification as audit provenance
without using it to decide the parent verdict.

Project each accepted parent verdict onto the exact witnesses in
`data/stale_descendant_observations.csv`, retaining the source bucket only as
audit provenance. Regenerate the complete
monitor-evidence publication from the authenticated source estate so every
committed payload follows the same current publication contract, including an
empty stale-gate axis for canonical and unresolved-unknown rows, plus blank
child heights where the offline source cannot authenticate consensus height.
Publish the exact BIP34 child height for 19,610 Xaya canonical observations
whose source artifacts record block-file positions rather than authenticated
consensus heights.

Require a stale-descendant projection to match the source chain, Bitcoin
height, and header hash, so a mistyped source height cannot enter monitor
evidence or satisfy its publication preflight. Make the error-block module
validator reject duplicate canonical keys and duplicate child observations,
and require aggregate chain declarations to match the exact witness ledger.
Require every committed error-block sweep inventory to meet its recorded
minimum row baseline before replacing a publication report. Add Elastos to the
rejected-row sweep coverage map.

Classify the preserved Elastos and Syscoin raw extracts against Bitcoin Core
and publish 44 additional valid direct stales. Include the shared
Elastos/Syscoin stale descendant, recover child identity for all retained
monitor rows, and rebuild the monitor evidence,
novelty outputs, and stale-ancestry module. Make normalized evidence inputs
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

Publish all 32 authenticated stale-descendant witnesses through their exact
per-chain monitor rows with `classification=stale_descendant`,
`validation_status=VALID_STALE_DESCENDANT`, and
`relevance_reason=valid_stale_descendant`. Retain each witness's source bucket
only in the audit ledger. Publication fails closed if
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
observations. The generic classifier's primary accepted and rejected
publication outputs now use the established normalized `btc_height` /
`btc_header_hash` / `btc_bits` schema. Its full `--classified-output` inventory
retains the source-specific `btc_stale_height` / `btc_hash` / `btc_bits_hex`
fields and validation annotations. The normalized rejected rows no longer carry
standalone `nbits_match` or `post_bch_fork` columns; those diagnostics remain
represented by `validation_status` and `expected_nbits` and are preserved as
standalone fields in the full classifier inventory.

Publish consensus-invalid full-proof-of-work Bitcoin blocks ("error blocks")
as a first-class, re-derivable dataset and add `error_block` as a primary
classification value.

- New `data/error-blocks/error_blocks.csv` is simultaneously the rich evidence
  dataset and the exact-key exclusion gate. Its 39 rows each carry
  `classification=error_block` and a named,
  mechanically re-checkable `rejection_reason`; the gate keys off that value
  directly via `src/stale_blocks_analysis/error_blocks.py`. A committed
  `data/error-blocks/mtp_context.csv` sidecar carries the canonical parents'
  median-time-past for all three MTP-rule rows.
- `error_block` is added to the primary `classification` vocabulary alongside
  `canonical`/`stale`/`unknown`/`stale_descendant`/`near`: a consensus-invalid
  full-PoW block witnessed via merge mining that was never a stale/orphan
  contender. This is a **breaking vocabulary change for the
  merge-mining-monitor importer** and its ported relevance classifier; renames
  and additions must land in lockstep with the monitor (documented in
  `docs/data-reference.md` and `docs/upstreaming.md`). Blocks that merely fail
  the PoW target are not error blocks; they remain `near`.
- The canonical error-block catalogue, MTP context, and child-observation
  ledger are reviewed together. The offline validator
  `scripts/analysis/validate_error_blocks.py` re-derives every row's full PoW
  and named violation from committed bytes and checks exact witness coverage
  in CI.
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
- Represent height 656,478 only as a valid `stale_descendant`. Its predecessor
  is a trusted stale root, so the candidate is not a direct stale or an error
  block. No validated-stales baseline changes.
- New `scripts/reports/report_error_blocks_by_chain.py` generates per-chain
  observation views under `results/analysis/error-blocks/by-chain/` as
  diagnostics (not committed loader inputs), via `just error-blocks-report`.

Recover node-verified child block identity for the five active hydration chains
(Namecoin, RSK, Syscoin, Elastos, and Fractal) and publish it through the
monitor-evidence exports, so merge-mining-monitor's dataset importer can key
imported rows exactly like live capture and deduplicate against it. Hathor's API
acquisition retains source-authenticated child identity directly, so it does
not need a separate hydration ledger.

- New `scripts/extract/recover_child_identity.py` recovers each row's child
  block hash and timestamp by height -> hash -> block RPC against the live
  child nodes, verifying the Bitcoin parent linkage re-derives from every
  fetched child block. The five active hydration ledgers
  contain 2,325 chain/header observations (1,932 distinct Bitcoin parent
  headers; 239 parents observed by more than one chain). Small historical
  Devcoin and Ixcoin ledgers add ten source-row-authenticated observations;
  across all seven generic ledgers the directory contains 2,335 observations
  for 1,933 distinct parents, 245 of them observed by more than one chain.
  Results are committed under `data/child-identity/`.
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
  `notes` as `child_identity_hydration=hydrated:N`, and the five active
  hydration chains are targeted unconditionally: a missing, empty, or
  verification-less identity file surfaces as `missing_identity` (fatal to a
  publication build) instead of silently narrowing the target set.
- The RSK monitor export appends the seven columns the monitor's
  `rsk_merge_mining_evidence` sidecar requires (`rsk_miner`,
  `merge_mining_hash`, `is_uncle`, `uncle_index`, `uncle_parent_height`,
  `rsk_merkle_proof`, `rsk_coinbase_tail`), sourced from the live RSK node
  and cross-checked against the classified recovery metadata.
- The stale-descendants parent-summary export is deliberately outside the exact
  child-identity contract: its rows represent parent verdicts rather than
  individual chain witnesses, so its child identity columns stay empty. The
  counts row records `child_height=unavailable` and
  `parent_verdicts_only_witnesses_in_observation_ledger`;
  all 32 authenticated source-chain witnesses are published through their
  exact per-chain rows with source-authenticated child evidence. Six of those
  observations have complete historical child headers and belong to the 17
  refresh chains reported by `results/child-header-coverage.csv`; the live-chain
  observations use the independently node-verified child identities under
  `data/child-identity/`.
- Because the strict/weak orphan projections mirror the monitor export's
  schema, the regenerated RSK projection also carries the seven sidecar
  columns; the other chains' projections gain only `child_block_time`.
- Regenerate all 28 ordinary monitor artifacts, the error-observation
  aggregate, counts, and manifest from the same complete inputs. Normal
  publication includes every available canonical row for every chain, with no
  per-chain allowlist, together with accepted direct stales, accepted
  descendants, and strict/weak unknown-row observations.
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
