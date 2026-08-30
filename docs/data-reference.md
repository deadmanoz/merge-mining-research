# Dataset reference

Column-level reference for the committed datasets that the analysis package
loads and the reference outputs under `results/`. Fetched upstream data
(`data/stale-blocks/`), raw extracts, and other scratch artifacts are not
committed and are out of scope here; see the [input data notes](../data/README.md)
for the data-boundary rules and [repository guidance](../AGENTS.md) for the
research semantics these columns encode.

## Conventions

- **Hash byte order.** All `*_hash` / `*_prev_hash` columns are big-endian display
  order (the `0000...` form). `btc_header_hex` is the raw 80-byte header in
  wire order, hex-encoded (160 characters); double-SHA256 of those bytes, reversed,
  equals the display hash.
- **Line endings.** All committed CSVs are LF.
- **Encoding of the gate verdict.** The chain-specific publication gate runs at
  classification time and its verdict is persisted per row as
  `validation_status` / `expected_nbits`. For chains exposing the required
  evidence, it checks header hash and self-PoW, active-parent linkage, expected
  `nBits`, median-time-past, Bitcoin's historical minimum block versions,
  coinbase scriptSig length, and BIP34's coinbase-height rule. RSK has no
  recoverable parent coinbase scriptSig, so it cannot independently apply the
  two coinbase-dependent checks; exact-key cross-chain exclusions protect known
  shared failures. Loaders read and filter the persisted verdict; they never
  recompute it.
- **Validity scope.** Either exact accepted direct-stale status means
  publication-gate accepted under the checks available for that chain and row.
  It does not mean a complete Bitcoin block was available or fully
  consensus-validated. See the
  [data validity contract](data-validity.md).
- **Dedup key.** Stale events are deduplicated by `(height, hash)`, not height
  alone, so competing same-height stale hashes are preserved as distinct rows.

## Per-chain validated stale CSVs: `data/validated-stales/<chain>_validated_stales.csv`

One row per recovered direct-stale BTC header candidate for a merge-mined
chain. Every committed row is `classification = stale` and
`validation_status` is exactly `VALID` or
`VALID (post-BCH, difficulty matches BTC)`. These files are the
publication-gate-accepted output; no other `VALID`-prefixed spelling is
accepted. Every file begins with the same 16-column core layout: normalized
Bitcoin-parent fields, the registered child-height slot, the four child-header
fields, and the verdict fields. Source-specific variants (`btc_stale_height`, `btc_hash`,
`btc_bits_hex`) are normalized into this layout. Chain-specific research
columns trail that shared core:

| Column | Notes |
| --- | --- |
| `btc_height` | Candidate Bitcoin height inferred as active-parent height + 1. |
| `btc_header_hash` | The candidate header's own hash, display order. |
| `btc_prev_hash` | Parent on the canonical chain. |
| `btc_time` | Header nTime (unix seconds). |
| `btc_bits` | Header nBits, lowercase 8-char hex. |
| `coinbase_scriptsig_hex` | Preserved coinbase evidence for later pool-attribution research. |
| `coinbase_outputs` | Semicolon-separated `value:scriptPubKeyHex` (or address) list; empty where the extraction preserved none (RSK). |
| `btc_header_hex` | Full 80-byte header, hex (160 chars). |
| `<chain>_height` (`dvc_height`, `nmc_height`, `child_height`, ...) | Height on the merge-mined sibling chain where independently resolved. The column occupies the same position in every validated schema and remains blank when unavailable. Namecoin classifier inventory heights are historical block-file scan order, so normalization blanks them and hydrates only the exact node-verified identity height; see `docs/chains/namecoin.md`. |
| `child_block_hash` | Authenticated child block hash for the 17 refreshed historical source families. |
| `child_header_hex` | Authenticated serialized 80-byte child header for the 17 refreshed historical source families. |
| `child_block_time` | Unsigned decimal timestamp decoded from `child_header_hex`. |
| `child_nbits` | Lowercase 8-character child target field, decoded from the same header except for Xaya's authenticated external `PowData` target. |
| `classification` | `stale` for these files. |
| `validation_status` | Exactly `VALID` or `VALID (post-BCH, difficulty matches BTC)`: passed the declared publication gate, not a full-block validity assertion. |
| `expected_nbits` | Canonical nBits at that BTC height (the gate's reference). |

Chain-specific research columns trail the shared layout where retained:
namecoin's `nbits_match` / `post_bch_fork` gate detail,
`btc_bip34_height`, and `btc_parent_height` (its `btc_header_hex`
is populated for 1,421 of 1,649 rows and empty where the loader snapshot did
not preserve the header; the monitor export supplies verified hydration), and
coiledcoin's `eligius_attack_window`.

## Error blocks: `data/error-blocks/error_blocks.csv`

Exact `(height, hash)` keys of consensus-invalid full-proof-of-work Bitcoin
blocks that must be removed from stale publication surfaces. Every row has
`classification=error_block`; blank or unknown classifications fail closed
when the dataset is loaded. The current 39 rows include the 946,213 and 957,780
`time_below_mtp` blocks, the 717,696 `nbits_retarget_not_applied` block, the
Hathor-witnessed 649,674 `bip34_coinbase_height_missing` block, and four
stale-ancestry candidates at 331,673, 331,674, 402,610, and 422,059 whose bytes
re-derive `bip34_coinbase_height_mismatch`. Of the invalid keys, 25 carry a
mismatched BIP34 coinbase height, one omits the
required BIP34 height, three fail BIP66's minimum version 3 rule, five
fail BIP65's minimum version 4 rule, one violates median-time-past, two are
time-too-old against median-time-past (946,213 and 957,780), one carries a
103-byte coinbase scriptSig above Bitcoin's 100-byte limit, and one failed to
apply the difficulty retarget at an epoch boundary. The dataset retains the signed
header version, child-chain provenance, raw coinbase scriptSig, rejection
reason, and the named rules violated. It is a compact audit record rather
than a self-contained merge-mining proof. It is applied by public loaders, upstream
novelty calculations, the upstream sidecar builder, full-evidence and
relevance exports, and unknown-ancestry reconciliation.

The `rejection_reason` / `rules_violated` token `nbits_retarget_not_applied`
means the block sits at a retarget-boundary height (`height % 2016 == 0`, an
epoch start) but carries the PREVIOUS epoch's `nBits` instead of the
newly-retargeted value the epoch start must use: the miner failed to apply
the difficulty retarget, a hard consensus violation. It is offline
re-checkable against the committed
`data/bitcoin-epoch-reference/btc_nbits_by_epoch.json` table: the row's
`btc_bits` must differ from the table value at its height and equal the table
value at `height - 2016`. This is distinct from a plain `nBits mismatch`
rejection at a non-boundary height, which is the contamination gate's target
class (a share/near row), not an error block: the error-block case is
specifically the retarget-not-applied at an epoch boundary where the header
still meets full proof of work.

## RSK: `data/validated-stales/rsk_validated_stales.csv`

RSK cannot be attributed by parsing a BTC coinbase because the proof does not
preserve it. Like every other chain, the committed file is
VALID-stales-only and carries the shared validated-stales layout (`btc_height`,
`btc_header_hash`, `btc_prev_hash`, `btc_time`, `btc_bits`,
`coinbase_scriptsig_hex` and `coinbase_outputs` as empty placeholders - the
extraction preserves only the midstate-compressed coinbase, not the decoded
fields - `btc_header_hex`, `rsk_height`, `classification`,
`validation_status`, `expected_nbits`), followed by RSK-specific evidence and
historical evidence columns:

| Column | Meaning |
| --- | --- |
| `rsk_height`, `rsk_timestamp` | Position and time on the RSK chain. |
| `rsk_miner` | RSK miner address. |
| `pool_label` | Historical label retained for provenance; ignored by the current loader. |
| `merge_mining_hash` | RSK merge-mining tag committed in the BTC coinbase. |
| `coinbase_op_return`, `coinbase_ascii_strings` | Raw coinbase evidence. |
| `is_uncle`, `uncle_index`, `uncle_parent_height` | RSK uncle (stale) metadata. |

The historical full stale/unknown inventory (`rsk_stale_blocks.csv`, 304
stale-labelled candidates + 37,031 unknown rows) is not committed. Five parents
are consensus-invalid and one belongs to the stale-descendant module, leaving
298 direct-stale rows in the committed validated file.

## Stale descendants

The stale-descendant module separates parent verdicts from child-chain witness
provenance:

- `data/stale_descendants.csv` contains 21 accepted Bitcoin parent verdicts.
  Loaders require `classification=stale_descendant` and
  `validation_status=VALID_STALE_DESCENDANT`, authenticate the serialized
  parent header, and require the persisted Bitcoin Core off-active verdicts.
- `data/stale_descendant_observations.csv` contains 32 authenticated
  child-chain witnesses for those parents. Exact source coordinates, source
  SHA-256, and child identity bind each row to the recovered evidence.

Reconciliation evaluates every authenticated candidate, begins only from the
declared trusted-root set, and verifies the full predecessor path. A direct
stale root is accepted only when its predecessor is on Bitcoin's active main
chain. A consensus-invalid full-proof-of-work candidate is classified as an
error block before stale-descendant publication. `source_classification` in the
witness ledger records the archive bucket for audit; it does not decide the
parent verdict. The four ancestry-derived error blocks are reviewed members of
the canonical `error_blocks.csv` and `error_block_observations.csv` module.
Reconciliation treats their hashes as terminal error verdicts and fails closed
if it finds any additional consensus-invalid candidate. Children and deeper
descendants of a catalogued error terminal inherit that invalid verdict and go
only to the disposable error-candidate diagnostic. The diagnostic also retains
incomplete or low-work rows as publication blockers, but only an authenticated
full-PoW violation is classified for canonical error-module admission. A
candidate is likewise unpublishable when the committed epoch reference cannot
supply canonical `expected_nbits` for its inferred height.

Key columns beyond the standard BTC header fields include
`active_mainchain_status` and `root_active_mainchain_status` for the placement
gates; `ancestry_relation`; `root_stale_hash` / `root_stale_height` /
`root_stale_sources` / `root_stale_chains` for the trusted stale root;
`stale_fork_depth`, `path_hashes`, and `path_chain_sets` for the walked ancestry;
`observed_btc_heights`, `observed_btc_times`, `observed_btc_bits`,
`observed_chains`, and `source_observation_count` for the aggregated witnesses;
and `pow_valid`, `header_hash_match`, `bip34_height_status`, and `notes` for the
validation result.

The witness ledger follows the error-observation provenance shape: parent and
child identities, child header evidence, source coordinates and SHA-256,
height/identity provenance, parent row number, and a composite provenance
field. Source paths are publication coordinates, not classification rules.
When a never-split inventory and its canonical companion contain the same
authenticated child event, reconciliation keeps one deterministic source
coordinate only after their parent evidence is compatible. Conflicting copies
fail closed, and distinct authenticated events remain distinct witnesses.

## Upstream contribution sidecar: `data/new_stale_blocks_for_upstream.csv`

The set of publication-gate-accepted stale `(height, hash)` pairs this project
contributes that are not already in `bitcoin-data/stale-blocks`. Rebuilt from the committed inputs
above by `scripts/reports/build_upstream_stale_sidecar.py`.
The builder reads direct stales from the validated per-chain inputs and
descendants through the canonical parent loader. It never uses the previous
sidecar as an input.
Because this sidecar intentionally combines direct stales and accepted stale
descendants without a classification column, ancestry reconciliation never
uses it as a stale-root input. Direct roots come only from effective upstream
and accepted per-chain direct-stale inventories.

| Column | Meaning |
| --- | --- |
| `height` | Canonical BTC height. |
| `hash` | Stale block hash, display order. |
| `header` | Full 80-byte BTC header, hex (160 chars). |

## Generated full-evidence exports: `results/full-evidence/`

The full-evidence export is generated on demand by
`scripts/reports/build_auxpow_full_evidence.py` or `just full-evidence`. It is
not a stale census input and is gitignored because private archive runs can
write bulky row-level inventories. The export is for downstream consumers that
need candidate evidence before rechecking it against Bitcoin Core.
When an external publication is assembled through a staging directory,
`--reported-output-dir` records the logical final location in its manifests
without changing where the files are written.

The 2026-07-30 complete refresh retained 30 external artifacts. Its historical
coverage report authenticated 2,933,154 of 2,933,154 rows and all 6 accepted
stale-descendant observations belonging to those 17 sources, with zero
unrecoverable rows.

Each `<chain>_evidence.csv` uses this normalized schema:

| Column | Meaning |
| --- | --- |
| `chain`, `source_kind`, `source_path`, `source_row_number` | Source identity and row provenance. External archive roots are redacted as `<chain-archive>/...`. |
| `artifact_scope` | `full_classifier_inventory`, `stale_only_publication`, or `stale_descendant_parent_verdicts`. |
| `child_height`, `child_block_hash`, `child_header_hex`, `child_block_time`, `child_nbits` | Child-chain location and authenticated header evidence when available. `child_block_hash` is the internal/wire-order double-SHA256 digest, `child_header_hex` is the 80-byte canonical header serialization, `child_block_time` is the header timestamp, and `child_nbits` is eight lowercase hexadecimal characters. For Xaya, the header and timestamp come from `CPureBlockHeader`, while effective `child_nbits` comes from the adjacent `PowData` wrapper. For the five identity-hydration chains the existing hash and timestamp remain hydrated from `data/child-identity/` (see below); their historical data is not re-derived by this work. Hathor publishes its source-authenticated block identity and timestamp directly. |
| `btc_height`, `btc_header_hash`, `btc_prev_hash`, `btc_time`, `btc_bits`, `btc_nonce`, `btc_header_hex` | Normalized Bitcoin parent header fields. |
| `coinbase_scriptsig_hex`, `coinbase_outputs`, `full_coinbase_hex` | Coinbase evidence. Hathor-style full rows with only `full_coinbase_hex` are parsed during export. |
| `classification` | Preserved source classification: `canonical`, `stale`, `unknown` (normalized from the historical `orphan` spelling on read), `stale_descendant`, `near`, or source-specific values. |
| `validation_status`, `expected_nbits`, `rejection_reason` | Persisted gate verdicts or rejection details when present. |

`auxpow-full-evidence-counts.csv` and
`auxpow-full-evidence-manifest.*` summarize counts for `canonical`, `stale`,
`unknown`, `stale_descendant`, `near`, rejected rows, malformed rows, and missing
evidence fields. The manifest's `canonical_evidence_status` distinguishes
`canonical_retained`, `no_canonical_rows_in_discovered_artifact`,
`canonical_rows_not_represented_stale_only_publication_path`, and
`not_checked_missing_source`.

## Canonical parents

Canonical Bitcoin parents recovered from a chain's merge-mining commitments
are retained evidence: they record which pool was building on which canonical
block, via which chain, at what time. The classifier partitions its results by
the primary `classification` into four files sharing one column schema (via the
shared `write_classifier_outputs`): `<chain>_canonical_blocks.csv`
(`classification = canonical`, empty `validation_status`/`expected_nbits`, with
Bitcoin Core's height authoritative), `<chain>_stale_blocks.csv` (stale rows
only), `<chain>_unknown_blocks.csv` (unknown rows), and the committed
`<chain>_validated_stales.csv` (the VALID-stale subset the loaders read). The
scratch paths under `data/` are gitignored (`_stale_blocks`, `_canonical_blocks`,
`_unknown_blocks`). Canonical and unknown storage normally remains in the
private archive's `classified/` family.

Every available canonical row is part of the normal publication and lives in
the corresponding
`results/monitor-evidence/<chain>_monitor_evidence.csv` output. There is no
per-chain canonical allowlist. A source's own coverage limit remains visible
in its provenance: VCash, for example, is a 68-row partial canonical subset
rather than a complete chain recovery, so no stale, strict, or weak total may
be inferred from it.

RSK keeps its miner-address parallel schema in one private inventory. Hathor's
unified classifier writes the standard terminal category files for canonical,
stale, unknown, near, and error-block rows.

## Child identity: `data/child-identity/`

Five active child chains (Namecoin, RSK, Syscoin, Elastos, and Fractal) were
recovered without child block identity: their acquisition artifacts carry the
child height but no child block hash or timestamp. Hathor is active too, but
its API acquisition retains the source-authenticated block identity and
timestamp directly, so it is not a separate hydration target.
merge-mining-monitor keys live-captured events by
`(source, child_height, child_block_hash)`, so imported rows need the exact
identity to deduplicate against live capture.

`scripts/extract/recover_child_identity.py` recovers the identity per parent
header by height -> hash -> block RPC against the still-reachable child nodes.
The RSK work list also includes error-observation ledger parents, which
ordinary inventories exclude; when classified uncle metadata is absent it
tries the recorded height as a canonical child.
Every row is verified by re-deriving the Bitcoin
parent linkage from the fetched child block and requiring it to match the
row's own `btc_header_hash`: the decoded CAuxPow parent for Namecoin/Syscoin,
the serialized AuxPoW tail for Elastos, the `getblockheader (hash, false,
true)` proof for Fractal, and `sha256d(bitcoinMergedMiningHeader)` for RSK
(uncle rows resolve through `eth_getUncleByBlockNumberAndIndex`). All 2,325
chain/header observations across the five active hydration chains verify
against today's canonical child chains (1,932 distinct Bitcoin parent
headers; 239 parents were observed by more than one chain, a single miner
attaching one Bitcoin parent to several merge-mined chains at once).

The directory also contains five-row historical identity ledgers for Devcoin
and Ixcoin. Those rows pin source-row-authenticated 80-byte child headers for
archive observations; the four new BIP34 error witnesses additionally record
independent node RPC verification. They authenticate historical evidence and
do not imply that the archive rows were live monitor events. Across all seven
generic ledgers the directory contains 2,335 observations for 1,933 distinct
Bitcoin parents, 245 of them observed by more than one chain.

Each `<chain>_child_identity.csv` carries `chain`, `btc_header_hash`,
`child_height`, `child_block_hash`, `child_block_time`, `verification`, `note`,
`child_header_hex`, and `child_nbits`. A verified row is usable only when
`child_height` is a nonnegative integer and the child hash and time are valid.
When a serialized child header is present, its hash, timestamp, and `nBits`
must agree with the normalized fields. `btc_header_hash` stays in
display (RPC) order like every other
pipeline artifact; `child_block_hash` follows the pipeline's established
column contract of internal (wire) byte order for the Bitcoin-family chains,
and forward order for RSK, whose keccak block hashes have no
reversed display convention -- the same orders merge-mining-monitor stores,
so its importer decodes the column without re-reversing. The RSK file adds
the fields merge-mining-monitor's `rsk_merge_mining_evidence` sidecar
requires: `rsk_miner`, `merge_mining_hash`, `is_uncle`, `uncle_index`,
`uncle_parent_height`, `rsk_merkle_proof`, `rsk_coinbase_tail`.

The monitor-evidence export joins these files by `(chain, btc_header_hash)`
into the `child_block_hash` / `child_block_time` columns (and, for RSK, the
sidecar columns) at build time; a row without a verified identity stays
empty, and an identity recorded at a different child height is refused. The
per-chain counts note records the join coverage as
`child_identity_hydration=hydrated:N`.

## Bitcoin epoch reference: `data/bitcoin-epoch-reference/`

The strict and weak BTC-orphan gates use a compact, committed view of
Bitcoin's canonical retarget history rather than an operator's private node or
runtime cache. `btc_nbits_by_epoch.json` maps every retarget-boundary height to
its compact target. `btc_epoch_headers.json` carries the corresponding block
hash, timestamp, median time, and target, followed by a six-confirmation
horizon block that closes timestamp coverage through the refresh point.
`manifest.json` records the public Esplora source and exact finalized horizon.

Regenerate the three files with `just refresh-bitcoin-epoch-reference`. The
refresh is incremental, verifies the last retained epoch against the public
canonical chain, and refuses to continue if that identity changes. Scheduled
CI runs it weekly, proposes changes as a pull request, and merges that pull
request once CI passes.

## Monitor-facing evidence exports: `results/monitor-evidence/`

A final-category projection of the full-evidence export, generated by
`scripts/reports/build_monitor_evidence.py` or `just monitor-evidence`. It
keeps only the categories the merge-mining-monitor ingests as final: every
available canonical row, publication-gate-accepted direct-stale candidates,
accepted stale descendants, and strict/weak BTC orphans. Unknown rows survive
only when the relevance inventory (see the vocabularies below) supplies a
`strict_btc_orphan` / `weak_btc_orphan` verdict for their header hash;
excluded and `pending` rows are omitted. Normal publication includes canonical
evidence uniformly for every chain. `--skip-canonical` is permitted only in an
explicit `--allow-partial` diagnostic build with a disposable output
directory.

The per-chain `*_monitor_evidence.csv` payloads are stored in Git LFS. Run
`git lfs pull --include="results/monitor-evidence/*_monitor_evidence.csv"`
before reading or rebuilding them. `monitor-evidence-counts.csv` and
`monitor-evidence-manifest.json` remain ordinary Git files so counts,
provenance, and validation-contract changes are directly reviewable. The
shared evidence writer emits LF explicitly because LFS objects do not pass
through Git's text-normalization filter.

`error-block-observations_monitor_evidence.csv` is a separate 86-row aggregate
for the 39 catalogue parents. It uses the 34-column union schema: the shared
27 monitor-evidence columns plus the seven RSK sidecar columns
(`rsk_miner`, `merge_mining_hash`, `is_uncle`, `uncle_index`,
`uncle_parent_height`, `rsk_merkle_proof`, `rsk_coinbase_tail`). Non-RSK rows
leave those sidecar cells blank. RSK rows must carry a semantically valid
sidecar (20-byte miner, 32-byte merge-mining hash, `is_uncle` `0`/`1`, uncle
placement present only for uncles, proof/tail blank or hex) copied from
`data/child-identity/rsk_child_identity.csv` without replacing the ledger
child hash. RSK keccak child hashes stay in forward node order; Bitcoin-family
`child_block_hash_order=display` hashes are exported in internal order. The
five RSK error-observation parents are excluded from ordinary RSK publication,
so this aggregate is the only published place those sidecars live.

Its rows retain the original archive or
live-observation source coordinates but use `classification=error_block` and
the catalogue's consensus rejection reason. `expected_nbits` is the required
epoch target, so it can intentionally differ from the header's `btc_bits` for
a retarget violation. The compact recovered witness ledger lives at
`data/error-blocks/error_block_observations.csv`; it is checked against the
current parent catalogue before publication. Every ledger row must identify its
child either with a well-formed hash or with a serialized child
header from which that hash can be authenticated. The release path stages every
ordinary artifact, the error aggregate, counts, and manifest as one coherent
transaction after validating them against the current schemas and source
contracts.

Each `<chain>_monitor_evidence.csv` uses the full-evidence schema plus two
columns the monitor's importer parses verbatim. The current schema includes
`child_header_hex`, `child_block_time`, and `child_nbits`; rows from the 17
historical child-header refresh pipelines carry a complete authenticated
bundle. The five identity-hydration
chains additionally publish `child_block_hash` / `child_block_time` hydrated
from `data/child-identity/` (coverage recorded in the counts `notes` as
`child_identity_hydration=hydrated:N`; a publication build fails closed when
a non-canonical final row lacks a verified identity). Canonical rows remain
publishable when their historical source never recorded exact child identity;
the counts `notes` disclose that limit as `canonical_unhydrated=N`. The RSK
export appends the seven `rsk_merge_mining_evidence` sidecar columns listed in
the child-identity section. Sources outside the 17 historical-header pipelines
emit the child evidence their native source proves; absent fields stay empty
rather than being inferred. The standalone stale-descendants export contains
one row per accepted parent and therefore leaves child identity blank. Its
counts notes are `child_height=unavailable` and
`parent_verdicts_only_witnesses_in_observation_ledger`. The
32 exact source-chain witnesses come from
`data/stale_descendant_observations.csv` and enter their chain artifacts once
with `classification=stale_descendant`,
`validation_status=VALID_STALE_DESCENDANT`, and
`relevance_reason=valid_stale_descendant`. Their source-bucket classifications
remain audit fields in the witness ledger and never override the accepted
parent verdict. The 28 ordinary artifacts, error-observation aggregate, and
both metadata files describe the same source generation. The six historical
observations carry complete authenticated child headers; live-chain
observations use the independently verified identities in
`data/child-identity/`. The committed ledger is the sole witness interface, so
all 32 observations are projected. A complete publication fails closed when a
required child identity is missing or disagrees with its generic ledger; a
partial diagnostic records that hydration shortfall instead of claiming a
usable identity.

i0coin and CoiledCoin publish their authenticated child hash, header, time, and
`nBits`, but the normalized `child_height` value remains empty because their
offline archives provide no authenticated consensus height. Doichain's retained
historical inventories likewise leave their unauthenticated file-order values blank; a
future run can fill exact heights through its documented RPC normalization
pass. The old block-file scan counters have been removed rather than presented
as heights. Height columns remain present uniformly. Any non-empty export with
no exact child height records `child_height=unavailable`; downstream importers
that require a height must skip those rows until an exact height source becomes
available.
The child-header coverage report
cross-references those accepted observations by source chain and Bitcoin
header hash so their coverage is explicit:

| Column | Meaning |
| --- | --- |
| `btc_stale_relevance` | Empty for accepted stales/descendants, whose state is already represented on the primary `classification` plus `validation_status` axes, and for canonical rows in canonical-bearing local runs; `strict_btc_orphan` / `weak_btc_orphan` for admitted unknown rows. |
| `relevance_reason` | `valid_direct_stale`, `valid_stale_descendant`, `strict_height_nbits_match`, or `timestamp_epoch_nbits_match`. |

Namecoin requires partial header hydration for monitor export. The validated
loader carries `btc_header_hex` for 1,421 of its 1,649 rows. The remaining 228
accepted rows, plus 21 published unknown relevance rows, are hydrated from the
Namecoin `block.dat` prototype extracts when available, otherwise from the
private archive's classified and raw-extraction pair. The committed monitor
CSV publishes the resulting headers, but regenerating those hydrated fields
still requires non-public inputs. A recovered header is written only when its
double-SHA256 verifies against the row's `btc_header_hash`; a missing,
malformed, or mismatching candidate is never written. Hydration touches only
Namecoin's `btc_header_hex` column.

`monitor-evidence-counts.csv` and `monitor-evidence-manifest.json` record
per-chain category counts, publication-projected source rows across the main
source and any replacement or companion sources, whether
unknown rows were present without a relevance inventory to judge them, and --
for namecoin -- the header-hydration coverage in the `notes` field
(`namecoin_header_hydration=hydrated:N/still_missing:M/hash_mismatch_rejected:K`,
with `no_namecoin_header_hydration_sources_found` appended when no extract file
was available). A non-empty chain export also records
`child_height=unavailable` when one or more rows lack an exact height. The JSON
manifest also carries a machine-readable
`validation_contracts` object. Its `ordinary_monitor_evidence` contract's
`valid_token_scope=publication_gate_accepted_not_full_block_validity` value is
the normative interpretation of both exact accepted direct-stale statuses for
ordinary evidence. The `error-block-observations` contract is separate: its
`VALID_ERROR_BLOCK` token means an authenticated witness of a
consensus-invalid Bitcoin parent, not a valid Bitcoin block. Consumers must
select the contract for the artifact they are reading rather than applying
the ordinary stale contract globally.

For monitor projection of full-inventory sources, `source_rows` replaces raw stale-classified rows
with the committed gate-accepted direct-stale rows. It can therefore
be smaller than the full-evidence or child-header coverage total when a stale
candidate was rejected. A canonical row present in both the main inventory and
its canonical companion is likewise counted once, matching the deduplicated
publication projection. The current validation differences are 9 i0coin rows, 1
Groupcoin row, and 1 Emercoin row; this is validation accounting, not
missing source acquisition.

## Strict/weak BTC orphans: `results/strict-weak-orphans/<chain>_strict_weak_orphans.csv`

The committed strict/weak slice of the evidence, produced per chain like
the validated-stales loader inputs: each chain's file is its
monitor-evidence export filtered to the `classification=unknown` rows,
which are exactly the rows admitted with a `strict_btc_orphan` or
`weak_btc_orphan` verdict (same schema and row order as the export). The
verdict is per header, not per observation: a header seen by several chains
carries the strongest verdict any chain's evidence establishes, so the same
header can appear in more than one chain's file with the same verdict.
Every complete-coverage per-chain monitor-evidence export gets a file; a
header-only file means the chain has no admitted rows. Canonical-only partial
sources such as VCash and stale-only publication inputs are omitted because
they cannot establish a zero result. Hathor's complete retained corpus
publication therefore carries a header-only zero-result file.
`strict-weak-orphans-counts.csv`
summarizes the per-chain bucket counts. Generated by
`scripts/reports/build_strict_weak_orphans.py` (`just strict-weak-orphans`);
the underlying row-level relevance inventory
(`results/analysis/btc-stale-relevance/btc-stale-relevance-inventory.csv`) is gitignored for
size.

## Per-chain novelty: `results/per-chain-novelty/<chain>.csv`

One row per publication-gate-accepted direct stale for a chain, written by
`scripts/compute_chain_novelty.py`. Used by the per-chain docs.

| Column | Meaning |
| --- | --- |
| `btc_height` | Canonical BTC height. |
| `btc_hash` | Stale block hash, display order. |
| `in_upstream` | `yes` if the pair is already in `bitcoin-data/stale-blocks`, else `no`. |
| `first_seen_chain` | The earlier-born chain that first claims this hash under the chronological-novelty convention (`CHAINS_BY_AUXPOW_ACTIVATION`), or empty if this chain is the first. This is a reproducible attribution convention, not a real-time observation claim. |

## Value vocabularies

The taxonomy has two axes. The **primary `classification`** records what the
evidence shows about a recovered BTC parent header; the **derived
`btc_stale_relevance`** refines the unknown bucket with a final verdict. The
merge-mining-monitor uses the same two-axis design (its BTC-orphan classifier
is a port of this repo's relevance classifier), and its importer reads the
relevance strings verbatim - renames must land in lockstep with the monitor.
"Orphan" is used only in the strict/weak relevance sense throughout this
repository; the broad evidence state is `unknown`.

**`classification`** (primary axis): `canonical` (Bitcoin Core reported the
header on the active chain at classification time), `stale` (an operational
direct-stale header candidate: the recovered BTC parent header was not active
and its prev hash was active), `unknown` (neither the header nor its prev hash is
known to the active chain; stays `unknown` on this axis; historical private
artifacts may use `orphan`, and readers normalize that spelling), `stale_descendant`
(a stale-fork continuation chaining back to a known stale root), `near` (the
header fails Bitcoin's PoW target - a child-chain artifact that was never a
Bitcoin block and remains outside the Bitcoin-parent population), `error_block`
(a consensus-invalid full-proof-of-work Bitcoin block witnessed via
merge-mining evidence: the header hash meets the Bitcoin target in force at
the claimed position and the merge-mining commitments are authentic, but the
block violates at least one named, mechanically re-checkable consensus rule, so it
was never a stale/orphan contender). Error blocks are catalogued in
`data/error-blocks/error_blocks.csv` and excluded from stale publication by
exact parent identity. Blocks that merely fail the PoW target are not error
blocks; they remain `near`. Adding `error_block` is a
breaking vocabulary change for the merge-mining-monitor importer and its
ported relevance classifier: renames and additions must land in lockstep with
the monitor.

**`btc_stale_relevance`** (derived refinement of unknown rows, emitted by
`scripts/analysis/classify_btc_stale_relevance.py`; constants in
`stale_blocks_analysis.config`). An accepted direct-stale or stale-descendant
candidate is already represented on the primary `classification` plus
`validation_status` axes, so it carries an EMPTY `btc_stale_relevance` here
(with `relevance_reason` `valid_direct_stale` / `valid_stale_descendant`);
this derived axis holds only the unknown-row refinement values:

- `strict_btc_orphan` - unknown row with valid self-PoW plus strict height
  evidence whose nBits match Bitcoin's at that height. This derived classifier
  conservatively admits coinbase-height evidence only from the universal
  BIP34 boundary at 227,931, avoiding version-dependent inference in the
  earlier transition window.
- `weak_btc_orphan` - unknown row with valid self-PoW and timestamp-selected BTC
  nBits consistency within plus/minus one retarget epoch (no strict height).
- `excluded` - everything ruled out: canonical/near sources, PoW or
  nBits failures, known stale/mainchain membership, insufficient evidence.
- `pending` - the row's height or timestamp lies beyond the nBits table's
  coverage horizon; no final verdict yet, re-classifiable when the table is
  extended.

**`validation_status`**: `VALID` or
`VALID (post-BCH, difficulty matches BTC)` (passed the available chain-specific
publication gates, not full block validation), `VALID_STALE_DESCENDANT`
(descendant accepted under its declared profile), `REJECTED: ...` /
`REJECTED_...` (failed a gate, for example
an nBits mismatch with the canonical BTC height or a BIP34 height mismatch),
`UNKNOWN: ...` (required context or evidence unavailable at gate time).
Committed per-chain validated CSVs contain only the two exact accepted
direct-stale statuses. Two rejected spellings exist historically - the nBits
gates write `REJECTED: <detail>` and
the descendant reconciler writes `REJECTED_<reason>` - so consumers must match
on the `REJECTED` prefix, never on an exact string.

Either accepted direct-stale spelling means the declared publication profile
passed. It is not a claim that Bitcoin Core accepted a complete block. The
compact direct-stale rows do not contain the
complete Bitcoin transaction set, so the project cannot check the candidate's
full merkle tree, block transaction rules, weight, witness commitment, sigops,
finality, scripts, subsidy, fees, or UTXO effects.

**Chain status** (used in the per-chain docs): the data-availability axis is
`live` / `historical` / `catalogued` (does this project have live, recovered,
or merely catalogued evidence), and the chain-liveness axis is `active` /
`dead` / `dormant` / `zombie` (a zombie chain still produces blocks at
negligible sub-Bitcoin difficulty). These are independent axes; the
merge-mining-monitor uses the same vocabulary.

**Pool labels**: pool attribution is implemented as a separate layer
(see [`pool-attribution.md`](pool-attribution.md)): `just attribute` matches
coinbase evidence against the pinned `bitcoin-data/mining-pools` registry and
labels the merge-mining-recovered stales, writing an export with `pool`,
`template_producer`, and
`attribution_basis` columns as a gitignored run product. The upstream census
is not labelled in this repo; the combined census-plus-recovered set is
assembled by the companion analysis repo. No committed dataset
carries a shared pool-label column. RSK's committed
source data is a historical exception because it already carries miner-address
labels; consumers should not treat that chain-specific field as a completed
cross-chain attribution dataset.
