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
- **Validity scope.** `VALID` means publication-gate accepted under the checks
  available for that chain and row. It does not mean a complete Bitcoin block
  was available or fully consensus-validated. See the
  [data validity contract](data-validity.md).
- **Dedup key.** Stale events are deduplicated by `(height, hash)`, not height
  alone, so competing same-height stale hashes are preserved as distinct rows.

## Per-chain validated stale CSVs: `data/validated-stales/<chain>_validated_stales.csv`

One row per recovered direct-stale BTC header candidate for a merge-mined
chain. Every committed row is `classification = stale` and
`validation_status = VALID` with a `VALID`-prefixed variant allowed. These
files are the publication-gate-accepted output; namecoin and i0coin carry
`VALID (post-BCH ...)` annotations under the documented prefix contract. Every
file begins with the same 16-column core layout: normalized Bitcoin-parent
fields, the registered child-height slot, the four child-header fields, and the
verdict fields. Legacy per-extractor variants (`btc_stale_height`, `btc_hash`,
`btc_bits_hex`) were normalized in the data pass. Chain-specific research
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
| `<chain>_height` (`dvc_height`, `nmc_height`, `child_height`, ...) | Height on the merge-mined sibling chain where independently resolved. The column occupies the same position in every validated schema and remains blank when unavailable. Namecoin's `nmc_height` is a recorded legacy acquisition field that cannot be reverified from the compact public artifacts; see `docs/chains/namecoin.md`. |
| `child_block_hash` | Authenticated child block hash for the 17 refreshed historical source families. |
| `child_header_hex` | Authenticated serialized 80-byte child header for the 17 refreshed historical source families. |
| `child_block_time` | Unsigned decimal timestamp decoded from `child_header_hex`. |
| `child_nbits` | Lowercase 8-character child target field, decoded from the same header except for Xaya's authenticated external `PowData` target. |
| `classification` | `stale` for these files. |
| `validation_status` | `VALID` (or `VALID (...)` prefix form): passed the declared publication gate, not a full-block validity assertion. |
| `expected_nbits` | Canonical nBits at that BTC height (the gate's reference). |

Chain-specific research columns trail the shared layout where retained:
namecoin's `nbits_match` / `post_bch_fork` gate detail,
`btc_bip34_height`, and `btc_parent_height` (its `btc_header_hex`
is populated for 1,397 of 1,625 rows and empty where the loader snapshot did
not preserve the header; the monitor export supplies verified hydration), and
coiledcoin's `eligius_attack_window`.

## Error blocks: `data/error-blocks/error_blocks.csv`

Exact `(height, hash)` keys of consensus-invalid full-proof-of-work Bitcoin
blocks that must be removed from publication surfaces. This dataset supersedes
the former `data/stale_block_exclusions.csv` overlay. The current 33 rows
comprise 31 carried-over consensus-invalid keys, the 946,213
`time_below_mtp` row recovered from merge-mining-monitor live evidence, and
the 717,696 `nbits_retarget_not_applied` row found by the rejected-row sweep
(witnessed independently by emercoin and syscoin). The
former `exclusion_scope` column is gone: the gate keys off
`classification == "error_block"`, and blank or unknown classifications fail
closed when the dataset is loaded. The single former `direct_stale_only` key
at Bitcoin height 656,478 extends a known stale predecessor rather than an
active-chain block; it is now handled as a stale-descendant single-home, so it
remains in the upstream catalogue and in `data/stale_descendants.csv`. It is
not an error-block exclusion: projection of a raw source row still requires
the accepted sidecar's chain-specific observation and the compact
`data/stale_descendant_corrections.csv` exact-key correction overlay. Of the
invalid keys, 21 fail the applicable
BIP34 coinbase-height rule, three fail BIP66's minimum version 3 rule, five
fail BIP65's minimum version 4 rule, one violates median-time-past, one is
time-too-old against median-time-past, one carries a 103-byte coinbase
scriptSig above Bitcoin's 100-byte limit, and one failed to apply the
difficulty retarget at an epoch boundary. The dataset retains the signed
header version, child-chain provenance, raw coinbase scriptSig, rejection
reason, and the named rules violated. It is a compact audit record rather
than a self-contained AuxPoW proof. It is applied by public loaders, upstream
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

## Direct-stale corrections: `data/stale_descendant_corrections.csv`

This compact exact-key overlay records source rows originally labelled as
direct stales that are instead accepted stale descendants. Each row carries a
Bitcoin height, header hash, and the fixed
`reclassified_from_direct_stale` reason. It is deliberately separate from the
descendant sidecar: monitor projection requires both the overlay key and the
sidecar's accepted chain-specific observation, so an unrelated sidecar entry
cannot rewrite a raw direct-stale source row.

## RSK: `data/validated-stales/rsk_validated_stales.csv`

RSK cannot be attributed by parsing a BTC coinbase because the proof does not
preserve it. Like every other chain, the committed file is
VALID-stales-only and carries the shared validated-stales layout (`btc_height`,
`btc_header_hash`, `btc_prev_hash`, `btc_time`, `btc_bits`,
`coinbase_scriptsig_hex` and `coinbase_outputs` as empty placeholders - the
extraction preserves only the midstate-compressed coinbase, not the decoded
fields - `btc_header_hex`, `rsk_height`, `classification`,
`validation_status`, `expected_nbits`), followed by RSK-specific evidence and
historical compatibility columns:

| Column | Meaning |
| --- | --- |
| `rsk_height`, `rsk_timestamp` | Position and time on the RSK chain. |
| `rsk_miner` | RSK miner address. |
| `pool_label` | Historical label retained for provenance; ignored by the current loader. |
| `merge_mining_hash` | RSK merge-mining tag committed in the BTC coinbase. |
| `coinbase_op_return`, `coinbase_ascii_strings` | Raw coinbase evidence. |
| `is_uncle`, `uncle_index`, `uncle_parent_height` | RSK uncle (stale) metadata. |

The historical full stale/unknown inventory (`rsk_stale_blocks.csv`, 304
stale-labelled candidates + 37,031 unknown rows) is not committed. Five of its
stale-labelled candidates are removed as consensus-invalid and one is moved to
the stale-descendant sidecar, leaving 298 rows in the committed validated file.

## Stale descendants: `data/stale_descendants.csv`

BTC stale-fork continuations whose ancestry walks back to a known stale root.
These are kept separate from direct stales. A raw classifier `unknown` row
stays `unknown`, while this sidecar carries the descendant promotion. It also
holds one former direct-stale row whose predecessor was shown to be stale
rather than active. The file retains the gate verdict for transparency, so not
every row is loadable: loaders take only
`classification = stale_descendant` and `validation_status =
VALID_STALE_DESCENDANT` (currently 21 of 25 rows; the other 4 are
`REJECTED_bip34_height_mismatch`).

Those 4 are error blocks: their own committed bytes prove the BIP34
coinbase-height rule broken. The reconciliation now routes such candidates to
the sidecar's `_error_blocks` peer
(`data/stale_descendants_error_blocks.csv`, gitignored) with the derived
pipe-joined `rules_violated`, and keeps this file's `classification` column
purely `stale_descendant`. The committed file above still predates that split;
the next publication rebuild drops it to 21 rows and emits those 4 to the peer.

Key columns beyond the standard BTC header fields: `promotion_subclass`,
`root_stale_hash` / `root_stale_height` / `root_stale_sources` /
`root_stale_chains` (the known stale root the descendant chains back to),
`stale_fork_depth`, `path_hashes` / `path_chain_sets` (the walked ancestry),
`observed_btc_heights` / `observed_btc_times` / `observed_btc_bits` (multi-source
observations), `pow_valid`, `header_hash_match`, `bip34_height_status`, and
`notes`.

## Upstream contribution sidecar: `data/new_stale_blocks_for_upstream.csv`

The set of publication-gate-accepted stale `(height, hash)` pairs this project
contributes that are not already in `bitcoin-data/stale-blocks`. Rebuilt from the committed inputs
above by `scripts/reports/build_upstream_stale_sidecar.py`.
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
| `artifact_scope` | `full_classifier_inventory`, `stale_only_publication`, or `stale_descendant_sidecar`. |
| `child_height`, `child_block_hash`, `child_header_hex`, `child_block_time`, `child_nbits` | Child-chain location and authenticated header evidence when available. `child_block_hash` is the internal/wire-order double-SHA256 digest, `child_header_hex` is the 80-byte canonical header serialization, `child_block_time` is the header timestamp, and `child_nbits` is eight lowercase hexadecimal characters. For Xaya, the header and timestamp come from `CPureBlockHeader`, while effective `child_nbits` comes from the adjacent `PowData` wrapper. For the six live-lifecycle chains the existing hash and timestamp remain hydrated from `data/child-identity/` (see below); their historical data is not re-derived by this work. |
| `btc_height`, `btc_header_hash`, `btc_prev_hash`, `btc_time`, `btc_bits`, `btc_nonce`, `btc_header_hex` | Normalized Bitcoin parent header fields. |
| `coinbase_scriptsig_hex`, `coinbase_outputs`, `full_coinbase_hex` | Coinbase evidence. Hathor-style full rows with only `full_coinbase_hex` are parsed during export. |
| `classification` | Preserved source classification: `canonical`, `stale`, `unknown` (normalized from the legacy `orphan` spelling on read), `stale_descendant`, `near`, or source-specific values. |
| `validation_status`, `expected_nbits`, `rejection_reason` | Persisted gate verdicts or rejection details when present. |

`auxpow-full-evidence-counts.csv` and
`auxpow-full-evidence-manifest.*` summarize counts for `canonical`, `stale`,
`unknown`, `stale_descendant`, `near`, rejected rows, malformed rows, and missing
evidence fields. The manifest's `canonical_evidence_status` distinguishes
`canonical_retained`, `no_canonical_rows_in_discovered_artifact`,
`canonical_rows_not_represented_stale_only_publication_path`, and
`not_checked_missing_source`.

## Canonical parents

Canonical Bitcoin parents recovered from a chain's AuxPoW commitments are
retained evidence: they record which pool was building on which canonical
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

Parallel-schema chains that do not split, such as RSK (miner-address schema)
and Hathor (canonical in-file), keep their single commingled private inventory.

## Live-chain child identity: `data/child-identity/`

The six live-lifecycle chains (Namecoin, RSK, Syscoin, Hathor, Elastos,
Fractal) were recovered without child block identity: their acquisition
artifacts carry the child height but no child block hash or timestamp.
merge-mining-monitor keys live-captured events by
`(source, child_height, child_block_hash)`, so imported rows need the exact
identity to deduplicate against live capture.

`scripts/extract/recover_child_identity.py` recovers the identity per parent
header by height -> hash -> block RPC against the still-reachable child nodes
(a public API for Hathor). Every row is verified by re-deriving the Bitcoin
parent linkage from the fetched child block and requiring it to match the
row's own `btc_header_hash`: the decoded CAuxPow parent for Namecoin/Syscoin,
the serialized AuxPoW tail for Elastos, the `getblockheader (hash, false,
true)` proof for Fractal, `sha256d(bitcoinMergedMiningHeader)` for RSK (uncle
rows resolve through `eth_getUncleByBlockNumberAndIndex`), and the block-id
identity for Hathor, whose merge-mined block hash IS its BTC parent header
hash. All 2,287 chain/header observations across the six chains verified
against today's canonical child chains (1,919 distinct Bitcoin parent
headers; 232 parents were observed by more than one chain, a single miner
attaching one Bitcoin parent to several merge-mined chains at once).

Each `<chain>_child_identity.csv` carries `chain`, `btc_header_hash`,
`child_height`, `child_block_hash`, `child_block_time`, `verification`, and
`note`. A verified row is usable only when `child_height` is a nonnegative
integer and the child hash and time are valid. `btc_header_hash` stays in
display (RPC) order like every other
pipeline artifact; `child_block_hash` follows the pipeline's established
column contract of internal (wire) byte order for the Bitcoin-family chains
and Hathor, and forward order for RSK, whose keccak block hashes have no
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

Each `<chain>_monitor_evidence.csv` uses the full-evidence schema plus two
columns the monitor's importer parses verbatim. The current schema includes
`child_header_hex`, `child_block_time`, and `child_nbits`; rows from the 17
historical child-header refresh pipelines carry a complete authenticated
bundle. The six live-lifecycle
chains additionally publish `child_block_hash` / `child_block_time` hydrated
from `data/child-identity/` (coverage recorded in the counts `notes` as
`child_identity_hydration=hydrated:N`; a publication build fails closed when
a non-canonical final row lacks a verified identity). Canonical rows remain
publishable when their historical source never recorded exact child identity;
the counts `notes` disclose that limit as `canonical_unhydrated=N`. The RSK
export appends the seven `rsk_merge_mining_evidence` sidecar columns listed in
the child-identity section. Sources outside the 17 historical-header pipelines
emit the child evidence their native source proves; absent fields stay empty
rather than being inferred. The standalone stale-descendants export remains outside the
exact-child-identity contract because each row aggregates observations from
several chains. Its child identity columns therefore stay empty and its counts
note is `child_identity=represented_by_source_chain_observations`. The
corresponding source-chain rows are admitted to the monitor payloads through
`relevance_reason=valid_stale_descendant`. The 28 observations sourced from
unknown rows preserve that source classification and carry the sidecar's
`validation_status=VALID_STALE_DESCENDANT` verdict. The Namecoin and RSK
observations corrected from direct stales are projected as `stale_descendant`
with the same validation verdict only when the direct-stale correction overlay
and the sidecar agree on the source chain, Bitcoin height, and header hash.
The six historical observations carry complete authenticated child
headers; live-chain observations use the independently verified identities in
`data/child-identity/`. A publication build fails closed if any accepted
`(chain, btc_header_hash)` observation is absent; a partial diagnostic reports
the identity as deferred instead of claiming representation.

i0coin and CoiledCoin publish their authenticated child hash, header, time, and
`nBits`, but the normalized `child_height` value remains empty because their
offline archives provide no authenticated consensus height. Doichain's retained
historical inventories likewise leave their former file-order values blank; a
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
loader carries `btc_header_hex` for 1,397 of its 1,625 rows. The remaining 228
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
`validation_contract` object. Its
`valid_token_scope=publication_gate_accepted_not_full_block_validity` value is
the normative interpretation of `validation_status=VALID` for downstream
consumers. In particular, it is not permission for an importer to relabel the
candidate as a fully validated Bitcoin block without independently validating
the complete block and historical chain state.

For full-inventory sources, `source_rows` removes every raw stale-classified
row and inserts the committed gate-accepted validated overlay. It can therefore
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
sources such as VCash and stale-only publication inputs such as Hathor are
omitted because they cannot establish a zero result.
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
known to the active chain; stays `unknown` on this axis - legacy artifacts
wrote `orphan`, and readers accept both), `stale_descendant`
(a stale-fork continuation chaining back to a known stale root), `near` (the
header fails Bitcoin's PoW target - a child-chain artifact that was never a
Bitcoin block; permanently out of scope, never reclassified), `error_block`
(a consensus-invalid full-proof-of-work Bitcoin block witnessed via
merge-mining evidence: the header hash meets the Bitcoin target in force at
the claimed position and the AuxPoW commitments are real, but the block
violates at least one named, mechanically re-checkable consensus rule, so it
was never a stale/orphan contender). Error blocks are catalogued in
`data/error-blocks/error_blocks.csv`, which supersedes the former
`data/stale_block_exclusions.csv` overlay. Blocks that merely fail the PoW
target are not error blocks; they remain `near`. Adding `error_block` is a
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

**`validation_status`**: `VALID` (passed the available chain-specific
publication gates, not full block validation), `VALID_STALE_DESCENDANT`
(descendant accepted under its
declared profile), `REJECTED: ...` / `REJECTED_...` (failed a gate, for example
an nBits mismatch with the canonical BTC height or a BIP34 height mismatch),
`UNKNOWN: ...` (required context or evidence unavailable at gate time).
Committed per-chain validated CSVs contain only `VALID` rows. Two rejected
spellings exist historically - the nBits gates write `REJECTED: <detail>` and
the descendant reconciler writes `REJECTED_<reason>` - so consumers must match
on the `REJECTED` prefix, never on an exact string.

The `VALID` spelling is a compatibility token, not a claim that Bitcoin Core
accepted a complete block. The compact direct-stale rows do not contain the
complete Bitcoin transaction set, so the project cannot check the candidate's
full merkle tree, block transaction rules, weight, witness commitment, sigops,
finality, scripts, subsidy, fees, or UTXO effects.

**Chain status** (used in the per-chain docs): the data-availability axis is
`live` / `historical` / `catalogued` (does this project have live, recovered,
or merely catalogued evidence), and the chain-liveness axis is `active` /
`dead` / `dormant` / `zombie` (a zombie chain still produces blocks at
negligible sub-Bitcoin difficulty). These are independent axes; the
merge-mining-monitor uses the same vocabulary.

**Pool labels**: unified pool attribution is planned future work. The current
public pipeline preserves coinbase evidence but does not depend on
`bitcoin-data/mining-pools` or emit a shared pool-label column. RSK's committed
source data is a historical exception because it already carries miner-address
labels; consumers should not treat that chain-specific field as a completed
cross-chain attribution dataset.
