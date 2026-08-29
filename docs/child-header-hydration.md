# Historical child-header hydration

The 17 historical Namecoin-family pipelines now emit the child block hash,
80-byte header, timestamp, and `nBits` directly from the original block source.
The classifier preserves the four fields in canonical, stale, unknown, near,
and validated outputs. Full-evidence and monitor-evidence exports retain them
in the stable order `child_height`, `child_block_hash`, `child_header_hex`,
`child_block_time`, `child_nbits`.

Every committed validated CSV retains the same 16-column core schema even when
its source cannot populate every child field. Unavailable values remain blank;
chain-specific research columns follow the core columns.

This is not a post-processing workflow. An existing raw, classified, or
validated CSV without the header bundle is insufficient. Regeneration starts
from a raw block, decoded block record, immutable block dump, or an
authoritative node/API response and exercises the chain's normal extractor.

## Source regeneration

The original sources were read without modification. The table intentionally
omits hostnames, mount paths, credentials, and operator-specific locations.

| Chain | Normal source route | Refresh status |
| --- | --- | --- |
| Devcoin | Raw RPC block by true height and source hash | Regenerated and authenticated. |
| ixcoin | Raw RPC block by true height and source hash | Regenerated and authenticated. |
| i0coin | Original `blk*.dat` snapshot; consensus height unavailable | Header bundle regenerated and authenticated. |
| Groupcoin | Original decoded `getblock` JSON dump | Regenerated and authenticated. |
| CoiledCoin | Original `blk*.dat` blocks scanned by embedded BTC parent | Regenerated and authenticated. |
| Geistgeld | Original decoded `getblock` JSON dump | Regenerated and authenticated. |
| Huntercoin | Original per-height block binaries plus hash index | Regenerated and authenticated. |
| Bitmark | Copied datadir or raw blocks through the normal RPC extractor | Regenerated and authenticated. |
| Terracoin | Copied datadir through decoded `getblock` RPC | Regenerated and authenticated. |
| Emercoin | Copied datadir through PoW-only decoded `getblock` RPC | Regenerated and authenticated. |
| Myriadcoin | Copied datadir, SHA-256d branch only | Regenerated and authenticated. |
| Unobtanium | Copied datadir through the normal raw RPC extractor | Regenerated and authenticated. |
| Argentum | Raw RPC block, SHA-256d branch only | Regenerated and authenticated. |
| Crown | Raw RPC block by true height and source hash | Regenerated and authenticated. |
| Electric Cash | Raw RPC block by true height and source hash | Regenerated and authenticated. |
| Xaya | Original `blocks.zip` / `blk*.dat` snapshot | Regenerated and authenticated. |
| Bitcoin Vault | Authoritative raw Blockbook response by height/hash | Regenerated and authenticated. |

The regeneration read archives without modifying them. Node-based recovery ran
from copies or read-only source mounts with writable runtime state elsewhere.

## Authentication contract

For every populated row:

- `child_header_hex` is exactly 160 hexadecimal characters.
- Double-SHA256 of the 80-byte header equals `child_block_hash` in internal
  wire order.
- Header bytes 68 through 71 decode as a little-endian uint32 to
  `child_block_time`.
- Header bytes 72 through 75 decode as a little-endian uint32 to `child_nbits`
  for Bitcoin-shaped child headers; CSVs render the value as eight lowercase
  hexadecimal characters.
- The source-supplied display hash, when available, equals the display hash
  derived from the same header.
- The AuxPoW payload from the same source block supplies the row's Bitcoin
  parent header, so the child evidence cannot be joined from another row.

Byte ranges in this document are zero-based, inclusive, and relative to the
start of the child header unless an enclosing source format is named.

Xaya keeps the same hash and timestamp rules for its 80-byte
`CPureBlockHeader`, but its effective `child_nbits` is the little-endian uint32
in the adjacent `PowData` wrapper. A merge-mined Xaya row must have zero in the
header's own `nBits` field and a non-zero effective target in `PowData`; the
shared validator enforces both invariants.

For the 17 historical targets, a missing or partial child bundle stops
classification, and any contradiction stops classification or report
generation. This deliberately makes a mixed pre-hydration/refreshed historical
archive tree unusable for publication until its normal extraction inputs have
been regenerated. Other source families use their documented native evidence
profile: complete bundles receive the same authentication, and every field
supplied by a format with fewer child-header fields is validated. Child bundle
validation runs before the classifier's parent-header PoW filter, so a
contradictory bundle stops the run even when that parent would later be
filtered out.

Ordinary Bitcoin-family RPC extractors obtain their column order from
`standard_auxpow_extraction_columns()`: the native chain-height column, the four
authenticated child-header fields, then the common Bitcoin parent and coinbase
fields. Huntercoin, Xaya, and the generic `blk*.dat` scanner retain richer
source-acquisition fields needed to authenticate or reconstruct their inputs;
their classifier outputs normalize into the same evidence schema. These are
acquisition differences, not per-chain publication formats.

The coverage report is scoped to the 17 historical targets. Five active child
chains continue to use the independently verified child hash and time records
under `data/child-identity/`; they are not presented as 80-byte
historical-header recoveries. Hathor is also active, but publishes its
source-authenticated block identity and timestamp directly.

## Refresh and coverage

Run each normal extractor and classifier into a staging tree. Rebuild
validated, full-evidence, strict/weak, monitor-evidence, and operator-managed
canonical artifacts there. Compare every pre-existing field, classification,
row identity, count, and ordering against the prior artifact. The new child
columns and documented schema normalization may differ; any unexplained delta
stops publication.

The generic classifier installs its three publication buckets as one
transaction. Hidden sibling `.previous-*` files are temporary rollback copies
and are removed after a successful install. If an interrupted install or
rollback failure leaves one behind, treat it as recovery evidence rather than
as a current publication artifact.

Generate the coverage report with:

```bash
just child-header-coverage --input-dir <staged-evidence-dir> \
  --output <staged-results-dir>/child-header-coverage.csv
```

The report covers all 17 chains, records total, hydrated, and unrecoverable
rows, reason counts, time range, and child-minus-parent timestamp range, and
fails before replacing its output on an authentication contradiction. It also
cross-references publication-gate-accepted rows in `data/stale_descendants.csv`
by source chain and Bitcoin header hash, the same identity on which the
per-chain classifier inventories deduplicate. Repeated provenance references
for the same chain and parent hash therefore count as one observation. Those
observations remain `unknown` in the per-chain classifier inventory, but their
source-chain rows are part of the hydration scope and receive separate total,
hydrated, and unrecoverable counts in the report. This prevents accepted
descendants from disappearing behind aggregate per-chain coverage.

A row is "unrecoverable" in this report when the sampled refreshed artifact did
not populate its complete authenticated child bundle; the term does not claim
that the original source is permanently unavailable. The reason column
distinguishes a wholly missing bundle from a partially populated one. A
populated chain whose timestamp deltas are all zero is marked `degenerate` for
investigation. A chain with hydrated rows but missing or malformed parent
timestamps is marked `incomplete`; `child_parent_delta_coverage` reports the
exact parent-timestamp count as `available/hydrated`. Zero-row or
zero-hydration chains are `not_applicable`.

Missing or incomplete bundles are successful report outcomes because their
counts and reasons are the report's purpose. Authentication contradictions are
hard failures and leave the previous report untouched. A publication decision
must inspect the reported unrecoverable counts rather than treating process
exit alone as a complete-coverage assertion.

The completed refresh authenticated all **2,933,154 of 2,933,154** historical
source rows, with zero unrecoverable rows. All **6 of 6** accepted
stale-descendant observations belonging to those 17 sources also carry
complete authenticated child headers. `results/child-header-coverage.csv`
records the per-chain totals and time ranges.

The timestamp-delta columns are diagnostics across every evidence state, not
canonical-Bitcoin assertions. Crown's maximum delta of 1,544,645,238 seconds
comes from one self-target-PoW-valid `unknown` parent header whose serialized
Bitcoin-parent `nTime` is zero. The child header and its timestamp authenticate
correctly against the Crown source; the outlier is retained as unknown evidence
and does not describe a canonical Bitcoin block.

The normal publication build now emits every available canonical row together
with accepted direct stales, accepted descendants, and strict/weak unknown-row
observations for every chain. It does not use a chain allowlist. The committed
monitor-evidence and strict/weak projections were regenerated from those
inputs. The committed ordinary monitor payloads retain the preceding 30 exact
per-chain observations behind the accepted descendant sidecar: 28 preserve
their source `unknown` classification while carrying
`validation_status=VALID_STALE_DESCENDANT`, while the Namecoin and RSK rows
corrected from direct stales are published in their final `stale_descendant`
state with the same verdict. The current sidecar has 31 source observations:
26 legacy `unknown`/`orphan` rows, the same two direct-stale corrections, and
three exact canonical-bucket observations for height 941,882. The
aggregate-only error-observation refresh leaves all 28 ordinary artifacts
byte-identical; the three canonical corrections appear in the next complete
ordinary publication rebuild. Complete normalized full-evidence and
canonical-classifier inventories were retained as dated external refreshes
because those broad artifacts are too large for the repository's normal
source-data boundary.
