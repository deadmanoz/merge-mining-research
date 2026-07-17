# Namecoin

| Field | Value |
|---|---|
| Ticker | NMC |
| AuxPoW activation | NMC height 19,200 on 2011-10-11 |
| Associated Bitcoin parent | BTC height 148,553, dated 2011-10-08 |
| AuxPoW chain ID | 1, with strict chain-ID checking |
| Chronological position | 1 of 26 (first production AuxPoW witness) |
| In Stifter et al. 2018 baseline | **Yes** (one of the paper's seven measured Bitcoin-parent chains; Table 1, and the paper's canonical first AuxPoW chain) |
| Source tag (in code) | `namecoin` |
| Loader | `load_namecoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/namecoin_validated_stales.csv` |

Namecoin is the earliest production AuxPoW witness in this project's configured
chronology. Stifter et al. identify Namecoin block 19,200 on 11 October 2011 as
the activation block and associate its AuxPoW with Bitcoin block 148,553,
whose header timestamp is dated 8 October. These are different dates and are
recorded separately here. The project chronology is a reproducible attribution
convention, not a claim about which child chain observed an individual Bitcoin
stale first.

Primary historical references are the
[release-pinned Namecoin Core chain parameters](https://github.com/namecoin/namecoin-core/blob/462d5412ec2887155684c1b8c30abfe095395d3e/src/kernel/chainparams.cpp#L104-L147)
and Stifter et al.,
["Echoes of the Past: Recovering Blockchain Metrics From Merged Mining"](https://eprints.cs.univie.ac.at/6448/1/2018-1134.pdf).

## Public data and provenance

The recovery was produced from an archival Namecoin Core `blk*.dat` snapshot.
The raw block files and complete candidate inventories are not published. This
repository publishes the compact accepted loader input, the extraction and
classification code, the consensus-invalid exclusion overlay, and derived
novelty and monitor tables. A reader can rerun the documented header-level
checks over the public union of the loader and monitor exports. The public
checkout does not contain the complete original candidate inventory, complete
Bitcoin block bodies, or self-contained AuxPoW proofs, and cannot rerun initial
candidate selection or prove full Bitcoin block validity.

The archival snapshot's acquisition date, terminal Namecoin height and hash,
and Namecoin Core revision are not recorded in a committed provenance
manifest. The ranges below describe the recovered accepted rows, not the
terminal boundary or completeness of the source snapshot.

The corrected snapshot contains **1,625 distinct direct-stale Bitcoin header
candidates accepted by the declared header-context profile**:

| `validation_status` | Rows |
|---|---:|
| `VALID` | 1,353 |
| `VALID (post-BCH, difficulty matches BTC)` | 272 |
| **Total** | **1,625** |

The rows span:

- Bitcoin heights 149,589 through 934,425
- recorded legacy Namecoin heights 22,379 through 809,650
- Bitcoin parent timestamps 2011-10-17 through 2026-01-31

The current public block-file extractor deliberately writes a reproducible
`child_sequence`, the child block hash, and a blank `child_height`: block-file
order is not consensus height. The published helper for resolving child hashes
through RPC does not currently have a Namecoin configuration. The exact
`nmc_height` values above therefore remain historical acquisition metadata from
the legacy inventory and are not reproducible from the compact public artifacts
alone. A fresh extraction would need to resolve each child hash through a
Namecoin node before classification.

`btc_header_hex` is present for 1,397 loader rows. The committed monitor
evidence publishes hydrated headers for the remaining 228 accepted rows, so
all 1,625 accepted rows now have a public header source. Every row retains the
detached parent coinbase scriptSig, and 1,476 retain decoded output data. No row
retains the complete serialized parent coinbase transaction, its parent-merkle
branch, the Namecoin child block hash, or a self-contained AuxPoW proof.
Reproducing the 228 header hydrations still requires prototype or private
extraction artifacts that are not in the public checkout.

The pinned upstream dataset carries a matching full-block blob for 295 of the
1,625 direct candidates. The repository confirms that each blob starts with
the expected header, but none has undergone full historical consensus replay
here. The other 1,330 direct candidates have no matching full block body in the
pinned dataset.

The `VALID` token is retained for compatibility. It means that the row passed
the declared publication gate, not that Bitcoin Core validated a complete
Bitcoin block. See the [data validity contract](../data-validity.md).

On 20 July 2026, all 1,625 direct rows were replayed against Bitcoin Core tip
958,882 and passed the complete available-evidence header-context profile.
This was not a full-block consensus replay.

## Recovery and validation

The public workflow is:

1. `scripts/extract/extract_auxpow_from_blkdat.py` parses supported
   Namecoin-wire-format `CAuxPow` records, enforces Namecoin's chain ID 1, and
   extracts the child hash plus Bitcoin parent header and coinbase evidence.
   The configured height-19,200 transition is reference metadata because the
   extractor cannot apply a consensus-height boundary until child hashes have
   been resolved through RPC.
2. The extractor checks that `SHA256d(header)` satisfies the target encoded in
   that header's `nBits`. This is a self-target proof-of-work check, not proof
   that the header matches Bitcoin's contemporaneous difficulty schedule.
3. `scripts/classify/classify_auxpow_candidates.py` treats a returned header as
   canonical only when Bitcoin Core reports positive confirmations. A
   candidate whose own header is not active but whose parent is active is a
   direct stale candidate at `parent_height + 1`. Pass
   `--classified-output <chain-archive>/namecoin/classified/namecoin_blkdat_classified.csv`
   to preserve every canonical, stale, rejected-stale, and unknown candidate
   for later hydration and ancestry reconciliation.
4. The candidate timestamp must be greater than the active parent's Bitcoin
   median-time-past.
5. The classifier compares the candidate `nBits` with the canonical Bitcoin
   value at that recovered height. This rejects Bitcoin-family headers using a
   different difficulty schedule.
6. The recovered signed block version must meet Bitcoin's historical minimum:
   version 2 from BIP34 height 227,931, version 3 from BIP66 height 363,725,
   and version 4 from BIP65 height 388,381.
7. The recovered coinbase scriptSig must be between 2 and 100 bytes, matching
   Bitcoin's consensus bounds.
8. BIP34 is checked under the rules contemporaneous with the candidate. From
   height 224,413, version 2 or newer blocks must begin the coinbase scriptSig
   with the exact minimally encoded recovered height while version 1 remains
   valid. From height 227,931, version 1 is rejected and the prefix is mandatory
   for every valid block. Modern Bitcoin Core buries the deployment at 227,931,
   so the classifier implements the earlier transition explicitly.
9. The committed loader input contains only `classification == "stale"` rows
   whose validation status starts with `VALID`. Candidates are deduplicated by
   `(height, hash)`, not by height alone.

These checks establish necessary header and contextual conditions. They do not
link the detached coinbase evidence back to the header merkle root or validate
the complete candidate block's transactions, merkle tree, weight, witness
commitment, sigops, finality, scripts, subsidy, or fees. Passing the gate
therefore does not establish full Bitcoin consensus validity.

Direct-stale loaders apply every exact-key publication correction. The general
upstream catalogue applies only the consensus-invalid keys, retaining the
direct-only correction as stale-descendant evidence. This prevents an older
source from reintroducing an invalid or misclassified direct candidate without
discarding the corrected descendant.

## Publication corrections

A publication audit found 31 Namecoin stale candidates that passed the
header-target and canonical-height `nBits` checks but failed Bitcoin consensus.
Twenty-one fail BIP34's mandatory coinbase-height rule: 12 version 2 candidates
at heights 225,013 through 226,912 during the historical transition, plus nine
later candidates. Three version 2 headers after height 363,725 fail BIP66's
minimum version 3 rule. Five headers below version 4 after height 388,381 fail
BIP65's minimum version 4 rule. One candidate violates median-time-past, and
one has a 103-byte coinbase scriptSig above Bitcoin's 100-byte limit.

A separate correction applies only to direct-stale classification. The header
at Bitcoin height 656,478 extends a known stale at height 656,477 rather than an
active-chain block. It passes the available branch-context checks and remains
accepted in `data/stale_descendants.csv`, but it is not a direct stale.

The correction makes three related changes:

- removes the 31 consensus-invalid rows and the one direct-only reclassification
  from `data/validated-stales/namecoin_validated_stales.csv`;
- rejects equivalent rows in any other committed chain input; and
- records the 32 exact keys, signed header versions, coinbase evidence, and
  exclusion scope in
  `data/stale_block_exclusions.csv` until the pinned upstream source publishes
  a corresponding correction.

The historical Namecoin contribution therefore contains **1,061 accepted direct
additions**, not 1,089. The historical upstream commit still records the
original 1,089-row addition and is retained as provenance:
[bitcoin-data/stale-blocks commit `ddba8a4`](https://github.com/bitcoin-data/stale-blocks/commit/ddba8a4c503338151633134e657efb7fd25c85a5).

## Upstream and chronological novelty

At the snapshot immediately preceding the historical contribution, 564 of the
corrected direct Namecoin rows were already present upstream and 1,061 were
additions. At the currently pinned upstream snapshot, all 1,625 accepted
Namecoin direct rows are
present, so current isolated novelty versus upstream is zero.

| Current split | Rows |
|---|---:|
| Also in effective upstream after exclusions | 1,625 |
| Novel versus upstream | 0 |
| Earlier-chain attribution | 0 |
| Chronologically novel at this position | 0 |

This does not mean Namecoin contributed no recoveries. It means its accepted
contribution has already been incorporated into the pinned upstream dataset.

## Private research boundary

Full canonical, near, and unknown inventories remain in the private research
archive and are not loader inputs. Archived investigations tested whether
selected unknown chains could represent Bitcoin stale forks, but those
investigations did not justify promoting unknown rows into the public stale
dataset. Their detailed counts, scripts, and intermediate tables are outside
this repository's current public reproducibility boundary.

The preserved historical classifier inventory contains 466,184 extracted
self-target-valid candidates: 456,685 labelled canonical, 1,658 labelled
stale, and 7,841 written with the legacy `orphan` spelling now read as
`unknown`. A separate 344,707-row investigation table contains 335,208
`near`, 1,658 `stale`, and the same 7,841 unknown rows. These are legacy
classifications, not a current normalized canonical-coverage export. Producing
that export still requires reclassifying all 466,184 raw candidates against a
current Bitcoin Core node.

The public loader therefore continues to exclude `classification == "unknown"`
rows. No public claim is made here that those rows are deep Bitcoin
reorganisations or that they belong to a particular Bitcoin-derived chain.
The publication-facing relevance pass retains 21 of them as observations: 11
meet the strict BTC-orphan relevance rule and 10 meet the weak rule. They remain
`classification == "unknown"`, are not direct-stale promotions, and appear only
in the strict/weak and monitor evidence artifacts.

## Public artifacts

- `data/validated-stales/namecoin_validated_stales.csv`: corrected publication-gate-accepted
  loader input. The historical filename is retained for compatibility.
- `data/stale_block_exclusions.csv`: compact consensus-invalid and direct-only
  publication overlay with raw coinbase scriptSig evidence. It is an audit
  record, not a self-contained AuxPoW proof.
- `results/per-chain-novelty/namecoin.csv`: row-level upstream and chronology
  comparison.
- `results/monitor-evidence/namecoin_monitor_evidence.csv`: monitor-facing
  accepted and relevance-classified evidence.
- `scripts/extract/extract_auxpow_from_blkdat.py`: public `blk*.dat` extractor.
- `scripts/classify/classify_auxpow_candidates.py`: active-chain, `nBits`,
  median-time-past, historical minimum-version, coinbase scriptSig length, and
  BIP34 validation path.
- `src/stale_blocks_analysis/stale_blocks.py`: loader and exclusion application.
- `docs/auxpow-recovery.md`: cross-chain methodology and summary.
- `docs/data-reference.md`: schemas and value vocabularies.
- `LICENSE-DATA`: data licensing terms.

These 1,625 rows define the accepted Namecoin direct header-candidate set for this
release. This is not a claim of full Bitcoin block validity or exhaustive chain
coverage because complete Bitcoin block bodies are generally unavailable and
the source snapshot boundary is not publicly documented. Full re-extraction
and the archived unknown-origin investigations still require private source
inventories and are not reproduced by this repository.
