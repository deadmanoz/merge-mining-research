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
classification code, the consensus-invalid error-blocks dataset, and derived
novelty and monitor tables. A reader can rerun the documented header-level
checks over the public union of the loader and monitor exports. The public
checkout does not contain the complete original candidate inventory, complete
Bitcoin block bodies, or self-contained AuxPoW proofs, and cannot rerun initial
candidate selection or prove full Bitcoin block validity.

The archival snapshot's acquisition date, terminal Namecoin height and hash,
and Namecoin Core revision are not recorded in a committed provenance
manifest. The ranges below describe the recovered accepted rows, not the
terminal boundary or completeness of the source snapshot.

The published dataset contains **1,649 distinct direct-stale Bitcoin header
candidates accepted by the declared header-context profile**:

| `validation_status` | Rows |
|---|---:|
| `VALID` | 1,353 |
| `VALID (post-BCH, difficulty matches BTC)` | 296 |
| **Total** | **1,649** |

The rows span:

- Bitcoin heights 149,589 through 944,852
- recorded historical Namecoin heights 22,379 through 820,198
- Bitcoin parent timestamps 2011-10-17 through 2026-04-13

The current public block-file extractor writes the child block evidence and a
blank height slot: block-file order is not consensus height. The `nmc_height`
values above originated as historical acquisition metadata from the archival
inventory. Normalization therefore blanks the height from Namecoin's
full/unknown/canonical classifier sources before publication; it never treats
that scan-order value as consensus data. Every accepted row's published height
is instead node-verified:
`scripts/extract/recover_child_identity.py`
(which does carry a Namecoin RPC configuration, `NAMECOIN_RPC_*`) fetched the
canonical Namecoin block at each recorded height and required its decoded
CAuxPow parent hash to equal the row's own `btc_header_hash`, committing the
verified child block hash and timestamp to
`data/child-identity/namecoin_child_identity.csv`. A fresh extraction can
either replay that height -> hash -> block verification against a Namecoin
node or resolve child hashes directly, as before.

`btc_header_hex` is present for 1,421 loader rows. The committed monitor
evidence publishes hydrated headers for the remaining 228 accepted rows, so
all 1,649 accepted rows now have a public header source, and every monitor
row also carries the node-verified Namecoin child block hash and timestamp
hydrated from `data/child-identity/` (internal byte order, per the
`child_block_hash` contract). Every row retains the detached parent coinbase
scriptSig, and 1,500 retain decoded output data. No row retains the complete
serialized parent coinbase transaction, its parent-merkle branch, or a
self-contained AuxPoW proof. Reproducing the 228 header hydrations still
requires prototype or private extraction artifacts that are not in the
public checkout.

The pinned upstream dataset carries a matching full-block blob for 319 of the
1,649 direct candidates. The repository confirms that each blob starts with
the expected header, but none has undergone full historical consensus replay
here. The other 1,330 direct candidates have no matching full block body in the
pinned dataset.

Either exact accepted direct-stale status means that the row passed the
declared publication gate, not that Bitcoin Core validated a complete
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
   whose validation status is one of the two exact accepted direct-stale
   verdicts. Candidates are deduplicated by
   `(height, hash)`, not by height alone.

These checks establish necessary header and contextual conditions. They do not
link the detached coinbase evidence back to the header merkle root or validate
the complete candidate block's transactions, merkle tree, weight, witness
commitment, sigops, finality, scripts, subsidy, or fees. Passing the gate
therefore does not establish full Bitcoin consensus validity.

Direct-stale loaders apply the exact-key error-block gate before publication.
Stale-ancestry reconciliation independently publishes height 656,478 through
the parent verdict and witness tables. Source bucket labels are audit evidence
and cannot override either result.

## Consensus-invalid and descendant routing

The current source classification routes 32 Namecoin direct-stale candidates
to the error-block module. They passed the header-target and canonical-height
`nBits` checks but failed Bitcoin consensus.
Twenty-one fail BIP34's mandatory coinbase-height rule: 12 version 2 candidates
at heights 225,013 through 226,912 during the historical transition, plus nine
later candidates. Three version 2 headers after height 363,725 fail BIP66's
minimum version 3 rule. Five headers below version 4 after height 388,381 fail
BIP65's minimum version 4 rule. One candidate violates median-time-past, and
one has a 103-byte coinbase scriptSig above Bitcoin's 100-byte limit.
One further candidate at height 717,696 carries the prior epoch's `nBits`.
That parent is already catalogued from authenticated Emercoin and Syscoin
witnesses. Namecoin's block-file occurrence carries scan order rather than a
durable child identity, so it does not add an error-observation ledger row.

The header at Bitcoin height 656,478 extends a trusted stale root at height
656,477 rather than an active-chain block. It passes the available
branch-context checks and is represented as a stale descendant, not a direct
stale. `data/validated-stales/namecoin_validated_stales.csv` therefore contains
neither that descendant nor the 32 consensus-invalid candidates.
`data/error-blocks/error_blocks.csv` records the invalid candidates by exact
parent identity with their signed header versions, coinbase evidence, and
rejection reasons.
The current raw source also records height 941,882 as unknown; its authenticated
Namecoin child observation is published against the shared accepted descendant
parent verdict.

The historical Namecoin contribution therefore contains **1,061 accepted direct
additions**, not 1,089. The historical upstream commit still records the
original 1,089-row addition and is retained as provenance:
[bitcoin-data/stale-blocks commit `ddba8a4`](https://github.com/bitcoin-data/stale-blocks/commit/ddba8a4c503338151633134e657efb7fd25c85a5).

## Upstream and chronological novelty

At the time of the historical contribution, 564 accepted direct Namecoin rows
were already present upstream and 1,061 were additions. In the pinned upstream
dataset, all 1,649 accepted
Namecoin direct rows are
present, so current isolated novelty versus upstream is zero.

| Current split | Rows |
|---|---:|
| Also in effective upstream after the error-blocks gate | 1,649 |
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
stale, and 7,841 written with the historical `orphan` spelling that readers
normalize to `unknown`. A separate 344,707-row investigation table contains
335,208 `near`, 1,658 `stale`, and the same 7,841 unknown rows. These are historical
source classifications, not the current normalized canonical-coverage export.
The 30 August reclassification of the same 466,184 candidates against current
Bitcoin Core yields 456,660 canonical, 1,649 accepted direct stale, 32
`error_block`, and 7,843 unknown rows. That same-generation source drives the
committed Monitor projection.

The public loader therefore continues to exclude `classification == "unknown"`
rows. No public claim is made here that those rows are deep Bitcoin
reorganisations or that they belong to a particular Bitcoin-derived chain.
The publication-facing relevance pass retains 21 of them as observations: 11
meet the strict BTC-orphan relevance rule and 10 meet the weak rule. They remain
`classification == "unknown"`, are not direct-stale promotions, and appear only
in the strict/weak and monitor evidence artifacts.

## Public artifacts

- `data/validated-stales/namecoin_validated_stales.csv`: publication-gate-accepted
  direct-stale loader input.
- `data/error-blocks/error_blocks.csv`: the consensus-invalid error-blocks
  dataset and exact-key exclusion gate, with raw coinbase scriptSig evidence.
  It is an audit record, not a self-contained AuxPoW proof.
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

These 1,649 rows define the accepted Namecoin direct header-candidate set for this
release. This is not a claim of full Bitcoin block validity or exhaustive chain
coverage because complete Bitcoin block bodies are generally unavailable and
the source snapshot boundary is not publicly documented. Full re-extraction
and the archived unknown-origin investigations still require private source
inventories and are not reproduced by this repository.
