# i0coin

The current result processes the complete March 2026 snapshot: 87 block files,
4,700,682 distinct child headers and 11,626,267,268 bytes of raw block data.
It contributes **191 accepted direct-stale Bitcoin headers**, including 25
additional I0coin observations compared with the January 2018 snapshot.
All 25 headers were already recovered through other child chains.

| Field | Value |
|---|---|
| Ticker | I0C |
| AuxPoW activation | 2011-12-20, at I0C height 160,000 |
| Acquisition | Offline March 2026 snapshot; no live I0coin node required |
| Chronological position | 3 of 27, after Namecoin and Geistgeld |
| In Stifter et al. 2018 baseline | Yes |
| AuxPoW chain ID | 2 |
| Target block interval | 90 seconds |
| Source tag | `i0coin` |
| Loader | `load_i0coin_stales()` |
| Validated CSV | `data/validated-stales/i0coin_validated_stales.csv` |

i0coin launched in August 2011 and became the third SHA-256d AuxPoW chain in
this project's activation chronology. Its target interval provides roughly
6.67 child-block opportunities per ten-minute Bitcoin interval. This is a
sampling opportunity, not a guarantee that each Bitcoin stale was observed.

## 1. Acquisition and coverage

The source is the [March 2026 snapshot announcement](https://bitcointalk.org/index.php?topic=624935.msg66548791#msg66548791)
and its [complete I0coin.7z archive](https://drive.google.com/file/d/11-D1r5s8267YmOT1VaObrcmVoV8d_JAn/view?usp=sharing),
acquired on 2026-09-08. The archive is 4,577,214,986 bytes with SHA-256
`6363c3635099640d47e4afc5bacb0cf53d9f5103f2aef1bb027e357d2cd74a9d`.
The complete archive integrity test and extraction passed. The original
archive, extracted files, per-file checksums and processing receipts are
retained privately alongside the earlier snapshot.

All files `blk00000.dat` through `blk00086.dat` were processed. Their child
header timestamps range from **2011-08-16 01:20:20 UTC** to
**2026-03-26 12:34:42 UTC**. The record count and timestamp bounds describe
stored data; they do not assert active-chain membership or full child-chain
consensus validation.

Bitcoin-parent coverage is narrower. The recovered canonical parents span
BTC **158,531 to 689,505**, with timestamps from 2011-12-22 to 2021-07-03.
Accepted direct stales span BTC **160,948 to 645,179**, from 2012-01-06 to
2020-08-24. The full scan found no later accepted direct stale. The snapshot's
2026 endpoint should therefore not be presented as the endpoint of its
accepted Bitcoin stale evidence.

## 2. Extraction and independent verification

The normal `scripts/extract/extract_auxpow_from_blkdat.py --chain i0coin`
entry point scans every framed block and extracts the Bitcoin parent from
each AuxPoW-bearing child. Its default filter retains parents whose hash
meets the target encoded in their own `nBits`; Bitcoin's contextual target
is checked separately during classification. Every qualifying child
observation is preserved. File order is never used as a consensus height.

| Extraction stage | Records |
|---|---:|
| Distinct stored child headers | 4,700,682 |
| Non-AuxPoW child records | 162,662 |
| Parsed AuxPoW records | 4,538,020 |
| Parents meeting their own encoded proof-of-work target | 189,652 |
| Parents failing that self-target filter | 4,348,368 |
| Malformed flagged AuxPoW records | 0 |
| Qualifying witnesses failing the independent proof audit | 0 |

A separate bounded binary parser checked all flagged AuxPoW records and
fully verified every qualifying witness. It checked the parent coinbase's
Merkle inclusion, child commitment branch and deterministic chain index,
chain IDs, committed tree size and nonce, parent work against the child's
encoded target, complete child transaction serialization and child Merkle
root. All 189,652 observations matched the normal extraction across 15
parent, child and coinbase fields. The audit also rejected 171 deliberately
corrupted proofs. All previously recovered 13 targeted witnesses reproduced
with identical raw bytes and heights.

The audit follows the historical rules in I0coin commit
`4e166c8c9ac8b452dc3007520bf8b61950ad91c1`. In particular, **1,492 qualifying
proofs legitimately omit the `fabe6d6d` marker**: their first child commitment
root starts no later than byte offset 20 in the coinbase script, as the legacy
rule permits. A mandatory-marker check would falsely reject them.

Every qualifying child's ancestry was traced through the retained headers
to the known genesis hash
`00000000de13b7f748fb214e3f9c284fe6a57e1559fee545bfe473f72599c0d1`.
This establishes a height by counting parent links, without claiming that
the child belongs to the active chain. The private source family retains
these heights and complete Bitcoin coinbases. Published direct-stale and
error witnesses carry the derived heights; the historical full-inventory
and canonical source contracts continue to leave their normalized height
cells blank.

The independent proof audit does not replay child-chain difficulty changes,
transaction scripts or UTXO consensus. Likewise, the Bitcoin evidence usually
contains a parent header and coinbase proof, not the complete Bitcoin block.

## 3. Bitcoin classification and publication

`scripts/classify/classify_auxpow_candidates.py` classifies every qualifying
parent against Bitcoin Core. A noncanonical header whose predecessor is
canonical becomes a direct-stale candidate. Available-evidence gates check
header identity, self-target work, Bitcoin's expected `nBits`, median time
past, historical block version, coinbase script length and BIP34 height.
A separate review repeated these checks for all 191 accepted rows, including
all 25 additions, with no failures.

| Final classifier bucket | Observations |
|---|---:|
| Canonical | 27,661 |
| Accepted direct stale | 191 |
| Unknown | 161,799 |
| Directly classified error block | 1 |
| **Total** | **189,652** |

The unknown total includes nine candidates whose encoded `nBits` failed
Bitcoin's contextual difficulty gate. Independent active-parent checks place
them at heights 376,385 to 376,388, where Bitcoin required `181287ba` rather
than their `1a1bf2d4`. Their hashes exceed the required target by roughly
2,018 to 93,852 times, so they also fail Bitcoin's actual work requirement.

One additional self-target-valid parent's encoded target exceeds Bitcoin's
proof-of-work limit. Its predecessor is not on the active Bitcoin chain, and
its hash exceeds the target selected for a timestamp-based comparison by
roughly 1,883 times. That comparison does not authenticate its Bitcoin height.
Neither review identified an additional admissible invalid-block parent.

All 103,383 previous source observations and all 166 previous accepted
stales remain represented. Of the 191 accepted rows, 154 have status `VALID`
and 37 have `VALID (post-BCH, difficulty matches BTC)`. The loader admits
only those exact statuses and applies the shared error exclusion gate.

The full scan adds I0coin witnesses for the already catalogued invalid
Bitcoin parents at heights **331,673 and 331,674**. They remain excluded from
stale and orphan publication despite appearing in the classifier's unknown
bucket. The directly classified BIP66 failure at **367,047** was already
catalogued. Its existing child witness height is corrected from 1,546,542
to **1,546,541**, independently confirmed by counting links to genesis.
No new invalid Bitcoin parent was discovered. The error module now records
three I0coin witnesses, with complete coinbase evidence retained.

The normalized private full-evidence export contains **189,649** observations
after excluding those three catalogued invalid parents: 27,661 canonical,
191 accepted direct stale and 161,797 unknown observations. An independent
comparison verified every retained source observation and its normalized fields.

The complete relevance pass identifies **2 strict and 0 weak** I0coin unknown
observations. Unknown relevance is a separate classification axis; it does not
promote an unanchored parent to an accepted direct stale.

### Novelty

`results/per-chain-novelty/i0coin.csv` compares the 191 accepted observations
with the exact upstream pin in `data-sources.tsv`. **140 are already upstream
and 51 are absent upstream**. Under the project's earlier-chain precedence
rule, all 51 are first-claimed by I0coin. Namecoin also observes 107 of the
191 headers, overlapping the upstream-known set.

The additional I0coin witnesses change some later chains' chronological
attribution, but every added header was already known elsewhere in this
project. Earlier-chain precedence is a reproducible attribution convention,
not a claim about the order in which miners actually saw a stale block.

## 4. Reproducible artifacts

The private run retains the raw archive and block-file hashes, original
extraction, full classifier inventory and splits, full serialized witnesses,
independent audit scripts and receipts, genesis-linked heights, complete
source selection, unknown relevance assessment and full-evidence exports.
The public interfaces are the validated loader CSV, per-chain novelty CSV,
Monitor evidence and counts, error catalogue and witness ledger, and derived
upstream contribution sidecars. Regeneration uses the normal complete-input publication gates.
