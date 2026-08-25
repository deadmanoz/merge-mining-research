# Data validity contract

This repository publishes evidence about Bitcoin parent headers recovered from
merge-mined sibling chains. It does not generally possess the complete Bitcoin
block corresponding to each recovered header. The public data therefore makes
a narrower claim than “Bitcoin Core validated this complete block.”

## What `stale` means here

A row with `classification=stale` is a **direct-stale header candidate**. The
project has established that:

1. the 80-byte header parses and hashes to the published identifier when the
   header is available;
2. the header hash satisfies the target encoded by its own `nBits`;
3. Bitcoin Core does not report the candidate on the active chain;
4. the candidate's `prev_hash` is an active-chain Bitcoin block, fixing the
   candidate height at `parent_height + 1`;
5. the candidate `nBits` equals Bitcoin's required value at that height;
6. the candidate timestamp is greater than the active parent's Bitcoin
   median-time-past;
7. the signed block version meets the BIP34, BIP66, and BIP65 historical
   minimums; and
8. where the real coinbase scriptSig is available, its serialized length is
   between 2 and 100 bytes and its first push encodes the required BIP34 height
   whenever that rule applies.

These are necessary conditions for a valid Bitcoin stale block. They are strong
evidence that the miner constructed a competing Bitcoin header at that height,
but they are not sufficient to prove that the complete block was valid.

## What `VALID` does and does not mean

`validation_status=VALID` is a legacy, downstream-compatible token. In the
per-chain CSVs it means **passed the repository's declared direct-stale
header-context profile**. It must not be read as “full Bitcoin consensus
validation succeeded.” `VALID (...)` variants have the same scope and add a
historical diagnostic annotation.

Several private intermediate filenames and internal counters retain the
legacy label `btc_valid` or `btc_difficulty`. In those Phase 1 contexts the
label means only that the header hash meets the target encoded in its own
`nBits`. It does not mean that the header met Bitcoin's contemporaneous target;
that comparison occurs later through the expected-`nBits` gate.

The profile currently checks:

| Check | Covered |
|---|---|
| Header serialization and published hash | Yes, when `btc_header_hex` is present or publicly hydrated |
| Proof of work against the header's own target | Yes |
| Active-chain predecessor and inferred height | Yes, through Bitcoin Core RPC during classification |
| Required Bitcoin `nBits` at the inferred height | Yes |
| Candidate time greater than the active parent's median-time-past | Yes |
| Historical minimum signed block version | Yes |
| Coinbase scriptSig serialized length of 2 to 100 bytes | Yes when the real parent coinbase scriptSig is available |
| BIP34 coinbase-height prefix | Yes when the real parent coinbase scriptSig is available; exact-key error-blocks exclusions protect shared rows from weak-only sources |
| Coinbase transaction hash to header merkle-root proof | Not revalidated by the generic public classifier |
| Complete transaction merkle root and duplicate-transaction check | No, requires the full Bitcoin block |
| Block transaction, finality, weight, witness, and sigop rules | No, requires the full Bitcoin block |
| UTXO, script, subsidy, and fee validity | No, requires historical chain state and the full Bitcoin block |

Because validity is asymmetric, a failed necessary rule is conclusive evidence
that a candidate is invalid, while passing all available checks means only that
no failure was found within this profile. The error-blocks dataset therefore may
call a rejected row consensus-invalid, but accepted rows are described as
publication-gate-accepted header candidates rather than fully consensus-valid
blocks. RSK's midstate-compressed proof does not expose the real parent
coinbase scriptSig, so RSK cannot independently apply the scriptSig-length or
BIP34-prefix checks.

## Current audit snapshot

On 20 July 2026, the committed direct-stale inputs were replayed chain by
chain against Bitcoin Core at active-chain tip 958,882. The audit covered 26
CSV inputs, 22 of them non-empty, containing 3,652 accepted per-chain
observations and 2,113 unique header hashes. Every accepted observation passed
all checks supported by its evidence: header reconstruction and hash, self-PoW,
candidate absence from the active chain, active predecessor and inferred
height, required `nBits`, median-time-past, historical signed-version floors,
persisted `expected_nbits`, and the coinbase scriptSig length and BIP34 prefix
where the coinbase was available.

On 3 August, source-driven Elastos and Syscoin reclassification added 44
direct observations, each of which passed the same available-evidence profile
against Bitcoin Core. The current committed direct set therefore contains
3,696 observations and 2,133 unique header hashes.

The evidence limitations remain part of that result. Namecoin has 228 headers
that are absent from its loader CSV but were hash-verified after hydration into
the monitor export. RSK has no recoverable parent coinbase for any of its 298
accepted rows, so its scriptSig-length and BIP34 checks remain untested. The
audit found no remaining failure in the committed direct sets, but it was not a
full-block consensus replay.

## Evidence classes

| Public state | Meaning | Full-block validity claim |
|---|---|---|
| `canonical` | Bitcoin Core reports the header on the active chain | Yes for the canonical Bitcoin block identified by Core |
| `stale` + `VALID*` | Direct-stale header candidate passing the declared profile | No |
| `stale_descendant` + `VALID_STALE_DESCENDANT` | Header candidate whose recovered ancestry reaches a known stale root and passes its declared gates | No |
| `unknown` + `strict_btc_orphan` | Core-absent header with strong BIP34-height and Bitcoin-epoch `nBits` evidence | No, and not classified as stale |
| `unknown` + `weak_btc_orphan` | Core-absent header with weaker timestamp/epoch evidence | No, and not classified as stale |
| `error_block` | Consensus-invalid full-proof-of-work Bitcoin block catalogued in `data/error-blocks/error_blocks.csv`; the candidate fails at least one necessary Bitcoin rule | Explicitly invalid under the recorded reason |
| `stale_descendant` single-home (formerly a `direct_stale_only` overlay row) | Candidate must not enter a direct-stale loader but remains accepted as a stale descendant | Depends on the replacement evidence class |

Cross-chain repetition strengthens provenance because independent sibling
ledgers preserve the same header. It does not upgrade a header candidate into a
fully validated Bitcoin block, and duplicate observations are never counted as
separate Bitcoin events after `(height, hash)` deduplication.

Downstream exports preserve `classification` and `validation_status` as
evidence labels. The Merge Mining Monitor verifies the serialized header, its
published hash, and self-target proof of work, but its Rust CSV importer admits
non-`unknown` classifications without replaying active-parent, height, `nBits`,
median-time-past, coinbase-length, or BIP34 checks. It does not use
`validation_status` as an independent consensus verdict. The monitor-evidence
staging preflight is stricter than that importer: it requires the complete
published schema, canonical lowercase serialized parent headers, authenticated
parent fields and available child bundles, category/status/relevance contracts,
duplicate-free confirmed stale identities, and the applicable strict-height or
weak-timestamp epoch predicates. It also preserves committed ordinary
identities during add-only updates. These checks still do not replay active
parent, MTP, coinbase, or other contextual gates, so acceptance confirms the
upstream publication contract rather than independent full-block validation.
Consumers must retain this distinction.

## Namecoin release scope

The corrected Namecoin set contains 1,625 distinct direct-stale header
candidates. All 1,625 have a public header source after monitor-export
hydration: 1,397 headers are embedded in
`data/validated-stales/namecoin_validated_stales.csv`, and 228 are supplied by
`results/monitor-evidence/namecoin_monitor_evidence.csv`. All 1,625 rows retain
the parent coinbase scriptSig, but the compact CSV does not retain the complete
serialized coinbase transaction or its parent-merkle branch.

The pinned upstream `bitcoin-data/stale-blocks` checkout currently carries a
matching full-block blob for 295 of the 1,625 accepted Namecoin candidates. Its
public sanity check confirms that each blob starts with the expected header; it
does not perform full historical Bitcoin consensus validation, and none of the
295 blobs has undergone a full consensus replay in this project. The remaining
1,330 candidates have no matching full Bitcoin block body in that pinned
dataset.

The error-blocks dataset records 32 consensus-invalid Namecoin candidates: 21
fail BIP34's coinbase-height rule, three fail BIP66's minimum block version,
five fail BIP65's minimum block version, two violate the median-time-past rule
(380,992 `median_time_past_violation` and 946,213 `time_below_mtp`), and one
has a 103-byte coinbase scriptSig. A separate direct-only correction moves the
candidate at Bitcoin height 656,478 out of the direct-stale set and into the
accepted stale-descendant sidecar because its predecessor is a known stale,
not an active-chain block.

Accordingly, the defensible public statement for this release is:

> Namecoin preserves 1,625 distinct direct-stale Bitcoin header candidates that
> pass the declared available-evidence header-context checks. Thirty-two
> additional candidates are excluded because they fail a necessary Bitcoin
> rule, and one former direct-stale row is retained separately as an accepted
> stale descendant. Full Bitcoin block validity has not been established for
> any of the 1,625 accepted direct candidates.

This validity scope is independent of coverage completeness. Namecoin's source
snapshot boundary is not recorded in a committed provenance manifest, so the
1,625-row set is neither a claim of full Bitcoin block validity nor a claim of
exhaustive Namecoin-chain recovery.
