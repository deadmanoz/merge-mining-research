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

## What an accepted direct-stale status does and does not mean

The only accepted direct-stale statuses are exactly `VALID` and
`VALID (post-BCH, difficulty matches BTC)`. Either means **passed the
repository's declared direct-stale header-context profile**. Neither means
“full Bitcoin consensus validation succeeded.”

Several private intermediate filenames and internal counters use the label
`btc_valid` or `btc_difficulty`. In those Phase 1 contexts the
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
blocks. The F2Pool blocks at heights 783,426 and 784,121 are the committed
demonstration: both carry accepted statuses, and both are known
`bad-blk-sigops` invalid from independently observed full blocks — recorded in
the `data/error-blocks/body_invalid_stales.csv` overlay (see
[`error-blocks.md`](error-blocks.md) "Externally attested body-invalid
stales"), not by rewriting their accepted verdicts. RSK's midstate-compressed proof does not expose the real parent
coinbase scriptSig, so RSK cannot independently apply the scriptSig-length or
BIP34-prefix checks.

## Published audit

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
against Bitcoin Core. The 30 August same-generation Namecoin and Fractal
refresh added another 33 accepted direct observations under that profile. The
current committed direct set therefore contains 3,729 observations and 2,137
unique header hashes.

The evidence limitations remain part of that result. Namecoin's 228
historically loader-absent headers are now embedded in the loader CSV,
back-filled from the committed monitor evidence and byte-verified against each
row's committed hash and decoded fields. RSK has no recoverable parent coinbase for any of its 298
accepted rows, so its scriptSig-length and BIP34 checks remain untested. The
audit found no remaining failure in the committed direct sets, but it was not a
full-block consensus replay.

## Evidence classes

| Public state | Meaning | Full-block validity claim |
|---|---|---|
| `canonical` | Bitcoin Core reports the header on the active chain | Yes for the canonical Bitcoin block identified by Core |
| `stale` + an exact accepted direct-stale status | Direct-stale header candidate passing the declared profile | No |
| `stale_descendant` + `VALID_STALE_DESCENDANT` | Header candidate whose authenticated ancestry reaches a declared trusted stale root, remains outside the active main chain, and passes its declared gates | No |
| `unknown` + `strict_btc_orphan` | Core-absent header with strong BIP34-height and Bitcoin-epoch `nBits` evidence | No, and not classified as stale |
| `unknown` + `weak_btc_orphan` | Core-absent header with weaker timestamp/epoch evidence | No, and not classified as stale |
| `error_block` | Consensus-invalid full-proof-of-work Bitcoin block catalogued in `data/error-blocks/error_blocks.csv`; the candidate fails at least one necessary Bitcoin rule | Explicitly invalid under the recorded reason |

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
weak-timestamp epoch predicates. Those ordinary-artifact checks still do not
replay active-parent, MTP, coinbase, or other contextual gates, so acceptance
confirms the upstream publication contract rather than independent full-block
validation.

The error module has a separate complete preflight. It re-derives the declared
consensus failures, including MTP and coinbase rules, from the canonical 39-row
catalogue, 86-row observation ledger, and MTP context. The staged error
aggregate must then match every canonical ledger identity and derived field.
Any full-coinbase enrichment is parsed and must authenticate the published
coinbase scriptSig. A release stages all ordinary artifacts, that verified
error aggregate, counts, and manifest as one transaction.

## Namecoin release scope

The Namecoin set contains 1,649 distinct direct-stale header
candidates. All 1,649 carry `btc_header_hex` directly in
`data/validated-stales/namecoin_validated_stales.csv`; the 228 historically
header-less rows were back-filled from
`results/monitor-evidence/namecoin_monitor_evidence.csv`. All 1,649 rows retain
the parent coinbase scriptSig, but the compact CSV does not retain the complete
serialized coinbase transaction or its parent-merkle branch.

The pinned upstream `bitcoin-data/stale-blocks` checkout currently carries a
matching full-block blob for 319 of the 1,649 accepted Namecoin candidates. Its
public sanity check confirms that each blob starts with the expected header; it
does not perform full historical Bitcoin consensus validation, and none of the
319 blobs has undergone a full consensus replay in this project. The remaining
1,330 candidates have no matching full Bitcoin block body in that pinned
dataset.

The current Namecoin source classification routes 32 consensus-invalid
candidates to the error-block module: 21 fail BIP34's coinbase-height rule,
three fail BIP66's minimum block version, five fail BIP65's minimum block
version, one violates median-time-past at height 380,992, one has a 103-byte
coinbase scriptSig, and one carries the prior epoch's `nBits` at height 717,696.
Two additional Namecoin-witnessed live captures at
946,213 and 957,780 fail `time_below_mtp`, and four ancestry-derived parents
fail BIP34's coinbase-height rule. Those six do not belong to the direct-stale
set and do not change its 1,649 accepted plus 32 excluded accounting. Bitcoin
height 656,478 belongs to the stale-descendant module because its predecessor
is a trusted stale root, not an active-chain block. The recovered Namecoin
observation at height 941,882 is also projected through the shared accepted
descendant verdict.

Accordingly, the defensible public statement for this release is:

> Namecoin preserves 1,649 distinct direct-stale Bitcoin header candidates that
> pass the declared available-evidence header-context checks. Thirty-two
> additional candidates are excluded because they fail a necessary Bitcoin
> rule, and heights 656,478 and 941,882 have Namecoin observations represented
> separately as accepted stale descendants. Full Bitcoin block validity has not
> been established for any of the 1,649 accepted direct candidates.

This validity scope is independent of coverage completeness. Namecoin's source
snapshot boundary is not recorded in a committed provenance manifest, so the
1,649-row set is neither a claim of full Bitcoin block validity nor a claim of
exhaustive Namecoin-chain recovery.
