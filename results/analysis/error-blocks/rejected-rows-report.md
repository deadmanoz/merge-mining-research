# Error-blocks rejected-row mining sweep

Generated: 2026-07-30 21:47 UTC (amended 2026-08-04 to include Elastos)

Re-examination of every `REJECTED:` row across the reachable per-chain
classified inventories on the chain archive host. A row is an error
block when it fails a *contextual* consensus rule while meeting the
full Bitcoin proof-of-work target; rows failing the *target* are
shares/near rows, not error blocks. The distinction is re-verified
per row from the committed header bytes via
`hash_meets_btc_difficulty`, never inherited from the rejection
label: a contextual row is confirmed only when its named failure
re-derives from the committed header/coinbase bytes via the same
`btc_stale_validation` gates the validator uses AND its digest meets
the canonical expected-nBits target, not just the header's own
embedded bits (a contextual row meeting only an easy self-declared
target is a share/contamination, the same rule the offline validator
enforces). Membership is
checked against the committed `data/error-blocks/error_blocks.csv`
dataset by `(height, hash)` with the header-derived display hash,
never the `btc_header_hash` column.

## Summary

- Inventories reachable: 8/8
- REJECTED rows examined: 45
- Contextual-class rejections: 32
- Target-class rejections: 13
- NEW confirmed error blocks (full PoW + canonical target + contextual re-derived, not in dataset): 0
- Full-PoW contextual rows whose named failure did NOT re-derive (not confirmed): 0
- Full-PoW median-time-past rows (named failure needs canonical parent context, not re-derivable offline, not confirmed): 0
- Full-PoW contextual rows re-deriving their named failure but failing the canonical expected-nBits target (share/contamination, not confirmed): 0
- Full-PoW contextual rows from a canonical-fill-scratch inventory (unverified btc_height, not promoted): 0
- Target-class rows meeting the canonical expected target despite the nBits label (error-block candidates, manual review, not auto-promoted): 3 (0 un-promoted, 3 already in the dataset)

## Per-chain results

| chain | total rows | REJECTED | contextual | target | unrecognized | full-PoW pass | full-PoW fail | not re-derived | not offline-rederivable | untrustworthy height | already in dataset | NEW |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| devcoin | 484 | 16 | 16 | 0 | 0 | 16 | 0 | 0 | 0 | 0 | 16 | 0 |
| ixcoin | 478 | 13 | 13 | 0 | 0 | 13 | 0 | 0 | 0 | 0 | 13 | 0 |
| i0coin | 176 | 10 | 1 | 9 | 0 | 10 | 0 | 0 | 0 | 0 | 1 | 0 |
| groupcoin | 32 | 2 | 1 | 1 | 0 | 2 | 0 | 0 | 0 | 0 | 1 | 0 |
| emercoin | 97 | 1 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| unobtanium | 44 | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 1 | 0 |
| syscoin | 18360 | 1 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| elastos | 9156 | 1 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 1 | 0 |

## Negative results

- No reachable chain had zero REJECTED rows.
- Chains where every target-class rejection failed the canonical expected-target re-verification (correctly excluded shares/near rows): i0coin, groupcoin.
- No NEW error blocks: every full-PoW contextual-failure row whose named failure re-derives and whose digest meets the canonical expected-nBits target is already catalogued in the committed dataset.

## Target-class rows meeting the canonical expected target

These rows were rejected for an nBits/target mismatch, yet their
header digests meet the *canonical expected* `nBits` target —
full proof of work at the real Bitcoin difficulty with a wrong
`nBits` field (a contextual failure wearing a target-class
label). Re-verifying an nBits-mismatch row against its own
`btc_bits` is circular, so the canonical expected target is the
decisive check. They are error-block candidates listed for
manual review and are NOT promoted by this sweep. A row already
in the committed dataset is marked as such (already catalogued /
promoted): it is reported here because the sweep re-derives the
anomaly from the inventory, but it is NOT an un-promoted manual
candidate.

- emercoin height 717696 hash `0000000000000000000045c5040bf46b4cd6c6f8f4004c149cd602e4e356e71c` — nBits mismatch with canonical BTC height (got 170b98ab, expected 170b8c8b) — ALREADY IN THE DATASET (catalogued/promoted)
- syscoin height 717696 hash `0000000000000000000045c5040bf46b4cd6c6f8f4004c149cd602e4e356e71c` — nBits mismatch with canonical BTC height (got 170b98ab, expected 170b8c8b) — ALREADY IN THE DATASET (catalogued/promoted)
- elastos height 717696 hash `0000000000000000000045c5040bf46b4cd6c6f8f4004c149cd602e4e356e71c` — nBits mismatch with canonical BTC height (got 170b98ab, expected 170b8c8b) — ALREADY IN THE DATASET (catalogued/promoted)

## Rejection-reason detail

### devcoin (`~/mmr-child-header-regen-20260729/staging/chains/devcoin/classified/devcoin_stale_blocks.csv`)

### ixcoin (`~/mmr-child-header-regen-20260729/staging/chains/ixcoin/classified/ixcoin_stale_blocks.csv`)

### i0coin (`~/mmr-child-header-regen-20260729/staging/chains/i0coin/classified/i0coin_stale_blocks.csv`)

### groupcoin (`~/mmr-child-header-regen-20260729/staging/chains/groupcoin/classified/groupcoin_stale_blocks.csv`)

### emercoin (`~/mmr-child-header-regen-20260729/staging/chains/emercoin/classified/emercoin_stale_blocks.csv`)

### unobtanium (`~/mmr-child-header-regen-20260729/staging/chains/unobtanium/classified/unobtanium_stale_blocks.csv`)

### syscoin (`~/canonical-fill-scratch/syscoin/syscoin_stale_blocks.csv`)

### elastos (`~/canonical-fill-scratch/elastos/elastos_stale_blocks.csv`)

Row-level rejection detail remains in the authoritative inventories on
the chain archive host; this report is the compact committed summary.
