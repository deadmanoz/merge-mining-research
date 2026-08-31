# Error-blocks time-rule sweep

Generated: 2026-07-30 04:52 UTC

Re-examination of stale-classified rows and BIP34-height unknown rows
across the reachable per-chain classified inventories on the chain
archive host, for error blocks of the 946213 and 957780 class:
full-proof-of-work Bitcoin headers whose `nTime` violates a time
rule. Full PoW and the
header `nTime` are re-derived from the committed header bytes via
`hash_meets_btc_difficulty`, never inherited from a classification
label. The canonical parent context (`time`/`mediantime` of the
canonical block at `height - 1`) is batch-fetched from the Bitcoin
node on the archive host and cached in the gitignored
`cache/time_sweep_mtp.json`. Membership is checked against the
committed `data/error-blocks/error_blocks.csv` dataset by
`(height, hash)`.

Time rules applied per candidate:

- `time_below_mtp`: candidate `nTime` <= the canonical parent's
  median-time-past (the `mediantime` of the canonical block at
  `height - 1`). This check is robust: the parent MTP is committed
  canonical-chain context. A confirmed finding must ALSO meet the
  canonical expected-nBits target at the claimed height (the
  inventory's `expected_nbits` column, else the committed epoch
  table at the height's epoch start): a `time_below_mtp` violation
  whose digest meets only an easy self-declared embedded target is
  a share/contamination observation, tallied separately as
  `canonical_target_fail`, never a confirmed error block (the same
  rule the offline validator enforces).
- `time_beyond_future_limit`: candidate `nTime` > the canonical
  parent's block `time` + 2h (`MAX_FUTURE_BLOCK_TIME`). Reference
  caveat: Bitcoin's real future bound is network-adjusted time + 2h,
  which is NOT reconstructable offline. The canonical parent time is
  only a neighbor-evidence approximation, so a modest excess is NOT
  proof of a real violation (a block 2-7h after its parent is normal
  under the real rule). Findings under this rule are reported for
  manual review and are NOT auto-promoted.

Claimed-height trust: a time-rule check is only meaningful when the
claimed height is a real canonical-chain height. The 16 regen-chain
stale inventories carry an authoritative height: the classifier set
`btc_height` = (active-chain prev height) + 1 after confirming the
parent is on the canonical chain. Unknown rows and the
canonical-fill-scratch stale inventories (syscoin/elastos/fractal)
carry a `btc_height` that is NOT verified against the canonical
chain (a share/child height or contamination), so a time-rule check
against it is uninterpretable; those full-PoW rows are tallied as
`untrustworthy height` negatives, never as violations.

## Summary

- Inventories reachable: 19/19
- Stale-classified rows examined: 29535
- Unknown rows examined: 2691512
- Unknown rows skipped for no parseable claimed height: 1352175
- Candidates with full-PoW pass: 1368201
- Full-PoW candidates with an untrustworthy claimed height (no valid check possible): 1366885
- `time_below_mtp` violations (trustworthy heights): 0
- `time_beyond_future_limit` flags (trustworthy heights, approximate reference, manual review): 15
- `time_below_mtp` observations failing the canonical expected-nBits target (share/contamination, not confirmed): 0
- Already catalogued in the dataset: 0
- NEW confirmed error blocks: 0 observations across 0 distinct (height, hash) blocks (the same new BTC error block can be witnessed in several sibling-chain inventories)

## Per-chain results

| chain | stale rows | unknown rows | full-PoW candidates | untrustworthy height | time_below_mtp | time_beyond_future_limit | already in dataset | NEW |
|---|---|---|---|---|---|---|---|---|
| argentum | 2 | 634277 | 289866 | 289864 | 0 | 0 | 0 | 0 |
| bitmark | 1 | 81921 | 41709 | 41708 | 0 | 0 | 0 | 0 |
| coiledcoin | 27 | 13308 | 1 | 0 | 0 | 0 | 0 | 0 |
| crown | 23 | 383622 | 237212 | 237189 | 0 | 0 | 0 | 0 |
| devcoin | 484 | 75141 | 42360 | 41940 | 0 | 7 | 0 | 0 |
| elcash | 3 | 2711 | 2714 | 2711 | 0 | 0 | 0 | 0 |
| emercoin | 97 | 16545 | 16095 | 15998 | 0 | 0 | 0 | 0 |
| geistgeld | 0 | 2290 | 0 | 0 | 0 | 0 | 0 | 0 |
| groupcoin | 32 | 2713 | 32 | 0 | 0 | 0 | 0 | 0 |
| huntercoin | 13 | 29 | 13 | 0 | 0 | 0 | 0 | 0 |
| i0coin | 176 | 86249 | 149 | 0 | 0 | 0 | 0 | 0 |
| ixcoin | 478 | 253974 | 126344 | 125928 | 0 | 7 | 0 | 0 |
| myriadcoin | 40 | 166844 | 116845 | 116805 | 0 | 0 | 0 | 0 |
| terracoin | 35 | 523315 | 253948 | 253913 | 0 | 0 | 0 | 0 |
| unobtanium | 44 | 430931 | 213325 | 213281 | 0 | 1 | 0 | 0 |
| xaya | 40 | 17642 | 40 | 0 | 0 | 0 | 0 | 0 |
| syscoin | 18360 | 0 | 17881 | 17881 | 0 | 0 | 0 | 0 |
| elastos | 9156 | 0 | 9152 | 9152 | 0 | 0 | 0 | 0 |
| fractal | 524 | 0 | 515 | 515 | 0 | 0 | 0 | 0 |

## Negative results

- Chains with full-PoW candidates but no time-rule violation (trustworthy heights): argentum, bitmark, coiledcoin, crown, elcash, emercoin, groupcoin, huntercoin, i0coin, myriadcoin, terracoin, xaya, syscoin, elastos, fractal.
- No `time_below_mtp` (time-too-old) violations among trustworthy-height candidates: the 946213 and 957780 class does not recur in these historical classified inventories. The 946213 and 957780 rows themselves are recent (2026) and not present in these historical inventories, so they do not appear here as already-catalogued.
- 1352175 unknown rows were skipped for lacking a parseable claimed height (no `btc_height`, a malformed value, an implausible value above the canonical tip, or a `btc_height` disagreeing with the decoded BIP34 coinbase height).
- 1366885 full-PoW candidates carried a non-authoritative claimed height (unknown rows, and the canonical-fill-scratch stale inventories): their `btc_height` is not verified against the canonical chain, so no valid time-rule check is possible. They are negatives, not violations.
- No NEW confirmed time-rule error blocks promoted: see the future-limit caveat and the review list below.

## `time_beyond_future_limit` flags (NEEDS_CONTEXT, not promoted)

These trustworthy-height rows have `nTime` more than 2h beyond
the canonical parent's block time. Under Bitcoin's REAL future
rule (network-adjusted time + 2h) a modest excess is normal and
NOT a violation — network-adjusted time tracks the wall clock,
which is near the block's own `nTime`. The canonical parent time
is only a neighbor-evidence approximation, so these are reported
for manual review and are NOT promoted into the dataset. The
`time_beyond_future_limit` rule is also still deferred in the
offline validator's `TIME_RULES` (it needs a network-adjusted-
time reference that is not committed).

- height 256558 hash `000000000000000205dcc98671ad7a96cdcdc028bb94b3d4f9922f49ed6319f6` (seen on devcoin|ixcoin) — nTime 7.49h beyond the canonical parent time
- height 256558 hash `00000000000000097dc0e4c05d2c8d386c5e7f9e378583f712095a17f9a91ce4` (seen on devcoin|ixcoin) — nTime 2.36h beyond the canonical parent time
- height 256558 hash `000000000000002dfbdd2e33bd2aa6d4f3d41a202d954c07f5221a79b1cc648f` (seen on devcoin|ixcoin) — nTime 5.01h beyond the canonical parent time
- height 261419 hash `0000000000000015a6ab8f6f2c055b1813902c58fd485903bb7a2afff1d89fcf` (seen on devcoin|ixcoin) — nTime 2.32h beyond the canonical parent time
- height 297835 hash `000000000000000007b28cb11b554efb34d62d51b13a1bb84a37ac1a80e5704b` (seen on devcoin|ixcoin) — nTime 2.60h beyond the canonical parent time
- height 297835 hash `000000000000000053b3fce44eaa50c0dca6d6c5d2d63818e08ae72b9894a5fe` (seen on devcoin|ixcoin) — nTime 2.16h beyond the canonical parent time
- height 297835 hash `000000000000000064cb2f55ea3758db22489b77997a1a198d1cc3a249820ec7` (seen on devcoin|ixcoin) — nTime 3.84h beyond the canonical parent time
- height 379924 hash `0000000000000000011bf0d411f64a5c4d9c1abad8c5d1c9b1b974af7fc79b7a` (seen on unobtanium) — nTime 125.22h beyond the canonical parent time

Row-level candidate detail remains in the authoritative inventories on
the chain archive host; this report is the compact committed summary.

The authored resolution of the future-limit flags is maintained at
[docs/error-blocks.md#future-limit-follow-up-investigation](../../../docs/error-blocks.md#future-limit-follow-up-investigation).
