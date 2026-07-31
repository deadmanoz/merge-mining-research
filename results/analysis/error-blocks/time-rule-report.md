# Error-blocks time-rule sweep

Generated: 2026-07-30 04:52 UTC

Re-examination of stale-classified rows and BIP34-height unknown rows
across the reachable per-chain classified inventories on the chain
archive host, for error blocks of the 946213 class: full-proof-of-work
Bitcoin headers whose `nTime` violates a time rule. Full PoW and the
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
  canonical-chain context.
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
- `time_beyond_future_limit` flags (trustworthy heights, approximate reference, manual review): 15 — RESOLVED 2026-07-30: 0 violations, all consistent with late mining (see the follow-up section below)
- Already catalogued in the dataset: 0
- NEW confirmed error blocks: 0

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
- No `time_below_mtp` (time-too-old) violations among trustworthy-height candidates: the 946213 class does not recur in these historical classified inventories. The 946213 row itself is recent (2026) and not present in these historical inventories, so it does not appear here as already-catalogued.
- 1352175 unknown rows were skipped for lacking a parseable claimed height (no `btc_height`, a malformed value, an implausible value above the canonical tip, or a `btc_height` disagreeing with the decoded BIP34 coinbase height).
- 1366885 full-PoW candidates carried a non-authoritative claimed height (unknown rows, and the canonical-fill-scratch stale inventories): their `btc_height` is not verified against the canonical chain, so no valid time-rule check is possible. They are negatives, not violations.
- No NEW confirmed time-rule error blocks promoted: see the future-limit caveat and the review list below. (2026-07-30 follow-up: all 15 flags resolved as late-mined, 0 violations; see below.)

## `time_beyond_future_limit` flags (NEEDS_CONTEXT, not promoted — RESOLVED 2026-07-30: 0 violations)

These trustworthy-height rows have `nTime` more than 2h beyond
the canonical parent's block time. Under Bitcoin's REAL future
rule (network-adjusted time + 2h) a modest excess is normal and
NOT a violation — network-adjusted time tracks the wall clock,
which is near the block's own `nTime`. The canonical parent time
is only a neighbor-evidence approximation, so these are reported
for manual review and are NOT promoted into the dataset. The
`time_beyond_future_limit` rule is also rejected by the
offline validator's `TIME_RULES` (it needs a network-adjusted-
time reference that is not committed, so it fails closed).

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

## Follow-up investigation (2026-07-30): future-limit flags resolved

The 15 flags above (8 distinct blocks; the devcoin/ixcoin blocks each
appear in both chains' inventories) were resolved by cross-referencing
each candidate's `nTime` against the CHILD chain's block time. The
AuxPoW commitment in a child block is an existence proof: the BTC
header must have existed by the time the child block that commits to
it was created. The child block time is therefore an independent
upper bound on the header's real creation time, and a candidate whose
`nTime` sits within minutes of that commit time cannot be meaningfully
future-dated — under the real rule (network-adjusted time + 2h) the
bound tracks the wall clock, which the commit time approximates.

Method: for each candidate, take the committing child block's time
and compute delta = btc `nTime` − child block time. A delta within
±5 minutes is two orders of magnitude below the 7200s future-limit
threshold and is consistent with ordinary timestamp jitter, not a
future-limit violation.

Verdict: 0 of the 8 distinct blocks are provable
`time_beyond_future_limit` violations. All 8 are consistent with late
mining — the header was genuinely created after the canonical winner
for its height, which is exactly why it is stale — and NONE were
promoted to the dataset. Even the extreme case, unobtanium 379924
(`011bf0d4`, 125.22h beyond the canonical parent time), was genuinely
created ~125h after the canonical winner and committed 152s before
its own `nTime`: a very late block, not a future-dated one.

| height | hash (prefix) | seen on | delta = btc `nTime` − child block time |
|---|---|---|---|
| 256558 | `05dcc986` | devcoin / ixcoin | +252s / +123s |
| 256558 | `97dc0e4c` | devcoin / ixcoin | +99s / +131s |
| 256558 | `2dfbdd2e` | devcoin / ixcoin | +4s / −30s |
| 261419 | `15a6ab8f` | devcoin / ixcoin | +41s / +42s |
| 297835 | `07b28cb1` | devcoin / ixcoin | −290s / −129s |
| 297835 | `53b3fce4` | devcoin / ixcoin | +290s / +90s |
| 297835 | `64cb2f55` | devcoin / ixcoin | +149s / +270s |
| 379924 | `011bf0d4` | unobtanium | +152s |

All deltas are within ±5 minutes (max 290s).

Category boundary this establishes: `time_beyond_future_limit` is NOT
mechanically re-checkable from committed evidence alone, because
Bitcoin's real bound is network-adjusted time + 2h and
network-adjusted time is not reconstructable offline. The one
exception is when child-chain commit-time evidence shows the `nTime`
more than 2h beyond the commit time itself — the commit-time upper
bound makes that a provable violation. None of these candidates came
close. By contrast, `time_below_mtp` IS mechanically re-checkable:
the parent's median-time-past is committed canonical-chain context.
This is why the dataset contains a `time_below_mtp` row (946213) but
no `time_beyond_future_limit` rows.
