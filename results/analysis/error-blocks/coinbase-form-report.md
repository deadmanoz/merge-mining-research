# Error-blocks coinbase-form sweep

Generated: 2026-07-30 21:30 UTC

Proactive application of Bitcoin's coinbase-form consensus rules to
every catalogued stale candidate across all reachable chains —
including rows currently accepted as VALID stales — to find error
blocks hiding among them: full-proof-of-work Bitcoin headers whose
coinbase scriptSig breaks the 2..100 byte consensus limit or whose
BIP34 height serialization is wrong. The committed error-blocks
dataset carries exactly ONE `coinbase_scriptsig_length_above_100`
member across a 15-year corpus; this sweep determines whether that
single-member situation is real or an artifact of incomplete prior
coverage.

Rules applied (gates reused from
`stale_blocks_analysis.btc_stale_validation`, never reimplemented):

- Coinbase scriptSig length (`coinbase_scriptsig_length_error`):
  the scriptSig must be 2..100 bytes (Bitcoin consensus). The rule
  token is `coinbase_scriptsig_length_above_100` (the historical
  name; the gate enforces the full 2..100 bound, so above-100 and
  below-2 violations are tallied separately). This check is
  HEIGHT-INDEPENDENT: the bound held at every height, so it applies
  to every source, including the canonical-fill-scratch
  inventories whose claimed height is untrustworthy.
- BIP34 height serialization (`bip34_height_error`): from
  `BIP34_HEIGHT = 227931` the coinbase scriptSig must
  start with the exact serialized height push
  (`bip34_coinbase_height_mismatch`). The version/BIP sweep already
  covered BIP34 height *presence*; this sweep's distinct angle is
  the scriptSig *form*, reusing the same gate for consistency.
  This check is HEIGHT-DEPENDENT: it only runs where the claimed
  height is authoritative.

The rule tokens match the offline validator's `RULE_GATES` keys,
so a promoted finding re-derives in `validate_error_blocks.py`.
Full PoW is re-derived per row from the committed header bytes via
`hash_meets_btc_difficulty` (sha256d of the 80-byte header meets
the header's own embedded nBits target), never inherited from a
classification label. A confirmed finding must ALSO meet the
canonical expected-nBits target at the claimed height (the
inventory's `expected_nbits` column, else the committed epoch table
at the height's epoch start): a gate violation whose digest meets
only an easy self-declared embedded target is a share/contamination
observation, tallied separately as `canonical_target_fail`, never a
confirmed error block (the same rule the offline validator
enforces). A PoW-passing, canonical-target-passing row that fails a
gate is an error-block finding; membership is checked against the
committed `data/error-blocks/error_blocks.csv` dataset by
`(height, hash)`.

Candidate sources and claimed-height trust:

- The 16 regen-chain stale inventories on the chain archive host:
  authoritative `btc_height` — both checks run.
- syscoin/elastos/fractal canonical-fill-scratch stale inventories:
  their `btc_height` is NOT verified against the canonical chain
  (the Task 8 height-trust caveat), so only the height-independent
  length check runs; the BIP34-form check is skipped
  (`untrustworthy height` tally).
- The committed `data/validated-stales/<chain>_validated_stales.csv`
  (the ACCEPTED stales): their `btc_height` passed the
  active-parent gate, so it is authoritative; applying the gates
  here cross-checks whether any accepted stale is actually a
  coinbase-form error block. Chains whose CSV carries no usable
  rows (empty, or every row missing the header/coinbase bytes —
  RSK does not expose the real parent coinbase) are
  `no usable rows` negatives.

## Summary

- Inventories reachable: 45/45
- Rows examined: 33187
- Rows skipped for an unparseable header/scriptSig (no PoW or length check possible): 0
- Full-PoW pass: 32661
- Full-PoW fail (share/near rows, excluded): 0
- Full-PoW candidates length-checked only (scratch inventories, height untrustworthy for BIP34): 28040
- Full-PoW candidates skipped for no parseable claimed height (BIP34 check only): 0
- scriptSig length violations above 100 bytes: 2
- scriptSig length violations below 2 bytes: 0
- BIP34 height-serialization violations: 24
- Violation observations failing the canonical expected-nBits target (share/contamination, not confirmed): 0
- Already catalogued in the dataset: 26 observations across 14 distinct (height, hash) blocks (the same BTC error block is recorded by several sibling chains)
- NEW confirmed error blocks: 0
- Unresolved length-violation observations (full PoW, no trustworthy claimed height — not promotable, not counted as NEW): 0

## The single-member question

The dataset carried exactly one `coinbase_scriptsig_length_above_100` member before this sweep. Across the whole reachable corpus (32661 full-PoW candidates in 45 inventories), this sweep found 2 scriptSig-length violation observation(s): 2 above 100 bytes, 0 below 2 bytes. Every one of them is already catalogued, so the single-member situation is REAL: miners essentially never broadcast a full-PoW block whose coinbase scriptSig breaks the 2..100 byte consensus limit; the one catalogued case is the only observed instance, not a coverage artifact.

## Per-inventory results

| chain | source | rows | full-PoW pass | length-checked only | above 100 | below 2 | BIP34-form violations | already in dataset | NEW |
|---|---|---|---|---|---|---|---|---|---|
| argentum | stale | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| bitmark | stale | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| coiledcoin | stale | 27 | 27 | 0 | 0 | 0 | 0 | 0 | 0 |
| crown | stale | 23 | 23 | 0 | 0 | 0 | 0 | 0 | 0 |
| devcoin | stale | 484 | 484 | 0 | 1 | 0 | 13 | 14 | 0 |
| elcash | stale | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| emercoin | stale | 97 | 97 | 0 | 0 | 0 | 0 | 0 | 0 |
| geistgeld | stale | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| groupcoin | stale | 32 | 32 | 0 | 0 | 0 | 0 | 0 | 0 |
| huntercoin | stale | 13 | 13 | 0 | 0 | 0 | 0 | 0 | 0 |
| i0coin | stale | 176 | 176 | 0 | 0 | 0 | 0 | 0 | 0 |
| ixcoin | stale | 478 | 478 | 0 | 1 | 0 | 11 | 12 | 0 |
| myriadcoin | stale | 40 | 40 | 0 | 0 | 0 | 0 | 0 | 0 |
| terracoin | stale | 35 | 35 | 0 | 0 | 0 | 0 | 0 | 0 |
| unobtanium | stale | 44 | 44 | 0 | 0 | 0 | 0 | 0 | 0 |
| xaya | stale | 40 | 40 | 0 | 0 | 0 | 0 | 0 | 0 |
| syscoin | stale | 18360 | 18360 | 18360 | 0 | 0 | 0 | 0 | 0 |
| elastos | stale | 9156 | 9156 | 9156 | 0 | 0 | 0 | 0 | 0 |
| fractal | stale | 524 | 524 | 524 | 0 | 0 | 0 | 0 | 0 |
| argentum | validated | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| bitcoin-vault | validated | 9 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| bitmark | validated | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| coiledcoin | validated | 27 | 27 | 0 | 0 | 0 | 0 | 0 | 0 |
| crown | validated | 23 | 23 | 0 | 0 | 0 | 0 | 0 | 0 |
| devcoin | validated | 468 | 468 | 0 | 0 | 0 | 0 | 0 | 0 |
| doichain | validated | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| elastos | validated | 153 | 153 | 0 | 0 | 0 | 0 | 0 | 0 |
| elcash | validated | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| emercoin | validated | 96 | 96 | 0 | 0 | 0 | 0 | 0 | 0 |
| fractal | validated | 31 | 31 | 0 | 0 | 0 | 0 | 0 | 0 |
| geistgeld | validated | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| groupcoin | validated | 30 | 30 | 0 | 0 | 0 | 0 | 0 | 0 |
| hathor | validated | 6 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| huntercoin | validated | 13 | 13 | 0 | 0 | 0 | 0 | 0 | 0 |
| i0coin | validated | 166 | 166 | 0 | 0 | 0 | 0 | 0 | 0 |
| ixcoin | validated | 465 | 465 | 0 | 0 | 0 | 0 | 0 | 0 |
| lyncoin | validated | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| myriadcoin | validated | 40 | 40 | 0 | 0 | 0 | 0 | 0 | 0 |
| namecoin | validated | 1625 | 1397 | 0 | 0 | 0 | 0 | 0 | 0 |
| rsk | validated | 298 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| sixeleven | validated | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| syscoin | validated | 78 | 78 | 0 | 0 | 0 | 0 | 0 | 0 |
| terracoin | validated | 35 | 35 | 0 | 0 | 0 | 0 | 0 | 0 |
| unobtanium | validated | 43 | 43 | 0 | 0 | 0 | 0 | 0 | 0 |
| xaya | validated | 40 | 40 | 0 | 0 | 0 | 0 | 0 | 0 |

## Negative results

- Inventories with full-PoW candidates but no coinbase-form violation: argentum (stale), bitmark (stale), coiledcoin (stale), crown (stale), elcash (stale), emercoin (stale), groupcoin (stale), huntercoin (stale), i0coin (stale), myriadcoin (stale), terracoin (stale), unobtanium (stale), xaya (stale), syscoin (stale), elastos (stale), fractal (stale), argentum (validated), bitcoin-vault (validated), bitmark (validated), coiledcoin (validated), crown (validated), devcoin (validated), elastos (validated), elcash (validated), emercoin (validated), fractal (validated), groupcoin (validated), hathor (validated), huntercoin (validated), i0coin (validated), ixcoin (validated), myriadcoin (validated), namecoin (validated), syscoin (validated), terracoin (validated), unobtanium (validated), xaya (validated).
- Inventories with no usable rows (empty, or every row missing the committed header/coinbase bytes; RSK does not expose the real parent coinbase): rsk (validated).
- 28040 full-PoW candidates in the canonical-fill-scratch stale inventories (syscoin/elastos/fractal) carried a non-authoritative claimed height: they were evaluated for the height-independent scriptSig-length rule but NOT for the BIP34 height-serialization rule. They are length-checked negatives for the BIP34 check, not violations.
- No below-2 scriptSig length violations exist anywhere in the corpus: the only length-violation class observed is above 100 bytes.
- No NEW confirmed coinbase-form error blocks: every full-PoW violation found is already catalogued in the committed dataset.

Row-level candidate detail remains in the authoritative inventories
on the chain archive host and in the committed validated-stales
CSVs; this report is the compact committed summary.
