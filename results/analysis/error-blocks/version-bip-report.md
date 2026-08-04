# Error-blocks version/BIP sweep

Generated: 2026-07-30 15:45 UTC

Proactive application of Bitcoin's historical minimum-version and
BIP34 coinbase-height rules to every catalogued stale candidate
across all reachable chains — including rows currently accepted as
VALID stales — to find error blocks hiding among them: full-proof-
of-work Bitcoin headers that fail one of these consensus rules at
their claimed height. The committed error-blocks dataset was built
primarily from namecoin/devcoin/ixcoin-family observations; this
sweep covers the chains not systematically swept before.

Rules applied (enforcement heights from
`stale_blocks_analysis.config`):

- `BIP34_VERSION_2_HEIGHT = 224413`: version >= 2
  blocks need the BIP34 coinbase-height prefix
  (`bip34_v2_coinbase_height_mismatch`).
- `BIP34_HEIGHT = 227931`: the prefix is mandatory for ALL
  blocks and version 1 is invalid (`bip34_coinbase_height_mismatch`).
- `BIP66_HEIGHT = 363725`: minimum block version 3
  (`bip66_block_version_below_3`).
- `BIP65_HEIGHT = 388381`: minimum block version 4
  (`bip65_block_version_below_4`).

The gates are reused from
`stale_blocks_analysis.btc_stale_validation`
(`block_version_error`, `bip34_height_error`), never reimplemented,
and the rule tokens match the offline validator's `RULE_GATES` keys,
so a promoted finding re-derives in `validate_error_blocks.py`. Full
PoW is re-derived per row from the committed header bytes via
`hash_meets_btc_difficulty` (sha256d of the 80-byte header meets the
header's own embedded nBits target), never inherited from a
classification label. A confirmed finding must ALSO meet the
canonical expected-nBits target at the claimed height (the
inventory's `expected_nbits` column, else the committed epoch table
at the height's epoch start): a gate violation whose digest meets
only an easy self-declared embedded target is a
share/contamination observation, not a confirmed error block (the
same rule the offline validator enforces). A PoW-passing,
canonical-target-passing row that fails a gate at its
claimed height is an error-block finding; membership is checked
against the committed `data/error-blocks/error_blocks.csv` dataset
by `(height, hash)`.

Candidate sources and claimed-height trust:

- The 16 regen-chain stale inventories on the chain archive host:
  authoritative `btc_height` (the classifier set it from an
  active-chain prev).
- syscoin/elastos/fractal canonical-fill-scratch stale inventories:
  their `btc_height` is NOT verified against the canonical chain
  (the Task 8 height-trust caveat), so PoW-passing rows are tallied
  as `untrustworthy height` negatives, never evaluated as
  violations.
- The committed `data/validated-stales/<chain>_validated_stales.csv`
  (the ACCEPTED stales): their `btc_height` passed the active-parent
  gate, so it is authoritative; applying the gates here cross-checks
  whether any accepted stale is actually an error block. Chains
  whose CSV carries no usable rows (empty, or every row missing the
  header/coinbase bytes — RSK does not expose the real parent
  coinbase) are `no usable rows` negatives.

## Summary

- Inventories reachable: 45/45
- Rows examined: 33187
- Rows skipped for no parseable claimed height: 492
- Rows skipped for an unparseable header (no PoW check possible): 0
- Full-PoW pass: 32169
- Full-PoW fail (share/near rows, excluded): 0
- Full-PoW candidates with an untrustworthy claimed height (scratch inventories, not evaluated): 27548
- Version-rule violation observations (BIP66/BIP65): 6
- BIP34 coinbase-height violation observations (v2 + mandatory): 24
- Violation observations failing the canonical expected-nBits target (share/contamination, not confirmed): 0
- Already catalogued in the dataset: 30 observations across 15 distinct (height, hash) blocks (the same BTC error block is recorded by several sibling chains)
- NEW confirmed error blocks: 0

## Per-inventory results

| chain | source | rows | full-PoW pass | untrustworthy height | version violations | BIP34 violations | already in dataset | NEW |
|---|---|---|---|---|---|---|---|---|
| argentum | stale | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| bitmark | stale | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| coiledcoin | stale | 27 | 27 | 0 | 0 | 0 | 0 | 0 |
| crown | stale | 23 | 23 | 0 | 0 | 0 | 0 | 0 |
| devcoin | stale | 484 | 484 | 0 | 2 | 13 | 15 | 0 |
| elcash | stale | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| emercoin | stale | 97 | 97 | 0 | 0 | 0 | 0 | 0 |
| geistgeld | stale | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| groupcoin | stale | 32 | 32 | 0 | 1 | 0 | 1 | 0 |
| huntercoin | stale | 13 | 13 | 0 | 0 | 0 | 0 | 0 |
| i0coin | stale | 176 | 176 | 0 | 1 | 0 | 1 | 0 |
| ixcoin | stale | 478 | 478 | 0 | 1 | 11 | 12 | 0 |
| myriadcoin | stale | 40 | 40 | 0 | 0 | 0 | 0 | 0 |
| terracoin | stale | 35 | 35 | 0 | 0 | 0 | 0 | 0 |
| unobtanium | stale | 44 | 44 | 0 | 1 | 0 | 1 | 0 |
| xaya | stale | 40 | 40 | 0 | 0 | 0 | 0 | 0 |
| syscoin | stale | 18360 | 17881 | 17881 | 0 | 0 | 0 | 0 |
| elastos | stale | 9156 | 9152 | 9152 | 0 | 0 | 0 | 0 |
| fractal | stale | 524 | 515 | 515 | 0 | 0 | 0 | 0 |
| argentum | validated | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| bitcoin-vault | validated | 9 | 9 | 0 | 0 | 0 | 0 | 0 |
| bitmark | validated | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| coiledcoin | validated | 27 | 27 | 0 | 0 | 0 | 0 | 0 |
| crown | validated | 23 | 23 | 0 | 0 | 0 | 0 | 0 |
| devcoin | validated | 468 | 468 | 0 | 0 | 0 | 0 | 0 |
| doichain | validated | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| elastos | validated | 153 | 153 | 0 | 0 | 0 | 0 | 0 |
| elcash | validated | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| emercoin | validated | 96 | 96 | 0 | 0 | 0 | 0 | 0 |
| fractal | validated | 31 | 31 | 0 | 0 | 0 | 0 | 0 |
| geistgeld | validated | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| groupcoin | validated | 30 | 30 | 0 | 0 | 0 | 0 | 0 |
| hathor | validated | 6 | 6 | 0 | 0 | 0 | 0 | 0 |
| huntercoin | validated | 13 | 13 | 0 | 0 | 0 | 0 | 0 |
| i0coin | validated | 166 | 166 | 0 | 0 | 0 | 0 | 0 |
| ixcoin | validated | 465 | 465 | 0 | 0 | 0 | 0 | 0 |
| lyncoin | validated | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| myriadcoin | validated | 40 | 40 | 0 | 0 | 0 | 0 | 0 |
| namecoin | validated | 1625 | 1397 | 0 | 0 | 0 | 0 | 0 |
| rsk | validated | 298 | 0 | 0 | 0 | 0 | 0 | 0 |
| sixeleven | validated | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| syscoin | validated | 78 | 78 | 0 | 0 | 0 | 0 | 0 |
| terracoin | validated | 35 | 35 | 0 | 0 | 0 | 0 | 0 |
| unobtanium | validated | 43 | 43 | 0 | 0 | 0 | 0 | 0 |
| xaya | validated | 40 | 40 | 0 | 0 | 0 | 0 | 0 |

## Negative results

- Inventories with authoritative-height full-PoW candidates but no version/BIP34 violation: argentum (stale), bitmark (stale), coiledcoin (stale), crown (stale), elcash (stale), emercoin (stale), huntercoin (stale), myriadcoin (stale), terracoin (stale), xaya (stale), argentum (validated), bitcoin-vault (validated), bitmark (validated), coiledcoin (validated), crown (validated), devcoin (validated), elastos (validated), elcash (validated), emercoin (validated), fractal (validated), groupcoin (validated), hathor (validated), huntercoin (validated), i0coin (validated), ixcoin (validated), myriadcoin (validated), namecoin (validated), syscoin (validated), terracoin (validated), unobtanium (validated), xaya (validated).
- Inventories with no usable rows (empty, or every row missing the committed header/coinbase bytes; RSK does not expose the real parent coinbase): rsk (validated).
- 492 rows were skipped for lacking a parseable claimed height (no `btc_height`, a malformed value, or an implausible value above the canonical tip).
- 27548 full-PoW candidates in the canonical-fill-scratch stale inventories (syscoin/elastos/fractal) carried a non-authoritative claimed height: their `btc_height` is not verified against the canonical chain, so no valid version/BIP check is possible. They are negatives, not violations.
- No NEW confirmed version/BIP error blocks: every full-PoW violation meeting the canonical expected-nBits target is already catalogued in the committed dataset.

Row-level candidate detail remains in the authoritative inventories
on the chain archive host and in the committed validated-stales
CSVs; this report is the compact committed summary.
