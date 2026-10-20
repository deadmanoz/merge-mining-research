# Historical Bitcoin events in the merge-mining record

This note connects specific published observations to historical accounts.
Exact header matches corroborate an event; they do not establish that the
recovery is new to every other archive or researcher. Sibling observations
can preserve the same Bitcoin work across several chains, so the number of
witnesses is not a count of independent miners.

## July 2015 BIP66 forks

The [historical fork list](https://en.bitcoin.it/w/index.php?title=July_2015_chain_forks&oldid=58130)
records six invalid-branch blocks on July 4 and three on July 5. The
[contemporaneous Bitcoin.org alert](https://bitcoin.org/en/alert/2015-07-04-spv-mining)
describes miners extending a version-2 block after BIP66's version-3
enforcement threshold. Later version-3 headers on that branch fail consensus
because their ancestor is invalid, even though the descendant headers do not
themselves fail the minimum-version rule.

Four hashes from the six-block July 4 list match the published merge-mining
evidence across 13 child-chain observations:

| Height | Hash suffix | Position in listed branch | Witnesses |
|---|---|---:|---|
| 363,732 | `15390b4` | 2 | Huntercoin 772,341; Ixcoin 267,463; Namecoin 237,731 |
| 363,733 | `531ec61` | 3 | Huntercoin 772,368; I0coin 1,525,817; Ixcoin 267,466; Namecoin 237,734 |
| 363,735 | `b185de7` | 5 | I0coin 1,525,825; Ixcoin 267,469; Namecoin 237,736 |
| 363,736 | `5901436` | 6 | I0coin 1,525,833; Ixcoin 267,471; Namecoin 237,737 |

The historical list attributes positions 2, 3, 5, and 6 (`363,732`, `363,733`,
`363,735`, and `363,736`) to F2Pool, matching the `🐟` (`f09f909f`) marker in
their recovered coinbase scriptSigs, and attributes the unwitnessed
intermediate block at `363,734` (`0966d65e...e381aa18`, position 4) to AntPool.

For `363,733`, `363,735`, and `363,736`, complete non-witness coinbase
transactions retained in the I0coin records hash directly (`sha256d`) to their
respective Bitcoin header Merkle roots. Each pays exactly `2,500,000,000`
satoshis (`25 BTC`). This independently corroborates the single-transaction
empty-block structure for those three blocks.

### Authenticated invalid-ancestry representation

All four witnessed descendants (`363,732`, `363,733`, `363,735`, and `363,736`)
are catalogued in [`data/error-blocks/error_blocks.csv`](../data/error-blocks/error_blocks.csv)
with `classification=error_block` and `rejection_reason=consensus_invalid_parent`,
and their 13 child observations are recorded in
[`data/error-blocks/error_block_observations.csv`](../data/error-blocks/error_block_observations.csv)
(see [`docs/error-blocks.md`](error-blocks.md#huntercoin-witnesses-of-the-bip66-invalid-fork)).
Rather than relabelling version-3 descendants as direct version-2 failures or
leaving them in the `unknown / strict_btc_orphan` population,
[`data/error-blocks/ancestry_evidence.csv`](../data/error-blocks/ancestry_evidence.csv)
and `src/stale_blocks_analysis/error_ancestry.py` (run by
`just validate-error-blocks`) authenticate the complete 80-byte header path
offline:

- Every predecessor edge from `363,736` through `363,731` is checked for header
  identity, height placement, expected epoch `nBits`, and full Bitcoin proof of
  work.
- The unwitnessed intermediate header at `363,734` is supplied as an ancestry
  anchor from the frozen six-header BTC Relay fixture at commit
  `1cf676d387c4514770b91e4ca15094194f446677` without fabricating a child-chain
  observation.
- The root header at `363,731`
  (`0000000000000000009cc829aa25b40b2cd4eb83dd498c12ad0d26d90c439d99`,
  pinned to
  [`bitcoin-data/invalid-blocks` JSONL line 115](https://github.com/bitcoin-data/invalid-blocks/blob/aadce82e948f63bde0befd14f21a84aa45f45cde/data/invalid-blocks.jsonl#L115))
  re-derives `bip66_block_version_below_3` at its reviewed canonical
  predecessor `363,730`
  (`000000000000000006a320d752b46b532ec0f3f815c5dae467aff5715a6e579e`).

### Other version-2 errors that month

The error catalogue also contains three distinct hashes later in July 2015 that
meet full Bitcoin PoW and directly fail `bip66_block_version_below_3` with
header version 2:

| Bitcoin header time (UTC) | Height | Witness chains |
|---|---|---|
| 2015-07-05 16:21:19 | 363,967 | Namecoin |
| 2015-07-08 02:34:17 | 364,341 | Namecoin, Devcoin, Ixcoin |
| 2015-07-26 13:01:03 | 367,047 | Namecoin, Devcoin, I0coin, Groupcoin, Unobtanium |

These are direct byte-derived version violations, extending the examples beyond
the two multi-block forks described by the wiki; they do not establish that
anyone extended these particular invalid blocks. Header timestamps are
miner-supplied time evidence, not independently measured wall-clock arrival
times.

No hash matches to the wiki's three July 5 fork blocks (`363,829`–`363,831`)
were found in the published CSVs searched. That is a coverage statement about
this publication, not proof of absence from every raw archive or sibling chain.

## AntPool and related pools, December 2024 and March 2025

[0xB10C's observations](https://b10c.me/observations/14-antpool-and-friends-invalid-mining-jobs/)
concern overpaying empty-block Stratum jobs built on four competing
predecessors. The merge-mining matches in this repository are to the
predecessors, not those invalid jobs:

| Predecessor height | Hash suffix | Published evidence |
|---|---|---|
| 873,558 | `2ba3bd04af` | Accepted direct-stale candidate: Elastos, RSK |
| 874,036 | `e581c9c12f` | Canonical: Namecoin, RSK |
| 875,589 | `b905ac264e` | Accepted direct-stale candidate: RSK |
| 885,796 | `acdeb985ea` | Accepted direct-stale candidate: Namecoin, Elastos, Fractal |

At `875,589` (`b905ac264e`), the committed RSK row carries the historical RSK
miner-address label `Luxor`, while coinbase-wins attribution against the
pinned upstream `.bin` archive resolves the Bitcoin parent to `AntPool`
(`attribution_basis=coinbase`; see
[`docs/pool-attribution.md`](pool-attribution.md#rsk-historical-labels-only)).

The March predecessor at `885,796` (`acdeb985ea`) was described as unknown in
the article. All three recovered observations (Namecoin `761,223`, Elastos
`1,897,534`, and Fractal `499,271`) preserve the same Bitcoin header; their
coinbase evidence contains `/slush/`, pointing to Braiins Pool (which is folded
into the `AntPool & friends` template-producer cluster for that window; see
[`docs/pool-attribution.md`](pool-attribution.md#dual-attribution-tag-owner-and-template-producer)).
A coinbase marker identifies the advertised tag, not necessarily the operator
of the underlying template or mining infrastructure, and the published
header-context verdict is not full-block consensus validation.

No published observation found in this comparison extends any of the four
predecessors into a full-work block. This does not prove the invalid jobs never
produced sibling-chain blocks: below-Bitcoin-target work and some unknown
observations are absent from the Monitor projection, and searching raw AuxPoW
for those jobs remains a separate investigation. None of the three recovered
stale predecessors is classified as invalid merely because an invalid successor
job referenced it. Earlier full-work `bad-cb-amount` empty-block coinbase
overpayments from the same failure class (`494,933` and `544,568` on Namecoin,
and `584,802` on Elastos) are catalogued separately in
[`data/error-blocks/error_blocks.csv`](../data/error-blocks/error_blocks.csv)
(see [`docs/error-blocks.md`](error-blocks.md#externally-verified-body-invalid-blocks)).
