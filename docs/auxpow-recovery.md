# AuxPoW recovery of Bitcoin stale blocks

The stale-block census in this repository goes back further and runs
deeper than the canonical `bitcoin-data/stale-blocks` dataset alone
can support. The extra coverage comes from parsing merge-mining proofs
embedded in blocks of chains that share Bitcoin's proof-of-work. Namecoin-
family chains use `CAuxPow`; RSK uses a distinct midstate-compressed proof;
Hathor uses an RFC-0006, `Hath`-tagged split-header proof.
The source artifacts provide a Bitcoin parent header and varying amounts of
commitment data. A row is accepted as a direct-stale header candidate only when
its header hash satisfies its encoded target, its parent is on Bitcoin's active
chain, and it passes the publication gates available for that chain. Those
gates include expected `nBits`, median-time-past, historical minimum block
versions, coinbase scriptSig length, and BIP34's contemporaneous
coinbase-height rule where the real coinbase scriptSig is available. RSK cannot
independently apply the two coinbase-dependent checks because its proof is
midstate-compressed. Exact-key cross-chain exclusions protect known shared
failures.

Passing these necessary header and contextual checks does not establish full
Bitcoin block validity. Most compact recovery rows omit the complete Bitcoin
block body, and some omit a self-contained AuxPoW proof. See the
[data validity contract](data-validity.md) before interpreting `stale` or
`validation_status=VALID`.

The 20 July 2026 audit replayed all 3,652 then-accepted direct observations
against Bitcoin Core tip 958,882. Every row passed its available checks. The
3 August source reclassification added 44 Elastos and Syscoin direct
observations that passed the same profile against Bitcoin Core. This includes
active-parent linkage and median-time-past for the complete set; RSK's 298 rows
remain unable to test coinbase scriptSig length or BIP34 prefix because the
required coinbase data is not recoverable.

From height 224,413, version 2 or newer blocks required the exact height prefix
while version 1 remained valid. From height 227,931, version 1 was rejected and
the prefix was mandatory for every valid block. The minimum version then rose
to 3 at BIP66 height 363,725 and 4 at BIP65 height 388,381.

The technique is from Stifter et al., ["Echoes of the Past: Recovering
Blockchain Metrics From Merged Mining"](https://eprint.iacr.org/2018/1134.pdf)
(eprint 2018/1134; Financial Cryptography 2019). The paper establishes that AuxPoW recovery is
complementary to live monitoring - it captures both blocks that
external observers also saw and blocks they did not - and notes that
Namecoin's activation block was recorded on 11 Oct 2011, and Stifter et al.
associate its AuxPoW with Bitcoin height 148,553 on 8 Oct 2011. That
observation sets the practical production floor for the Namecoin-family AuxPoW
reconstruction, not a universal protocol activation height or a lower bound for
the distinct RSK and Hathor proof formats.

## The "In Stifter et al. 2018 baseline" field

Every per-chain page under `docs/chains/` carries an **In Stifter et al. 2018
baseline** row. It answers one narrow, analytic question: was this chain one of
the merge-mining forks whose blocks Stifter et al. actually measured? Concretely,
does the chain appear as a data source in Table 1 ("Considered Cryptocurrencies")
of *Echoes of the Past*? The paper states it "gathered data from 7 merge mined
children for Bitcoin": **Namecoin, IXCoin, I0Coin, GeistGeld, Devcoin, Groupcoin,
and Unobtanium** (plus the Bitcoin and Bitcoin Cash parent chains it
reconstructs, Bitcoin up to block 532,485). Those seven chains, and only those,
read **Yes**.

The field is **not** a claim about whether a chain's activity overlaps the
paper's coverage period. A chain can merge-mine squarely inside the paper's
window and still read **No** because the authors did not sample it (Crown and
CoiledCoin are the clear cases). Where a chain's window nonetheless overlaps the
paper's data cutoff, that fact belongs in the chain's own prose, not in this
field. The paper's Bitcoin data ends at block 532,485 (early July 2018); the
per-chain pages' recurring "2018-07-06 freeze" refers to that same cutoff. (The
short "Stifter et al. 2018" label follows the eprint year; the paper was
published at FC 2019.)

Per-chain detail (chain data provenance, extraction methodology, filtering, novelty splits): see `docs/chains/<chain>.md`.
For the cross-chain process/accounting snapshot, including data volumes,
stale-descendant semantics, final artifacts, and current consistency issues,
see [`process-data-outcomes.md`](process-data-outcomes.md).

## Integrated chains

Each chain contributes a historical-named
`data/validated-stales/<chain>_validated_stales.csv` file containing publication-gate-accepted
direct-stale header candidates
consumed by `src/stale_blocks_analysis/stale_blocks.py`. The public repo keeps
only canonical loader inputs and compact result outputs. The full classifier
output is bucket-split into `<chain>_stale_blocks.csv` (stale only),
`<chain>_unknown_blocks.csv`, and `<chain>_canonical_blocks.csv` (all sharing
one schema); these, raw extracts, and other bulky intermediates are preserved
in the private per-chain archive. RSK's committed
loader input is `data/validated-stales/rsk_validated_stales.csv` like every other chain
(shared validated-stales layout plus RSK miner-evidence and historical-label
columns); the historical
single-file exception is retired, and its full stale/unknown inventory lives
in the private archive.

Strict and weak BTC-orphan relevance checks use the committed
`data/bitcoin-epoch-reference/` inputs. They are regenerated from
mempool.space's public Esplora-compatible API and contain each Bitcoin
retarget-boundary block plus a six-confirmation horizon block. This separates
reproducible Bitcoin `nBits` and timestamp context from the private runtime
cache used for optional mainchain lookups.

`data/error-blocks/error_blocks.csv` is the consensus-invalid error-blocks
dataset and exact-key exclusion gate over the
pinned upstream dataset and committed per-chain inputs. It supersedes the
former `data/stale_block_exclusions.csv` overlay. Its 33 rows carry 31
consensus-invalid keys plus two rows added by this work. Of the 31 carried-over
keys, 21 fail BIP34's coinbase-height
rule, three version 2 headers after height 363,725 fail BIP66's minimum version
3 rule, five headers below version 4 after height 388,381 fail BIP65's minimum
version 4 rule, one violates median-time-past, and one has a 103-byte coinbase
scriptSig. The two added rows are the 946,213 `time_below_mtp` block (from
merge-mining-monitor live evidence) and the 717,696 `nbits_retarget_not_applied`
block (found by the rejected-row sweep). The former overlay's 32nd key, a
direct-stale-only correction at Bitcoin
height 656,478, is not an error block: its predecessor is a known stale rather
than an active-chain block, so it now lives only in the accepted
stale-descendant sidecar. It is not part of the error-block gate, but projection
of a raw direct-stale source row additionally requires the compact
`data/stale_descendant_corrections.csv` exact-key correction overlay and its
matching chain-specific sidecar observation. Loaders and upstream-derived reports apply the
gate by exact `(height, hash)` key, keying off `classification == "error_block"`.

A separate generated evidence layer serves downstream consumers that need more
than the stale census. Run `just full-evidence` to write normalized per-chain
artifacts and a manifest under `results/full-evidence/`. The exporter preserves
canonical, stale, unknown, near, rejected, and stale-descendant classifications
when the source inventory carries them; when only the stale-only publication
file is available, the manifest records that canonical rows are not represented
by that source. Passing `--chain-archive-dir` to
`scripts/reports/build_auxpow_full_evidence.py` lets private full inventories be
read in place without copying them into `data/`.

Historical extraction paths also preserve the 80-byte child header from the
same original block that supplied each AuxPoW proof. The derived
`child_block_hash`, `child_header_hex`, `child_block_time`, and `child_nbits`
travel together through classification and evidence export; any partial or
self-contradictory bundle stops classification. Xaya is the sole outer-format
exception: its block hash and timestamp come from `CPureBlockHeader`, while
its effective `nBits` comes from the adjacent `PowData` field. Run
`just child-header-coverage` against a staged evidence directory before
publishing a dated refresh. Existing historical CSVs without the header
bundle must be regenerated from their original sources, not post-processed.

Rows follow the documented **merge-mining evidence chronology**, matching
`CHAINS_BY_AUXPOW_ACTIVATION` in `config.py`.

One derived contribution sits outside the per-chain direct-stale counts:
`data/stale_descendants.csv` records headers whose ancestry walks back to a
known BTC stale root. Source-chain rows originally classified `unknown` remain
`unknown`; the sidecar carries their separate descendant promotion. One
historical direct-stale row is instead corrected out of that class because its
predecessor is stale rather than active. The sidecar carries the separate
`classification=stale_descendant` contribution for multi-block BTC stale-fork
continuations, and the analysis loader admits only rows with
`validation_status=VALID_STALE_DESCENDANT`. Current reconciliation evidence
finds 25 stale-rooted headers (20 direct children + 5 deeper descendants), of
which 21 are accepted under the declared descendant gate and 4 remain recorded
as BIP34-height rejections. A follow-up audit confirms
those 4 are not script artifacts: their coinbase BIP34 heights decode exactly
one block above the height implied by stale-root ancestry, while their header
hashes, PoW, nBits, prev_hash paths, and stale-root Core-parent heights all
check out.

The wider unknown graph is much deeper, but currently unanchored: the dedicated
depth report finds 25,050 chain tips at depth 3 or more, maxing out at a
103-link Myriadcoin dangling fragment and a 67-link
ixcoin/terracoin/unobtanium cross-seen fragment. No depth ≥ 3 chain tip
terminates at a known BTC stale, so these longer fragments remain investigation
targets rather than stale-block contributions. The full nBits-origin pass
covers all 25,050 deep tips: all satisfy their own encoded target, but 0 match
BTC's height-derived nBits and 0 match BTC's timestamp-derived nBits even with
±1 retarget epoch allowance.

| # | Chain | Accepted direct stales | Novel\* | Notes |
|---:|---|---:|---:|---|
| 1 | [Namecoin](chains/namecoin.md) | 1,625 | 0 | First production merge-mined chain with non-zero direct-stale header-candidate recovery; activates the practical AuxPoW recovery window at BTC 148,553 (Oct 2011). Chronological novelty is 0: all 1,625 accepted direct rows are present in effective upstream after the exclusion overlay is applied. |
| 2 | [Geistgeld](chains/geistgeld.md) | 0 | 0 | Dead chain, archival `getblock`-JSON dump shared by Nicholas Stifter (1.6 GB gzipped, 7.3M blocks, 2.49M AuxPoW-bearing). Catalogue activation 2011-10-08, tied with Namecoin (alphabetical tie-break to second). The dump shows earlier experimental AuxPoW activity from GG height 14,092 / 2011-09-16 using Geistgeld's copy of Durham's implementation. **Zero accepted direct-stale candidates**: of 2,291 self-target-PoW-valid unique parent headers, 1 is canonical and 2,290 are unknowns. Their relaxed `nBits` cluster does not match Bitcoin's target history. The private full inventory preserves 2,290 unknowns. |
| 3 | [i0coin](chains/i0coin.md) | 166 | 37 | Offline `blk*.dat` parse of a January 2018 snapshot on `<archival-host>`; chain no longer has live nodes. Provisional and incomplete: the snapshot bounds coverage at Jan 2018, so the 166 committed rows are a lower bound. |
| 4 | [ixcoin](chains/ixcoin.md) | 465 | 50 | Raw-hex parse on IXCore 0.14.x; needed a single source patch touching six files for GCC 13 / modern Boost. |
| 5 | [CoiledCoin](chains/coiledcoin.md) | 27 | 0 | Pre-0.6 Bitcoin Core fork, merge-mined to extinction in the January 2012 Eligius 51% attack; recovered from a single surviving archival node (`knotwork.com`), tip dormant since 2026-03-10. Narrow window BTC 161,761 → 187,452 (Jan 2012 → Jul 2012). 1 record in the Jan 2012 Eligius attack window; **0 chronologically novel** (all 27 first-claimed by upstream or by ixcoin/namecoin/i0coin). Not in Stifter et al. 2018 baseline. |
| 6 | [Devcoin](chains/devcoin.md) | 468 | 32 | Raw-hex parse - `getblock` doesn't expose `auxpow` JSON despite being a Bitcoin Core 22.x fork. 50k-DVC split coinbases carry many outputs. |
| 7 | [Groupcoin](chains/groupcoin.md) | 30 | 1 | Dead chain, archival `getblock`-JSON dump shared by Nicholas Stifter (1.8 GB gzipped, 235k blocks, 93% AuxPoW share). The accepted rows span BTC 181,492 → 312,238 (May 2012 → July 2014). `coinbasetx.vout[*].scriptPubKey.addresses` in the dump are Groupcoin-base58-encoded (e.g. `2h…`); the classifier emits raw pkscript hex semicolon-joined. Consensus validation removes one `nBits` mismatch and one post-BIP66 version 2 header; the private full inventory preserves 2,713 unknowns. |
| 8 | [Huntercoin](chains/huntercoin.md) | 13 | 2 | Dead chain, Arweave permaweb archive (`domob1812/arblockstore`). SHA-256d branch only (chain ID 6); Scrypt branch is out of scope. Feb–Mar 2014 window. The private full inventory preserves 29 unknowns - zero overlap with any other chain's stale or unknown inventory. |
| 9 | [Unobtanium](chains/unobtanium.md) | 43 | 3 | Bitcoin Core 0.11 fork; raw-hex parse like Devcoin/ixcoin. 99.84 % AuxPoW density across the scanned range; validated stales span May 2015 → Aug 2020. AuxPoW chain ID = 117 (0x75). |
| 10 | [Crown](chains/crown.md) | 23 | 5 | Bitcoin/Dash-derived strict-chain-ID AuxPoW chain, single-algo SHA-256d. Raw-hex CAuxPow parse from a Wayback-recovered live peer; 1,868,911 AuxPoW commitments over the PoW window yielded 23 accepted direct-stale candidates and 383,622 unknowns. Not in Stifter 2018. |
| 11 | [Myriadcoin](chains/myriadcoin.md) | 40 | 2 | **First multi-algo chain in the pipeline** (5 algos: SHA-256d / Scrypt / Groestl / Yescrypt / Argon2d). Only the SHA-256d branch is considered for Bitcoin-parent merge mining; the extractor filters on `nVersion` bits 9–11 (`BLOCK_VERSION_ALGO = 7<<9`) before AuxPoW parsing, dropping 78 % of blocks. `fStrictChainId=false`; the classifier applies the header's encoded self-target before Bitcoin RPC classification and later stale-candidate validation. Coverage spans BTC 467,186 → 642,669 (May 2017 → Aug 2020). Not in Stifter 2018. |
| 12 | [SixEleven](chains/sixeleven.md) | 0 | 0 | Complete legacy chain recovered with a pinned local node and block-file scan through child height 999,406. The scan yielded 7 canonical Bitcoin parents and no accepted stale or strict/weak evidence. |
| 13 | [Argentum](chains/argentum.md) | 2 | 0 | **Sparse Bitcoin-parent evidence case study**. Multi-algo SHA-256d subset; `fStrictChainId=false`. Extraction found 634,277 self-target-PoW-valid unknowns, 27 canonical parents, and 2 accepted direct-stale candidates. The Phase 1 count alone does not establish Bitcoin-mainnet difficulty or parent identity, and the accepted ratio is not a hashrate estimate. |
| 14 | [Terracoin](chains/terracoin.md) | 35 | 0 | Dash Core 0.12.2.x - boolean-verbose `getblock <hash> true` returns decoded `auxpow`. 99.95 % AuxPoW density, second only to Bitcoin Vault's 99.99 %. Only Dash-Core-derived chain in scope. AuxPoW from TRC 833,000 (2016-09-23, hard fork 1); coverage spans BTC 467,186 → 645,179 (May 2017 → Aug 2020). Not in Stifter 2018. |
| 15 | [Emercoin](chains/emercoin.md) | 96 | 29 | **First hybrid PoW/PoS chain in the pipeline**. Only PoW blocks carry AuxPoW, so the extractor filters the ~85 % PoS majority before reading Bitcoin parent headers. RPC exposes decoded AuxPoW JSON, not raw CAuxPow bytes. Coverage spans BTC 467,186 → 777,172 (May 2017 → Feb 2023), straddling BCH/BSV; canonical-at-height `nBits` validation filters stale candidates before commit; the private full inventory preserves 16,545 unknowns (original-run count; the committed input carries the 2026-06-24 refresh). Not in Stifter 2018. |
| 16 | [RSK](chains/rsk.md) | 298 | 117 | Distinct compressed merge-mining proof: the full BTC parent coinbase cannot be reconstructed, while `rsk_miner` is retained for later attribution research. The extraction starts at child height 139,999 by acquisition convention and walks canonical blocks plus uncles; 218 of 298 accepted candidates are uncle-derived. The historical label snapshot includes 53 Foundry-labelled candidates. RSKj 9.0.1 is the research-node version. |
| 17 | [Doichain](chains/doichain.md) | 0 | 0 | Pinned-source node and blkdat survey through the active-chain tip observed at child height 430,684. The scan found 429,401 AuxPoW commitments; a later exact-target audit confirmed 300,625 canonical-tip rows matched Bitcoin's full expected `nBits` and BIP34 height. The surveyed window yielded 0 accepted direct-stale candidates, 0 strict BTC orphans, and 0 weak BTC orphans. |
| 18 | [Bitmark](chains/bitmark.md) | 1 | 0 | Multi-algo SHA-256d subset with all eight algorithms merge-mineable. One publication-gate-accepted direct-stale candidate, already present in Unobtanium, Myriadcoin, and RSK; retained as cross-confirmation only. |
| 19 | [Xaya](chains/xaya.md) | 40 | 0 | Daniel Kraft's Xaya (CHI), a multi-algo chain (NEOSCRYPT solo or SHA256D merge-mined). The source enforces "SHA256D must be merge-mined", so every SHA256D block carries a merge-mining parent header. Recovered offline from Xaya's open `blocks.zip` dump (the legacy P2P network is dead, so no live node), parsing the `PowData` block-header wrapper. 1,695,912 merge-mined blocks yielded 38,483 self-target-PoW-valid parents. The original run recorded 34 stale-labelled candidates and 17,642 unknowns; the 2026-06-24 refreshed accepted set contains 40 direct-stale candidates spanning BTC 547,182 to 853,120 (October 2018 to July 2024). A historical private attribution pass was F2Pool-dominated; the public pipeline does not reproduce that result. **0 chronologically novel** (every accepted row was first claimed by upstream or an earlier chain). The 2024-11-15 snapshot (Xaya ~6.34M) bounds coverage; the tail to Xaya's ~7.3M deprecation height is a documented gap. Not in Stifter 2018. |
| 20 | [Elastos](chains/elastos.md) | 177 | 25 | Go-based node (`Elastos.ELA`), not a Bitcoin Core fork. Hybrid local-node + public-RPC extraction. The August source reclassification retains 175,053 canonical parents, accepts 177 direct stales, and rejects one candidate whose `nBits` does not match Bitcoin at its decoded height. Not in Stifter 2018. |
| 21 | [Syscoin](chains/syscoin.md) | 98 | 1 | Modern Bitcoin Core fork (v5.0.5); decoded-JSON extraction where `getblock <hash> 1` returns a decoded `auxpow` object. The August source reclassification accepts 98 direct stales after canonical-height `nBits` validation. Chain 2 (Jun 2019 →). Not in Stifter 2018. |
| 22 | [Hathor](chains/hathor.md) | 6 | 0 | **Only RFC-0006 split-header proof in the pipeline**: the 32-byte parent merkle root is reconstructed from the coinbase and merkle path; a three-part byte-order correction was required (see `docs/chains/hathor.md` §2). The current committed loader input contains 6 accepted direct-stale candidates and **0 chronologically novel** candidates. Acquisition and classification now use one range-neutral whole-corpus interface; the regenerated category publication follows separately. Not in Stifter 2018. |
| 23 | [Bitcoin Vault](chains/bitcoin-vault.md) | 9 | 6 | Dormant chain recovered without running a node, via Blockbook `/api/rawblock/<hash>`. The original run classified 8 stale-labelled candidates from 2,575 self-target-PoW-valid headers; the refreshed committed input adds one already-upstream accepted candidate. |
| 24 | [Electric Cash](chains/elcash.md) | 3 | 0 | Bitcoin Core 0.20.2 fork merge-mining from a fresh Dec 2020 genesis; the three accepted stales (Jun-Sep 2021) fall inside a 2021-2024 real-hashrate era that peaked Sep-Oct 2021, and all three re-observe Bitcoin Vault-first-claimed headers. Self-synced `elcashd`; standard Namecoin-style CAuxPow. Zombie chain, negligible current hashrate. |
| 25 | [Lyncoin](chains/lyncoin.md) | 0 | 0 | Live-peer P2P header recovery across the complete pre-Flex merge-mined era through child height 260,499. No accepted stale or strict/weak evidence was found in the recovered window. |
| 26 | [Fractal Bitcoin](chains/fractal.md) | 31 | 1 | Newest integrated chain. `fractald` v0.3.0 on the archival host; compact `getblockheader <hash> false true` extraction through FB height 1,807,154. The extractor requires the AuxPoW flag plus chain ID `0x2024`; the observed encoding was `0x20240100`. The run produced 601,760 AuxPoW rows, 59,504 self-target-PoW-valid unique parent headers, 31 accepted direct-stale candidates, and 493 unknowns. 15 rows also appear upstream; 29 were already first-seen by RSK or Namecoin, leaving 1 chronologically novel accepted candidate at BTC height 928,455. |

\* "Novel" = **chronologically novel at this chain's position** in
`CHAINS_BY_AUXPOW_ACTIVATION`: not in upstream `bitcoin-data/stale-blocks`
AND not in any chronologically-earlier integrated chain's validated set.
Computed by `scripts/compute_chain_novelty.py <chain>` (cumulative view).
Earlier-born chain has novelty precedence - this is a simplifying
attribution convention, not a claim about real-world block-observation
ordering (see `config.py:CHAINS_BY_AUXPOW_ACTIVATION` comment).
The historical first-recovery-count framing is preserved in
`data/new_stale_blocks_for_upstream.csv`.

## Surveyed, historical, and unwired

Other chain-specific infrastructure and qualified recovery states are
documented separately in
[`chains/surveyed-infra.md`](chains/surveyed-infra.md). The 2026-07-10 pass over
all nine sources formerly labelled "Catalogued (not recovered)" has a detailed
status and provenance record in
[`chains/catalogued-recovery.md`](chains/catalogued-recovery.md). Those entries
include partial, historical, surveyed, blocked, source-only, and excluded
records. Lyncoin and SixEleven are completed historical recoveries: their
canonical Monitor rows and header-only zero-stale loader inputs are integrated.
Doichain is a completed surveyed-window zero-stale result with a header-only
loader input; its aggregate canonical characterization is documented, but no
row-level canonical export is committed. The VCash record is a recovered
68-row canonical mapping subset, but it is not a recovered VCash blockchain
and does not establish stale or strict/weak totals. BLAST remains blocked with
no usable peer.

The i0coin validated set comes from a January 2018 third-party `blk*.dat`
snapshot rather than a live node or a complete history dump. It is therefore
provisional and bounded at January 2018; no fuller i0coin history has been
obtained.

## Pool attribution

Pool attribution is a separate layer over the recovery outputs, not a
dependency of the recovery pipeline itself. Most chains preserve
the Bitcoin parent coinbase scriptsig and output scripts from the AuxPoW proof.
RSK is the exception: its recovery artifacts preserve the RSK miner address and
historical `pool_label`, rather than the Bitcoin parent coinbase transaction.

The attribution layer reads the pinned `bitcoin-data/mining-pools` registry
(fetched by `scripts/fetch-data.sh`),
runs the shared coinbase-to-pool matcher over the merge-mining-recovered
stales, and emits an attribution export as a gitignored run product; see
[`pool-attribution.md`](pool-attribution.md) for the layer and its export
contract. No attribution results are committed, and the observed-vs-expected
analysis over those labels lives in the companion `stale_rate_analysis` repo
(not yet published).

## Limitations

- **Practical AuxPoW floor** (BTC ~148,553 / Oct 2011). The Stifter
  Geistgeld dump shows AuxPoW commitments ~22 days before this floor (GG
  height 14,092, parent_block.time 2011-09-16, BTC ~145,000), but those are
  Geistgeld's own experimental, relaxed-difficulty use of its copy of the
  Durham AuxPoW implementation (parent headers not on BTC mainchain) and contribute zero
  accepted direct-stale candidates (see `docs/chains/geistgeld.md`). Below this practical
  floor no AuxPoW-observable parent chain produced recoverable BTC
  stales; observability is zero by construction.
- **Chain-specific gaps**. Each merge-mined chain only witnesses BTC
  blocks while it was active and operating. Coverage is the union of
  per-chain windows, not a single continuous span.
- **Density and false negatives**. AuxPoW density (the fraction of
  child blocks that include a parent header at all) varies from ~10 %
  for some pools to ~100 % for fully merge-mined pool fleets. Low
  density means recovery captures only a sample of stales for those
  pools and periods.
- **Post-fork contamination**. Post-2017 evidence can contain parent headers
  from Bitcoin-family forks or other headers whose difficulty context is not
  Bitcoin's. The classifiers reject direct-stale candidates whose `nBits` does
  not match Bitcoin at the decoded height; an `nBits` mismatch alone does not
  identify the originating chain.
- **Consensus-invalid stale candidates**. A header can satisfy its own encoded
  target and extend a canonical Bitcoin parent without being a valid Bitcoin
  block. The classifiers apply BIP34's historical two-stage rule: version 2 or
  newer candidates require the exact coinbase-height prefix from height
  224,413, and every candidate requires it from height 227,931. Modern Bitcoin
  Core buries BIP34 at 227,931 and does not replay the earlier rolling-threshold
  transition for alternative historical branches, so the project applies the
  contemporaneous rule explicitly. From heights 363,725 and 388,381, the
  version must also meet BIP66's minimum 3 and BIP65's minimum 4 respectively.
  The error-blocks dataset (`data/error-blocks/error_blocks.csv`) removes 31
  historical consensus-invalid candidates. RSK cannot
  expose the coinbase field because its proof stores a midstate-compressed
  coinbase, so its matching exclusions are applied by exact cross-chain
  identity.

## Per-chain methodology

The public in-repo reference is the summary table above plus
`docs/chains/<chain>.md`. Private operational notes, host layouts, and archival
locations are intentionally kept outside the repository.
