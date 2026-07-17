# Stale recovery process, data volumes, and outcomes

Snapshot date: 2026-07-22.

This document is the cross-chain accounting view for the stale-block recovery
work. It is deliberately more operational than the per-chain writeups: it
tracks what data went in, how the row counts changed through each processing
stage, what final artifacts exist, and which findings or inconsistencies affect
publication-quality interpretation.

The current snapshot reflects the integrated public loader inputs after the
2026-07 data-consistency pass: every chain's committed loader input is a
publication-gate-accepted `<chain>_validated_stales.csv` (RSK included), the
catalogued-source evidence outputs (VCash, Lyncoin, SixEleven, Doichain) and
Electric Cash are represented, Emercoin and Xaya carry the 2026-06-24
canonical-refresh re-runs, and the upstream `bitcoin-data/stale-blocks` pin
has been bumped to a revision that already includes this project's historical
1,089-row Namecoin addition. A publication overlay now records 31
consensus-invalid keys and one direct-stale-only correction. Twenty-eight of
the invalid keys belonged to the 1,089-row addition, leaving 1,061 accepted
direct additions; the other three invalid keys already existed upstream. The
direct-only key also existed upstream and remains accepted as a stale
descendant.

Here `classification=stale` means a direct-stale header candidate and `VALID`
means that it passed the available chain-specific publication gates. Neither
token asserts that a complete Bitcoin block was available or fully
consensus-validated. See the [data validity contract](data-validity.md).

On 20 July 2026, all 3,652 accepted direct observations were replayed against
Bitcoin Core tip 958,882 and passed every check available from their evidence.
The replay covered 2,113 unique headers across 22 non-empty chain inputs. RSK's
298 rows lack the real coinbase scriptSig, so their scriptSig-length and BIP34
prefix remain untested. This was not a full-block consensus replay.

## Executive Accounting

The repository currently has 26 integrated registry entries with committed
loader inputs. Twenty-two are non-empty; Geistgeld, Doichain, Lyncoin, and
SixEleven have legitimate header-only inputs recording zero accepted
direct-stale candidates. The repository also carries one derived
stale-descendant sidecar and catalogued-source Monitor outputs under
`results/monitor-evidence/`. Lyncoin and SixEleven contribute canonical
evidence with zero accepted direct-stale candidates. VCash is a 68-row
canonical-only subset whose stale and strict/weak totals are not established.
Doichain has a completed zero-stale surveyed window; its aggregate
characterization records 300,625 canonical-tip commitments matching exact
Bitcoin `nBits` and BIP34 height, but no row-level canonical export is
committed.

| Layer | Current volume | Notes |
|---|---:|---|
| Effective upstream `bitcoin-data/stale-blocks` rows | 3,092 | The pinned CSV contains 3,123 data rows. `data/stale_block_exclusions.csv` removes 31 consensus-invalid rows. The direct-only correction remains in the general upstream catalogue; one effective row sits below the epoch-aligned analysis floor of 147,168, the start of the retarget epoch containing the practical production floor at 148,553. |
| Per-chain accepted direct-stale candidate observations at height >= 0 | 3,652 | Sum of all integrated direct-stale loader functions, including RSK's 298 rows, Emercoin's 96 and Xaya's 40 (2026-06-24 refresh), Electric Cash's 3, Fractal Bitcoin's 31, and Bitcoin Vault's 9 (the ninth integrated from the 2026-06-23 refresh). Cross-chain observations of the same header count once per chain here. |
| Accepted stale-descendant candidate observations | 20 | From `data/stale_descendants.csv`; these are not direct canonical-parent candidates. Xaya's full unknown inventory is not yet folded into reconciliation (see note below). |
| Merge-mining/derived candidate observations before dedup | 3,672 | Per-chain direct-stale observations plus accepted stale-descendant observations. |
| Unique accepted header candidates after upstream + merge-mining-evidence dedup | 3,420 | Dedup key is `(height, hash)`. At the epoch-aligned analysis floor of 147,168, the total is 3,419 because one effective upstream row is below the floor. |
| Unique events in post-compact base window | 898 | At `MIN_HEIGHT=421344` with every integrated loader included. |
| Upstream-novel direct rows across novelty CSVs | 562 | `results/per-chain-novelty/*.csv`, `in_upstream=no`; row-level across chains, so cross-chain duplicates count once per chain. 311 unique events are chronologically first-claimed. Excludes stale descendants. |
| Pending-upstream sidecar rows | 328 | `data/new_stale_blocks_for_upstream.csv`: 311 first-claimed direct upstream-new rows plus 17 upstream-new stale descendants. |

Important implementation boundary: downstream cross-source publication views
deduplicate by `(height, hash)`, so same-height competing stale hashes remain
distinct. Exact duplicates retain the upstream row as the catalogue record;
AuxPoW coinbase fields remain available as fallback evidence for later
attribution work. RSK carries miner-address evidence rather than the real
parent coinbase.

## Direct Stales vs Stale Descendants

The project has two different stale concepts that must not be conflated.

**Direct canonical-parent stale** means the recovered BTC parent header is not
on Bitcoin mainchain, but its `btc_prev_hash` is a canonical Bitcoin block. This
is what the per-chain classifiers emit as `classification=stale`, and this is
what each `data/validated-stales/<chain>_validated_stales.csv` row represents.

**Stale descendant** means a recovered header's `btc_prev_hash` is not
canonical and its recovered ancestry reaches a known BTC stale root. Most were
originally classified as `unknown`; one was corrected from direct stale after
its predecessor was shown to be stale rather than active. These rows are BTC
stale-fork continuations, not one-hop canonical-parent stale blocks. They
live in `data/stale_descendants.csv` and are loaded only if
`classification=stale_descendant` and
`validation_status=VALID_STALE_DESCENDANT`.

The label `direct_stale_child` in the recovery files is especially easy to
misread. It means "first child of a known stale root", not "direct stale block
whose parent is canonical". The direct canonical-parent stale is the
`root_stale_hash` / `terminal_stale_hash` anchor.

Current stale-descendant accounting:

| Class in sidecar | Unique headers | Source rows | Valid | Rejected |
|---|---:|---:|---:|---:|
| First child of stale root, depth 1 | 19 | 29 | 16 | 3 |
| Deeper stale descendant, depth 2 | 5 | 7 | 4 | 1 |
| Total stale-rooted candidates | 24 | 36 | 20 | 4 |

No promoted stale-rooted path goes deeper than depth 2. The wider unknown
graph does go much deeper, including depth 103 dangling fragments and depth 67
cross-seen fragments, but none of the depth >= 3 chain tips terminates at a
known stale. Those long fragments remain diagnostic unknown-substrate
evidence, not stale-block contributions.

Validation status:

- 20 rows are promoted into the main stale loader.
- 4 candidates are retained as `REJECTED_bip34_height_mismatch`.
- The independent BIP34 audit confirms all 4 rejections are invalid for their
  stale-fork position: header hash, PoW, nBits, prevhash path, and stale-root
  parent checks pass, but the decoded BIP34 height is exactly one block higher
  than the height implied by stale-root ancestry.

Key artifacts:

- `data/stale_descendants.csv`
- Private stale-ancestry diagnostics: direct matches, descendant paths, root
  summary, reconciliation summary, and the BIP34 rejection audit.

## Process Sequence

| Stage | Input | Processing | Output |
|---|---|---|---|
| 1. Upstream baseline | `data/stale-blocks/stale-blocks.csv` and `data/stale-blocks/blocks/` | Clone/update the exact manifest pin via `scripts/fetch-data.sh`; use the CSV for known-stale membership and retain available block binaries as source evidence. | Primary known-stale list and optional full-block evidence. |
| 2. Per-chain extraction | Child-chain nodes, snapshots, JSON dumps, REST APIs, or RSKj archive RPC | Extract BTC parent header and, where available, BTC parent coinbase evidence from AuxPoW or merge-mining proofs. | Raw extractor outputs, mostly private/gitignored. |
| 3. Self-target PoW filter | Extracted parent headers | Require `sha256d(header) <= target(nBits)` at the header's encoded target. This does not establish Bitcoin's contemporaneous target. | Self-target-PoW-passing candidate parent headers. |
| 4. BTC Core classification | Self-target-PoW-passing headers | `getblockheader(hash)` with positive confirmations -> canonical; otherwise, `getblockheader(prev_hash)` with positive confirmations -> stale-labelled candidate; otherwise -> unknown. A known side-chain header with non-positive confirmations is not treated as canonical. | Full classifier outputs, private archive convention (RSK included). |
| 5. Validation gates | Classified stale/unknown rows | Chain-specific gates such as `validation_status`, active-parent linkage, expected `nBits`, median-time-past, historical minimum block versions, coinbase scriptSig length, BIP34 height, BCH/BSV filters, and stale-descendant ancestry validation. | Compact committed direct-stale loader inputs under `data/validated-stales/` plus `data/stale_descendants.csv`. |
| 6. Full-evidence export | Full classifier inventories, stale-only publication files, stale-descendant sidecar | `scripts/reports/build_auxpow_full_evidence.py`; normalize monitor-facing evidence and record whether canonical rows were retained, absent from the discovered artifact, or not represented by a stale-only source. | Generated `results/full-evidence/*` artifacts and manifest. |
| 7. Cross-source accounting | Upstream rows, per-chain direct stales, and valid stale descendants | Apply the documented loader filters, form the union by `(height, hash)`, and retain merge-mining coinbase evidence as a fallback on upstream duplicates. | Aggregate union counts reported above; no standalone merged artifact is committed. |
| 8. Novelty accounting | Per-chain loaders, upstream rows, activation chronology | `scripts/compute_chain_novelty.py <chain>`. | `results/per-chain-novelty/<chain>.csv`. |
| 9. Analysis diagnostics | Full unknown inventories | Unknown ancestry, H1/H2 origin tests, and stale-fork event construction. | Private archive families documented by `results/analysis/README.md`. |

Mining-pool attribution is a planned later phase. The current public pipeline
retains coinbase evidence where available but does not fetch a pool registry or
emit a pool-attributed stale-event dataset.

The full extraction/classification/reconciliation sequence is not encoded in
the `justfile`; only selected evidence exports are. The public repository
retains a coinbase-marker registry and focused tests, but no standalone
coinbase-census runner. Several chain outputs therefore depend on private
archive conventions documented in the per-chain files and
`results/analysis/README.md`.

## Per-Chain Accounting

The "stage volume" column uses committed data where available and per-chain
documentation for private/archive intermediates. "Novel" means
chronologically novel at that chain's AuxPoW activation position: not in
upstream and not first claimed by any earlier-born integrated chain.

| Chain | Input data | Stage volume | Committed loader input | Novelty | Final outputs and findings |
|---|---|---|---|---:|---|
| Namecoin | Offline Namecoin `blk*.dat` parse from full node on `<archival-host>`. | The historical private classifier contains 466,184 self-target-valid candidates: 456,685 legacy canonical, 1,658 stale-labelled, and 7,841 unknown. These are not a current normalized canonical export. The committed filtered output is 1,625 accepted direct-stale header candidates: 1,353 `VALID` plus 272 `VALID (post-BCH, difficulty matches BTC)`. Thirty-one consensus-invalid candidates are excluded: 21 for BIP34 height, three for BIP66 version, five for BIP65 version, one for median-time-past, and one for coinbase scriptSig length. One further candidate is moved from direct stale to accepted stale descendant. | `data/validated-stales/namecoin_validated_stales.csv` (1,625 rows), `data/stale_block_exclusions.csv`, `data/stale_descendants.csv`, `results/per-chain-novelty/namecoin.csv`. | 0 | Original practical AuxPoW floor from BTC 148,553. All 1,625 accepted direct rows are in effective upstream after the exclusion overlay, so chronological novelty is 0. The 7,841 unknown rows yield 11 strict and 10 weak relevance observations, with no direct-stale promotions. Current canonical coverage requires reclassification against Bitcoin Core. |
| Geistgeld | Archival `getblock` JSON dump shared by Nicholas Stifter. | 7,309,972 streamed records; 2,493,631 AuxPoW-bearing; 2,291 self-target-PoW-passing; 1 canonical, 0 accepted direct-stale candidates, 2,290 unknown. | `data/validated-stales/geistgeld_validated_stales.csv` (0 rows), `results/per-chain-novelty/geistgeld.csv`. | 0 | Zero accepted direct-stale candidates. Early activity used Geistgeld's own experimental, relaxed-difficulty copy of the Durham AuxPoW implementation, not production BTC merge mining. |
| i0coin | Jan 2018 third-party `blk*.dat` snapshot; live network effectively dead. | Private full classifier: 103,383 rows = 16,958 canonical + 176 stale-labelled + 86,249 unknown. The 176 stale-labelled = 167 `VALID` + 9 `nBits`-rejected; one shared post-BIP66 version 2 candidate is then excluded, leaving 166 committed stales. | `data/validated-stales/i0coin_validated_stales.csv` (166 rows), `results/per-chain-novelty/i0coin.csv`. | 37 | Useful but provisional; the committed set is bounded by the January 2018 snapshot. The separate relevance axis contains 2 strict and 0 weak unknown-row observations. |
| ixcoin | Local `ixcoind`/IXCore node; raw-hex AuxPoW parse. | The historical private classifier has 301,260 rows: 46,808 canonical, 478 stale-labelled candidates, and 253,974 unknowns. Thirteen shared consensus-invalid candidates are excluded, leaving 465 publication-gate-accepted direct-stale header candidates. | `data/validated-stales/ixcoin_validated_stales.csv` (465 rows), `results/per-chain-novelty/ixcoin.csv`. | 50 | Large early-chain contribution. The separate relevance axis contains 3 strict and 0 weak unknown-row observations. |
| CoiledCoin | Local `coiledcoind` node built from pre-0.6 lineage with private raw/classifier archive. | Private full classifier: 13,943 rows = 608 canonical + 27 stale + 13,308 unknown. | `data/validated-stales/coiledcoin_validated_stales.csv` (27 rows), `results/per-chain-novelty/coiledcoin.csv`. | 0 | Chain merge-mined to extinction beginning with the Jan 2012 Eligius 51% attack; the recovered parent-block window runs to July 2012. One stale is in the Jan 2012 Eligius attack window. Zero chronologically novel: all 27 are first-claimed by upstream or by ixcoin/namecoin/i0coin. |
| Devcoin | Local `devcoind`; raw-hex AuxPoW parse despite modern codebase. | The historical private classifier has 129,725 rows: 54,100 canonical, 484 stale-labelled candidates, and 75,141 unknowns. Sixteen shared consensus-invalid candidates are excluded, leaving 468 publication-gate-accepted direct-stale header candidates. | `data/validated-stales/devcoin_validated_stales.csv` (468 rows), `results/per-chain-novelty/devcoin.csv`; row-level domain diagnostics remain private. | 32 | Strong early-chain recovery source. Historical H1/H2 analysis rejects broad lost-BTC-deep-reorg interpretation. The separate relevance axis contains 1 strict and 0 weak unknown-row observation. |
| Groupcoin | Complete `getblock` JSON dump shared by Nicholas Stifter. | 235,752 dump records; 218,494 AuxPoW-bearing; 4,868 unique PoW-valid parents; 2,123 canonical, 32 stale, 2,713 unknown; one `nBits` mismatch and one post-BIP66 version 2 row are excluded. | `data/validated-stales/groupcoin_validated_stales.csv` (30 rows), `results/per-chain-novelty/groupcoin.csv`. | 1 | Dead-chain recovery from privately shared archival data. |
| Huntercoin | Arweave `domob1812/arblockstore` archive; SHA-256d branch only. | Raw extractor: 43,288 rows. After the self-target PoW filter: 857 canonical, 13 stale-labelled candidates, and 29 unknown. | `data/validated-stales/huntercoin_validated_stales.csv` (13 rows), `results/per-chain-novelty/huntercoin.csv`; historical pool diagnostics remain private. | 2 | Dead network; archive ends early. A historical unknown-row pool audit supports H2/non-BTC substrate: 0/29 unknown rows carried recognizable BTC pool tags. The current public pipeline does not reproduce that audit. |
| Unobtanium | Local `unobtaniumd`; raw-hex parse from Bitcoin Core 0.11 lineage. | 1,881,845 raw AuxPoW rows; 445,933 self-target-PoW-valid unique headers; 14,958 canonical + 44 stale-labelled candidates + 430,931 unknown. One shared post-BIP66 version 2 candidate is excluded, leaving 43 accepted direct-stale candidates. | `data/validated-stales/unobtanium_validated_stales.csv` (43 rows), `results/per-chain-novelty/unobtanium.csv`; unknown-origin diagnostics remain private. | 3 | One of the longest continuous single-chain AuxPoW scan windows (about 11 years, May 2015 → present); Namecoin's is longer. Historical H1/H2 analysis rejected broad lost-BTC-deep-reorg interpretation. |
| Crown | Local `crownd`; raw-hex AuxPoW parse from a Wayback-recovered live peer. | 1,868,911 AuxPoW commitments over the PoW window; 389,128 self-target-PoW-valid unique headers; 5,483 canonical + 23 accepted direct-stale candidates + 383,622 unknown. | `data/validated-stales/crown_validated_stales.csv` (23 rows), `results/per-chain-novelty/crown.csv`. | 5 | Strict-chain-ID, single-algo SHA-256d recovery. Adds one unique upstream sidecar row because most Crown accepted rows overlap another integrated source. |
| Myriadcoin | Local `myriadcoind`; multi-algo raw-hex parse, SHA-256d branch only. | 2,310,366 blocks scanned; 513,722 SHA-256d AuxPoW-flagged; 181,589 self-target-PoW-valid unique headers; 14,705 canonical + 40 accepted direct-stale candidates + 166,844 unknown. | `data/validated-stales/myriadcoin_validated_stales.csv` (40 rows), `results/per-chain-novelty/myriadcoin.csv`. | 2 | First multi-algo integration. Demonstrates nVersion algo filtering before AuxPoW parsing. |
| Argentum | Local `argentumd`; multi-algo SHA-256d branch. | 1,290,127 raw SHA-256d-AuxPoW rows; 634,306 self-target-PoW-valid unique headers; 27 canonical + 2 accepted direct-stale candidates + 634,277 unknown. | `data/validated-stales/argentum_validated_stales.csv` (2 rows), `results/per-chain-novelty/argentum.csv`. | 0 | Sparse Bitcoin-parent evidence: 29 canonical or accepted observations against 634,277 unknowns. This ratio is not a hashrate estimate. |
| Terracoin | Local `terracoind`; Dash-derived JSON AuxPoW. | 2,368,318 AuxPoW-bearing blocks of 2,369,590 scanned; 534,607 self-target-PoW-valid intermediate rows; 11,257 canonical + 35 accepted direct-stale candidates + 523,315 unknown. | `data/validated-stales/terracoin_validated_stales.csv` (35 rows), `results/per-chain-novelty/terracoin.csv`; unknown-origin diagnostics remain private. | 0 | 99.95% AuxPoW density, second only to Bitcoin Vault's. Historical H1/H2 analysis rejected broad lost-BTC-deep-reorg interpretation; 22/22 Namecoin cross-confirmed unknown roots do not match Bitcoin's expected target epoch. |
| Emercoin | Local `emercoind`; hybrid PoW/PoS; RPC JSON exposes AuxPoW. | 570,365 post-MMHeight blocks scanned; 482,164 PoS/no-AuxPoW filtered out; 88,201 raw AuxPoW rows; 62,237 self-target-PoW-valid unique headers; 96 VALID direct-stale candidates after the 2026-06-24 canonical-refresh re-run (refresh split: 45,595 canonical + 97 stale-labelled + 16,545 unknown; the original 2026-05 run recorded 45,599 canonical + 93 stale-labelled + 16,545 unknown - the refresh reclassified 4 side-chain headers canonical to stale); canonical-at-height `nBits` validation filters stale candidates before commit. | `data/validated-stales/emercoin_validated_stales.csv` (96 rows), `results/per-chain-novelty/emercoin.csv`. | 29 | First hybrid PoW/PoS chain. |
| RSK | RSKj Vetiver 9.0.1 archive node; Ethereum-style JSON-RPC; canonical blocks plus uncles. | The historical private classifier has 37,335 rows: 304 stale-labelled candidates plus 37,031 legacy `orphan` rows read as unknown. Five candidates shared with Namecoin are excluded as invalid and one is moved to the stale-descendant sidecar, leaving 298 publication-gate-accepted direct-stale header candidates: 80 from canonical RSK blocks plus 218 from uncles/ommers. RSK cannot independently apply the coinbase scriptSig length or BIP34-prefix checks. | `data/validated-stales/rsk_validated_stales.csv` (298 rows; shared validated-stales layout plus RSK evidence columns), `results/per-chain-novelty/rsk.csv`. | 117 | Extraction starts at child height 139,999 even though earlier full-header proofs exist. No consolidated canonical export is available. Three strict observations inherit globally strongest verdicts from matching coinbase-bearing chains. |
| Bitmark | Synced Bitmark node/private raw archive; multi-algo SHA-256d subset. | 1,926,463 blocks scanned; 255,538 SHA-256d AuxPoW blocks; 82,819 self-target-PoW-valid unique headers; 897 canonical, 1 accepted direct-stale candidate, 81,921 unknown. | `data/validated-stales/bitmark_validated_stales.csv` (1 row), `results/per-chain-novelty/bitmark.csv`. | 0 | Cross-confirmation only; the accepted row is already present in Unobtanium/Myriadcoin/RSK. The integrated loader includes Bitmark; unique-count impact is zero. |
| Xaya | Offline `blocks.zip` snapshot (2024-11-15) from Xaya's open CDN; legacy P2P network dead, so no live node. Custom extractor parses the `PowData` block-header wrapper; CAuxPow tail is standard Namecoin. | 6,344,114 blocks scanned; 1,695,912 SHA256D merge-mined; 38,483 self-target-PoW-valid unique parents; 40 VALID direct-stale candidates after the 2026-06-24 canonical-refresh re-run (the original run recorded 34 stale-labelled candidates + 17,642 unknown + 20,807 canonical); canonical-at-height `nBits` validation filters stale candidates before commit (0 rejected). | `data/validated-stales/xaya_validated_stales.csv` (40 rows), `results/per-chain-novelty/xaya.csv`. | 0 | A historical private attribution pass was F2Pool-dominated; the public pipeline does not reproduce that result. 0 chronologically novel: every accepted row is first-claimed by upstream or an earlier chain. Full unknown inventory not yet folded into reconciliation; the snapshot tail to Xaya's ~7.3M deprecation height is a documented coverage gap. |
| Elastos | Hybrid extraction: local ELA node plus public `api.elastos.io/ela` tail. | 2,018,508 extracted rows produced 184,235 unique self-target-valid headers. The 2026-07-18 refresh split these into 175,078 canonical, 154 direct-stale candidates, and 9,003 unknown. The shared publication gate accepted 153 direct stales and rejected one candidate whose `nBits` did not match Bitcoin at its decoded height. | `data/validated-stales/elastos_validated_stales.csv` (153 rows), `results/per-chain-novelty/elastos.csv`. | 25 | Go node, not Bitcoin Core. The accepted rows span 2019-04-19 through 2026-01-31 UTC; all 153 carry `validation_status=VALID`. The consolidated canonical export remains private. Unknown parent-chain origin remains unresolved. |
| Syscoin | Local `syscoind` v5.0.5; decoded AuxPoW JSON. | Private full classifier: 116,994 rows = 98,634 canonical (backfilled by the 2026-07-18 refresh) + 79 stale + 18,281 unknown; canonical-at-height `nBits` validation filters stale candidates before commit (79 → 78). | `data/validated-stales/syscoin_validated_stales.csv` (78 rows), `results/per-chain-novelty/syscoin.csv`. | 1 | Clean modern JSON extraction. The separate relevance axis contains 1 strict and 0 weak unknown-row observation. |
| Bitcoin Vault | Trezor Blockbook REST `/api/rawblock/<hash>`; no node. | Original private run: 169,939 AuxPoW commitments, 2,575 self-target-PoW-valid headers, 2,567 canonical, 8 stale-labelled candidates, 0 unknown. The June 2026 refresh added one already-upstream candidate to the committed accepted set. | `data/validated-stales/bitcoin-vault_validated_stales.csv` (9 rows), `results/per-chain-novelty/bitcoin-vault.csv`. | 6 | First no-node recovery path. Post-2021 Binance era is weak-share-only and yields no further accepted direct-stale candidates. |
| Hathor | Public REST API; joining the mainnet P2P network requires allowlisting. | 147,216 self-target-valid reconstructed headers: 3,612 with canonical Bitcoin predecessor linkage and 143,604 unresolved. The linked set contains 3,606 canonical and 6 stale-labelled candidates. `nBits`, minimum-version, and BIP34 validation gate; all 6 candidates are `VALID`. | `data/validated-stales/hathor_validated_stales.csv` (6 rows), `results/per-chain-novelty/hathor.csv`. `load_hathor_stales()` wired. | 0 | Integrated. RFC-0006 split-header reconstruction required a three-part byte-order correction. The unresolved population is not identified as BCH and is not available for strict/weak assessment. 0 chronologically novel. |
| Fractal Bitcoin | `fractald` v0.3.0 archival node; compact `getblockheader <hash> false true` extraction. | Historical 2026-05-29 run: 1,807,154 FB blocks scanned; 1,205,394 non-merge-mined blocks skipped; 601,760 AuxPoW rows; 0 parse errors. The 2026-07-18 reclassification materialized 59,504 self-target-PoW-valid unique parent headers: 58,980 canonical, 31 stale-labelled candidates, and 493 unknown, with 0 rejected stale rows. | `data/validated-stales/fractal_validated_stales.csv` (31 rows), `results/per-chain-novelty/fractal.csv`. | 1 | Integrated. The consolidated canonical export remains private. The extractor requires the AuxPoW flag plus chain ID `0x2024`; a generic `0x100` test would falsely select the `0x20260100` Indexer class. Adds one net-new upstream sidecar row at BTC height 928,455. |
| Electric Cash | Self-synced `elcashd` node; standard Namecoin-style CAuxPow under a Bitcoin Core 0.20.2 codebase. | Fresh-genesis Dec 2020 chain; 2,429 classified unique parents: 2,426 canonical, 3 stale-labelled candidates, no unknown rows; all 3 VALID (Jun-Sep 2021, all first-claimed by Bitcoin Vault). | `data/validated-stales/elcash_validated_stales.csv` (3 rows), `results/per-chain-novelty/elcash.csv`. | 0 | Zombie chain still merge-mined at negligible hashrate (real-difficulty wins ceased Nov 2024); see `docs/chains/elcash.md`. |
| Catalogued-source recoveries ([Lyncoin](chains/lyncoin.md), [SixEleven](chains/sixeleven.md), [Doichain](chains/doichain.md)) | Lyncoin: live-peer raw P2P extended-header capture. SixEleven: pinned official node synced from six peers, followed by a complete legacy `blkNNNN.dat` scan with RPC identity validation. Doichain: pinned-source node and `blkNNNN.dat` survey through the active-chain tip observed at height 430,684. | Lyncoin: 56,653 self-target-PoW candidates -> 11 canonical, 0 stale, 0 strict, 0 weak. SixEleven: 80,364 candidates -> 7 canonical, 0 stale, 0 strict, 0 weak. Doichain: 429,401 commitments, including 300,625 canonical-tip rows independently confirmed against exact Bitcoin `nBits` and BIP34 height -> 0 accepted direct stale, 0 strict, 0 weak. | `results/monitor-evidence/{lyncoin,sixeleven,doichain}_monitor_evidence.csv`, header-only `data/validated-stales/{lyncoin,sixeleven,doichain}_validated_stales.csv`, and `results/strict-weak-orphans/{lyncoin,sixeleven,doichain}_strict_weak_orphans.csv`. | 0 | Complete scoped negative stale result for all three recovered windows. Lyncoin and SixEleven publish canonical Monitor rows; Doichain has aggregate-only canonical characterization. |
| VCash canonical subset | Private explorer archive containing 767 VCash-to-Bitcoin mappings; Bitcoin Core hydration recovered 68 canonical parents. | 68 canonical rows. No VCash blockchain was recovered and 699 mappings remain unresolved, so stale and strict/weak totals are not established. | `results/monitor-evidence/vcash_monitor_evidence.csv`. | Not applicable | Canonical-only partial Monitor evidence, not a complete VCash recovery or a zero-stale result. |

## Final Artifacts

Canonical/public loader inputs:

- `data/validated-stales/*_validated_stales.csv` for direct-stale chain inputs (RSK included,
  with its miner-evidence and historical-label columns appended to the shared
  validated-stales layout).
- `data/stale_descendants.csv` for publication-gate-accepted stale-fork
  continuation headers.
- `results/strict-weak-orphans/<chain>_strict_weak_orphans.csv` for the
  per-chain strict/weak BTC-orphan verdicts (one row per admitted
  unknown-row observation; the same header observed by several chains
  appears in each observer's file with the per-header verdict; header-only
  when a complete-coverage chain has none; canonical-only partial sources are
  omitted), plus the bucket-count summary in the same
  directory. Currently 21 unique strict/weak headers observed 34 times
  across 7 chains.
- `results/monitor-evidence/<chain>_monitor_evidence.csv` plus its counts and
  manifest: the committed, compact exports the merge-mining-monitor ingests
  (canonical + publication-gate-accepted direct-stale candidates + accepted
  descendants + strict/weak orphans). The manifest records that `VALID` is not
  a full-block consensus-validity assertion.

Per-chain outputs:

- `docs/chains/<chain>.md` for provenance, methodology, stage counts, findings,
  and remaining work.
- `results/per-chain-novelty/<chain>.csv` for row-level upstream and
  chronological novelty fields.

Analysis diagnostics are retained in the private archive under the namespace
documented by `results/analysis/README.md`: stale ancestry, H1/H2 unknown
origin, and candidate multi-block header-chain reconstruction.
Generated monitor evidence:

- `results/full-evidence/<chain>_evidence.csv` for normalized per-chain
  candidate rows when source files are available.
- `results/full-evidence/auxpow-full-evidence-counts.csv` and
  `results/full-evidence/auxpow-full-evidence-manifest.*` for per-source counts
  and canonical-retention status. These outputs are regenerated on demand and
  are ignored by git because private archive runs can include bulky full
  inventories.

## Issues Found and Resolved in This Pass

1. **`nBits`-mismatched committed validated rows.** Canonical-at-height
   `nBits` validation is now shared by the Emercoin, Syscoin, and Groupcoin
   classifiers. Rows that fail the check are excluded from committed validated
   CSVs and downstream novelty/sidecar outputs.

2. **Historical publication-gate gaps.** The audit found one candidate that
   violates median-time-past, one with a 103-byte coinbase scriptSig, and one
   whose predecessor is stale rather than active. The first two join 29 earlier
   consensus-invalid exclusions. The third remains accepted as a stale
   descendant but is removed from every direct-stale loader input. The shared
   classifiers now fail closed on active-parent context and enforce
   median-time-past plus coinbase scriptSig length when that evidence exists.

3. **Hathor reconstruction (resolved).** The classifier reconstructs the BTC
   header per RFC 0006: `aux_block_hash = SHA256d(SHA256(block_funds) ||
   SHA256(block_graph))` embedded in display order in the BTC coinbase, merkle
   path links byte-reversed before folding; the Hathor block hash equals the
   reconstructed BTC header hash. The first-draft algorithm (and the legacy
   `verify_hathor_extraction.py`, which checks only `prev_hash`) embedded the
   wrong value - the fix was confirmed by `SHA256d(header) == tx_id` on 50/50
   sampled blocks. See `docs/chains/hathor.md` §2.

4. **Pending-upstream sidecar drift.** `data/new_stale_blocks_for_upstream.csv`
   was regenerated from current committed inputs against the bumped upstream
   pin (which already includes the project's earlier 1,089-row Namecoin
   addition).
   It now has 328 rows: 311 first-claimed direct upstream-new stale rows and
   17 upstream-new stale descendants.

5. **Bitmark integration.** Bitmark is wired into the recovery loader and
   novelty paths. Its single stale remains an exact
   overlap, so unique counts are unchanged.

6. **Classifier-path drift.** `classify_rsk_stales.py` defaults to the
   committed RSK output paths and exposes path overrides.

7. **Missing rejection artifacts.** Elastos and Namecoin docs now identify
   their rejection CSVs as private/ignored archive evidence rather than
   committed in-repo artifacts. Cross-chain `nBits` failures are not retained
   as committed rows; the publication boundary is the validated loader CSV.

8. **README and terminology drift.** README dependency/layout claims were
   refreshed, and project docs now use `artifacts` consistently.

## Pending and Deferred Work

These entries should not be counted as new integrated-result claims until a
validated CSV or superseding refresh exists.

| Chain | Current state |
|---|---|
| i0coin | Current result is bounded by a January 2018 third-party snapshot; no fuller i0coin history has been obtained, so the committed counts are provisional. |
| Jincoin | Source builds, but live sync/private block archive path is not available. |
| Blast | Surveyed only; no peers/archive result. |

## Regeneration Order

Use this order when moving from this audit snapshot to final resources:

1. Recompute per-chain novelty CSVs for any newly integrated chain and any
   earlier-chain attribution that would change if i0coin is ever re-extracted
   from a fuller history.
2. Regenerate `data/new_stale_blocks_for_upstream.csv` from committed inputs.
3. Re-run `scripts/analysis/reconcile_unknown_stale_ancestry.py` if the known-stale set
   changes and the private full classifier inventories are mounted, then rerun
   the consensus rejection audit if the sidecar changes.
4. Refresh `docs/auxpow-recovery.md`, per-chain docs, README output claims,
   and this overview.
