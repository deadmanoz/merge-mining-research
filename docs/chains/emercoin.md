# Emercoin

| Field | Value |
|---|---|
| Ticker | EMC |
| AuxPoW activation | 2017-03-17 (EMC height 219,809; block timestamp 1489767965 UTC; `consensus.MMHeight` in `src/chainparams.cpp:158`) |
| Network status | Active (hybrid PoW/PoS, Peercoin lineage; DNS seed `seed.emercoin.com` healthy) |
| Chronological position | 15 of 26 (after terracoin; before rsk) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; Emercoin merge-mined inside the paper's window from 2017-03 but was not a sampled data source) |
| AuxPoW chain ID | `666` (`0x29A`), enforced via raw conditional at `src/pow.cpp:173` (`pblock->GetChainID() != AUXPOW_CHAIN_ID` rejected). No `fStrictChainId` flag - strict-chain-ID semantics are hard-coded. |
| Consensus model | Hybrid PoW/PoS. Only PoW blocks carry the AuxPoW commitment; PoS blocks have none. `IsProofOfStake()` predicate at `src/chain.h:211` reads `nFlags & BLOCK_PROOF_OF_STAKE` (bit 0). Measured PoW share over the post-MMHeight window: **15.5 %**. |
| PoW algorithm | SHA-256d (single-algo; not multi-algo like Myriadcoin/Argentum). |
| Block time | ~600 s combined; PoW spacing depends on PoS density between PoW blocks (`nTargetSpacingMax = 12 * nStakeTargetSpacing`, capped at 2 h). |
| Source tag (in code) | `emercoin` |
| Loader | `load_emercoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/emercoin_validated_stales.csv` |

Emercoin is the **first hybrid PoW/PoS chain in the integrated pipeline**. What it adds methodologically is the PoS filter - the node validates both branches, but only PoW blocks embed a Bitcoin-parent AuxPoW commitment, so the extractor must drop the PoS majority (~85 % of post-MMHeight blocks) before attempting to read the parent header. The filter pattern is reusable for any future Peercoin-lineage hybrid chain. With **96 committed accepted direct-stale candidates (40 new-to-upstream at the bumped upstream pin, 29 chronologically novel; the 2026-06-24 canonical-refresh re-run added 4 - the original 2026-05 run committed 93, trimmed to 92 by the `nBits` gate)** over a coverage window from May 2017 to February 2023, the chain delivered roughly **14.5× the chronologically-novel count of Myriadcoin** despite its low PoW share - the long BTC-mainchain time window (six years straddling the BCH and BSV forks) and the still-mostly-distinct miner substrate explain the strong novelty.

## 1. Chain data

**Source.** Local `emercoind` node on `<archival-host>`, built from `emercoin/emercoin` master (last upstream commit 2026-05-01) inside a Docker container with `ubuntu:20.04` base. Emercoin Core is a **Bitcoin Core 0.19-lineage fork** (`configure.ac` declares 0.19.2; the project versions itself Emercoin 0.8.x) with Peercoin's PoS layer grafted on top (`READWRITEAS`-era serialisation, `std::shared_ptr<CAuxPow>`). Three non-obvious build steps were needed and are documented in the Dockerfile:

1. **Drop `--disable-wallet`** - `src/init.cpp:70` includes `<wallet/wallet.h>` unconditionally (outside any `ENABLE_WALLET` guard), so wallet headers - and therefore BDB 4.8 - are required at compile time even with `--disable-wallet`. We disable the wallet at *runtime* via `disablewallet=1` in `emercoin.conf` instead.
2. **Build BDB 4.8 via `contrib/install_db4.sh`** - patched to use `/usr/share/misc/config.{guess,sub}` from `autotools-dev` because `git.savannah.gnu.org/gitweb` (the script's upstream source for those files) was unreachable at scaffold time.
3. **`make -C src emercoind emercoin-cli` only** - the `emercoin-tx` and `emercoin-wallet` targets fail to link with `undefined reference to GetMinFee(unsigned long)`. The free function lives in `src/policy/feerate.cpp`, which `src/Makefile.am` compiles into `libbitcoin_common.a`; `primitives/transaction.cpp` in `libbitcoin_consensus.a` calls it, and both utilities' link lines list the consensus lib *after* common, so a single-pass static linker cannot resolve the consensus-to-common back-reference. Emercoin source defect; neither binary is needed for IBD or AuxPoW extraction.

See `node-infra/emercoin/Dockerfile` for the multi-stage build.

**Provenance.** Docker scaffold at `node-infra/emercoin/`. P2P sync via the chain's healthy DNS seed (`seed.emercoin.com`, 5 IPs at scaffold time) - peers.list preseeded with the resolved IPs as fallback. IBD from a cold start to chain tip 790,173 completed in approximately five minutes on `<archival-host>` (the chain is only ~790 k blocks total - the hybrid PoW/PoS spacing keeps the block count modest despite ~12.5 years of operation since the 2013-12-09 genesis). Bitcoin Core on `<archival-host>` provided the BTC RPC for classification.

**Coverage.** Validated stales span BTC heights **467,186 → 777,172** (May 2017 → February 2023) and EMC heights **231,992 → 587,578**. The window straddles the **BCH** fork (Aug 2017, BTC ~478,558) and the **BSV** split (Nov 2018; the split happened at height 556,766 of the *BCH* chain - BTC itself was near 551,000 that day) - relevant to the unknown-count breakdown below. The chain itself continues to produce blocks (current tip 790,173 as of 2026-05-16), and merged mining continued past the last validated stale - the 2026-06-26 tail re-scan found 668 further AuxPoW parents that are canonical BTC blocks. The Feb 2023 cutoff coincides with ViaBTC's public EMC merged-mining offering (launched 2018-05-20) going offline on 2023-03-03, and the residual tail's stale arithmetic makes zero further recoveries unremarkable (see Holes).

**Holes.**

- **Pre-AuxPoW** (EMC 0 → 219,808): merged mining not yet active. Activation at EMC 219,809 per `consensus.MMHeight` in `src/chainparams.cpp:158`; the block was mined on 2017-03-17.
- **Hybrid PoW/PoS**: 482,164 of the 570,365 post-MMHeight EMC blocks scanned are PoS (no AuxPoW commitment) and were filtered at extraction time. The PoW share is 15.5 %.
- **Post-Feb 2023 silence**: extraction ran to EMC chain tip 790,173 but the latest validated stale is at BTC 777,172 (2023-02-18). 88,201 PoW blocks across the full window had AuxPoW parents; 93 of those parents were stale-classified, 92 remained after `nBits` validation in the original run, and the 2026-06-24 canonical-refresh re-run raises the committed count to 96 (mechanism in §2). A follow-up re-scan on 2026-06-26 covered the tail window EMC 587,579 to 797,184 (34,255 AuxPoW parents: 668 canonical BTC blocks, 23,894 BCH/BSV-parent contamination, 9,693 sub-BTC-difficulty shares, zero new stales; the stock emercoin classifier's BCH/BSV coinbase-height parse misfires on this gap data, so the tail split was derived with an era-aware discriminator instead). The tail's 668 parents fully met BTC difficulty, so merged mining continued after Feb 2023 at reduced scale; a recovered stale additionally requires the pool to win a real BTC block that then loses a propagation race, and at 668 canonical parents over ~3 years the expected stale count is below one - a zero-stale tail is the base-rate outcome, not evidence that merged mining stopped.
- **No `fStrictChainId` flag**: Emercoin performs its chain-ID check via a raw conditional at `src/pow.cpp:173`, not via a chainparams flag. This is analogous to the usual strict-chain-ID check, which prevents same-chain AuxPoW but does not establish that the parent is Bitcoin.
- **High unknown count**: 16,545 unknown rows (vs only 96 committed stales). The window straddles BCH (Aug 2017) and BSV (Nov 2018), and merge-mining pools that pointed EMC AuxPoW at BCH/BSV parents instead of BTC would surface here as deep forks from BTC's view. The relative unknown:stale ratio (~172:1) is much higher than Namecoin's (~5:1) because Namecoin pre-dates the BCH/BSV forks; Emercoin's coverage is entirely post-fork.

**Reference scripts.**

- `scripts/extract/extract_emercoin_auxpow.py:1` - RPC JSON `getblock` (Emercoin's RPC exposes the full `auxpow` object as structured JSON; no binary CAuxPow parse needed). Filters PoS via the `flags` field and reconstructs the 80-byte BTC parent header from the `auxpow.parent_block` JSON object, with a sha256d sanity check.
- `scripts/classify/classify_emercoin_stales.py:1` - BTC RPC batch classifier (PoW filter + `getblockheader` lookups). Adapted from `classify_huntercoin_stales.py`: it drops huntercoin's `chain_id` pre-filter (Emercoin's raw extract has no `chain_id` column) but is otherwise the same thin wrapper over the shared `run_classifier` driver.
- `node-infra/emercoin/{Dockerfile,docker-compose.yml,init.sh,justfile,peers.list,README.md}` - build infrastructure.

## 2. Extraction → potential stales

**Method.** RPC JSON against the local emercoind. For each EMC block ≥ 219,809, fetch `getblock <hash>` (verbose) and inspect the JSON. First check `flags` - skip if not `"proof-of-work"`. Then check for an `auxpow` field; skip if absent (PoW block without an AuxPoW commitment - rare in practice). Then read the BTC parent header fields directly from `auxpow.parent_block` (`hash`, `previousblockhash`, `merkleroot`, `time`, `bits`, `nonce`, `version`) and the parent coinbase tx from `auxpow.coinbasetx`. Reconstruct the 80-byte BTC header bytes for the downstream PoW filter, with a sha256d sanity check against the reported `parent_block.hash`.

**Phases.**

1. **PoS filter at extraction**: walk all EMC blocks ≥ 219,809 via JSON-RPC; skip blocks where `flags != "proof-of-work"`. This is the non-negotiable filter - PoS blocks have no AuxPoW commitment and a naive iterator would surface garbage rows or fail to parse. ~85 % of post-MMHeight blocks drop here.
2. **AuxPoW-present filter**: of remaining PoW blocks, skip those without an `auxpow` field (rare - early-activation gradient and a handful of solo-mined PoW blocks).
3. **Parent-header reconstruction**: rebuild the 80-byte BTC header from the JSON fields (`version` LE, `previousblockhash` LE-reversed, `merkleroot` LE-reversed, `time`/`bits`/`nonce` LE) and verify SHA256d matches `parent_block.hash`. Mismatch is a hard error (would indicate a JSON-field interpretation bug); zero mismatches occurred across the 88,201-row extraction.
4. **Self-target PoW filter** (in `classify_emercoin_stales.py`): keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. This does not establish Bitcoin's contemporaneous target.
5. **Dedup**: do *not* dedup at extraction time. Consecutive EMC PoW blocks can reference the same parent context. Dedup is implicit downstream in the classifier, yielding 62,237 unique self-target-PoW-valid hashes from 88,201 raw rows.
6. **BTC RPC classify**: batched `getblockheader` JSON-RPC via the shared `run_classifier` driver. Active-chain hit → `canonical`. Side-chain hit (`confirmations=-1`) → `stale` (the header is a Bitcoin block the node knows but that lost out - the distinction the original prototype lacked; see the refresh note below). Unknown header whose `prev_hash` is canonical → `stale`. Neither → `unknown`.

**Counts:**

| Stage | Rows |
|---|---:|
| EMC blocks scanned (219,809 → 790,173) | 570,365 |
| PoS filtered out (`flags == "proof-of-stake"`) + no AuxPoW | 482,164 (84.5 %) |
| Raw AuxPoW rows extracted | 88,201 (15.5 %) |
| Parse errors / header-reconstruction mismatches | 0 |
| After self-target PoW filter (unique) | 62,237 (70.6 % of raw) |
| After classification (original run) | **45,599 canonical + 93 stale-classified (92 committed) + 16,545 unknown** |
| After classification (2026-06-24 refresh) | **45,595 canonical + 97 stale-classified (96 committed) + 16,545 unknown** |

The 70.6 % PoW pass-rate is much higher than Myriadcoin's (35 %) - Emercoin's PoW blocks target a higher difficulty (single-algo, ~10-minute spacing), so most parents already meet a substantial fraction of BTC's target.

The 2026-06-24 canonical-refresh re-run reclassified the same archived 88,201-row extract with the side-chain-aware shared classifier. The original prototype treated any `getblockheader` hit as canonical; four of those hits (BTC 648,790, 656,477, 694,157, 714,637) are in fact Bitcoin Core side-chain headers (`confirmations=-1`) - real stale blocks the first pass silently filed as canonical. The refresh therefore moves exactly 4 headers canonical → stale (canonical 45,599 → 45,595; stale-classified 93 → 97, of which 96 pass validation - the BTC 717,696 `nBits` rejection stands), leaving the 16,545 unknowns and the 62,237 total unchanged. The original 92-row committed set is a strict subset of the refreshed 96.

**Chain-specific quirks.**

- **Hybrid PoW/PoS**: the defining methodological feature. The PoS filter via the RPC `flags` field is the gate; without it the extractor would fail or produce garbage on the PoS majority. This is the first chain in the pipeline with a non-PoW majority - the filter pattern is reusable for any future Peercoin-lineage hybrid (Reddcoin, Blackcoin, etc., if any of those ever shipped Bitcoin-parent AuxPoW).
- **JSON-exposed AuxPoW**: unlike Namecoin/ixcoin/devcoin/myriadcoin/elastos (binary CAuxPow blob parse), Emercoin's RPC exposes the full `auxpow` object as structured JSON - `parent_block.{hash, version, previousblockhash, merkleroot, time, bits, nonce}` plus decoded `coinbasetx`. No binary parser needed; the extractor reconstructs the 80-byte BTC header bytes from the JSON for the downstream PoW filter and validates via SHA256d hash match.
- **Chain ID via raw conditional**: `src/pow.cpp:173` performs the AuxPoW chain-ID check inline rather than through a chainparams flag. Like the standard strict-chain-ID rule, this does not prove Bitcoin parent identity; it prevents a parent header from using the auxiliary chain's own ID.
- **Six-year coverage straddling BCH and BSV forks**: BTC range 467,186 → 777,172 covers May 2017 → Feb 2023, which includes the BCH fork (Aug 2017, BTC ~478,558) and the BSV split (Nov 2018). The 16,545-row unknown count is largely BCH/BSV-parent pollution - pools that merge-mined EMC against those forks would surface in the BTC node's view as headers whose `prev_hash` isn't on mainchain. The relative unknown:stale ratio (~172:1 against the 96 committed stales) is much higher than older chains' for this reason.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_emercoin_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status.startswith("VALID")
```

The loader delegates to the shared `load_auxpow_validated_stales()`, which also applies the exact-key error-blocks gate (`data/error-blocks/error_blocks.csv`) and the `min_height` floor (inert here - Emercoin's minimum BTC height 467,186 sits above the default floor, so the loader returns 96 rows either way). It parses `coinbase_outputs` as raw pkscript hex semicolon-joined (matches myriadcoin/i0coin/ixcoin/elastos format). The extractor preserves the parent-coinbase outputs verbatim without address decoding so they remain available for later attribution research. 96 entries pass the committed validation filter (2026-06-24 refresh; 92 in the original run). One stale-classified row at BTC height 717,696 is rejected because its encoded `btc_bits` (`170b98ab`) does not match Bitcoin's canonical bits (`170b8c8b`) - the same header Syscoin's candidate set independently surfaces and rejects at the same height.

**Post-filter count: 96 accepted direct-stale header candidates (2026-06-24 refresh).**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py emercoin`. Per-stale row-level breakdown at `results/per-chain-novelty/emercoin.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 56 | 58.3 % |
| novel vs upstream | 40 | 41.7 % |

The 40-novel-vs-upstream figure is Emercoin's count of accepted direct-stale
candidates missing from the upstream dataset - well ahead of Myriadcoin's 24
and Terracoin's 22 because the longer BCH/BSV-era coverage window contributes
more accepted candidates absent from upstream.

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Emercoin is 15th chronologically. Earlier-born integrated chains: namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven, argentum, terracoin.

| Split | Count |
|---|---:|
| also in upstream | 56 |
| also in earlier-born chain (`namecoin`: 34, `devcoin`: 5, `crown`: 4, `i0coin`: 3, `myriadcoin`: 2 - first-claim distribution) | 48 |
| **novel at this position** | **29** |

The 48 earlier-chain-claimed stales reflect the same SHA-256d miner substrate that Namecoin (mostly) and the older chains had already been recording - Namecoin alone claims 34 of Emercoin's 96 committed candidates chronologically. The **29 chronologically novel hashes** are genuinely new-to-the-multi-chain-set contributions at Emercoin's position, **14.5× Myriadcoin's chronologically-novel count** of 2. This is the substantive payoff despite the low PoW share - the long coverage window and the BCH/BSV-era miner population diversity matter more than per-block AuxPoW density.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/emercoin_validated_stales.csv` - 96 accepted direct-stale candidates
  (committed; the loader's refreshed input; 92 in the original run).
- `results/per-chain-novelty/emercoin.csv` - per-stale `(height, hash, in_upstream, first_seen_chain)` table.
- `node-infra/emercoin/{Dockerfile,docker-compose.yml,init.sh,justfile,peers.list,README.md}` - build infrastructure.

**Private archive artifacts.**

- Split inventories (2026-06-24 refresh state): `emercoin_canonical_blocks.csv` (45,595 canonical; the original run archived no canonical file - the refresh backfilled it), `emercoin_stale_blocks.csv` (97 stale-classified: 96 VALID plus the BTC 717,696 `nBits` rejection), and `emercoin_unknown_blocks.csv` (16,545 unknown) - reconciling to the 62,237 self-target-PoW-valid total.
- `emercoin_auxpow_raw.csv` - 88,201 raw AuxPoW rows (extractor output, pre-PoW-filter).
- `emercoin_gap_stale_blocks.csv` - the 2026-06-26 tail re-scan's 668 canonical parent rows (EMC 587,579 onward).

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (Emercoin row).
- Emercoin upstream: `github.com/emercoin/emercoin` (last commit 2026-05-01).
- Public explorer: `explorer.emercoin.com` - alive but uses a non-standard API (`Unknown API call` for the usual iquidus-style endpoints); tip-height sanity is via the running node directly.

**Methodological note.**

Emercoin is the first hybrid PoW/PoS chain in the pipeline. The PoS-filter pattern (read the RPC `flags` field and skip `"proof-of-stake"` blocks before any AuxPoW handling) is reusable for any future Peercoin-lineage hybrid. The filter is a single conditional in the extractor: skip any block whose RPC `flags` field is not `"proof-of-work"`. The economic implication of hybrid consensus - a 15 % PoW share means roughly 15 % of the per-block AuxPoW yield of a pure-PoW chain of equivalent length - is significant for forward planning: a 790 k-block hybrid chain delivers AuxPoW-extractable data comparable to a 120 k-block pure-PoW chain, not the full 790 k.

## 5. Integration history

- **2026-05-15** - Discovery brief (Tier-3 candidate; a "~15 % PoW" prior later confirmed by measurement at 15.5 %).
- **2026-05-16** - Original recovery: Docker scaffold and build, ~5-minute IBD to tip 790,173, the 88,201-row extraction, classification, and same-day integration of 93 validated stales (pre-`nBits`-gate schema).
- **2026-05-19/20** - The expected-`nBits` contamination gate lands; the BTC 717,696 candidate is rejected (`170b98ab` vs canonical `170b8c8b`) and the committed set goes 93 → 92.
- **2026-06-24** - Canonical-refresh re-run of the archived extract with the side-chain-aware shared classifier: 4 headers the prototype had filed as canonical are Bitcoin Core side-chain headers (`confirmations=-1`) and reclassify to stale; committed set 92 → 96, canonical 45,599 → 45,595 (§2).
- **2026-06-26** - Tail re-scan EMC 587,579 → 797,184: 34,255 AuxPoW parents, 668 canonical BTC blocks, zero new stales (§1 Holes).
- **2026-07** - Publication: the 96-row refresh CSV becomes the committed loader input, and the upstream pin bump absorbs previously-novel rows (novel-vs-upstream 63 → 40).
- **2026-07-22** - Terracoin's activation re-date (2016-09-23, hard fork 1) flips the chronological order: Emercoin moves back one position. SixEleven's integration places it 15th of 26 in the current registry.
