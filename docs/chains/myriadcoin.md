# Myriadcoin

| Field | Value |
|---|---|
| Ticker | XMY (legacy MYR) |
| AuxPoW activation | 2015-09-26 (XMY height 1,402,000; block timestamp 1443262763 UTC) |
| Network status | Active (multi-algo PoW; SHA-256d branch is one of five; DNS seeds healthy) |
| Chronological position | 11 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown; before SixEleven) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; in-window from 2015-09 but not a sampled data source) |
| AuxPoW chain ID | `90` (`0x005A`), **`fStrictChainId=false`**. The SHA-256d branch accepts AuxPoW from any SHA-256d parent; parent identity is established downstream, not by the Phase 1 PoW filter. |
| Algorithms | 5 active (SHA-256d, Scrypt, Groestl, Yescrypt, Argon2d). The original set had **Qubit and Skein** in two of the slots; two separate hard forks replaced them - Yescrypt for Qubit at XMY 1,764,000 (`nFork1MinBlock`, Aug 2016) and Argon2d for Skein at XMY 2,772,000 (`nFork2MinBlock`, ~2019, MIP4). The `nVersion` algo enum kept the legacy slots, so `NUM_ALGOS_IMPL=7` but `NUM_ALGOS=5`. |
| Algo encoding (in `nVersion`) | Bits 9–11 (`BLOCK_VERSION_ALGO = 7 << 9`). SHA-256d = `0` (no bits set). AuxPoW flag = bit 8 (`VERSION_AUXPOW = 1 << 8`). Chain ID at bits 16+ (`VERSION_CHAIN_START = 1 << 16`). |
| Block time | ~60 s combined across 5 algos (`nPowTargetSpacingV2 = 60`); ~300 s per-algo (SHA-256d branch contributes roughly 1/5 of total block production). MIP3 "longblocks" later raised the combined target: 2 min from XMY 2,903,040 (inside the coverage window's tail), 4 min from 3,386,880, 8 min from 3,628,800. |
| Source tag (in code) | `myriadcoin` |
| Loader | `load_myriadcoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/myriadcoin_validated_stales.csv` |

Myriadcoin is the **first multi-algo chain in the integrated pipeline** (dual-PoW Huntercoin was integrated earlier, but both of its branches are merge-mined; Myriadcoin is the first chain with native-PoW branches that carry no AuxPoW at all). What it adds methodologically is the `nVersion` algo-bits filter - the node validates all five algorithms, but only the SHA-256d branch carries Bitcoin-parent AuxPoW commitments, so the extractor must drop ~78% of blocks (the non-SHA-256d four) before parsing. The filter pattern has since been reused by Argentum and Bitmark (same bits, different SHA-256d constants). With 40 validated stales (24 new-to-upstream at the current pin, 2 chronologically novel) over a 3¼-year coverage window from May 2017 to August 2020, the chain sits in a similar quality band to Terracoin and Unobtanium - modest absolute haul, meaningful enrichment of the multi-chain set.

## 1. Chain data

**Source.** Local `myriadcoind` node on `<archival-host>`, built from `myriadcoin/myriadcoin` master (last upstream commit 2021-12-10) inside a Docker container with `ubuntu:20.04` base. Myriadcoin Core is a **Bitcoin Core 0.18.1-lineage fork** (`configure.ac` declares 0.18.1.0 and the `v0.18.1.0` tag is master's ancestor; autotools build, `ADD_SERIALIZE_METHODS`-era serialisation - newer than ixcoin/Unobtanium's 0.11 ancestry, older than xaya's 29.x line). No vintage patches were needed on focal - the standard `--disable-wallet --disable-tests --disable-bench --disable-zmq` configure flags produced a clean build.

**Provenance.** Docker scaffold at `node-infra/myriadcoin/`. P2P sync via the chain's 10 DNS seeds (8x `*.myriadcoin.org`, `myriadseed1.cryptapus.org`, `xmy-seed1.coinid.org`); IBD reached the tip in about six hours (~5 GB datadir), with `peers.list` as an `addnode=` fallback and no recorded recourse to it. Bitcoin Core on `<archival-host>` provided the BTC RPC for classification.

**Coverage.** Validated stales span BTC heights **467,186 → 642,669** (May 2017 → Aug 2020) and XMY heights **2,060,939 → 3,105,294**. The window overlaps almost exactly with Terracoin's (467,186 → 645,179, May 2017 → Aug 2020) - the two validated sets even open on the identical stale event (both chains embed the same BTC 467,186 parent header). The chain itself continues to produce blocks (current tip 3,712,365 as of 2026-05-16), but the validated-stale set ends in Aug 2020. No hashrate evidence was collected to explain the cutoff; a declining SHA-256d merge-mining population relative to Bitcoin's rising difficulty is a plausible but unverified reading.

**Holes.**

- **Pre-AuxPoW** (XMY 0 → 1,401,999): Bitcoin parent merge-mining not yet active. AuxPoW activates at XMY 1,402,000 per `consensus.nStartAuxPow` in `src/chainparams.cpp:76`; the block was mined on 2015-09-26 (one month later than the catalogue's "2015-08" month-precision estimate).
- **Post-Aug 2020 silence**: extraction ran to XMY chain tip 3,712,365 but the latest validated stale is at BTC 642,669 (2020-08-07). 392 SHA-256d blocks across the window had no AuxPoW flag set (early activation gradient - miners transitioned gradually); 1,796,252 non-SHA-256d blocks were correctly filtered out by the algo check before AuxPoW parsing.
- **`fStrictChainId=false`**: the SHA-256d branch will accept AuxPoW from any SHA-256d parent, not just Bitcoin. The extracted rows divide into Bitcoin-canonical, stale-labelled, and unknown classes after Bitcoin Core lookup. Unknown does not identify a particular alternative parent chain.
- **`validation_status` / `expected_nbits` gate columns**: the validated CSV now persists the nBits gate. Coverage straddles BCH (Aug 2017) and BSV (Nov 2018) forks, so the gate matters in principle; in practice the `btc_bits` values in the validated set are consistent with BTC's mainchain difficulty schedule throughout, and all 40 stales are `validation_status=VALID` (0 REJECTED).

**Reference scripts.**

- `scripts/extract/extract_myriadcoin_auxpow.py:1` - RPC raw-hex `getblock` + binary CAuxPow parse, with `nVersion`-bit algo filter (skip if `(version & BLOCK_VERSION_ALGO) >> 9 != 0`).
- `scripts/classify/classify_myriadcoin_stales.py:1` - BTC RPC batch classifier (PoW filter + `getblockheader` lookups).
- `node-infra/myriadcoin/{Dockerfile,docker-compose.yml,init.sh,justfile,README.md}` - build infrastructure.

## 2. Extraction → potential stales

**Method.** RPC raw-hex against the local myriadcoind. For each XMY block ≥ 1,402,000, fetch `getblock <hash> 0` and parse the binary block. First check the algo encoding in `nVersion` bits 9–11; skip non-SHA-256d blocks entirely. Then check the `VERSION_AUXPOW` flag (bit 8); skip SHA-256d blocks without it (rare - early activation gradient only). Then parse the binary CAuxPow tail using the standard Namecoin-style parser (`CMerkleTx` + `vChainMerkleBranch` + `nChainIndex` + 80-byte `parentBlockHeader`).

The block header is `class CBlockHeader : public CPureBlockHeader { shared_ptr<CAuxPow> auxpow; }` - standard Namecoin-style wrapping. **No** xaya-style `PowData` inner-struct sandwich; the Devcoin/Unobtanium/Terracoin extractor pattern ports almost verbatim, only adding the algo filter as a preliminary step.

**Phases.**

1. **Parse with algo filter**: walk all XMY blocks ≥ 1,402,000 via raw hex; decode `nVersion` first; discard blocks where algo bits indicate Scrypt/Groestl/Yescrypt/Argon2d (or pre-2019 Skein/Qubit). Only SHA-256d-flagged blocks proceed to AuxPoW parsing.
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. This does not establish Bitcoin's contemporaneous target.
3. **Dedup**: do *not* dedup at extraction time - multiple consecutive XMY blocks reference the same BTC `prevhash` but each contains a different parent header. Downstream cross-source publication views deduplicate only exact `(height, hash)` identities.
4. **BTC RPC classify** (`classify_myriadcoin_stales.py`): batch `bitcoin-cli getblockheader`. Hit → `canonical`. Miss → look up `prev_hash`. Prev canonical → `stale`. Neither → `unknown`.

**Counts:**

| Stage | Rows |
|---|---:|
| XMY blocks scanned (1,402,000 → 3,712,365) | 2,310,366 |
| After algo + AuxPoW-flag filter (SHA-256d with AuxPoW) | 513,722 (22.2 %) |
| Non-SHA-256d filtered out | 1,796,252 (77.7 %) |
| SHA-256d without AuxPoW flag (early gradient) | 392 |
| Parse errors | 0 |
| After self-target PoW filter (unique) | 181,589 (35.3 % of SHA-256d-AuxPoW) |
| After classification | **14,705 canonical + 40 stale + 166,844 unknown** |

The 22.2% SHA-256d fraction is consistent with the equal-time-share assumption across five algorithms with combined ~60 s target spacing. The 35.3% self-target PoW pass rate is an extraction characteristic only; it is not a comparison with Bitcoin's contemporaneous difficulty. The 14,705 canonical rows come from the 2026-06-24 canonical refresh; the original 2026-05 run persisted only the stale/unknown split, leaving canonical implicit.

**Chain-specific quirks.**

- **Multi-algo PoW**: the chain's defining feature. Only the SHA-256d branch is Bitcoin-parent merge-mined; Scrypt merges with Litecoin/Dogecoin (out of scope); Groestl/Yescrypt/Argon2d are native PoW with no AuxPoW. The extractor's nVersion-bit algo filter is the gate.
- **`fStrictChainId=false`**: the SHA-256d branch accepts AuxPoW from any SHA-256d parent. The classifier's self-target PoW check cannot identify the parent chain; Bitcoin Core classification and validation do so for accepted rows.
- **Activation date correction**: catalogue records "2015-08" (month-precision); actual activation block 1,402,000 was mined 2015-09-26. `CHAINS_BY_AUXPOW_ACTIVATION` uses the precise date. Per the project chronological-ordering convention, we record production-activation, not chain genesis (2014-02-23).
- **Pool population overlaps Terracoin**: both chains' validated windows are May 2017 → Aug 2020. The 38 stales claimed by earlier chains (chronological precedence) split as devcoin 17 / namecoin 10 / i0coin 5 / crown 4 / unobtanium 2 - meaning the SHA-256d miner substrate Myriadcoin witnessed in 2017–2020 is the same one those earlier chains had already been recording for years.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_myriadcoin_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

The loader delegates to the shared `load_auxpow_validated_stales()` helper and parses `coinbase_outputs` as raw pkscript hex semicolon-joined (matches i0coin/ixcoin/elastos/unobtanium blkdat format). The extractor preserves the parent-coinbase outputs verbatim without address decoding so they remain available for later attribution research. All 40 entries pass the filter (the committed CSV is VALID-only).

**Post-filter count: 40 accepted direct-stale header candidates.**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py myriadcoin`. Per-stale row-level breakdown at `results/per-chain-novelty/myriadcoin.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 16 | 40.0 % |
| novel vs upstream | 24 | 60.0 % |

The 24-novel-vs-upstream figure is Myriadcoin's count of stales missing from the upstream dataset, comparable to Terracoin's 22.

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Myriadcoin is 11th chronologically. Earlier-born integrated chains: namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown.

| Split | Count |
|---|---:|
| also in upstream | 16 |
| also in earlier-born chain (`devcoin`: 17, `namecoin`: 10, `i0coin`: 5, `crown`: 4, `unobtanium`: 2 - first-claim distribution) | 38 |
| **novel at this position** | **2** |

The 38 earlier-chain-claimed stales are the same SHA-256d miner substrate that Devcoin/Namecoin/i0coin/Crown/Unobtanium had already been recording - each of those chains contributed at least one chronologically-earlier observation. The 2 chronological-novel hashes - BTC 508,169 (2018-02-07) and BTC 509,239 (2018-02-14) - are the genuinely new-to-the-multi-chain-set contributions at Myriadcoin's position; both were later cross-confirmed by Emercoin, whose novelty table credits them to `first_seen_chain=myriadcoin`.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/myriadcoin_validated_stales.csv` - 40 validated stales (committed; the loader's input).
- Private archive `myriadcoin_btc_valid.csv` - 181,589 PoW-passing rows (intermediate, before classification; 105 MB).
- Private archive split inventories: `myriadcoin_stale_blocks.csv` (40 stale), `myriadcoin_canonical_blocks.csv` (14,705 canonical; from the 2026-06-24 canonical refresh), and `myriadcoin_unknown_blocks.csv` (166,844 unknown) - reconciling to the 181,589 classified total.
- `results/monitor-evidence/myriadcoin_monitor_evidence.csv` - compact committed monitor-evidence export.
- Private archive `myriadcoin_auxpow_raw.csv` - 513,722 raw SHA-256d-AuxPoW rows (extractor output, pre-PoW-filter; 667 MB).
- `results/per-chain-novelty/myriadcoin.csv` - per-stale `(height, hash, in_upstream, first_seen_chain)` table.
- `node-infra/myriadcoin/{Dockerfile,docker-compose.yml,init.sh,justfile,peers.list,README.md}` - build infrastructure.

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (Myriadcoin row).
- Myriadcoin upstream: `github.com/myriadcoin/myriadcoin` (last commit 2021-12-10).
- Public explorer: `chainz.cryptoid.info/xmy/` - tip-height sanity check and peer harvest source at recovery time (2026-05); the site no longer hosts XMY as of 2026-07.
- `chains.csv` row (deadmanoz.xyz catalogue): "Myriadcoin (SHA-256d branch)" - catalogue confirmation.

**Methodological note.**

Myriadcoin is the first multi-algo chain in the pipeline. The algo-filter pattern (decode `nVersion` algo bits at extraction time and discard non-SHA-256d branches before AuxPoW parsing) has since been reused by Argentum and Bitmark - same bits 9-11, but each chain encodes SHA-256d under a different constant (Myriadcoin 0, Argentum and Bitmark 1), so only the comparison constant changes. Auroracoin (also 5-algo with a SHA-256d branch) remains an uncovered candidate. The filter logic is ~3 lines in the extractor: read `nVersion` from the first 4 bytes of the block hex, mask with `BLOCK_VERSION_ALGO`, compare to `ALGO_SHA256D` (0).

## 5. Integration history

- **2026-05-15/16** - Docker node built (`ubuntu:20.04`, Myriadcoin Core master) and synced (~6 h IBD to tip 3,712,365); extraction, classification, and the 40-row validated CSV all landed in the origin recovery session (then 33 new-to-upstream at the pre-bump pin, 4 chronologically novel at the pipeline's earlier 16-chain numbering).
- **2026-05-29** - nBits-gate schema regeneration added the persisted `validation_status` / `expected_nbits` columns (all 40 VALID).
- **2026-06-24** - Canonical refresh backfilled the 14,705 canonical rows (the original run persisted only the stale/unknown split).
- **2026-07** - Published in merge-mining-research; at the current upstream pin and 26-chain chronology the figures are 24 new-to-upstream (the pin bump absorbed 9) and 2 chronologically novel (Crown's integration reclaimed 2 of the original 4).
