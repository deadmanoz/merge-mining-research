# Huntercoin

| Field | Value |
|---|---|
| Ticker | HUC |
| AuxPoW activation | 2014-01-31 (genesis; merge-mined from block 0 - see §2 quirks) |
| Network status | **Dead** - no reachable live node or explorer; data only available via the Arweave permaweb archive |
| Chronological position | 8 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin; before unobtanium) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; Huntercoin's February–March 2014 window is inside the paper's period but it was not a sampled data source) |
| AuxPoW chain ID | 6 (SHA-256d branch; the Scrypt branch with chain ID 2 / LTC parent is out of scope) |
| Block time | 120 s per algorithm (dual SHA-256d + Scrypt), ~60 s combined |
| Source tag (in code) | `huntercoin` |
| Loader | `load_huntercoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/huntercoin_validated_stales.csv` |
| Full stale/unknown inventory | Private chain archive (13 stale + 29 unknown rows) |

Huntercoin (HUC) was a dual-PoW chain (SHA-256d merge-mined with Bitcoin and Scrypt merge-mined with Litecoin in parallel) launched February 2014 by Andrew Colosimo and Mikhail Syndeev (Sindeyev); Daniel Kraft has maintained the core code since 2014 (Xaya legacy page, https://xaya.io/huntercoin-legacy; bitcointalk ANN, https://bitcointalk.org/index.php?topic=435170.0). The chain is **dead**: although the maintainers describe a limited-support phase, no block explorer returned a current tip and no live node was reachable during review, so recovery relies on an Arweave permaweb archive of the first ~100k HUC blocks (`domob1812/arblockstore`). The publication-gate-accepted set contains 13 direct-stale candidates spanning February–March 2014, one of the smaller in-scope accepted sets.

## 1. Chain data

**Source.** Arweave permaweb archive at `domob1812/arblockstore`, fetched via `scripts/prep/fetch_huntercoin_arweave.py`. The archive covers the first ~100,000 HUC blocks (genesis → ~March 2014 endpoint). No live Huntercoin node or explorer was reachable during review, so the archive is the only usable data source.

**Provenance.** Fetched once to `<archival-host>` (or local), parsed by `scripts/extract/extract_huntercoin_auxpow.py`, classified by `scripts/classify/classify_huntercoin_stales.py`. The raw extractor output is kept in the private chain archive (43,288 HUC AuxPoW SHA-256d-branch headers, including rows that fail their encoded self-target). The standard classifier output is also preserved privately (857 canonical + 13 stale-labelled candidates + 29 unknown rows = 899).

**Coverage.** Validated stales span BTC heights **285,130 → 290,178** (2014-02-10 → 2014-03-12; 7 rows February, 6 rows March). HUC heights **43,156 → 88,274** (early chain only - the Arweave archive doesn't extend to the chain's actual tip). The chain ran until at least 2018, so anything after this window is not in scope for this extraction unless a new archive surfaces.

**Holes.**

- **Post-Arweave-archive (HUC > ~100,000 / BTC > 290,178)**: not extracted. The Arweave archive is the only source and ends there.
- **Scrypt branch (chain ID 2, LTC parent)**: explicitly out of scope. This doc covers only the SHA-256d branch with `chain_id == 6`.
- **Dummy blocks**: Huntercoin's early genesis-window blocks don't carry meaningful AuxPoW headers; the chain-id filter (`chain_id == 6` for SHA-256d) drops these naturally.
- **`validation_status` / `expected_nbits` gate columns**: the validated CSV now persists the nBits gate. Coverage is February–March 2014, **pre-BCH (Aug 2017)** and **pre-BSV (Nov 2018)**, so contamination isn't a concern; all 13 stales are `validation_status=VALID` (0 REJECTED).
- **Schema standardisation history**: the original Huntercoin recovery output used a non-standard schema (`btc_parent_hash` instead of `btc_header_hash`, `btc_timestamp` instead of `btc_time`, `pow_valid` for Huntercoin target validity, and a three-way `canonical / stale-novel / stale-known` vocabulary). The project-wide unknown-inventory pass rewrote the full inventory to the shared schema with `classification == "stale" | "unknown"`. The follow-up pool-attribution pass also removed the redundant `huntercoin_orphan_stales.csv` shortcut sidecar - the 29 unknown rows live under `classification == "unknown"` in the split unknown inventory (`huntercoin_unknown_blocks.csv`), matching every other chain's file layout.

**Reference scripts.**

- `scripts/prep/fetch_huntercoin_arweave.py:1` - Arweave fetcher; pulls the `domob1812/arblockstore` archive into local block data.
- `scripts/extract/extract_huntercoin_auxpow.py:1` - AuxPoW extractor; parses both SHA-256d and Scrypt branches but only the SHA-256d branch (chain ID 6) feeds our pipeline.
- `scripts/classify/classify_huntercoin_stales.py:1` - chain-specific classifier; applies the self-target PoW filter and emits the shared stale/unknown inventory schema.

## 2. Extraction → potential stales

**Method.** Arweave-archive fetch → AuxPoW parse (SHA-256d branch only, chain_id == 6) → BTC RPC classification on `<archival-host>`. AuxPoW format is Vince Durham / Daniel Kraft serialisation, byte-identical to Namecoin's - the existing binary parser is reused.

**Phases.**

1. **Fetch**: pull the `domob1812/arblockstore` archive from Arweave. One-off.
2. **Parse**: walk every HUC block in the archive; for each AuxPoW-bearing block, extract parent header + coinbase tx + Merkle branch from the SHA-256d branch (chain ID 6). Drop the Scrypt branch (chain ID 2).
3. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in the parent header. This filter is separate from the raw extractor's `pow_valid` flag, which refers to Huntercoin's child-chain target.
4. **BTC RPC classify** (against the existing Bitcoin Core node on `<archival-host>`): `getblockheader <hash>`. Hit → `canonical`. Miss → look up `prev_hash`. Prev canonical → `stale`. Neither canonical → `unknown`.

**Counts.** The raw extractor holds **43,288** SHA-256d-branch AuxPoW rows - every row is `chain_id == 6` and Huntercoin-PoW-valid, and all 43,288 parent-header hashes are distinct. The self-target PoW filter (phase 3) is the dominant cut: **899 rows meet the Bitcoin target encoded in their parent header** (`SHA256d(header) ≤ target(nBits)`, recomputed directly from `btc_header_hex`). Bitcoin RPC then classifies those 899:

| Classification (self-target-PoW-valid rows) | Rows |
|---|---:|
| `canonical` (parent on the BTC mainchain) | 857 |
| `stale` (parent off-chain, prev canonical) | 13 |
| `unknown` (parent + prev both off-chain) | 29 |
| **Total PoW-valid** | **899** |

The committed loader admits only the publication-gate-accepted stale rows (all 13 pass).

An earlier diagnostic instead RPC-classified *every* raw row before the PoW filter, to gauge how many are stale-shaped: 857 parent-canonical, **42,208** with an off-chain parent but a canonical `prev` (stale-shaped), and 211 with both off-chain. The 42,208 stale-shaped rows are overwhelmingly sub-BTC-difficulty AuxPoW noise - only 13 survive the self-target filter - which is the substance of the H2 reading in §3. (Those three provisional categories sum to 43,276; the ~12-row difference from the 43,288 raw total is unresolved RPC-probe remainder in the recovered 2026-05-14 diagnostics, all of it sub-difficulty, so it touches none of the 899 PoW-valid rows or any committed count.)

**Chain-specific quirks.**

- **Dual-PoW chain**: SHA-256d branch (chain ID 6, BTC parent) AND Scrypt branch (chain ID 2, LTC parent), both source-confirmed (`chronokings/huntercoin` `main.cpp`: `chain_id[NUM_ALGOS] = { 0x0006, 0x0002 }`). The extraction filters to chain ID 6 only; the Scrypt branch is out of scope for this project. Target spacing is `nTargetSpacing = 60 * NUM_ALGOS` = 120 s per algorithm (~60 s combined; the dev comment reads "A block every minute for all algos in total"), and the empirical rate across the sampled HUC range is ~57 s/block.
- **Genesis is the AuxPoW activation.** Genesis `nTime` 1391199780 = 2014-01-31 20:23 UTC, merge-mined from block 0: the genesis coinbase names both parents (`Bitcoin block 283440: …` and `Litecoin block 506479: …`) and the source sets `fStrictChainId = true` with no delayed AuxPoW start height. So 2014-01-31 is the real genesis/activation date, not merely a catalogue value.
- **Dead network, Arweave archive**: the only chain in scope whose data source is a third-party permaweb archive. No live node or explorer was reachable during review; if the Arweave archive becomes unavailable, no further extraction is possible.
- **Standard classifier output schema**: the private full inventory now uses the project-wide schema (`btc_header_hash`, `btc_time`, `classification`) and contains only self-target-PoW-valid non-canonical rows. `pow_valid`, `chain_id`, and `btc_merkle_root` remain in the raw extractor output, not in the standard inventory.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_huntercoin_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status.startswith("VALID")
```

All 13 entries pass (the committed CSV is VALID-only).

**Post-filter count: 13 accepted direct-stale header candidates.**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py huntercoin`. Per-stale row-level breakdown at `results/per-chain-novelty/huntercoin.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 7 | 53.8 % |
| novel vs upstream | 6 | 46.2 % |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Huntercoin is 8th chronologically. The earlier-born integrated chains are namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, and groupcoin. Geistgeld contributes zero validated stales, and Groupcoin contributes no first-claim overlap for Huntercoin's 13 stales. Breakdown:

| Split | Count |
|---|---:|
| also in upstream | 7 |
| also in earlier-born chain (`namecoin`: 5, `i0coin`: 5, `ixcoin`: 1 - first-claim distribution) | 11 |
| **novel at this position** | **2** |

The 11 earlier-chain attributions are heavy-overlap: namecoin and i0coin each first-claim 5 of the 13 under the chronological-precedence convention (only 2 hashes fall in both their validated sets), and ixcoin first-claims the 11th. Counting observation rather than first-claim precedence, devcoin and groupcoin independently record several of these stales too, so five distinct earlier-born chains carry at least one of Huntercoin's stales - unsurprising, as February–March 2014 was when the Namecoin-family chains were at full merge-mining hashrate. Only **2 are novel** at Huntercoin's position. This makes Huntercoin one of the lowest-marginal-yield chains in the integrated set on a chronological basis - but with the small sample size (13 stales total), the *proportional* marginal yield (2/13 = 15%) is comparable to other chains.

### Unknown inventory

The 29 self-target-PoW-passing **unknowns-by-our-standard** (parent not in BTC mainchain, prev_hash also not in BTC mainchain) live in the private unknown-inventory bucket (`huntercoin_unknown_blocks.csv`) under `classification == "unknown"`. These rows are evidence of an isolated chain segment that **no other AuxPoW chain in scope captured**:

| Cross-reference | Hits |
|---|---:|
| Huntercoin unknown `prev_hash` ∈ any chain's validated stales | **0 / 29** |
| Huntercoin unknown `prev_hash` ∈ any chain's unknown inventory | **0 / 29** |
| Huntercoin unknown `parent_hash` ∈ any chain's unknown `prev_hash` | **0 / 29** |
| Huntercoin unknown `parent_hash` ∈ any chain's unknown inventory | **0 / 29** |

Across all integrated chains' validated-stale sets (`namecoin`, `i0coin`, `ixcoin`, `coiledcoin`, `devcoin`, `unobtanium`, `terracoin`, `elastos`, `syscoin`, `rsk`, plus `bitcoin-data/stale-blocks` upstream) AND the archived unknown inventories (`namecoin_stale_blocks.csv` 7,841 unknowns, `devcoin_unknown_blocks.csv` 75,141 unknowns, `ixcoin_unknown_blocks.csv` 253,974 unknowns, `syscoin_unknown_blocks.csv` 18,281 unknowns, `elastos_unknown_blocks.csv` 9,003 unknowns) - **none** of Huntercoin's 29 unknown hashes appear anywhere. The chain segment is fully isolated to Huntercoin's AuxPoW recording.

**Historical pool-attribution audit (decisive on the H1/H2 question):** an earlier private analysis returned **0 / 29 recognisable BTC pool tags** across the 29 unknown coinbase scriptSigs and outputs, with every row labelled `Unknown`. By contrast, the 13 validated stales were **13 / 13 recognisable** (F2Pool 7, Eligius 4, CloudHashing 2). The table and conclusion are retained as historical research evidence. The current public recovery pipeline does not reproduce this attribution pass. The two populations shared **no pools at all**:

| Population | Rows | Recognisable BTC pool tags | Distinct pools |
|---|---:|---:|---:|
| Unknowns | 29 | 0 (0.0%) | 1 (`Unknown`) |
| Validated stales | 13 | 13 (100.0%) | 3 (F2Pool, Eligius, CloudHashing) |

Under the pre-committed decision rule (≤25% recognisable BTC pool tags → H2), this is unambiguous: **H2 is supported** for Huntercoin's isolated 29-unknown chain segment. The miners producing these AuxPoW headers were not pointing at recognised BTC pools, and the unknown miner population is disjoint from the validated-stale miner population that *was* mining BTC at the same February–March 2014 window. Combined with the cross-chain isolation table above, the simplest reading is that these 29 rows record a defunct non-BTC SHA-256d substrate (or Huntercoin-specific synthetic/test AuxPoW noise), not lost deep-BTC-reorg material.

This aligns the Huntercoin unknown subset with the project-wide H1/H2 finding: Namecoin, Devcoin, Terracoin and Unobtanium all converge on H2, and Huntercoin joins them as a further H2-convergent chain.

Private-archive outputs from this audit (not committed in this repository):

- `huntercoin-unknown-pool-attribution.csv` - per-unknown `huc_height, btc_header_hash, btc_prev_hash, btc_bits, btc_time, btc_time_utc, identified_pool, pool_source` rows.
- `huntercoin-unknown-pool-attribution-summary.json` - machine-readable summary including the validated-stale comparison.
- The historical analysis script is also retained privately; the current
  public pipeline does not reproduce the audit.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**Artifacts.** Loader inputs under `data/`, novelty tables under
`results/per-chain-novelty/`, and the strict/weak and monitor-evidence
exports are committed here. The pool-attribution diagnostics live in the
private archive.

- `data/validated-stales/huntercoin_validated_stales.csv` - 13 validated stales (loader input; committed). Standard schema.
- `results/per-chain-novelty/huntercoin.csv` - per-stale `(height, hash, in_upstream, first_seen_chain)` table.
**Private archive artifacts.**

- `huntercoin_auxpow_raw.csv` - raw extractor output (43,288 SHA-256d-branch AuxPoW rows).
- Split inventories: `huntercoin_stale_blocks.csv` (13 stale) and `huntercoin_unknown_blocks.csv` (29 unknown).
- `huntercoin-unknown-pool-attribution.csv` and its summary JSON - historical
  pool-attribution diagnostics.

**External references.**

- `domob1812/arblockstore` on Arweave - sole data source for the chain.
- `docs/auxpow-recovery.md` - cross-chain summary table (Huntercoin row).

**Remaining work.**

None on the AuxPoW-recovery side. The three follow-ups are closed:

- **Item 1 - pool-tag audit on the 29 unknowns**: resolved. 0/29 recognisable BTC pool tags vs 13/13 in the validated stales. See §3.
- **Item 2 - unknown-inventory schema rewrite**: resolved. Full inventory at standard schema; redundant `huntercoin_orphan_stales.csv` removed. See §1.
- **Item 3 - Arweave archive extension search**: closed with a documented null result on 2026-05-14. The `domob1812/arblockstore` Arweave archive maxes at HUC block 100,000 (Arweave GraphQL `Block-Height` tag confirmed via `sort: HEIGHT_DESC` - newest indexed records carry HUC heights 99,389-100,000, with Arweave indexing timestamps in October 2021 - and the fetched payloads are preserved in the private archive). No longer archive exists at any of the checked vectors: `chronokings/huntercoin` and `domob1812/huntercore` have empty GitHub-releases listings (no `bootstrap.dat`); `huntercoin/huntercoin` returns 404; `chainz.cryptoid.info/huc/` is delisted (HTTP 307 → root, and HUC is absent from the 109-chain `/api.dws?q=summary` index); archive.org returns 0 hits for "huntercoin blockchain" or "huntercoin bootstrap.dat"; Wayback CDX shows no octet-stream captures of huntercoin.org. Per the project's rules, no third-party outreach was attempted.

## 5. Integration history

- **2026-05-14** - Arweave archive fetched and classified. The original run used a non-standard schema (`btc_parent_hash`/`btc_timestamp`/`pow_valid`) and a three-way `canonical / stale-known / stale-novel` vocabulary; the integration pass normalised it to the shared schema (13 direct stales), computed the cross-chain isolation of the 29 unknowns, closed the Arweave archive-extension search with a documented null result, and defined the unknown-coinbase pool-tag audit in a remaining-work brief.
- **2026-05-31** - Arweave/data-hunt re-verification: the archive maxes at HUC block 100,000, and every alternative source vector was re-checked with nothing found beyond the permaweb archive.
- **2026-06** - Pool-tag H1/H2 audit run: 0/29 recognisable BTC pool tags on the unknowns vs 13/13 on the validated stales (F2Pool 7, Eligius 4, CloudHashing 2), supporting H2. Founder/launch facts were corrected (launch February 2014; founders Colosimo + Syndeev; Kraft maintainer since 2014).
- **2026-06-24** - Canonical refresh / full-evidence build (857 canonical + 13 stale + 29 unknown = 899).
- **2026-07** - Published in merge-mining-research: `orphan`→`unknown` terminology, the redundant `huntercoin_orphan_stales.csv` sidecar removed, and the private diagnostics renamed `huntercoin-unknown-pool-attribution*`.
