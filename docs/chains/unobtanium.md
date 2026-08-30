# Unobtanium

| Field | Value |
|---|---|
| Ticker | UNO |
| AuxPoW activation | 2015-05-08 (UNO height 600,000) |
| Network status | Dormant (chain alive but upstream repo last touched Feb 2024 (commit `54d68b0`, [GitHub commit history](https://github.com/unobtanium-official/Unobtanium/commits/master)); small peer set, DNS seeds partially degraded) |
| Chronological position | 9 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin; before Crown) |
| In Stifter et al. 2018 baseline | **Yes** (one of the paper's seven measured Bitcoin-parent chains; Table 1) |
| AuxPoW chain ID | `117` (0x75) - defined in source as `AUXPOW_CHAIN_ID = 0x75` (`src/primitives/block.h:17`); equivalently the high 16 bits of an AuxPoW block header's `nVersion` (`(nVersion >> 16) & 0xffff`). AuxPoW is permitted from UNO height 600,000 (`AUXPOW_START_MAINNET`, `src/auxpow.h:10`). No collision with Namecoin (1), i0coin (2), ixcoin (3), Devcoin (4), Syscoin/CoiledCoin (16), Terracoin (50), or RSK. |
| Block time | ~3 minutes (~184 s observed; `chainparams.cpp:nTargetSpacing = 60` is stale and doesn't match actual DAA) ≈ 3.3 UNO blocks per BTC block |
| Source tag (in code) | `unobtanium` |
| Loader | `load_unobtanium_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/unobtanium_validated_stales.csv` |

Unobtanium has one of the **longest continuous single-chain AuxPoW scan windows** of any merge-mined chain in scope: about 11 years from May 2015 to the present. (Namecoin's 2011 → present run is longer, as are ixcoin's and Devcoin's early-2012 → present runs.) Its 43 validated stales are modest in number, but the long scan provides a useful view across multiple Bitcoin mining eras and independently corroborates events recovered from other AuxPoW chains.

## 1. Chain data

**Source.** Local `unobtaniumd` node on `<archival-host>`, built from `unobtanium-official/Unobtanium` master at commit `54d68b08` inside a Docker container with `ubuntu:20.04` base. Unobtanium Core is a **Bitcoin Core 0.11 fork** (the oldest actively maintained Bitcoin Core lineage of any integrated chain; CoiledCoin's pre-0.6 lineage is older but survives only as a preserved build). Building on modern Ubuntu required OS-vintage workarounds - the 2024 master branch already contains GCC 11 / Boost 1.74 patches ("Add missing boost build flags", "Fix qt5 byte array for gcc11+"), plus an additional **OpenSSL 1.1 crypter sed patch** applied during the Docker build to satisfy the deprecation of `SHA256_Init`/`SHA256_Update` in OpenSSL 3.

**Provenance.** Docker scaffold at `node-infra/unobtanium/`. P2P sync: DNS seeds `node1.unobtanium.uno` and `node2.unobtanium.uno` resolve but the open upstream issue `#53` (Jan 2026, "No block source available") flagged degradation; sync used DNS plus `addnode=` entries pinned to ~10 peers harvested from `chainz.cryptoid.info/uno/api.dws?q=nodes` (13 live, 8 confirmed reachable on TCP 65534). Bitcoin Core on `<archival-host>` provided BTC RPC for classification.

**Coverage.** Accepted direct-stale candidates span BTC heights **374,611 → 645,179** (Sep 2015 → Aug 2020) and UNO heights **662,179 → 1,519,005**. The 11-year extraction window is the scanned range; no later accepted direct-stale candidates were observed.

**Holes.**

- **Pre-AuxPoW** (UNO 0 → 599,999): solo SHA-256 mining, no embedded BTC parent headers. AuxPoW is permitted from UNO height 600,000 (May 2015), set by `AUXPOW_START_MAINNET = 600000` in `src/auxpow.h:10` and enforced in `main.cpp` (a block carrying AuxPoW is rejected while `nHeight < GetAuxPowStartBlock()`).
- **Post-Aug 2020 silence**: extraction ran to UNO chain tip but the latest stale is Aug 2020. Either the chain's hashrate fell below the floor where any single AuxPoW-embedded BTC header could meet BTC's difficulty, or post-2020 miners stopped pointing UNO at BTC. The 99.84% AuxPoW *density* (memory) is across the full 11-year window - almost every UNO block carries some parent header; just few of those parents now meet BTC's tightening difficulty.
- **`validation_status` / `expected_nbits` gate columns**: the validated CSV persists the consensus gate. Coverage straddles BCH (Aug 2017) and BSV (Nov 2018) forks, so the `nBits` check matters in principle. One shared version 2 candidate after BIP66 height 363,725 is excluded; the remaining 43 stales are `validation_status=VALID`.
- **Full classifier unknown inventory is private/off-repo**: the standard full classifier output is preserved in the private chain archive, bucket-split into `unobtanium_stale_blocks.csv`, `unobtanium_unknown_blocks.csv`, and `unobtanium_canonical_blocks.csv`; the unknown bucket can be copied to a local gitignored `unobtanium_unknown_blocks.csv` when running unknown analyses. The committed loader input remains `data/validated-stales/unobtanium_validated_stales.csv`.
- **AuxPoW chain ID = 117 (0x75)**: defined in source as `AUXPOW_CHAIN_ID = 0x75` (`src/primitives/block.h:17`). The Bitcointalk 769073 registry doesn't publish it and it isn't in `chainparams.cpp`, but it is also reproducible from the high 16 bits of any AuxPoW UNO block header's `nVersion`. No collision with the other integrated chains.

**Reference scripts.**

- `scripts/extract/extract_unobtanium_auxpow.py:1` - RPC raw-hex `getblock` + binary CAuxPow parse (Bitcoin Core 0.11 RPC doesn't expose decoded `auxpow`).
- `scripts/classify/classify_unobtanium_stales.py:1` - BTC RPC batch classifier.
- `node-infra/unobtanium/{Dockerfile,docker-compose.yml,justfile,README.md}` - build infrastructure.

## 2. Extraction → potential stales

**Method.** RPC raw-hex against the local unobtaniumd. For each UNO block ≥ 600,000, fetch `getblock <hash> 0` and parse the binary CAuxPow tail. Bitcoin Core 0.11's `getblock` predates the modern JSON `auxpow` decoding, so the binary path is unavoidable. The AuxPoW format is the standard Namecoin-style layout (`CMerkleTx` + `vChainMerkleBranch` + `nChainIndex` + 80-byte `parentBlockHeader`), so the existing parser is reused unchanged.

**Phases.**

1. **Parse**: walk all UNO blocks ≥ 600,000 via raw hex; extract parent header + coinbase tx + Merkle branch.
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. This does not establish Bitcoin's contemporaneous target.
3. **Dedup**: with ~3.3 UNO blocks per BTC interval, do *not* dedup at extraction time (different miners contribute different parent headers within the same BTC interval). Downstream cross-source publication views deduplicate only exact `(height, hash)` identities.
4. **BTC RPC classify** (`classify_unobtanium_stales.py`): batch `bitcoin-cli getblockheader`. Hit → `canonical`. Miss → look up `prev_hash`. Prev canonical → `stale`. Neither → `unknown`.

**Counts** (per recovery report):

| Stage | Rows |
|---|---:|
| UNO blocks scanned (600,000 → 2,484,934) | 1,884,935 |
| Raw AuxPoW rows | 1,881,845 (99.84% density) |
| After self-target PoW filter | 445,933 unique |
| After classification | **14,958 canonical + 44 stale-labelled + 430,931 unknown** |
| Committed after the error-blocks consensus gate | **43 stale** |

The 430,931 unknown rows are headers from non-BTC SHA-256 parents (UNO miners merge-mined to NMC / DVC / IXC / etc., not just BTC). Most of those unknowns should overlap with the other Namecoin-family chains' validated sets - this is exactly the cross-chain unknown-substrate question. The unknown rows were produced in the archived inventory; `data/unobtanium_unknown_blocks.csv` can be recreated as a local gitignored mirror when running the analysis scripts.

**Chain-specific quirks.**

- **Bitcoin Core 0.11 vintage**: the oldest active Bitcoin-Core-derived node in the integrated set; CoiledCoin is older by code lineage, but its recovery path is a preserved pre-0.6 build rather than a normally maintained modern node. Build needs `--without-gui --disable-tests --disable-bench`, GCC 11 + Boost 1.74 patches from the master branch, plus an `OpenSSL 1.1` crypter sed patch to work around `SHA256_Init` deprecation under OpenSSL 3.
- **Block-time discrepancy**: `chainparams.cpp:nTargetSpacing = 60` is unused/stale (its own comment even reads `// 30 seconds`). The operative difficulty algorithm is Kimoto Gravity Well with a 180 s target (`BlocksTargetSpacing = 3 * 60`, `src/pow.cpp:147`), active from block 450,000 (`PROOF_OF_WORK_FORK_BLOCK_MAINNET`), well before AuxPoW at 600,000. Empirical block time is ~184 s. Don't trust the `nTargetSpacing` constant for UNO - measure from the chain.
- **AuxPoW chain ID = 117 (0x75)**: defined as `AUXPOW_CHAIN_ID = 0x75` in `src/primitives/block.h:17` (not in the Bitcointalk 769073 registry or `chainparams.cpp`); also reproducible from any AuxPoW UNO block header's `nVersion` high 16 bits.
- **Loader uses raw scriptPubKey hex (no semicolon-separated address column)**: `coinbase_outputs` is raw `pkscript_hex;pkscript_hex;...` (matches the i0coin/ixcoin/elastos `blk*.dat` format), preserving the original outputs without the `addr:value|...` to `addr;addr` rewriting used by Devcoin, Syscoin, and Terracoin.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_unobtanium_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

The `validation_status` gate is now persisted on this CSV: all 43 entries are `validation_status=VALID`; the loader also applies the exact-key error-blocks exclusion gate (`data/error-blocks/error_blocks.csv`).

**Post-filter count: 43 accepted direct-stale header candidates.**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py unobtanium`. Per-stale row-level breakdown at `results/per-chain-novelty/unobtanium.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 21 | 48.8 % |
| novel vs upstream | 22 | 51.2 % |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Unobtanium is 9th chronologically. The earlier-born integrated chains are namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, and huntercoin. Geistgeld contributes zero validated stales, while Groupcoin and Huntercoin contribute no first-claim overlap for Unobtanium's 43 stales:

| Split | Count |
|---|---:|
| also in upstream | 21 |
| also in earlier-born chain (`devcoin`: 20, `namecoin`: 15, `i0coin`: 4 - first-claim distribution) | 39 |
| **novel at this position** | **3** |

The "3 novel" figure matches the historical recovery note. The candidates are
at BTC 374,611 (2015-09-15), BTC 377,993 (2015-10-08), and BTC 485,016
(2017-09-13). An earlier private attribution pass labelled the first two
`stratumPool` and the third `BTC.TOP`; the current public pipeline does not
reproduce those labels.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

### Unknown-chain origin (H1 vs H2)

An earlier private analysis ran against UNO's full 430,931-row unknown
inventory. It is the third-largest single unknown sample in the project (after
Argentum's 634,277 and Terracoin's 523,315), and more than five times
Devcoin's. Three prior chains (Namecoin, Devcoin, and Terracoin)
concluded H2; Unobtanium converges on the same answer. The aggregate results
are retained below, but the one-off script and row-level files are private.

| Test | Result |
|---|---:|
| nBits epoch consistency | **0 / 430,931** (0.0 %) |
| nBits epoch consistency in multi-block unknown chains | 0 / 73,076 (0.0 %) |
| Multi-block unknown graph | 27,348 roots, 73,076 nodes, max chain depth 47 |
| Recursive walk terminus | **all 430,931 → dangling** (zero walk to a known stale) |
| Namecoin cross-confirmed unknown-roots present in UNO unknowns | **18 / 31** (Stifter overlap window; the prior expectation of 0 was wrong) |
| ↳ of which pass BTC nBits-epoch test | **0 / 18** |
| BCH/BSV fork-window unknowns (BTC 478,558 / 556,766 ± 6) | 0 / 4 (epoch-match: 0 / 0) |

*Anchor note: the analysis constant 556,766 is the BCH-chain height at the BSV split; Bitcoin's own height on 2018-11-15 was near 551,000, so the BSV window as coded probes BTC blocks from ~Jan 2019 rather than the split itself. The finding is negative at either anchor.*

**Summary.** Zero of 430,931 unknown rows match Bitcoin's expected `nBits` epoch. This is stronger than Devcoin's 6 of 75,141 and matches Terracoin's 0 of 523,315. H1 is rejected on one of the largest evidence bases in the project (Terracoin's 0 of 523,315 is larger).

**Cross-chain finding.** 18 of 31 Namecoin cross-confirmed unknown roots are
present in UNO's unknown inventory, and **0 / 18 pass the BTC nBits-epoch
test**. All 18 are 2017 to 2019 events. A historical private attribution pass
labelled most of them BTC.TOP, Huobi Pool, or WAYI.CN (two remained Unknown),
but those labels are not reproduced by the current public pipeline. The epoch result is direct evidence
that this shared SHA-256d substrate does not match Bitcoin's expected target history.

**Loader decision.** `load_unobtanium_stales()` keeps loading only publication-gate-accepted direct-stale rows. The unknown class overwhelmingly fails the Bitcoin expected-`nBits` epoch test and is not direct-stale evidence.

The private archive retains the aggregate JSON, the 134 MB per-row analysis,
and the cross-chain overlap detail.

## 4. Outputs & references

**Artifacts.** Loader inputs under `data/`, novelty tables under
`results/per-chain-novelty/`, and the strict/weak and monitor-evidence
exports are committed here. Row-level analysis diagnostics live in the private
archive.

- `data/validated-stales/unobtanium_validated_stales.csv` - 43 validated stales (committed; the loader's input).
- Private archive split inventories: `unobtanium_canonical_blocks.csv` (14,958 canonical, backfilled by the 2026-06-24 canonical refresh), `unobtanium_stale_blocks.csv` (44 stale-labelled candidates), and `unobtanium_unknown_blocks.csv` (430,931 unknown); the three reconcile to the 445,933 self-target-PoW-valid headers. The unknown bucket can be copied back to a gitignored `data/unobtanium_unknown_blocks.csv` working mirror for unknown analyses.
- `results/per-chain-novelty/unobtanium.csv` - per-stale `(height, hash, in_upstream, first_seen_chain)` table.
- Private unknown-origin diagnostics include the aggregate summary, the 134 MB
  per-row analysis, and the 31-row Namecoin overlap table.
- `node-infra/unobtanium/{Dockerfile,docker-compose.yml,justfile,README.md}` - build infrastructure with the OpenSSL 1.1 sed patch.

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (Unobtanium row).
- Private archival data `unobtanium_unknown_blocks.csv` holds the split unknown bucket with the 430,931 unknowns.

**Remaining work.**

- **AuxPoW chain ID resolution** - resolved as **117 (0x75)** (2026-05-14), decoded from the high 16 bits of the UNO block header's `nVersion` field and since confirmed as the source constant `AUXPOW_CHAIN_ID = 0x75` (`src/primitives/block.h:17`). No collision with the other integrated chains.
- **Unknown-chain origin (H1 vs H2)** - resolved in a historical private
  analysis (2026-05-14). **0 / 430,931** unknowns pass the BTC nBits-epoch
  consistency test; **0 / 73,076** in multi-block-unknown-chain nodes; all
  430,931 walks terminate in dangling. Eighteen of 31 Namecoin cross-confirmed
  unknown roots are present, and all 18 fail the epoch test. See §3(d). The
  aggregate evidence supports a SHA-256d substrate that does not follow Bitcoin's target history; the
  current public release does not reproduce the historical pool labels.
