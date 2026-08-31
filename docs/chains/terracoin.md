# Terracoin

| Field | Value |
|---|---|
| Ticker | TRC |
| AuxPoW activation | 2016-09-23 (TRC height 833,000, hard fork 1; `nAuxpowStartHeight=833000`) - first validated stale at BTC 467,186 (May 2017) |
| Network status | Active (small but functional; Mining-Dutch / Zergpool / Pool4ever are the current SHA-256 pools) |
| Chronological position | 14 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven, argentum; before emercoin) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; in-window but not a sampled data source) |
| AuxPoW chain ID | 50 (0x0032), strict |
| Block time | 120 s (≈ 5 TRC blocks per BTC block) |
| Source tag (in code) | `terracoin` |
| Loader | `load_terracoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/terracoin_validated_stales.csv` |

Terracoin is the **only Dash-Core-derived chain** in scope (RSK, Elastos, and Hathor are also non-Bitcoin-Core codebases, but on Java, Go, and Python lineages). Despite the Dash heritage, the boolean-verbose `getblock <hash> true` RPC returns a decoded `auxpow` JSON object in the same shape as Syscoin, so extraction is pure JSON field access. Its 99.95% AuxPoW density (2,368,318 of 2,369,590 scanned TRC blocks) is second only to Bitcoin Vault's 99.99%. The public result contains 35 accepted direct-stale candidates spanning BTC 467,186 to 645,179 (May 2017 to August 2020). Historical pool attribution remains private and is not part of the current recovery pipeline.

## 1. Chain data

**Source.** Local `terracoind` v0.12.2.5 node on `<archival-host>`, built from `terracoin/terracoin` at tag `v0.12.2.5` (the last release, 2020-03-05; repo last touched May 2021) inside a Docker container with `ubuntu:20.04` base. The build disables the wallet (`--disable-wallet`), so Berkeley DB is not needed at all, and compiles clean on ubuntu:20.04's GCC 9 / Boost 1.71 with no source patches - none of the GCC 13 / modern Boost shims that ixcoin / Unobtanium needed.

**Provenance.** Docker scaffold at `node-infra/terracoin/`. Both DNS seeds (`seed.terracoin.io`, `dnsseed.southofheaven.ca`) return no A records and the 45 seed IPs pinned in `chainparamsseeds.h` were unreachable, so sync ran from the official `bootstrap.dat.gz` (1.3 GB, genesis → Apr 2021, ~70% of the AuxPoW range) plus `addnode=` peers discovered via the Chainz TRC nodes API (since gone offline - see §4). Bitcoin Core on `<archival-host>` provided the BTC RPC for classification.

**Coverage.** Accepted direct-stale candidates span BTC heights **467,186 → 645,179** (May 2017 → Aug 2020) and TRC heights **995,584 → 1,810,854**. The window is post-BCH (478,558, Aug 2017) and straddles the BSV split (Nov 2018), so expected-`nBits` validation matters for excluding altchain-parent contamination.

**Holes.**

- **Pre-AuxPoW** (TRC 0 → 832,999): merged mining not yet active. The chain was launched Oct 2012, suffered a well-known ~1.2 TH/s 51% attack in July 2013, and was relaunched by the Terracoin Foundation in Feb 2016 on a Dash-Core-derived codebase. Hard fork 1 at TRC 833,000 (block time 2016-09-23) activated DGW difficulty and merged mining; hard fork 2 at TRC 1,087,500 (2017-10-02) enabled the Dash masternode/governance features, and the client line later moved to Dash Core 0.12.2.x. Pre-AuxPoW history is historical trivia, not data we recover.
- **Activation-to-first-stale gap**: AuxPoW activated 2016-09-23 (BTC ~431,000), but the first validated stale is at BTC 467,186 (May 2017), roughly eight months and 162,500 TRC blocks later. Nothing in the opening stretch of the AuxPoW era yielded a validated stale parent.
- **`validation_status` / `expected_nbits` gate columns**: the validated CSV
  persists the nBits gate. The 2026-07-30 normal source rerun also recovered
  parent-coinbase addresses directly from `getblock`. Coverage straddles
  BCH/BSV forks, so the gate matters in principle; in practice the validated
  set's `btc_bits` values all match BTC's mainchain difficulty schedule, and
  all 35 stales are `validation_status=VALID` (0 REJECTED).
- **Within Stifter window**: Terracoin's AuxPoW activated 2016-09-23 and the validated set begins May 2017, both before Stifter et al. 2018's 2018-07-06 data freeze, yet the paper does not sample Terracoin. The validated window continues past the freeze to Aug 2020.

**Reference scripts.**

- `scripts/extract/extract_terracoin_auxpow.py:1` - JSON-driven extractor (`getblock <hash> true` → `auxpow.tx`, `auxpow.parentblock`).
- `scripts/classify/classify_terracoin_stales.py:1` - BTC RPC batch classifier.
- `scripts/compute_chain_novelty.py terracoin` - novelty vs upstream and vs chronologically earlier chains (replaces the bespoke `crossref_terracoin_stales.py` cross-reference).
- `node-infra/terracoin/{Dockerfile,docker-compose.yml,justfile,README.md}` - build infrastructure.

## 2. Extraction → potential stales

**Method.** RPC against the local terracoind. `getblock <hash> true` (Dash 0.12.2.x supports only the boolean `verbose` form, not verbosity levels) returns a fully-decoded `auxpow` object with the parent block header hex, decoded coinbase transaction (scriptsig + outputs), and the Merkle branches. Same extraction shape as Syscoin and Elastos - no binary parsing of `blk*.dat`.

**Phases.**

1. **Parse**: for each TRC block ≥ 833,000, read `auxpow.parentblock` (80 bytes) + `auxpow.tx.vin[0].coinbase` (scriptsig) + `auxpow.tx.vout` (outputs).
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. This does not establish Bitcoin's contemporaneous target.
3. **Dedup**: do *not* deduplicate at extraction time - multiple consecutive TRC blocks reference the same BTC `prevhash` but each contains a different parent header (different miner / nonce / coinbase). Downstream cross-source publication views deduplicate only exact `(height, hash)` identities.
4. **BTC RPC classify** (`classify_terracoin_stales.py`): batch `bitcoin-cli getblockheader`. Hit → `canonical`. Miss → look up `prev_hash`. Prev canonical → `stale`. Neither → `unknown`.

**Counts in the private intermediate output** (`terracoin_btc_valid.csv`, the PoW-passing-but-unclassified set):

| Stage | Rows |
|---|---:|
| Raw extraction (all AuxPoW-bearing TRC blocks ≥ 833,000) | 2,368,318 |
| After PoW filter (`terracoin_btc_valid.csv`) | 534,607 |
| After classification | **11,257 canonical + 35 stale + 523,315 unknown** |

The canonical rows were not persisted by the original 2026-04-24 run; the 2026-06-24 canonical refresh re-extracted the chain (byte-identical `terracoin_btc_valid.csv`) and backfilled the 11,257 canonical split.

The 99.95% AuxPoW-density figure is exact at the extraction stage: 2,368,318 AuxPoW-bearing blocks of 2,369,590 scanned (TRC 833,000 → 3,202,589; 1,272 skipped, 0 parse errors). Almost every TRC block from activation onward carries an AuxPoW parent header. The next filter retains only headers whose hash meets the target encoded in that header; it is not yet the Bitcoin contemporaneous-target check.

**Chain-specific quirks.**

- **Dash heritage**: the only Dash-Core-derived chain in scope (RSK, Elastos, and Hathor are non-Bitcoin-Core on other lineages). AuxPoW extraction is unaffected (`getblock` JSON works as for Syscoin), and with the wallet disabled at configure time the build needs neither Berkeley DB nor source patches.
- **`coinbase_outputs` uses the legacy `scriptPubKey.addresses` plural array**:
  terracoind is Dash-Core-0.12.x-derived, predating Bitcoin Core 0.18.0 (Apr
  2019), and exposes parent-coinbase addresses via the legacy plural
  `scriptPubKey.addresses` rather than the modern singular `.address` field.
  The normal extractor reads both shapes, so the regenerated classifier and
  validated outputs carry actual `addr:value|...` evidence. An earlier
  attribution pass recognised two additional `1Hash` rows from those output
  addresses; this is a historical result, not a current pipeline stage.
- **Strict chain ID enforcement**: `fStrictChainId=true`, `nAuxpowChainId=0x0032`. This prevents the parent header from using Terracoin's own chain ID; it does not establish Bitcoin parent identity or a Bitcoin-valid version.
- **Historical attribution context**: a private 2026-04-25 scriptSig-marker pass identified 28 of the 35 accepted rows (BTC.TOP 12, 1THash 8, Huobi Pool 6, WAYI.CN 2; 7 unidentified), and the coinbase-outputs backfill later added the two `1Hash` rows noted above. Mining-Dutch / Zergpool / Pool4ever (header table) are the chain's *current* SHA-256 network pools, not recovered-stale attributions. The public recovery pipeline does not reproduce any of those labels. The public result is the accepted direct-stale set and its novelty accounting.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_terracoin_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

The loader parses `coinbase_outputs` ("addr:value|..." with addresses sourced from the legacy plural `scriptPubKey.addresses` field - see §2 "Chain-specific quirks"). All 35 entries pass the filter.

**Post-filter count: 35 accepted direct-stale header candidates.**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py terracoin`. Per-stale row-level breakdown at `results/per-chain-novelty/terracoin.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 13 | 37.1 % |
| novel vs upstream | 22 | 62.9 % |

The 22-novel-vs-upstream figure is Terracoin's count of stales missing from the upstream dataset at the current pin (29 before upstream merged this project's contribution).

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Terracoin is 14th chronologically. The earlier-born integrated chains are namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven, and argentum:

| Split | Count |
|---|---:|
| also in upstream | 13 |
| also in earlier-born chain (`devcoin`: 18, `namecoin`: 8, `i0coin`: 5, `crown`: 3, `unobtanium`: 1 - first-claim distribution) | 35 |
| **novel at this position** | **0** |

> **Differs from the "4 novel" figure in earlier project notes.** The 4-novel count was a multi-chain cross-reference at extraction time. Under chronological precedence - with all chronologically-earlier integrated chains layered in, including Crown (AuxPoW activation 2015-08-25, chronological position 10) - every one of Terracoin's 35 validated stales is first-claimed by an earlier-born chain, so **0** are chronologically novel at Terracoin's position. Terracoin's standalone value is therefore the **22 novel-vs-upstream** stales (view a), not chronological-precedence novelty.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

### Unknown-chain origin (H1 vs H2)

An earlier private analysis, adapted from the Devcoin precedent, ran against
the 523,350-row classifier inventory (35 stale-labelled candidates plus
523,315 unknown rows). The aggregate results
are retained below. Its one-off script and row-level diagnostics remain in the
private archive and are not reproduced by this public release.

| Test | Result |
|---|---:|
| nBits epoch consistency | **0** / 523,315 (0.0%) |
| nBits consistency in multiblock unknown chains | 0 / 104,827 (37,168 roots, max depth 40) |
| Walk-terminus | dangling: 523,315 (no unknown walks into a Terracoin stale) |
| Namecoin-cross-confirmed unknown-roots present | 22 / 22 |
| Namecoin-cross-confirmed roots passing TRC epoch-match | 0 / 22 |
| BCH-fork-window unknowns (BTC 478,558 ± 6) | 1 (none epoch-matching) |
| BSV-fork-window unknowns (BTC 556,766 ± 6) | 1 (none epoch-matching) |

*Anchor note: the analysis constant 556,766 is the BCH-chain height at the BSV split; Bitcoin's own height on 2018-11-15 was near 551,000, so the BSV row as coded probes BTC blocks from ~Jan 2019 rather than the split itself. The finding is negative at either anchor.*

**Conclusion: H2, decisively.** Terracoin's 523,315 unknowns contain **zero headers matching Bitcoin's expected `nBits` epoch**. All 22 of the Namecoin-cross-confirmed unknown roots that Terracoin owns appear in the Terracoin unknown set, but none pass the epoch test. A historical private attribution pass labelled them **BTC.TOP: 16, Unknown: 4, Huobi Pool: 1, WAYI.CN: 1**. That label distribution is supporting context, not a result reproduced by the current public pipeline.

This wraps the cross-chain question: Namecoin (~7,841 unknowns, H2), Devcoin (75,141, H2 stronger), Terracoin (523,315, H2 strongest) all converge on the same answer. The broad unknown class across the integrated set is not lost BTC deep-reorg material.

## 4. Outputs & references

**Artifacts.** Loader inputs under `data/`, novelty tables under
`results/per-chain-novelty/`, and the strict/weak and monitor-evidence
exports are committed here. Row-level analysis diagnostics live in the private
archive.

- `data/validated-stales/terracoin_validated_stales.csv` - 35 validated stales (committed; the loader's input).
- `results/monitor-evidence/terracoin_monitor_evidence.csv` - 11,257
  canonical and 35 accepted stale observations.
- Private archive `terracoin_btc_valid.csv` - 534,607 PoW-passing rows (intermediate, before classification).
- Private archive split inventories: `terracoin_canonical_blocks.csv` (11,257 canonical, backfilled by the 2026-06-24 refresh), `terracoin_stale_blocks.csv` (35 stale), and `terracoin_unknown_blocks.csv` (523,315 unknown).
- `results/per-chain-novelty/terracoin.csv` - per-stale `(height, hash, in_upstream, first_seen_chain)` table.
- Private unknown-origin diagnostics include the per-row H1/H2 evidence and
  the 22 Namecoin-cross-confirmed roots.
- `node-infra/terracoin/{Dockerfile,docker-compose.yml,justfile,README.md}` - build infrastructure.

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (Terracoin row).
- Terracoin Foundation explorers at `explorer.terracoin.io` (Abe) and `insight.terracoin.io` - block-level sanity checks (both reachable as of 2026-07).
- `chainz.cryptoid.info/trc/` - supplied the recovery-time `addnode=` peers via its nodes API; the Chainz TRC listing has since expired ("hosting expired", observed 2026-07).

**Remaining work.**

None. The two follow-ups (`coinbase_outputs` address resolution; unknown-chain origin H1 vs H2) both closed 2026-05-14. Findings folded into §2 "Chain-specific quirks" and §3 "Unknown-chain origin (H1 vs H2)" respectively.

## 5. Integration history

- **2026-04-24** - original recovery (predecessor repo): Docker terracoind on ubuntu:20.04 synced from `bootstrap.dat` plus Chainz-pinned peers in ~95 minutes; extraction read 2,368,318 AuxPoW rows in ~44 minutes; classification yielded 35 stale + 523,315 unknown (canonical rows not persisted). Cross-reference at the time: 6 in upstream, 29 new-to-upstream, 4 novel across all prior recoveries.
- **2026-04-25** - pipeline integration under source tag `terracoin`; private scriptSig-marker attribution pass (28/35 identified - §2).
- **2026-05-14** - both follow-ups closed: the coinbase-outputs backfill (legacy plural `scriptPubKey.addresses`; +2 `1Hash` attributions) and the H1/H2 unknown-origin analysis (§3).
- **2026-05-29** - nBits-gate schema regeneration: node restarted from the archived datadir, all 35 rows re-validated `VALID`, backfilled outputs byte-identical.
- **2026-06-24** - canonical refresh: full re-extraction reproduced `terracoin_btc_valid.csv` byte-for-byte and backfilled the 11,257-row canonical split.
- **2026-07** - public release: novelty recomputed at the bumped upstream pin (13 in upstream / 22 novel; 7 of the original 29 were absorbed when upstream merged this project's contribution). The 2026-07 fact-check corrected the AuxPoW activation date from Oct 2017 (hard fork 2's month) to 2016-09-23 (TRC 833,000's block time). At that point Terracoin moved from position 14 to 13, ahead of Emercoin. SixEleven's subsequent insertion earlier in the chronology moved Terracoin back to its current position 14; novelty counts were unaffected.
- **2026-07-30** - the normal source extraction/classification path regenerated
  the canonical and validated outputs with authenticated child headers and
  source-native parent-coinbase addresses; all 11,257 canonical rows entered
  the uniform Monitor publication.
