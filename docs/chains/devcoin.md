# Devcoin

| Field | Value |
|---|---|
| Ticker | DVC |
| AuxPoW activation | 2012-01-07 (DVC height 25,000, BTC height ~161,000) |
| Network status | Active (small but functional P2P network; `seed01.devcoin.org` live) |
| Chronological position | 6 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin) |
| In Stifter et al. 2018 baseline | **Yes** (one of the paper's seven measured Bitcoin-parent chains; Table 1) |
| AuxPoW chain ID | 4 |
| Block time | 10 minutes (≈ 1:1 with BTC) |
| Source tag (in code) | `devcoin` |
| Loader | `load_devcoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/devcoin_validated_stales.csv` |

Devcoin was the sixth Namecoin-family SHA-256d AuxPoW chain by merged-mining activation order, launched in 2011 (genesis nTime 1311305081 = 2011-07-22 UTC; public introduction cited as 5 Aug 2011) and merge-mining-enabled at DVC block 25,000 on 7 Jan 2012 with Daniel Kraft's AuxPoW (ported via Syscoin's fork). It is the most prolific of the Dec 2011 to Jan 2012 cohort by accepted direct-stale candidate count (468 vs ixcoin's 465 and i0coin's 166) and a leading source of novel-vs-upstream candidates (92 at the current upstream pin; only RSK contributes more). Devcoin's distinctive coinbase structure, a 50,000 DVC reward split 5,000 to the miner and 45,000 to project funds across many output recipients, makes output-based pool attribution a future, separate analysis rather than part of the current loader.

## 1. Chain data

**Source.** Local `devcoind` node on `<archival-host>`, built from `devcoin/core` at commit `301c1ae` (the upstream tip at extraction time) inside a Docker container. Devcoin Core is a **Bitcoin Core 22.x fork**, among the most modern codebases of any chain in scope, though Syscoin's newer Bitcoin Core lineage is more recent. The deployed build did not expose decoded AuxPoW through `getblock <hash> 1`, so extraction used `getblock <hash> 0` and parsed the raw block bytes returned by RPC. Direct parsing of `blk*.dat` files was not needed.

**Provenance.** Docker scaffold at `node-infra/devcoin/`. P2P sync proceeded via DNS seed `seed01.devcoin.org` (the only live one of four) plus optional `addnode=` fallback. Bitcoin Core on `<archival-host>` provided the BTC RPC for classification.

**Coverage.** Validated stales span BTC heights **161,761 to 661,866** (Jan 2012 to 18 Dec 2020) and DVC heights **25,699 to 450,501**. This wide window includes the relatively sparse early stale-block record and extends several years past the BCH fork.

**Holes.**

- **Pre-AuxPoW** (DVC 0 → 24,999): solo SHA-256 mining, no embedded BTC parent headers.
- **BIP34 transition**: before height 224,413, height is resolved from the active-chain parent without enforcing a coinbase prefix. From 224,413 through 227,930, the prefix is required for version 2 or newer blocks while version 1 remains valid. From 227,931 it is required for every valid block.
- **Publication gate**: the committed CSV persists expected `nBits`, median-time-past, historical minimum-version, coinbase scriptSig length, and BIP34 verdicts. Sixteen historical candidates are excluded: 13 for BIP34 height, two post-BIP66 version 2 headers, and one 103-byte coinbase scriptSig, leaving 468 public rows. Passing this gate is not full Bitcoin block validation; see the [data validity contract](../data-validity.md).
- **Current audit**: on 20 July 2026, all 468 accepted direct rows were replayed against Bitcoin Core tip 958,882 and passed every available header-context check. This was not a full-block consensus replay.
- **Coinbase output noise**: `coinbase_outputs` is a `|`-delimited list of
  `addr:value` pairs; the loader preserves them in semicolon form for future
  attribution work. The current public loader does not identify a pool.

**Reference scripts.**

- `scripts/extract/extract_devcoin_auxpow.py:1` - RPC-driven extractor (raw-hex `getblock` + binary CAuxPow parse - note: despite the 22.x codebase, the `getblock` JSON in the deployed build did not expose decoded AuxPoW; binary parsing was used).
- `scripts/classify/classify_devcoin_stales.py:1` - BTC RPC batch classifier.
- Historical multi-block-fork and unknown-origin analyses are retained in the
  private archive; their original one-off scripts are not part of this public
  release.
- `node-infra/devcoin/{Dockerfile,docker-compose.yml,justfile,README.md}` - build infrastructure.

## 2. Extraction → potential stales

**Method.** RPC raw-hex against the local devcoind. For each DVC block ≥ 25,000, fetch `getblock <hash> 0` and parse the binary CAuxPow tail. The AuxPoW format is the Daniel Kraft / Vince Durham lineage - byte-identical to Namecoin/i0coin/ixcoin/CoiledCoin.

> **Surprise from extraction**: a clean JSON path via `getblock <hash> 1` was anticipated (since Devcoin is a Bitcoin Core 22.x fork with `AuxpowToJSON()` available in the codebase). In practice the deployed build of `devcoind` did not return a decoded `auxpow` object in the JSON response, so the raw-hex + binary parse was the path taken. Same pattern as ixcoin (0.14.x) and Unobtanium (0.11.x) despite those chains' much older lineage.

**Phases.**

1. **Parse**: walk all DVC blocks ≥ 25,000 via raw hex; extract parent header + coinbase tx + Merkle branch.
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. Bitcoin's contemporaneous target is checked later for stale-labelled candidates.
3. **Dedup** on `btc_header_hash`.
4. **BTC RPC classify** (`classify_devcoin_stales.py`): batch `bitcoin-cli getblockheader`. Hit → `canonical`. Miss → look up `prev_hash`. Prev canonical → `stale`. Neither → `unknown`.
5. **Header-context publication gate**: require expected `nBits`, median-time-past, Bitcoin's historical minimum block versions, the coinbase scriptSig length bound, and BIP34's version-sensitive height rule.

**Counts in the private full classifier output** (129,725 rows total):

| `classification` | Count |
|---|---:|
| `canonical` | 54,100 |
| `unknown` | 75,141 |
| `stale`-labelled candidate | 484 |
| **Total** | **129,725** |

The 54,100 canonical parents are dropped from the persisted output; the committed
pipeline keeps only the 468 VALID stales, and the private split inventory
`devcoin_stale_blocks.csv` holds the remaining 75,625 non-canonical rows (484
stale + 75,141 unknown). The canonical rows were not persisted by the original
2026-04 prototype split and were backfilled by the 2026-06-23 canonical refresh;
the earlier "75,625 = 484 stale + 75,141 unknown" figure was that non-canonical
subset, not the full classifier output. The full historical CSV is gitignored due
to size. The committed validated file contains 468 rows after the
consensus-invalid overlay removes 16 candidates.

**Chain-specific quirks.**

- **50k DVC coinbase output structure**: Devcoin's block reward of 50,000 DVC was split 5,000 to the miner and 45,000 across many recipient addresses (project funds). The recovered BTC parent coinbases naturally have far fewer outputs, but the *Devcoin* coinbase that wraps them carries the unusual structure - relevant when reading `dvc_height` provenance.
- **Multi-block-fork reconstruction (2 candidates)**: a historical private
  diagnostic records two candidate BTC header-chain reconstructions from
  Devcoin unknown rows. This is a much smaller yield than Namecoin's 18
  candidate reconstructions, but the chains' overlapping windows provide
  corroborating provenance.
- **`coinbase_outputs` semicolon-joined**: the loader transforms the `|`-delimited `addr:value|addr:value` form into `;`-joined `addr;addr` (drops `OP_RETURN` entries), preserving the established loader schema for later attribution research.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_devcoin_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status.startswith("VALID")
```

The `validation_status` gate is persisted on this CSV. All 468 entries are
`validation_status=VALID`; the loader also applies the exact-key exclusion
overlay.

**Post-filter count: 468 accepted direct-stale header candidates.**

**Derived strict/weak relevance: 1 strict, 0 weak observation.** This is an
unknown row admitted to the separate relevance axis, not a direct-stale
promotion. It remains `classification=unknown` in the monitor evidence.

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py devcoin`. Per-stale row-level breakdown at `results/per-chain-novelty/devcoin.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 376 | 80.3 % |
| novel vs upstream | 92 | 19.7 % |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Devcoin is 6th chronologically. The chronologically-earlier chains with integrated loaders are `namecoin`, `geistgeld`, `i0coin`, `ixcoin`, and `coiledcoin`. Geistgeld contributes zero accepted direct-stale candidates. Breakdown:

| Split | Count |
|---|---:|
| also in upstream | 376 |
| also in earlier-born chain (`namecoin`: 299, `ixcoin`: 95, `i0coin`: 27 - first-claim distribution) | 421 |
| **novel at this position** | **32** |

> **Reconciles the historical "76 novel" figure.** A private historical result records 76 hashes flagged as Devcoin-novel during the original recovery analysis. Those are precisely the rows that are *not in upstream* but *not yet excluding chains added later*. The 76 set is a superset of our chronological-novel 32, with the difference (44) being hashes that ixcoin - earlier-born but integrated after Devcoin - now claims under chronological precedence. The historical pipeline placed Devcoin before ixcoin; chronological order reverses that precedence.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**Artifacts.** Loader inputs under `data/`, novelty tables under
`results/per-chain-novelty/`, and the strict/weak and monitor-evidence
exports are committed here. Row-level analysis diagnostics live in the private
archive.

- `data/validated-stales/devcoin_validated_stales.csv` - 468 publication-gate-accepted direct-stale header candidates (committed; the loader's input).
- Private archive split inventories: `devcoin_canonical_blocks.csv` (54,100 canonical, backfilled by the 2026-06-23 canonical refresh), `devcoin_stale_blocks.csv` (484 stale), and `devcoin_unknown_blocks.csv` (75,141 unknown).
- Private historical novelty result: 76 Devcoin-recovered candidates not in the then-current upstream set. It is a superset of the public chronological-novel 32; later-integrated, earlier-born chains receive precedence for the remainder.
- Private diagnostics include two candidate multi-block BTC header-chain
  reconstructions and the H1/H2 evidence over all 75,141 unknown rows.
- `results/per-chain-novelty/devcoin.csv` - per-stale `(height, hash, in_upstream, first_seen_chain)` table.
- `node-infra/devcoin/{Dockerfile,docker-compose.yml,justfile,README.md}` - build infrastructure.

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (Devcoin row).

## 5. Unknown-chain origin - RESOLVED

The same H1/H2 origin question used for Namecoin was applied to Devcoin's
75,141 unknown rows in an earlier private analysis. Its aggregate findings are
retained here, but the one-off reproducer and row-level outputs are not part of
this public release.

The private archive retains the per-unknown evidence table and aggregate
counts.

| Test | Result | Interpretation |
|---|---:|---|
| nBits epoch consistency, full unknown set | 6 / 75,141 (0.0080%) | Rejects deep-BTC-reorg as a broad explanation. |
| `nBits` epoch consistency, multiblock unknown-chain nodes | 2 / 8,607 (0.0232%) | The multiblock unknown graph almost entirely fails Bitcoin's expected-target history. |
| Recursive walk terminus | 75,139 dangling, 2 stale-rooted | Almost every row still dangles; only two walk into known Devcoin stale-rooted BTC forks. |
| Multiblock unknown graph | 3,668 roots, 8,607 nodes, max depth 37 | Large unknown graph, but not BTC-epoch-consistent. |

The six BTC-epoch-matching unknown rows are:

| Time | Pool | BTC height | Terminus | Notes |
|---|---|---:|---|---|
| 2013-09-07 09:37:46 UTC | Eligius | 256,559 | stale | One of the known Devcoin stale-rooted BTC fork descendants. |
| 2013-09-07 15:30:52 UTC | Eligius | 256,559 | stale | One of the known Devcoin stale-rooted BTC fork descendants. |
| 2014-09-07 15:42:27 UTC | AntPool | 319,569 | dangling | Missing parent is a Stifter `is_shadow_block=True` row. |
| 2014-11-26 08:23:53 UTC | F2Pool | 331,674 | dangling | Missing parent is a Stifter `is_shadow_block=True` row. |
| 2014-11-26 08:31:33 UTC | F2Pool | 331,675 | dangling | Same Stifter shadow parent as the prior row; depth 2. |
| 2016-01-21 20:06:08 UTC | EclipseMC | 394,335 | dangling | Missing parent is a Stifter `is_shadow_block=True` row. |

**Conclusion.** Devcoin answers the same way as Namecoin, but more strongly: the broad unknown class is not lost BTC deep-reorg material. The overwhelming majority of Devcoin unknowns fail BTC's contemporaneous nBits schedule, including essentially the entire multiblock unknown graph. The few BTC-like exceptions are already known historical fork/shadow-chain fragments.

**Loader decision.** `load_devcoin_stales()` should continue loading only rows
with `classification == "stale"` and a `VALID`-prefixed `validation_status`.
No Devcoin unknown subset is sufficiently BTC-rooted to admit into fork-rate
accounting.

**Remaining work.**

- **Future pool attribution on 50k-output coinbases**: when attribution work begins, confirm that it uses the recovered BTC parent's coinbase rather than Devcoin's own multi-recipient coinbase, and test P2Pool-style multi-payout edge cases explicitly.
