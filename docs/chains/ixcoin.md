# ixcoin

| Field | Value |
|---|---|
| Ticker | IXC |
| AuxPoW activation | 2011-12-31 (IXC height 45,001, BTC height ~159,910) |
| Network status | Dormant (~8 reachable peers at sync time, DNS seeds dead) |
| Chronological position | 4 of 26 (after namecoin, geistgeld, i0coin; before coiledcoin) |
| In Stifter et al. 2018 baseline | **Yes** (one of the paper's seven measured Bitcoin-parent chains; Table 1) |
| Source tag (in code) | `ixcoin` |
| Loader | `load_ixcoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/ixcoin_validated_stales.csv` |

ixcoin was the fourth SHA-256d AuxPoW chain by merged-mining activation order (after Namecoin, Geistgeld, and i0coin). AuxPoW chain ID is **3** (Namecoin is 1). Merge-mining activated at IXC 45,001 on 2011-12-31, about twelve weeks after Namecoin's activation, so ixcoin's recovery window slightly post-dates Namecoin's. The chain is now dormant but not formally dead; eight peers were reachable when the sync was performed in 2026.

## 1. Chain data

**Source.** Local archival `ixcoind` node on `<archival-host>`, built from `IXCore/IXCoin` at commit `8207734` (the `v0.14.1` release-tag commit, "Merge pull request #2 from IXCore/DocUpdate", 2018-01-30; upstream `master` carries 13 later non-release commits through September 2018) inside a Docker container. Released binaries don't build cleanly on modern toolchains; the local build applies a single patch (`node-infra/ixcoin/patches/0001-modern-toolchain.patch`) that touches six source files to compile against GCC 13 + modern Boost. Extraction is via `getblock <hash> 0` (raw hex) - IXCore is a Bitcoin Core 0.14.x fork that doesn't expose decoded `auxpow` JSON, so the binary CAuxPow payload is parsed directly in Python.

**Provenance.** IXCore Dockerfile + patches at `node-infra/ixcoin/`. DNS seeds (`uk.ixcoin.co`, `nyc.ixcoin.co`, `sgp.ixcoin.co`) were all NXDOMAIN at sync time; peers were pinned via `addnode=` entries (initial seed IPs `64.71.72.56`, `65.21.12.118`, plus six more harvested from `chainz.cryptoid.info/ixc/api.dws?q=nodes`). Chain data is small (~1–2 GB) because IXC block rewards dropped to 0 at IXC 227,499 and were restored to 1 IXC at IXC 450,000 - most blocks contain only the coinbase transaction.

**Coverage.** Accepted direct-stale candidates span BTC heights **161,761 to 422,212** (11 Jan 2012 to 25 Jul 2016) and IXC heights **51,376 to 330,060**. The extraction was run over IXC 45,001 to chain tip (~1,029,664); no later accepted direct-stale candidates were observed.

**Holes.**

- **Pre-AuxPoW** (IXC 0 → 45,000): solo SHA-256 mining, no embedded BTC parent headers.
- **BIP34 transition**: before height 224,413, height is resolved from the active-chain parent without enforcing a coinbase prefix. From 224,413 through 227,930, the prefix is required for version 2 or newer blocks while version 1 remains valid. From 227,931 it is required for every valid block. The CSV's `btc_height` is the parent-derived value.
- **No BCH/BSV contamination** to filter: ixcoin's accepted candidate set ends at BTC 422,212 (Jul 2016), well before the BCH fork in Aug 2017. The public set contains 465 publication-gate-accepted direct-stale header candidates. Thirteen historical candidates are excluded: 11 fail BIP34 height, one post-BIP66 version 2 header fails the minimum version 3 rule, and one has a 103-byte coinbase scriptSig above Bitcoin's 100-byte limit. See the [data validity contract](../data-validity.md) for the gate's scope.
- **Current audit**: on 20 July 2026, all 465 accepted direct rows were replayed against Bitcoin Core tip 958,882 and passed every available header-context check. This was not a full-block consensus replay.
- **Network fragility**: only 8 reachable peers at sync. Chain data has been backed up; if the network collapses entirely before any further extraction work, the snapshot is the only remaining source.

**Reference scripts.**

- `scripts/extract/extract_ixcoin_auxpow.py:1` - raw-hex `getblock` extractor (binary CAuxPow parse, no decoded JSON path).
- `scripts/classify/classify_ixcoin_stales.py:1` - BTC RPC batch classifier.
- `node-infra/ixcoin/{Dockerfile,docker-compose.yml,justfile,patches/}` - IXCore build infrastructure.

## 2. Extraction → potential stales

**Method.** RPC raw-hex against the local ixcoind. For each IXC block 45,001 → tip, fetch `getblock <hash> 0` and parse the binary CAuxPow tail. The AuxPoW format is byte-identical to Namecoin's (Vince Durham's original specification), so the existing Namecoin binary parser is reused.

**Phases.**

1. **Parse**: walk all IXC blocks ≥ 45,001 via raw hex; for each block carrying CAuxPow, extract the parent header (80 bytes), coinbase tx, and Merkle branch.
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. This is not the later comparison against Bitcoin's contemporaneous target.
3. **Dedup** on `btc_header_hash` (the same BTC parent can be referenced by multiple IXC blocks before a new BTC tip is mined).
4. **BTC RPC classify** (`classify_ixcoin_stales.py`): batch `bitcoin-cli getblockheader <hash>` per candidate. Hit → `canonical`. Miss → look up `prev_hash`. Prev canonical → `stale`. Neither canonical → `unknown`.
5. **Header-context publication gate**: require expected `nBits`, median-time-past, Bitcoin's historical minimum block versions, the coinbase scriptSig length bound, and BIP34's version-sensitive height rule. This leaves 465 public rows and excludes 13 historical candidates.

**Counts in the private full classifier output** (301,260 rows total):

| `classification` | Count |
|---|---:|
| `canonical` | 46,808 |
| `unknown` | 253,974 |
| `stale`-labelled candidate | 478 |
| **Total** | **301,260** |

The 46,808 canonical parents were not persisted by the original 2026-04 prototype
split and were backfilled by the 2026-06-24 canonical refresh; the earlier
"254,452 = 253,974 unknown + 478 stale" figure was that non-canonical subset, not
the full classifier output. The full historical CSV is gitignored due to size. The
committed validated file contains 465 rows after the error-blocks dataset
(`data/error-blocks/error_blocks.csv`) removes 13 shared consensus-invalid
candidates.

**Chain-specific quirks.**

- **No `auxpow` JSON in RPC**: IXCore's 0.14.x heritage means `getblock <hash> 1` and `2` don't include a decoded AuxPoW object. Extraction always goes through `getblock <hash> 0` + binary parse. The same raw-RPC path was needed for the deployed Devcoin Core 22.x build and for Unobtanium's 0.11-era fork.
- **Empty-coinbase blocks** (IXC 227,499 → 449,999): block reward = 0 during this range; blocks carry only the coinbase tx with no outputs. The AuxPoW payload is still present and is what we extract.
- **BTC height inference before BIP34 enforcement**: same logic as the Namecoin pipeline. `nBits` epoch boundary and `nTime` give a height window that is narrowed by active-chain `prev_hash` resolution. During BIP34's transition, the recovered header version determines whether the coinbase prefix is mandatory.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_ixcoin_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

The `validation_status` gate is persisted on this CSV. All 465 entries are
`validation_status=VALID`; the loader also applies the exact-key error-blocks
exclusion gate (`data/error-blocks/error_blocks.csv`).

**Post-filter count: 465 accepted direct-stale header candidates.**

**Derived strict/weak relevance: 3 strict, 0 weak observations.** These are
unknown rows admitted to the separate relevance axis, not direct-stale
promotions. They remain `classification=unknown` in the monitor evidence.

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py ixcoin`. Per-stale row-level breakdown at `results/per-chain-novelty/ixcoin.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 399 | 85.8 % |
| novel vs upstream | 66 | 14.2 % |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

ixcoin is 4th chronologically. The chronologically-earlier chains with integrated loaders are `namecoin`, `geistgeld`, and `i0coin` (`coiledcoin`, 2012-01-05, is chronologically *later* than ixcoin). After adding upstream plus those earlier chains, the breakdown is:

| Split | Count |
|---|---:|
| also in upstream | 399 |
| also in earlier-born chain (`namecoin`: 328, `i0coin`: 29) | 357 |
| **novel at this position** | **50** |

> Differs from the "6 novel" figure in earlier project notes. The previous count was computed against the in-code merge-pipeline order, where `devcoin` and `syscoin` were merged before `ixcoin` and claimed 44 of these hashes first. Under chronological precedence (used here), `devcoin` (2012-01-07) and `syscoin` (2019-06-03) come **after** ixcoin, so ixcoin retains those novelty claims. This is exactly the order-dependence the chronological convention was designed to neutralise - see `config.py:CHAINS_BY_AUXPOW_ACTIVATION` and the explanatory note in `docs/auxpow-recovery.md`.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/ixcoin_validated_stales.csv` - 465 publication-gate-accepted direct-stale header candidates (committed; the loader's input).
- Private archive split inventories: `ixcoin_canonical_blocks.csv` (46,808 canonical, backfilled by the 2026-06-24 canonical refresh), `ixcoin_stale_blocks.csv` (478 stale), and `ixcoin_unknown_blocks.csv` (253,974 unknown).
- `results/per-chain-novelty/ixcoin.csv` - per-stale `(height, hash, in_upstream, first_seen_chain)` table (regenerate with `python scripts/compute_chain_novelty.py ixcoin`).

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (ixcoin row).
- `node-infra/ixcoin/README.md` - Docker setup.

**Remaining work.**

- Unknown-chain origin (H1 vs H2). Namecoin's current publication analysis does
  not support the broad deep-reorganisation hypothesis. The 253,974 ixcoin
  unknowns yield 3 strict observations under the separate relevance axis; the
  remaining population is still useful for characterising the unidentified
  parent-header substrate without presuming a Bitcoin origin.
- Extending coverage past BTC 422,212. The chain's IXC tip extends well past where accepted direct-stale candidates stop; understanding why would close the picture.
