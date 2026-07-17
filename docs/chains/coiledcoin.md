# CoiledCoin

| Field | Value |
|---|---|
| Ticker | CLC |
| AuxPoW activation | 2012-01-05 (CLC genesis; `GetAuxPowStartBlock()` returns 0, so AuxPoW is accepted from genesis onward) |
| Network status | Dead (bitcointalk thread marked `[DEAD]`; `mmpool/coiledcoin` archived as a dead coin; merge-mined to extinction in 2012, no advancing tip). Recovered from a single surviving archival node - see the intro. |
| Chronological position | 5 of 26 (after namecoin, geistgeld, i0coin, ixcoin; before devcoin) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; CoiledCoin merge-mined in 2012, inside the window, but was not sampled) |
| AuxPoW chain ID | 16 (collides with Syscoin chain 2; harmless at runtime) |
| Block time | 120 s nominal; ~50 min observed wall-clock cadence |
| Source tag (in code) | `coiledcoin` |
| Loader | `load_coiledcoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/coiledcoin_validated_stales.csv` |

CoiledCoin was announced 2012-01-05 by `makomk` and is famously associated with the January 2012 Eligius 51% attack: a majority-hashrate attack, launched within days of the chain's debut, that mined empty blocks and drove off miners (per a local note, possibly involving manipulation of AuxPoW commitments; that overwrite framing is not independently corroborated - the external record describes a conventional 51% attack, notable mainly because merge mining let Eligius attack CoiledCoin without giving up its Bitcoin block rewards). CoiledCoin is dead: the bitcointalk thread is marked `[DEAD]`, the maintainer's own archive (`mmpool/coiledcoin`) describes it as a dead coin, and no external explorer or advancing tip exists. It was recovered from a single surviving archival node: at sync time `LFM.knotwork.com:8368` (markm's node, distinct from creator makomk) was reachable but its tip had been dormant since 2026-03-10, while the second configured seed `server1.knotwork.net:8368` was unreachable.

## 1. Chain data

**Source.** Local archival `coiledcoind` node on `<archival-host>`, built from `mmpool/coiledcoin` at commit `0aa503c` (the last upstream commit, "Add checkpoint at block 438,000") inside a Docker container. CoiledCoin is a **pre-0.6 Bitcoin Core fork (Jan 2012)** with Vince Durham's original AuxPoW patch applied - the hardest build of any chain in scope. The container build builds Berkeley DB 4.8 from source fetched at build time (checksum-pinned) and applies a single atomic-ops patch (`bdb-atomic.patch`); modern Ubuntu doesn't package `libdb4.8` and the pre-0.6 codebase still uses it. P2P sync proceeded via `addnode=` entries to `markm`'s endpoints.

**Provenance.** Source tarball cached in the private chain archive (md5 `befbeeb92410260b9169bbde96a98178`). Docker scaffold + patches at `node-infra/coiledcoin/`. Raw extraction and full classifier outputs are private-archive material; the public repo keeps only the validated stale subset.

**Coverage.** Accepted direct-stale candidates span BTC heights **161,761 → 187,452** (parent-block timestamps 2012-01-11 → 2012-07-04, about six months). This is a much narrower window than ixcoin or Devcoin. No later accepted candidates were recovered, and no live, advancing tip is independently verifiable.

**Integration status.** Wired into the recovery loader and novelty pipeline. The validated CSV lives at `data/validated-stales/coiledcoin_validated_stales.csv` (the stale subset of the private full classifier output); `load_coiledcoin_stales()` is registered alongside the other Namecoin-family loaders; CoiledCoin follows ixcoin in the chronological integration order (position 5).

**Holes.**

- **Pre-AuxPoW**: none. CoiledCoin's `GetAuxPowStartBlock()` returns 0 - merged mining was accepted from genesis.
- **Before the BIP34 transition** (BTC < 224,413): the entire CoiledCoin-recovered range predates BIP34 enforcement. Heights are resolved from active-chain parents, with `nBits` epoch and `nTime` as supporting evidence.
- **Post-2012 activity**: the chain is dead, with no independently verifiable advancing tip. Any later candidate coverage is absent from the extraction.

**Reference scripts.**

- `scripts/extract/extract_auxpow_from_blkdat.py:1` - generic Namecoin-family `blk*.dat` extractor with `--chain coiledcoin`.
- `scripts/classify/classify_coiledcoin_stales.py:1` - chain-specific classifier (carries the `eligius_attack_window` flag column for the Jan 2012 attack period).
- `node-infra/coiledcoin/{Dockerfile,docker-compose.yml,justfile,bdb-atomic.patch,config.guess,config.sub,README.md}` - build infrastructure (Ubuntu 16.04 base with Berkeley DB 4.8.30 built from a checksum-pinned source fetch; `config.guess`/`config.sub` teach BDB's 2010 autotools about modern arches).

## 2. Extraction → potential stales

**Method.** Offline `blk*.dat` binary parse with the generic Namecoin-family extractor. Pre-0.6 Bitcoin Core's RPC predates `AuxpowToJSON()` and doesn't return AuxPoW data via any `getblock` verbosity, so the binary path is the only practical option (also matches Devcoin's pattern, where the JSON RPC also lacked AuxPoW exposure).

**Phases.**

1. **Parse**: walk all CLC blocks ≥ 1 in `blk*.dat`; for each AuxPoW-bearing block, extract parent header + coinbase tx + Merkle branch.
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header.
3. **Dedup** on `btc_header_hash`.
4. **BTC RPC classify** (`classify_coiledcoin_stales.py`): batch `bitcoin-cli getblockheader`. Hit → `canonical`. Miss → look up `prev_hash`. Prev canonical → `stale`. Neither → `unknown`.
5. **Eligius-attack flag**: rows whose parent-block timestamp falls in the Eligius attack window (2012-01-05 to 2012-01-15 UTC) get `eligius_attack_window=true`. This is the highest-value subset on this chain, AuxPoW-layer evidence associated with the documented Eligius majority-hashrate attack.

**Counts.** The offline parse scanned 1,379,338 CLC blocks (881,821 AuxPoW-flagged; 497,517 non-AuxPoW skipped) and, after the self-target PoW filter, yielded **13,943** unique parent headers (all unique; dedup removed none). Classifying each against Bitcoin Core:

| `classification` | Count |
|---|---:|
| `canonical` | 608 |
| `stale` | 27 |
| `unknown` | 13,308 |
| **Total** | **13,943** |

The 608 canonical parents are dropped from the persisted output; the committed pipeline keeps only the 27 VALID stales, and the private split inventory `coiledcoin_stale_blocks.csv` holds the remaining 13,335 non-canonical rows (27 stale + 13,308 unknown). The canonical rows were not persisted by the original 2026-05 prototype split and were backfilled by the 2026-06-23 canonical refresh; the earlier "13,335 = 27 stale + 13,308 unknown" figure was that non-canonical subset, not the full classifier output.

Of the 27 stales, **1 is in the Eligius attack window** (`eligius_attack_window=true`, BTC 161,761 / 2012-01-11). The other 26 span BTC 163,226 → 187,452 (Feb → Jul 2012), after the attack, in the dwindling tail of merge-mining activity before the chain went quiet.

**Chain-specific quirks.**

- **Chain ID 16 collides with Syscoin's AuxPoW chain ID 16** (Syscoin's "chain 2"). Harmless at runtime - each chain enforces its own `GetOurChainID()` (CoiledCoin's returns 16 in `src/main.cpp`) - but cross-chain validation tooling must key on `(chain_id, chain_name)` rather than chain ID alone.
- **Pre-0.6 build constraints**: Berkeley DB 4.8 built from a checksum-pinned source fetch, `boost::filesystem` API patched, OpenSSL primitives swapped to EVP variants, BOOST_FOREACH replaced. All handled by the Docker build.
- **Eligius attack provenance**: external sources describe a Luke-Jr / Eligius majority-hashrate (51%) attack that mined empty blocks and drove off miners; the stronger claim that AuxPoW commitments in BTC coinbases were used to overwrite CoiledCoin history is an unverified local note, not externally corroborated. The recovered Eligius-window stale block (1 of 27) is the artifact this chain was extracted to surface, concrete evidence at the AuxPoW layer of the kind of selfish-mining-adjacent behaviour the broader project investigates.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_coiledcoin_stales()` in `stale_blocks.py`):

```python
classification == "stale"
```

The `eligius_attack_window` flag is preserved in the validated CSV but does not affect the loader filter. All 27 entries in the validated CSV pass.

**Post-filter count: 27 accepted direct-stale header candidates.**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py coiledcoin`. Per-stale row-level breakdown at `results/per-chain-novelty/coiledcoin.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 19 | 70.4 % |
| novel vs upstream | 8 | 29.6 % |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain (with integrated loaders)**

Chronologically earlier with integrated loaders: `namecoin`, `geistgeld`, `i0coin`, `ixcoin`. Geistgeld contributes zero validated stales; ixcoin's validated set contains all 27 CoiledCoin hashes.

| Split | Count |
|---|---:|
| also in upstream | 19 |
| also in earlier-born chain | 27 (namecoin: 17, i0coin: 8, ixcoin: 2 - first-claim distribution) |
| **novel at this position** | **0** |

Every CoiledCoin stale is first-claimed by an earlier chain. The one record in the Eligius attack window (BTC 161,761) is first-claimed by i0coin (it is not in upstream, and namecoin does not carry it). The two records that would be novel against upstream alone - BTC 165,096 (2012-02-03) and BTC 184,836 (2012-06-16) - are both present in ixcoin's earlier-born validated set, so ixcoin claims them first.

> **Consistent with the "zero novel" figure from the original recovery.** CoiledCoin's genesis is 2012-01-05 (source `nTime` 1325782557; the genesis coinbase reads "5 January 2012 | BBC News | Mortgage rationing becomes worse"), which places it *after* ixcoin (2011-12-31) in the chronological order. All 27 CoiledCoin hashes also appear in ixcoin's and devcoin's validated sets; because ixcoin is chronologically earlier, it claims every one first. An earlier draft used an unsourced 2011-12-24 activation date that wrongly placed CoiledCoin before ixcoin and credited it with 2 novel stales; the source genesis corrects that to 0.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/coiledcoin_validated_stales.csv` - 27 validated stales (committed; the loader's input). Preserves the `eligius_attack_window` flag column.
- `node-infra/coiledcoin/{Dockerfile,docker-compose.yml,justfile,bdb-atomic.patch,config.guess,config.sub,README.md}` - build infrastructure.
- `results/per-chain-novelty/coiledcoin.csv` - per-stale `(height, hash, in_upstream, first_seen_chain)` table.

**Private archive artifacts.**

- Split inventories: `coiledcoin_canonical_blocks.csv` (608 canonical, backfilled by the 2026-06-23 canonical refresh), `coiledcoin_stale_blocks.csv` (27 stale), and `coiledcoin_unknown_blocks.csv` (13,308 unknown).
- `coiledcoin_auxpow_candidates.csv` - 13,943 self-target-PoW-valid raw candidates (pre-classification).
- `coiledcoin-25-Oct-2012.tgz` - cached source tarball.
- `coiledcoin-mf.zip` - original makomk Windows binaries from launch day (reference only).

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (CoiledCoin row).

## 5. Integration history

CoiledCoin was originally treated as a null result on the basis of a
**pipeline-order** novelty check in the retired `analysis.py` pipeline
(`namecoin → i0coin → syscoin → devcoin → ixcoin → …`). Devcoin and
ixcoin merged first and claimed every CoiledCoin hash, leaving zero novel
contributions. The chain was retained as a cross-confirmation source rather
than integrated.

A later doc-effort follow-up briefly reclassified it to 2 novel stales, on the
basis of an **unsourced 2011-12-24 activation date** that placed CoiledCoin
ahead of ixcoin in `config.py:CHAINS_BY_AUXPOW_ACTIVATION`. The chain's source
genesis is 2012-01-05 (`nTime` 1325782557; the genesis coinbase reads "5 January
2012 | BBC News | Mortgage rationing becomes worse"), which places it *after*
ixcoin (2011-12-31) and before devcoin (2012-01-07) - chronological position 5,
not 4. With the corrected date CoiledCoin is 0 novel again, consistent with both
the original pipeline-order result and the node-infra README. The chain remains
integrated alongside the other Namecoin-family chains, per the same-handling
principle ("each chain should be integrated in the same manner insofar as
possible"):

- `data/validated-stales/coiledcoin_validated_stales.csv` (27 rows) extracted from the prototype output.
- `COILEDCOIN_CSV` constant in `config.py`.
- `load_coiledcoin_stales()` in `stale_blocks.py` (ixcoin-family pattern: `classification == "stale"`).
- Registration in `CHAIN_SPECS` and `CHAINS_BY_AUXPOW_ACTIVATION` at its
  chronological position (5, after ixcoin), with `load_coiledcoin_stales()`
  supplying the public input.
- Per-source coverage and reporting updated.

The `eligius_attack_window` column is preserved on the validated CSV for diagnostic use; the loader doesn't act on it.
