# Crown

| Field | Value |
|---|---|
| Ticker | CRW |
| AuxPoW activation | 2015-08-25 (CRW height **453,273**; activation block timestamp 1440546428 UTC) |
| Network status | Merge-mining ended April 2019 (full MN-PoS replacement of PoW at CRW 2,330,000, Crown v0.13.0 "Jade"); 2026 chain-tip liveness unconfirmed, token dormant. All source-coded DNS seeds dead, peer discovery via a Wayback harvest of `monitor.crownplatform.com`. |
| Chronological position | 10 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium; before myriadcoin) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; Crown merge-mined from 2015, inside the window, but was not sampled) |
| AuxPoW chain ID | `20` (`0x14`), **`fStrictChainId=true`**. This prevents the parent header from using Crown's own chain ID; it does not prove that the parent is Bitcoin. |
| Algorithms | Single-algo SHA-256d. No per-algo `nVersion` filter - the only extraction gate is the AuxPoW version bit. |
| Algo encoding (in `nVersion`) | n/a (single-algo). AuxPoW flag = bit 8 (`VERSION_AUXPOW = 1 << 8`); chain ID at bits 16+ (`20` in the PoW era, cosmetically rotated to `22`/`0x16` in the PoS era). |
| Block time | 60 s (1-minute slots; Dash-derived target-spacing). |
| Source tag (in code) | `crown` |
| Loader | `load_crown_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/crown_validated_stales.csv` |

Crown is a 2014 Bitcoin/Dash-derived chain. It carries Dash's masternode and on-chain governance layer on top of a Bitcoin-Core base, with standard Namecoin-style (Daniel Kraft lineage) SHA-256d AuxPoW. It is the **10th chain by AuxPoW-activation date**, slotting between Unobtanium (2015-05-08) and Myriadcoin (2015-09-26). The recovery is also a methodological footnote worth flagging: Crown was previously **deferred** after the network had been declared dead because every DNS seed and the hardcoded bootstrap went unreachable. It was unblocked the same way Argentum was, by harvesting a broken-today-but-archived-yesterday operator dashboard via the Wayback CDX index. With 23 publication-gate-accepted direct-stale candidates (11 new-to-upstream, 5 chronologically novel) Crown sits in the same quality band as Myriadcoin and Terracoin: a modest absolute haul that genuinely enriches the multi-chain set, and a better result than the "expected novelty was low" prediction in the original discovery notes.

## 1. Chain data

**Source.** Local `crownd` v0.14.0.4 node on `<archival-host>`, built from source inside a Docker container with an `ubuntu:18.04` (bionic) base. Crown 0.14.x is mid-2010s Bitcoin-Core-derived, and its `rpcserver.cpp` still uses pre-1.66 Boost ASIO APIs (the two-arg `ssl::context` constructor, `acceptor::get_io_service()`, `ssl::context::impl()`) that Boost 1.66+ removed; bionic ships Boost 1.65, which retains them, so no source patches to `rpcserver.cpp` were needed - Ubuntu 20.04 (Boost 1.71) and later would require them. Two non-obvious build requirements: `libcurl`, which Crown's `configure` mandates (the AuxPoW *mining* helpers link it - harmless on a read-only node, but required at configure time), and `libdb++-dev`, because `db_cxx.h` leaks into `main.cpp`/`init.cpp` even with `--disable-wallet`.

**Provenance.** Docker scaffold at `node-infra/crown/`. P2P sync ran via a **single live peer** - `38.109.228.194:9340` (gthost) - recovered on 2026-05-16 from Wayback captures of `monitor.crownplatform.com/index.php?p=peers` (Crown's community masternode-tracker / monitor app, server-rendered, captured across 2020-08 → 2026-03). That harvest surfaced 74 historical IP candidates; three still accept TCP on port 9340, but only `38.109.228.194` completes the Bitcoin-protocol handshake (the other two TCP-accept but refuse the handshake - likely inbound-only / anti-DDoS configurations). All source-coded DNS seeds NXDOMAIN as of 2026-05-16. Bitcoin Core on `<archival-host>` provided the BTC RPC for classification.

**Coverage.** Validated stales span BTC heights **470,447 → 555,155** (2017-06 → 2018-12, an ~18-month window) and Crown heights **1,410,258 → 2,178,872**. The extraction itself ran from CRW 453,273 (AuxPoW activation) over the entire PoW merge-mined era to ~2,330,000, where Crown switched to full MN-PoS (April 2019); the AuxPoW window is that ~1.88M-block PoW era only. The June-2017 → December-2018 stale window is not a coverage hole - it is Crown's actual BTC-parent stale yield within an era of near-total merge-mining density (~99%).

**Holes.**

- **Pre-AuxPoW** (CRW 0 → 453,272): Bitcoin-parent merge-mining not yet active. AuxPoW activates at CRW 453,273, mined 2015-08-25 (block timestamp 1440546428). The chain itself launched at genesis in October 2014 (genesis block `nTime = 1412760826`, i.e. 2014-10-08 UTC; the genesis coinbase reads "10/Oct/2014") as a standalone PoW chain.
- **PoS-hybrid era** (CRW 2,330,000 → tip): Crown switched to a full MN-PoS consensus (replacing PoW) in April 2019. PoS blocks never set the AuxPoW flag and carry no parent header, so the extractor skips the entire PoS era via the same version-bit gate it uses for pre-activation blocks. In the PoS era the `nVersion` chain-ID field cosmetically rotates 20 → 22 - irrelevant to extraction, since the AuxPoW flag is what gates inclusion.
- **`getblock` exposes no decoded `auxpow` JSON field** - Crown's 0.12-era RPC does not surface the AuxPoW structure in verbose `getblock` output, so the extractor fetches raw block hex (`getblock <hash> false`) and parses the `CAuxPow` binary directly. Same approach as Devcoin / Myriadcoin / Argentum.
- **No Stifter prior-art baseline**: Crown was not in Stifter et al.'s 2018 merge-mining monitor, even though the chain had been merge-mining since 2015-09, well inside Stifter's coverage window. No prior-art baseline exists for this chain.

**Reference scripts.**

- `scripts/extract/extract_crown_auxpow.py` - RPC raw-hex `getblock` + binary `CAuxPow` parse. Single-algo, so the only filter is the `VERSION_AUXPOW` version-bit gate (`_gate`), which covers both pre-activation PoW blocks and the entire PoS era.
- `scripts/classify/classify_crown_stales.py:1` - BTC RPC batch classifier (self-target PoW filter + dedup + `getblockheader` lookups; canonical/stale/unknown trichotomy).
- `node-infra/crown/{Dockerfile,docker-compose.yml,bootstrap.sh,justfile,peers.list,README.md}` - build infrastructure with the `ubuntu:18.04` (bionic) toolchain.

## 2. Extraction → potential stales

**Method.** RPC raw-hex against the local `crownd`. For each Crown block ≥ 453,273, fetch `getblock <hash> false` (Crown's `getblock` takes a *bool* verbosity argument, 0.12-era RPC, not an int) and parse the binary block. Read `nVersion` from the first 4 bytes; if the `VERSION_AUXPOW` flag (bit 8) is clear, skip the block - this single check discards both the pre-merge-mining PoW blocks and the entire post-2,330,000 PoS era. For AuxPoW-flagged blocks, parse the binary `CAuxPow` tail using the standard Namecoin-style parser (`CMerkleTx` coinbase transaction + `vChainMerkleBranch` + `nChainIndex` + 80-byte `parentBlockHeader`), per `read_auxpow()` in `src/stale_blocks_analysis/auxpow_parse.py:147` (invoked via `extract_driver.py:165`).

The `CAuxPow` deserialisation order is byte-identical to ixcoin / Devcoin / Myriadcoin / Argentum, so the extractor's serialisation primitives port across verbatim - Crown is simpler than the multi-algo chains because there is **no algo filter** to apply before AuxPoW parsing.

**Phases.**

1. **Parse with AuxPoW gate**: walk all Crown blocks ≥ 453,273 via raw hex; decode `nVersion`; discard blocks without the `VERSION_AUXPOW` bit (pre-activation PoW + the whole PoS era).
2. **Self-target PoW filter** (`classify_crown_stales.py`): keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. `fStrictChainId=true` constrains the AuxPoW commitment's child-chain identity, not the parent header's Bitcoin-mainnet validity.
3. **Dedup**: keep only unique BTC header hashes - multiple Crown blocks can reference the same BTC parent.
4. **BTC RPC classify** (`classify_crown_stales.py`): batch `bitcoin-cli getblockheader`. Hit → `canonical`. Miss → look up `prev_hash`. Prev canonical → `stale`. Neither → `unknown`.

**Counts:**

| Stage | Rows |
|---|---:|
| AuxPoW commitments extracted (453,273 → tip) | 1,868,911 |
| Parse errors | 0 |
| After self-target PoW filter (unique) | 389,128 |
| After classification | **5,483 canonical + 23 stale + 383,622 unknown** |

The ~1.88M extracted commitments across the PoW era confirm the ~99% merge-mined density - virtually every PoW block above the activation height carries a valid AuxPoW commitment. That density is a Crown-side property (AuxPoW-commitment presence), not a statement about parent canonicity: of the 389,128 unique self-target-valid parent headers, only 5,483 (~1.4 %) are canonical Bitcoin. The 383,622-header unknown bucket far exceeds the number of Bitcoin blocks that ever existed across the extraction window, so most of it cannot be Bitcoin-mainnet - consistent with post-2017 non-BTC SHA-256d headers (BCH after 2017-08, BSV after 2018-11) that clear the self-target filter trivially. That non-BTC population was never affirmatively resolved; it is carried as an unjudged census, not as recovered BTC evidence. Pipeline timing on `<archival-host>`: IBD ~4 days through the single Wayback-recovered peer; extraction 25.8 minutes against localhost RPC with zero parse errors.

**Chain-specific quirks.**

- **PoS-hybrid era splits the chain in two.** Crown is the first chain in the pipeline with a PoS era. The extractor handles it for free - PoS blocks never set the AuxPoW flag, so the same version-bit gate that skips pre-activation blocks also skips all of PoS. The `nVersion` chain-ID rotation 20 → 22 in the PoS era is cosmetic and never read by the extractor.
- **No decoded `auxpow` in `getblock` JSON.** Crown's RPC predates the decoded-AuxPoW verbose output, forcing the raw-hex parse path. This is the Devcoin pattern, not the Syscoin/Terracoin pattern.
- **`fStrictChainId=true`.** Crown rejects a parent header that uses Crown's own chain ID. This prevents same-chain AuxPoW, but it does not identify the parent as Bitcoin. Parent identity is established separately through Bitcoin Core classification and the publication validation gates.
- **Catalogue activation date used.** Per the project chronological-ordering convention we record the 2015-08-25 production-activation date (CRW 453,273), not the October 2014 chain genesis (a standalone PoW chain with no Bitcoin-parent commitment).

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_crown_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

The loader parses `coinbase_outputs` as raw pkscript hex, semicolon-joined (matches the myriadcoin / argentum / ixcoin format). The extractor preserves the parent-coinbase outputs verbatim without address decoding so they remain available for later attribution research. All 23 entries pass the filter.

**Post-filter count: 23 accepted direct-stale header candidates.**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py crown`. Per-stale row-level breakdown at `results/per-chain-novelty/crown.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 12 | 52.2 % |
| novel vs upstream | 11 | 47.8 % |

The 11-novel-vs-upstream figure is Crown's count of stales missing from the upstream dataset - comparable to Myriadcoin's 24 and Terracoin's 22, scaled to Crown's smaller validated set.

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Crown is 10th chronologically. Earlier-born integrated chains: namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium.

| Split | Count |
|---|---:|
| also in upstream | 12 |
| also in earlier-born chain (`namecoin`: 8, `i0coin`: 5, `devcoin`: 2, `unobtanium`: 1, first-claim distribution) | 16 |
| **novel at this position** | **5** |

The 16 earlier-chain-claimed observations include 6 upstream-new rows and 10 rows that are also in upstream. They are the same SHA-256d miner substrate that Namecoin, i0coin, Devcoin and Unobtanium had already been recording; each of those chains contributed at least one chronologically-earlier observation of those parent headers. The 5 chronologically-novel hashes are the genuinely new-to-the-multi-chain-set contributions at Crown's position, ahead of Myriadcoin (2), Terracoin (0), and Argentum (0) under the current chronology.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/crown_validated_stales.csv` - 23 validated stales (committed; the loader's input).
- Private archive `crown_auxpow_raw.csv` - 1,868,911 raw AuxPoW commitment rows (extractor output, pre-PoW-filter; on `<archival-host>` only).
- Private archive `crown_btc_valid.csv` - 389,128 PoW-passing unique rows (intermediate, before classification; on `<archival-host>` only).
- Private archive split inventories: `crown_stale_blocks.csv` (23 stale), `crown_canonical_blocks.csv` (5,483 canonical), and `crown_unknown_blocks.csv` (383,622 unknown; on `<archival-host>` only).
- `results/per-chain-novelty/crown.csv` - per-stale `(btc_height, btc_hash, in_upstream, first_seen_chain)` table.
- `node-infra/crown/{Dockerfile,docker-compose.yml,bootstrap.sh,justfile,peers.list,README.md}` - build infrastructure (`ubuntu:18.04` (bionic) toolchain).

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (Crown row).
- Crown active fork / community sources discoverable via the `crownplatform` GitHub org.
- Genesis: the genesis coinbase `pszTimestamp` reads "The inception of Crowncoin 10/Oct/2014", but the genesis block `nTime = 1412760826` is 2014-10-08 UTC (the "10/Oct/2014" is a coinbase headline, not the block time). `chainparams.cpp` at https://github.com/Crowndev/crowncoin/blob/v0.14.0.4/src/chainparams.cpp
- April-2019 full MN-PoS switch at CRW 2,330,000 (Crown v0.13.0 "Jade"): https://medium.com/crownplatform/crown-mn-pos-simplified-9c5bdac13460
- 2026 dormant-token status (near-zero volume): https://coinmarketcap.com/currencies/crown/
- Peer-discovery source: Wayback captures of `monitor.crownplatform.com/index.php?p=peers` (Crown's community masternode-tracker / monitor app, 2020-08 → 2026-03).

**Methodological note.**

Crown is the project's case study in **un-deferring a chain declared dead**. The recovery was previously shelved because peer discovery failed across every channel the source code offered - DNS seeds, fixed seeds, hardcoded bootstrap. It was unblocked by the same Wayback-CDX technique that recovered Argentum: an operator-rendered dashboard (`monitor.crownplatform.com`, a community masternode tracker) that is broken-today but stable-in-the-archive yields a historical peer list, and a single nine-year-old IP that still answers is enough to bootstrap a full IBD (via the Wayback CDX index). Any merge-mined chain with a community-run monitor, pool admin page, or masternode tracker that has since gone offline is a candidate for the same trick. The substantive finding - 23 publication-gate-accepted direct-stale candidates over an 18-month window, 5 of them chronologically novel - genuinely enriches the multi-chain set. Crown's PoW era was a dense *merge-mining* environment (~99% of PoW blocks carry an AuxPoW commitment), but that is not the same as dense BTC-parent canonicity: only 5,483 of 389,128 unique self-target-valid parents are canonical Bitcoin, and the large unknown bucket is consistent with post-2017 non-BTC contamination rather than recovered Bitcoin. The lasting value here is as much methodological - un-deferring a chain declared dead - as it is the accepted-candidate count.
