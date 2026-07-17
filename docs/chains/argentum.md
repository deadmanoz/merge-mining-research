# Argentum

| Field | Value |
|---|---|
| Ticker | ARG |
| AuxPoW activation | 2016-04-10 (ANN thread 1432608 multi-algo + AuxPoW relaunch; ARG height **1,825,000**) |
| Network status | Active (live `argentum.cc` portal with 2025 footer; SHA-256d difficulty ~4.3 × 10¹⁰ at recovery time implies real BTC ASIC participation). All 3 source-coded DNS seeds + 41 fixed seeds dead - peer discovery via Wayback harvest of `chainetics.com/nodes/arg.php`. |
| Chronological position | 13 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; Argentum's SHA-256d AuxPoW ran from 2016, inside the paper's window, but it was not a sampled data source) |
| AuxPoW chain ID | `1187` (`0x004A3`), **`fStrictChainId=false`** (`src/chainparams.cpp:83-84`) - the SHA-256d branch accepts AuxPoW from **any** SHA-256d parent, not just Bitcoin. This permissiveness is what drives Argentum's extracted-block distribution (see §3). |
| Algorithms | 6 post-2018-03 fork (Scrypt, SHA-256d, Lyra2REv2, Myriad-Groestl, Argon2d, Yescrypt); pre-fork Scrypt + SHA-256d only. Only the SHA-256d branch is Bitcoin-parent merge-mined. |
| Algo encoding (in `nVersion`) | Bits 9–11 (`BLOCK_VERSION_ALGO = 7 << 9`). **`BLOCK_VERSION_SHA256D = 1 << 9 = 0x200` - explicit** (Scrypt is the default `0`). This is the **mirror image of Myriadcoin**, where SHA-256d is the default `0` and Scrypt is encoded explicitly. AuxPoW flag = bit 8 (`VERSION_AUXPOW = 1 << 8`). See `src/primitives/pureheader.h:36-37,59`. |
| Block time | 45 s overall post-2018 fork (270 s per-algo across six algorithms); 32 s overall pre-fork (Scrypt + SHA-256d only). `consensus.nPowTargetSpacingV1 = 32` / `V2 = 45` in `src/chainparams.cpp:78-79`. |
| Source tag (in code) | `argentum` |
| Loader | `load_argentum_stales()` in `src/stale_blocks_analysis/stale_blocks.py:511` |
| Validated CSV | `data/validated-stales/argentum_validated_stales.csv` |

Argentum is the **second multi-algo chain integrated into the pipeline** after Myriadcoin, and the closest structural analog - both are Daniel Kraft–lineage codebases with `fStrictChainId=false` and a SHA-256d branch carrying Bitcoin-parent AuxPoW alongside other algorithms that are out of scope. The one methodological difference from Myriadcoin is small but easy to miss: the algo-encoding constants are *inverted* relative to Myriadcoin, so the extractor filter is `(nVersion & 0x0E00) == 0x0200` rather than `== 0`. The substantive finding is the **unknown-to-stale ratio** - 634,277 unknowns against only 2 stales (0.0003% stale rate, two orders of magnitude below Myriadcoin's 0.024%) - which is what any write-up of Argentum should lead with, not the modest 2-stale yield itself. With both validated stales already claimed by Namecoin (position 1) by the project's chronological-precedence convention, Argentum's contribution at its own position is zero novel BTC stales but a clear signal of **vestigial-but-not-zero BTC-parent AuxPoW**.

## 1. Chain data

**Source.** Local `argentumd` node on `<archival-host>`, built from `dbkeys/argentum` (active fork, last commit 2024-02-07) inside a Docker container. Argentum Core is a **Bitcoin Core ~0.13-lineage fork** of Kraft 2014–2016 vintage (231-line `src/auxpow.h` + 237-line `src/auxpow.cpp` - same generation as Myriadcoin, newer than ixcoin/Unobtanium's 0.11 ancestry). The build chain required `debian:stretch` base + `libssl1.0-dev` + Boost 1.62 + GCC 6; modern toolchains all fail on `src/bignum.h` CBigNum/OpenSSL 1.1 incompatibility, and `tini` is absent from stretch main so the compose file uses `init: true` instead. `apt` points at `archive.debian.org` with `check-valid-until=no`.

**Provenance.** Docker scaffold at `node-infra/argentum/`. P2P sync via a single live peer - `38.109.228.194:13580` (gthost) - recovered by a deep-search agent on 2026-05-16 from Wayback captures of `chainetics.com/nodes/arg.php` (17 archived snapshots across 2024-03 → 2026-03; the page is server-rendered and currently returns empty live but stable in the archive). All three source-coded DNS seeds (`seed.argentum.cc`, `dnsseed.argentum.cc`, `dnsseed.argentumcoin.cc`) NXDOMAIN as of 2026-05-16; all 41 fixed seeds in `contrib/seeds/nodes_main.txt` are likewise unreachable after nine years. Bitcoin Core on `<archival-host>` (tip 949,736 at classification time) provided the BTC RPC for classification.

**Coverage.** Validated stales span BTC heights **467,186 → 472,975** (May 2017 → June 2017, a 38-day window) and ARG heights **2,408,038 → 2,479,765**. The extraction itself ran from ARG height 1,825,000 (AuxPoW activation) to tip 7,204,637 - a ~5.4M-block window spanning April 2016 to May 2026, ten years of chain history. The 38-day stale window is not a coverage hole; it is the chain's actual BTC-parent stale yield (see §2 for the unknown dominance discussion).

**Holes.**

- **Pre-AuxPoW** (ARG 0 → 1,824,999): Bitcoin-parent merge-mining not yet active. AuxPoW activates at ARG 1,825,000 per `consensus.nStartAuxPow` in `src/chainparams.cpp:82`; that block was mined ~2016-04. The chain itself launched 2013-05-22 as a standalone Scrypt-only PoW chain.
- **2,973 SHA-256d blocks above the activation height carry no AuxPoW flag** - the early activation gradient as miners transitioned. Comparable to Myriadcoin's 392 ungraded blocks.
- **`fStrictChainId=false`**: the SHA-256d branch accepts AuxPoW from any SHA-256d parent. The 634k unknown rows show that parent identity cannot be inferred from AuxPoW structure alone. Phase 1 checks only the target encoded in each parent header; Bitcoin Core classification and later validation determine which rows are usable Bitcoin evidence.
- **Not sampled by Stifter et al.**: Argentum's SHA-256d branch was actively merge-mining from 2016-04, inside the paper's coverage window, but Argentum was not one of the seven Bitcoin-parent chains the paper sampled, so no prior-art baseline exists for it.

**Reference scripts.**

- `scripts/extract/extract_argentum_auxpow.py:1` - RPC raw-hex `getblock` + binary CAuxPow parse, with `nVersion`-bit algo filter (`(version & BLOCK_VERSION_ALGO) != BLOCK_VERSION_SHA256D` skips non-SHA-256d branches before AuxPoW deserialisation, per the explicit-encoding distinction in the file's docstring).
- `scripts/classify/classify_argentum_stales.py:1` - BTC RPC batch classifier (self-target PoW filter + dedup + `getblockheader` lookups; canonical/stale/unknown trichotomy).
- `node-infra/argentum/{Dockerfile,docker-compose.yml,init.sh,justfile,peers.list,README.md}` - build infrastructure with the stretch + libssl1.0 toolchain.

## 2. Extraction → potential stales

**Method.** RPC raw-hex against the local `argentumd`. For each ARG block ≥ 1,825,000, fetch `getblock <hash> 0` and parse the binary block. First check the algo encoding in `nVersion` bits 9–11 with `(version & 0x0E00) == 0x0200`; skip non-SHA-256d blocks entirely. Then check the `VERSION_AUXPOW` flag (bit 8); skip SHA-256d blocks without it (3k blocks, early activation gradient only). Then parse the binary CAuxPow tail using the standard Namecoin-style parser (`CMerkleTx` + `vChainMerkleBranch` + `nChainIndex` + 80-byte `parentBlockHeader`).

The block header is `class CBlockHeader : public CPureBlockHeader { shared_ptr<CAuxPow> auxpow; }` - standard Namecoin-style wrapping, byte-identical to Myriadcoin's. The Myriadcoin extractor ports across with one substantive change: the algo filter constant. Where Myriadcoin's filter is `(version & BLOCK_VERSION_ALGO) == 0` (SHA-256d as default zero), Argentum's is `(version & BLOCK_VERSION_ALGO) == BLOCK_VERSION_SHA256D` (SHA-256d as explicit `1 << 9`, with Scrypt as the default zero). Confirmed in `src/primitives/pureheader.h:36-37` and `src/primitives/pureheader.cpp:26,61-68`.

**Phases.**

1. **Parse with algo filter**: walk all ARG blocks ≥ 1,825,000 via raw hex; decode `nVersion` first; discard blocks where algo bits don't match SHA-256d. Only SHA-256d-flagged blocks proceed to AuxPoW parsing.
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. This establishes only internal PoW consistency, not Bitcoin's contemporaneous target or parent identity.
3. **Dedup**: keep only unique BTC header hashes (multiple ARG blocks can reference the same BTC parent).
4. **BTC RPC classify** (`classify_argentum_stales.py`): batch `bitcoin-cli getblockheader`. Hit → `canonical`. Miss → look up `prev_hash`. Prev canonical → `stale`. Neither → `unknown`.

**Counts:**

| Stage | Rows |
|---|---:|
| ARG blocks scanned (1,825,000 → 7,204,637) | 5,379,638 |
| After algo filter (SHA-256d only) | 1,293,100 (24.0 %) |
| Non-SHA-256d filtered out | 4,086,538 (76.0 %) |
| Without AuxPoW flag (early gradient) | 2,973 |
| Parse errors | 0 |
| SHA-256d AuxPoW rows extracted | 1,290,127 |
| After self-target PoW filter (unique) | 634,306 (49.2 % of SHA-256d-AuxPoW) |
| After classification | **27 canonical + 2 stale + 634,277 unknown** |

The 24% SHA-256d fraction across the full 1.825M → tip window is broadly consistent with the post-2018-fork dilution to six algorithms (an equal-share assumption gives 1/6 ≈ 17% in that era, weighted against the 1/2 share that held in the pre-fork ~2016-04 → 2018-03 window). Pipeline timing on <archival-host>: extraction 99.9 min wall-clock (localhost RPC fetch sustained ~1,944 blk/s); classification 95.8 s at 6,625 headers/s against the local Bitcoin archive RPC.

**The 49 % self-target PoW pass-rate requires careful interpretation.** Roughly half of all SHA-256d-AuxPoW parent headers satisfy the targets encoded in those same headers. It does not show that they met Bitcoin's contemporaneous mainnet target. Bitcoin Core recognises only 27 as canonical, while 2 more have canonical predecessors and pass the publication gates; the remaining 634,277 are unknown.

**Chain-specific quirks.**

- **Algo-encoding inverse from Myriadcoin** - the gotcha. Argentum: `BLOCK_VERSION_SHA256D = 1 << 9 = 0x200` (explicit), Scrypt = default `0`. Myriadcoin: SHA-256d = default `0`, Scrypt = explicit. Confused filter constants would silently extract the wrong algo's branch. The extractor docstring (`scripts/extract/extract_argentum_auxpow.py:14-28`) calls this out and the filter is `(nVersion & 0x0E00) == 0x0200`, not `== 0`.
- **Pre-fork vs post-fork SHA-256d share differs.** Between ARG 1,825,000 (~2016-04) and 2,977,000 (~2018-03) the chain ran Scrypt + SHA-256d only, so SHA-256d produced ~50% of blocks; from 2,977,000 onward, with six algorithms, ~17%. A single ratio doesn't apply across the whole extraction window.
- **`fStrictChainId=false` leaves parent identity open.** The 634,277 unknown headers satisfy their encoded self-target but do not sit on Bitcoin's active chain and do not extend a canonical Bitcoin predecessor. They may belong to BCH, BSV, another SHA-256 chain, or a chain-specific header substrate; the current evidence does not identify a single origin.
- **Catalogue activation date used.** Per the project chronological-ordering convention we record the 2016-04-10 multi-algo + AuxPoW relaunch ANN date (catalogue precision), not the 2013-05-22 chain genesis (which was a standalone-Scrypt PoW chain with no Bitcoin parent commitment).

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_argentum_stales()` in `stale_blocks.py:511`):

```python
classification == "stale"
```

The loader follows the established multi-algo pattern: semicolon-joined raw pkscript hex in `coinbase_outputs`, with no address decoding at extract time. This preserves the outputs for later attribution research. Both validated entries pass the filter.

**Post-filter count: 2 accepted direct-stale header candidates.**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py argentum`. Per-stale row-level breakdown at `results/per-chain-novelty/argentum.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 2 | 100.0 % |
| novel vs upstream | 0 | 0.0 % |

Both stales are now in upstream: BTC 467,186 entered when upstream merged this project's contribution, so Argentum's isolated novel-vs-upstream count is zero.

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Argentum is 13th chronologically. Earlier-born integrated chains: namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven.

| Split | Count |
|---|---:|
| also in upstream | 2 |
| also in earlier-born chain (`namecoin`: 2 - both first-claims) | 2 |
| **novel at this position** | **0** |

Both validated stales are first-claimed by Namecoin (position 1). At Argentum's position in the integrated multi-chain set, the novel contribution is zero. This places Argentum at the bottom of the multi-algo set's chronological-novelty ranking: Myriadcoin contributes 2 chronologically-novel stales, while Terracoin and Argentum each contribute 0.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

### The actually interesting finding: near-vestigial BTC-parent AuxPoW

The main result of Argentum's recovery is not the 2-stale yield but the **634,277 unknowns : 2 stales** ratio. A 0.0003 % stale rate is two orders of magnitude below Myriadcoin's 0.024 % (40 stales / 166,844 unknowns), and three orders of magnitude below what would be expected if Argentum's SHA-256d miner population were merge-mining Bitcoin at meaningful scale.

The mechanism is straightforward, given the `fStrictChainId=false` design choice. The SHA-256d branch will accept AuxPoW from any SHA-256d parent; the source-side data does not establish parent identity. Of the self-target-PoW-valid headers, Bitcoin Core recognises 27 as mainchain-canonical, and 2 more extend canonical predecessors and pass the publication gates. The 634,277 unknowns remain evidence of an unidentified SHA-256 header substrate, not proven Bitcoin, BCH, or BSV blocks.

This makes Argentum a publishable case study for **vestigial-but-not-zero AuxPoW**: structural BTC-parent AuxPoW evidence is present (correct Daniel Kraft–lineage code, parseable commitments, real SHA-256d difficulty observed in the chain's own difficulty target), but functional BTC merge-mining is not. The contrast with Doichain (the vestigial-AuxPoW review) is instructive - Doichain is fully vestigial (0 BTC stales), Argentum is near-vestigial (2 BTC stales, real-but-microscopic BTC-parent fraction). The lesson, sharpened by the two-chain comparison: the presence of standard CAuxPow data structures and live SHA-256d difficulty on a merge-mineable chain says nothing about whether Bitcoin is actually one of the parents miners are using.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/argentum_validated_stales.csv` - 2 validated stales (committed; the loader's input).
- `out-of-repo extraction directory/argentum_btc_valid.csv` - 634,306 PoW-passing rows (intermediate, before classification; 27 classify canonical and were not persisted to the split inventories below; on <archival-host> only - 405 MB).
- `out-of-repo extraction directory/argentum_stale_blocks.csv` + `argentum_unknown_blocks.csv` are the classifier's split inventories: 2 stale rows and 634,277 unknown rows (634,279 combined; the unknown bucket carries the ~358 MB; intermediate, on <archival-host> only).
- `out-of-repo extraction directory/argentum_auxpow_raw.csv` - 1,290,127 raw SHA-256d-AuxPoW rows (extractor output, pre-PoW-filter; on <archival-host> only - 1.25 GB).
- `results/per-chain-novelty/argentum.csv` - per-stale `(height, hash, in_upstream, first_seen_chain)` table.
- `node-infra/argentum/{Dockerfile,docker-compose.yml,init.sh,justfile,peers.list,README.md}` - build infrastructure (stretch + libssl1.0 toolchain).

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (Argentum row).
- Argentum active fork: `github.com/dbkeys/argentum` (last commit 2024-02-07); canonical: `github.com/argentumproject/argentum` (last commit 2019-02-14).
- Argentum portal: `argentum.cc` (live, 2025 footer; tech-specs page shows real-time SHA-256d difficulty).
- Original launch ANN: `bitcointalk.org/index.php?topic=231524.0` (2013-06-11, Scrypt-only).
- Multi-algo + AuxPoW relaunch ANN: `bitcointalk.org/index.php?topic=1432608.0` (2016-04-10).
- Peer-discovery source: Wayback captures of `chainetics.com/nodes/arg.php` (17 snapshots, 2024-03 → 2026-03).

**Methodological note.**

Argentum is the project's clearest demonstration that **structural AuxPoW evidence is not equivalent to validated Bitcoin-parent evidence**. The source code and substantial SHA-256d activity suggested a potentially large recovery source, but the public validation path admits only 2 direct-stale candidates. The 634,277 unknowns satisfy only their encoded self-target and lack canonical Bitcoin linkage. A strict-chain-ID setting would not, by itself, resolve that ambiguity: standard AuxPoW chain-ID checks prevent same-chain parent reuse but do not prove that the parent is Bitcoin.
