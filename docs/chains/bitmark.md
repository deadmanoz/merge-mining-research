# Bitmark

| Field | Value |
|---|---|
| Ticker | BTMK |
| AuxPoW activation | 2018-06-07 (Fork 1 multi-algo + AuxPoW; BTMK height 450,947, empirically the first post-fork block) |
| Network status | Active, hybrid 8-algo PoW (live explorer `chainz.cryptoid.info/btmk/`; `project-bitmark/bitmark` repo maintained) |
| Chronological position | 18 of 26 (after Doichain, before Xaya) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; Bitmark's AuxPoW activated 2018-06-07, just inside the window, but it was not a sampled data source) |
| AuxPoW chain ID | `91` (`0x005B`), `fStrictChainId=true` (`src/chainparams.cpp:56-57`) |
| Algorithms | SHA-256d, Scrypt, Yescrypt, Argon2d, X17, LYRA2REv2, Equihash, CryptoNight (`NUM_ALGOS = 8`, `src/pureheader.h:11-22`) |
| Algo encoding (in `nVersion`) | Bits 9-11 (`BLOCK_VERSION_ALGO = 7 << 9`); **SHA-256d = `ALGO_SHA256D = 1`** (Scrypt is the default `0`) - the mirror of Myriadcoin, where SHA-256d is the default `0`. AuxPoW flag = bit 8 (`BLOCK_VERSION_AUXPOW = 1 << 8`). See `src/pureheader.h:11-30` and `src/core.h:29`. |
| Source tag (in code) | `bitmark` |
| Loader | `load_bitmark_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/bitmark_validated_stales.csv` |

Bitmark is a hybrid 8-algorithm PoW chain whose SHA-256d branch carries
Bitcoin-parent AuxPoW; the other seven algorithms either merge-mine
non-Bitcoin parents (Scrypt to Litecoin/Dogecoin, Equihash to Zcash,
CryptoNight to the Monero family) or are out of scope, so only the SHA-256d
branch is considered here. The extraction yields a **single** validated BTC
stale, and that stale is **cross-confirmation only**: it was already recovered
by three chronologically earlier chains (Unobtanium, Myriadcoin, and RSK), so
Bitmark's novel contribution is zero. The substantive character of the
recovery is the ratio - **81,921 self-target-PoW-valid unknowns against 1
accepted direct stale** - drawn from a SHA-256d branch that is only 13.3 % of
Bitmark's blocks (the lowest multi-algo SHA-256d share in the pipeline). Unlike
Myriadcoin and Argentum, Bitmark sets `fStrictChainId=true`, so every accepted
parent committed to Bitmark's chain ID 91; that constrains the AuxPoW
commitment but does not, by itself, prove the parent is Bitcoin. The one
methodological trap worth carrying forward is structural: Bitmark's `CAuxPow`
class lives inline in `src/core.{h,cpp}` rather than in separate
`src/auxpow.{h,cpp}` files, so a filename-only search is not a sufficient
negative test for AuxPoW support.

## 1. Chain data

**Source.** A synced Bitmark full node, reproducible via the
`node-infra/bitmark/` Docker scaffold, which builds `project-bitmark/bitmark`
(master, HEAD `ffd840e`, dated 2023-06-15). The node syncs the full chain
across all eight algorithms; branch filtering happens in the extractor by
decoding each child block's `nVersion` bits before parsing the AuxPoW tail.
Bitmark's genesis is 13 July 2014 (the mainnet genesis coinbase string in
`src/chainparams.cpp:63` reads "13/July/2014, with memory of the past, we look
to the future. TDR", `nTime = 1405274442` at `:74`), but Bitcoin-parent merge
mining only begins at the Fork 1 activation.

**Provenance.** Raw AuxPoW evidence was extracted offline from the synced node
via `scripts/extract/extract_bitmark_auxpow.py` over an SSH-tunnelled RPC.
The classifier (`scripts/classify/classify_bitmark_stales.py`) produces the
committed `data/validated-stales/bitmark_validated_stales.csv`, gated by Bitcoin PoW/target
validation on every row, an nBits-by-epoch contamination filter that rejects
non-BTC (e.g. BCH/BSV) parents whose difficulty does not match the BTC retarget
epoch, and Bitcoin Core classification of each parent as canonical, stale, or
absent (unknown). Unknown rows are persisted only on a Core-absence-attested
verdict. Bitcoin Core on `<archival-host>` provided the BTC RPC for
classification.

**Coverage.** The extraction window spans BTMK height 450,947 (2018-06-07) to
the tip at extraction time, 2,377,409 (2,377,409 - 450,947 + 1 = 1,926,463
blocks scanned). Within that window the SHA-256d branch yields 82,819
self-target-PoW-valid unique parent headers (897 canonical, 1 stale, 81,921
unknown). Anything before Fork 1 carries no AuxPoW proof and is out of scope.

**Holes.**

- **Pre-AuxPoW** (BTMK 0 to 450,946): Bitcoin-parent merge mining not yet
  active. Fork 1 is **not a hardcoded height** in Bitmark's source: activation
  is governed by a version-4 supermajority rule (75 of the last 100 blocks;
  the nominal `nForkHeight = 200` in `src/core.h` is explicitly disabled). The
  recovery pins 450,947 empirically via a boundary walk on the synced node - it
  is the first post-fork block, where the algo bits flip from SCRYPT v4 to
  LYRA2REv2 - and public sources agree it is the first fork block after the
  450,946 supermajority. Its timestamp is 2018-06-07 04:18:55 UTC.
- **Non-SHA-256d branches** (86.7 % of blocks): out of scope. Scrypt,
  Yescrypt, Argon2d, X17, LYRA2REv2, Equihash, and CryptoNight blocks are
  either merge-mined against non-Bitcoin parents or native PoW.
- **286 SHA-256d blocks above the activation height carry no AuxPoW flag** -
  the early activation gradient as miners transitioned.
- **`fStrictChainId=true` does not fix parent identity.** Strict chain ID means
  every accepted parent committed to Bitmark's chain ID 91 in its AuxPoW merkle
  tree, but any SHA-256d chain whose miners also merge-mine Bitmark can carry
  that commitment. The 81,921 unknown headers satisfy their encoded self-target
  and are absent from Bitcoin Core's view; the public pipeline does not resolve
  their origin.

**Reference scripts.**

- `scripts/extract/extract_bitmark_auxpow.py` - RPC raw-hex extraction with the
  `nVersion`-bit algo filter (`CHAIN_SPECS["bitmark"].activation_height` =
  450,947, `BLOCK_VERSION_ALGO = 7 << 9`, `ALGO_SHA256D = 1`,
  `VERSION_AUXPOW = 1 << 8`),
  parsing the standard Namecoin-style `CAuxPow` parent header and coinbase.
- `scripts/classify/classify_bitmark_stales.py` - BTC RPC batch classifier
  (self-target PoW filter, dedup, nBits-by-epoch contamination filter, and
  canonical/stale/unknown classification).
- `node-infra/bitmark/{Dockerfile,docker-compose.yml,init.sh,justfile,peers.list,README.md}`
  - build and run infrastructure (default P2P port 9265, loopback RPC 9266).

## 2. Extraction to potential stales

**Method.** RPC raw-hex against the local Bitmark node. For each BTMK block
>= 450,947, decode `nVersion` first: read the 3-bit algo field at bits 9-11
with `(version & BLOCK_VERSION_ALGO) >> 9` and skip anything that is not
`ALGO_SHA256D` (1); then require the `VERSION_AUXPOW` flag (bit 8) and skip
SHA-256d blocks without it. Only then parse the binary CAuxPow tail using the
standard Namecoin-style parser. The algo filter matters for correctness beyond
scope: `CPureBlockHeader` serialisation is algorithm-conditional (Equihash
blocks carry extra Zcash-layout fields), so filtering to SHA-256d guarantees
the parser only sees standard 80-byte Bitcoin headers.

The SHA-256d enum being `1` (Scrypt is the default `0`) is the inverse of
Myriadcoin, where SHA-256d is the default `0`; a confused constant would
silently extract the wrong algorithm's branch. The extractor's docstring calls
this out and the filter constant is `ALGO_SHA256D = 1`.

**Counts:**

| Stage | Rows |
|---|---:|
| BTMK blocks scanned (450,947 -> 2,377,409) | 1,926,463 |
| SHA-256d blocks (algo filter) | 255,824 (13.3 %) |
| Non-SHA-256d filtered out | 1,670,639 (86.7 %) |
| SHA-256d without AuxPoW flag (early gradient) | 286 |
| Parse errors | 0 |
| SHA-256d AuxPoW rows extracted | 255,538 |
| Unique self-target-PoW-valid parent headers | 82,819 |
| After classification | **897 canonical + 1 stale + 81,921 unknown** |

Pipeline timing recorded at recovery: node sync ~18 h from genesis; extraction
~186 min (~173 blk/s sustained over the tunnelled RPC).

**Interpretation.** The self-target PoW filter establishes only that a header
meets the target encoded within it; it is not Bitcoin's contemporaneous target
and does not establish parent identity. Bitcoin Core recognises 897 of the
82,819 unique headers as canonical, and 1 more extends a canonical predecessor
and passes the publication gates. The remaining 81,921 are unknown: they carry
BTC-plausible difficulty but are absent from Core's active chain and extend no
canonical Bitcoin predecessor. Their origin (deep BTC stales Core never
retained, or other SHA-256d chains sharing the merge-mining slot) is not
resolved by the public pipeline.

**Chain-specific quirks.**

- **`CAuxPow` inline in `core.{h,cpp}`.** Bitmark uses the standard
  Namecoin-style `CAuxPow` structure (`class CAuxPow : public CMerkleTx` at
  `src/core.h:390`), but the class lives inline in `src/core.{h,cpp}` rather
  than separate `src/auxpow.{h,cpp}` files, which do not exist. A filename-only
  survey would wrongly conclude the chain has no AuxPoW support.
- **Algo-encoding inverse from Myriadcoin.** `ALGO_SCRYPT = 0`,
  `ALGO_SHA256D = 1` (`src/pureheader.h:14-15`), so the extractor filter is
  `algo == 1`, not `== 0`. Myriadcoin encodes SHA-256d as the default `0`.
- **Strict chain ID, permissive parent.** `fStrictChainId=true` is tighter than
  Myriadcoin's and Argentum's permissive mode, but a strict chain ID only binds
  the AuxPoW commitment to Bitmark; it does not establish that the SHA-256d
  parent is Bitcoin.
- **Empirically pinned activation.** Because Fork 1 is supermajority-governed
  rather than a fixed constant, the 450,947 activation height is an observed,
  boundary-walked value rather than a value read out of the source.

## 3. Filtering to accepted direct-stale candidates

**Loader filter** (`load_bitmark_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

The loader delegates to `load_auxpow_validated_stales(_LOADER_SPECS["bitmark"])`
and returns the established multi-algo row shape with `source="bitmark"`;
`coinbase_outputs` is raw pkscript hex semicolon-joined, preserved unchanged for
later attribution research. The single validated entry passes the filter.

**Post-filter count: 1 accepted direct-stale header candidate.**

| BTC height | BTC hash | BTMK height | Notes |
|---:|---|---:|---|
| 565,106 | `00000000000000000028f07e327704f901b4235cd5ca5dbb1cda979e2bc091cd` | 640,031 | `/BTC.COM/` coinbase tag; publication-gate-accepted direct-stale candidate sharing the parent of canonical `00000000000000000003b334db24531a911ffefd48a98ee8784b96e4c15c50bd` (parent `0000000000000000002d66d8cd9087827d4a95c34b124b1a6b61e19c0c58c768` at height 565,105; header timestamps differ by ~15 s); already present in Unobtanium, Myriadcoin, and RSK |

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py bitmark`. Per-stale
row-level breakdown at `results/per-chain-novelty/bitmark.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 1 | 100.0 % |
| novel vs upstream | 0 | 0.0 % |

The recovered stale is present in upstream (height 565,106; the upstream record
is header-only, so the pool tag and cross-chain presence come from this
project's own AuxPoW extraction, not from upstream).

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Bitmark is 18th chronologically. The same BTC hash was already recovered by
three earlier-born integrated chains: Unobtanium (position 9, BTMK-side height
1,259,726), Myriadcoin (position 11, height 2,716,417), and RSK (position 16,
height 1,178,267).

| Split | Count |
|---|---:|
| also in upstream | 1 |
| also in earlier-born chain (unobtanium / myriadcoin / rsk) | 1 |
| **novel at this position** | **0** |

Under the project's chronological-precedence convention, Unobtanium
(AuxPoW-activated 2015-05-08) retains first-seen credit, ahead of Myriadcoin
(2015-09-26), RSK (2018-01-01), and Bitmark (2018-06-07). Bitmark's accepted
row is cross-confirmation, not a novel stale.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a
> simplifying convention for reproducible attribution, **not** a claim about
> which chain literally observed the stale first in real-world block time.

## 4. Outputs and references

**In-repo artifacts.**

- `data/validated-stales/bitmark_validated_stales.csv` - 1 validated stale (committed; the
  loader's input).
- `results/per-chain-novelty/bitmark.csv` - per-stale
  `(height, hash, in_upstream, first_seen_chain)` table recording the zero-novel
  attribution.
- `node-infra/bitmark/{Dockerfile,docker-compose.yml,init.sh,justfile,peers.list,README.md}`
  - build infrastructure for reproducing the node.

**Private archive artifacts** (row counts and checksums preserved; not tracked
in git).

- `bitmark_auxpow_raw.csv` - 255,538 raw SHA-256d-AuxPoW rows (extractor output,
  pre-PoW-filter).
- `bitmark_btc_valid.csv` - 82,819 self-target-PoW-valid unique headers
  (intermediate, before classification).
- `bitmark_stale_blocks.csv` (1 stale) / `bitmark_unknown_blocks.csv` (81,921) /
  `bitmark_canonical_blocks.csv` (897) - the classifier's split inventories.

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (Bitmark row 18).
- Source: `github.com/project-bitmark/bitmark` (master, HEAD `ffd840e`,
  2023-06-15). `src/core.h::CAuxPow` is the inline AuxPoW structure;
  `src/pureheader.h` holds the algo enum and `nVersion` bit masks;
  `src/chainparams.cpp` holds the chain ID and genesis.
- Live explorer: `chainz.cryptoid.info/btmk/`.
- Upstream: `bitcoin-data/stale-blocks` carries BTC height 565,106
  (header-only; no pool or first-seen metadata).

**Methodological note.**

Bitmark reinforces the Argentum lesson from a strict-chain-ID chain: structural
AuxPoW evidence is not equivalent to validated Bitcoin-parent evidence. A live
8-algo chain with real SHA-256d activity and standard `CAuxPow` commitments
still yields a single accepted direct-stale candidate, and that candidate is
already covered by three earlier chains. The 81,921 unknowns satisfy only their
encoded self-target; a `fStrictChainId=true` setting binds the commitment to
Bitmark but does not prove the parent is Bitcoin.
