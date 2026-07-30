# Xaya

| Field | Value |
|---|---|
| Ticker | CHI |
| AuxPoW activation | 2018-07-13 (chain genesis; SHA256D-AuxPoW accepted from genesis, although the genesis block itself is NEOSCRYPT) |
| Network status | Dead. The legacy Xaya Core P2P network is fully down (DNS seeds removed, fixed seeds unreachable; see `node-infra/xaya/peers.list`), and the CHI to WCHI migration (announced 2025-09-12, snapshot taken at Xaya Core block height 7,300,000 on 26 Oct 2025) wound the chain down. Recovered offline from Xaya's own open `blocks.zip` snapshot, not from a live node. |
| Chronological position | 19 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven, argentum, terracoin, emercoin, rsk, doichain, bitmark; before elastos) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; Xaya launched 2018-07-13, just after the paper's mid-2018 data cutoff) |
| AuxPoW chain ID | `1829` (`0x0725`); no `fStrictChainId` flag (the AuxPoW parent is a plain Bitcoin `CPureBlockHeader` that carries no chain ID) |
| Algorithms | Dual-algo: NEOSCRYPT (CPU/GPU, solo-mined) or SHA256D (merge-mined with Bitcoin). The source enforces "SHA256D must be merge-mined" and "NEOSCRYPT must not", so SHA256D block <=> carries a Bitcoin-parent `CAuxPow`. Only the SHA256D branch is in scope. |
| Block format | Non-standard for this lineage: a `PowData` wrapper is appended after the usual 80-byte header, encoding `{ algo:uint8, nBits:uint32, payload }` where the payload is a `CAuxPow` iff `(algo & 0x80)` (FLAG_MERGE_MINED), else a fake `CPureBlockHeader`. The embedded `CAuxPow` is the standard Namecoin layout; only the outer block parsing needs custom logic. |
| Block time | ~30 s nominal across both algorithms (data-derived: 6,344,114 blocks over 2018-07-13 to 2024-11-15). The SHA256D merge-mined branch is 26.7% of blocks (~1 every ~118 s). |
| Source tag (in code) | `xaya` |
| Loader | `load_xaya_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/xaya_validated_stales.csv` |

Xaya (CHI) is Daniel Kraft's blockchain-gaming platform and the successor to Huntercoin, built on a `namecoin-29.x` (Bitcoin Core 29.x lineage) base with Kraft's own Namecoin-style AuxPoW. It is the **19th chain by AuxPoW-activation date**, slotting between Bitmark (2018-06-07) and Elastos (2018-08-26). Two things make it notable. First, 26.7% of the 6.34M scanned blocks carry a SHA256D merge-mining parent, yielding 38,483 self-target-PoW-valid candidates. Second, it is the **first node-less full-history recovery driven by a chain's own published block dump**: the legacy P2P network is dead, but Xaya openly serves a raw `xayad` `blocks/` directory as a single `blocks.zip`, which is all the extractor needs.

The substantive result is a study in the chronological-novelty convention.
Xaya's 2026-06-24 refresh recovered **40 accepted direct-stale candidates**,
but **0 are chronologically novel**: every one was already first-claimed by an
earlier-born integrated chain (Namecoin, Emercoin, or RSK) or is already in
upstream. The original run contained 34 rows; the 2026-06-24 canonical-refresh
re-run reclassified six previously-canonical headers as stale, raising the
accepted set to 40 (the original 34 remain a strict subset). A historical
private attribution pass was F2Pool-dominated, but the public pipeline does not
reproduce that label distribution. The public conclusion is narrower: the accepted hashes
overlap earlier sources and therefore receive zero novelty under the
earlier-born-wins convention.

## 1. Chain data

**Source.** Xaya's own CDN openly serves `https://downloads.xaya.io/blocks.zip` (4.19 GiB, no auth, range-resumable), a raw `xayad` `blocks/` directory dump. Verified at acquisition: HTTP 200, content-length 4,501,429,021, last-modified 2024-11-15, PK zip magic (the CDN origin has since been intermittently unreachable). Every other acquisition path is dead: DNS and fixed seeds decommissioned, ElectrumX closed, explorer origins return Cloudflare 503, third-party explorers expired, and the official CHI to WCHI migration snapshot is UTXO/balances-only (not block history). The dead-network probe is recorded in `node-infra/xaya/peers.list`.

**Provenance.** Downloaded and unpacked on `<archival-host>` to `<chain-data-dir>/blocks/` (41 `blk*.dat`, 7.0 GB, genesis to ~6.34M, no `xor.dat`). Mainnet message-start bytes `cc be b4 fe`, confirmed against `blk00000.dat`. The wire format was cross-checked against `src/powdata.{h,cpp}`, `src/primitives/pureheader.h`, and `src/primitives/block.h` on `xaya/xaya` master. Bitcoin Core on `<archival-host>` provided the BTC RPC for classification.

**Coverage.** The refreshed accepted set spans BTC heights **547,182 to
853,120** (October 2018 to 20 July 2024). The extraction ran over the whole
snapshot (Xaya genesis to ~6.34M, 2018-07-13 to 2024-11-15). The stale window
is Xaya's actual BTC-parent stale yield within that span, not a coverage hole.

**Holes.**

- **Snapshot tail gap** (Xaya ~6.34M to ~7.3M): the published `blocks.zip` is dated 2024-11-15 and stops at roughly Xaya height 6.34M, short of the ~7,300,000 deprecation block where the chain wound down. This tail is a documented coverage gap and a future top-up if a live peer or an updated dump becomes available (an outreach email to Daniel Kraft for the tail is drafted but unsent).
- **NEOSCRYPT branch out of scope** (73.3% of blocks): NEOSCRYPT blocks are solo-mined and carry no Bitcoin parent, so they contribute nothing to BTC stale recovery. Only the 26.7% SHA256D branch is read.
- **No live node**: the legacy P2P network is fully down, so a node sync was impossible. The offline snapshot is the only data path.
- **Possible altchain contamination** in the raw candidate pool: Xaya spans 2018 to 2024, so unknown rows may include BCH/BSV-family or other SHA-256 parents. Unknown does not identify a particular source. These rows do not enter the accepted direct-stale set, and the non-skippable expected-`nBits` gate checks stale-labelled candidates.

**Reference scripts.**

- `scripts/extract/extract_xaya_auxpow.py:1` - parses Xaya's `PowData` block-header wrapper, keys on the `0x80` merge-mined flag, and reuses the shared AuxPoW/header helpers. The historical helper name `hash_meets_btc_difficulty` performs only the encoded self-target check described in the [validity contract](../data-validity.md). Emits the canonical `run_classifier` input schema.
- `scripts/classify/classify_xaya_stales.py:1` - thin `run_classifier(CHAIN_SPECS["xaya"])` wrapper (self-target PoW filter + dedup + `getblockheader` lookups + the expected-`nBits` gate). Exposes `--validated-output` so all outputs can be written into the offline archive directory.
- `node-infra/xaya/{Dockerfile,docker-compose.yml,init.sh,justfile,peers.list,README.md}` - node scaffold (`ubuntu:24.04` toolchain for `xayad` v1.13), retained for a future tail top-up.

## 2. Extraction → potential stales

**Method.** Offline `blk*.dat` parse on `<archival-host>`. For each block, read the 80-byte `CPureBlockHeader`, then the `PowData` `algo` byte at offset 80. If `(algo & 0x80)` is clear the block is solo-mined (NEOSCRYPT) and is skipped. Otherwise the block is merge-mined (SHA256D) and the standard Namecoin `CAuxPow` begins at offset 85 (80 header + 1 algo + 4 nBits), parsed by `read_auxpow()`. The extractor emits `child_header_hex`, `child_block_hash`, and `child_block_time` from `CPureBlockHeader`; `child_nbits` comes from the little-endian `PowData` uint32 at offsets 81 through 84, not the pure header's bytes 72 through 75. The parent header is then validated against Bitcoin difficulty. Keying on the `0x80` merge-mined flag rather than the exact `PowAlgo` integers mirrors the source's own `isMergeMined()` test (`algo & FLAG_MERGE_MINED`, `FLAG_MERGE_MINED = 0x80`); the full enum (`SHA256D=1, NEOSCRYPT=2, FLAG_MERGE_MINED=0x80`) is defined in `src/interfaces/mining.h`. It is validated by the clean extraction (0 parse errors).

The extractor requires the pure header's own `nBits` field to be zero and the
effective `PowData` target to be non-zero. A contradiction aborts extraction
at the source block rather than emitting a row for later rejection.

**Phases.**

1. **Parse with merge-mined gate**: walk all `blk*.dat` blocks; decode the `PowData` `algo` byte; discard blocks without the `0x80` merge-mined flag (the NEOSCRYPT majority).
2. **Self-target PoW filter** (`classify_xaya_stales.py`): keep only headers where `SHA256d(header) <= target(nBits)` using the target encoded in that header.
3. **Dedup**: keep only unique BTC header hashes (many Xaya blocks can reference the same BTC parent).
4. **BTC RPC classify**: batched `getblockheader`. Hit -> `canonical`. Miss -> look up `prev_hash`. Prev canonical -> `stale`. Neither -> `unknown`. Then the `validate_stale_nbits` gate over the stale rows.

**Counts:**

| Stage | Rows |
|---|---:|
| Blocks scanned (genesis to ~6.34M) | 6,344,114 |
| Merge-mined (SHA256D) | 1,695,912 |
| Parse errors | 0 |
| Self-target-PoW-valid unique parents | 38,483 |
| After classification | **34 stale + 17,642 unknown** (20,807 canonical dropped; original run. The 2026-06-24 canonical-refresh re-run moved six canonical headers to stale, committing 40 stales and 20,801 canonical; the unknown split and the 38,483 pool are unchanged) |

The 26.7% merge-mined share (1,695,912 of 6,344,114) confirms a dense AuxPoW environment over the snapshot window. **38,483 is the self-target-PoW-valid candidate pool, not the stale count**. Bitcoin Core classification identifies which of those parent headers are canonical, stale-labelled, or unknown.

**Chain-specific quirks.**

- **`PowData` block-header wrapper.** Xaya is the only chain in the pipeline whose on-disk block prepends a `PowData` structure after the 80-byte header. The custom outer parse is the one piece of Xaya-specific logic; the embedded `CAuxPow` is byte-identical to the Namecoin family, so the shared modules port across unchanged.
- **SHA256D <=> merge-mined.** Because the source enforces "SHA256D must be merge-mined", the merge-mined flag is a proxy for carrying an AuxPoW parent header. It does not by itself prove that the parent is Bitcoin.
- **Exact offline `child_height`.** Xaya activates BIP34 at height 1, so every merge-mined block in scope carries its consensus height at the start of the child coinbase scriptSig. The extractor reads that height after the `PowData`/`CAuxPow` wrapper and emits no scan-order field, so the classifier and monitor use the same exact `(source, child_height, child_block_hash)` identity as the other chains.
- **Chain ID 1829 (`0x0725`); no `fStrictChainId` flag.** Xaya's AuxPoW parent is a plain Bitcoin `CPureBlockHeader` that encodes no chain ID, so the Namecoin-style strict-chain-ID rule does not apply (the modern `xaya/xaya` tree has no such flag; the chain ID feeds only the AuxPoW merkle-index derivation). It does not establish Bitcoin parent identity; Bitcoin Core classification and the later validation gates do that work.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_xaya_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status.startswith("VALID")
```

The loader parses `coinbase_outputs` as raw pkscript hex, semicolon-joined
(matches the crown / myriadcoin / ixcoin format). The extractor preserves the
parent-coinbase outputs verbatim without address decoding so they remain
available for later attribution research. All 40 refreshed entries pass the
filter.

**Post-filter count: 40 accepted direct-stale header candidates (2026-06-24 refresh; the original run committed 34).**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py xaya`. Per-stale row-level breakdown at `results/per-chain-novelty/xaya.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 29 | 72.5 % |
| novel vs upstream | 11 | 27.5 % |

The 11-novel-vs-upstream figure is Xaya's contribution measured against upstream in isolation. None of these 11 reach the upstream sidecar as net-new rows, because each is already contributed by an earlier-born chain (see view (b)).

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Xaya is 19th chronologically. Earlier-born integrated chains: namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven, argentum, terracoin, emercoin, rsk, doichain, bitmark.

| Split | Count |
|---|---:|
| also in upstream | 29 |
| also in earlier-born chain (`namecoin`: 16, `emercoin`: 11, `rsk`: 7 - first-claim distribution) | 34 |
| **novel at this position** | **0** |

All 40 accepted rows in the 2026-06-24 refresh are accounted for by upstream or an earlier-born chain: 29 are already upstream and the other 11 are first-claimed by an earlier chain. Xaya therefore adds **0 chronologically novel candidates and 0 net-new upstream sidecar rows**, while providing independent cross-chain evidence for 40 accepted header candidates across a large 2018 to 2024 window. The overlap does not, by itself, establish a shared miner population.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/xaya_validated_stales.csv` - 40 accepted direct-stale candidates
  (committed; the loader's input; 34 in the original run).
- Private archive `xaya_btc_valid.csv` - 38,483 self-target-PoW-valid unique parent rows (intermediate, before classification; on `<archival-host>` only).
- Private archive split inventories (2026-06-24 refresh): `xaya_canonical_blocks.csv` (20,801 canonical), `xaya_stale_blocks.csv` (40 stale), and `xaya_unknown_blocks.csv` (17,642 unknown; on `<archival-host>` only, plus a local gitignored scratch copy); these reconcile to the 38,483 self-target-PoW-valid parents. Not yet folded into unknown-to-stale-descendant reconciliation, which requires the full multi-chain inventory set.
- `results/per-chain-novelty/xaya.csv` - per-stale `(btc_height, btc_hash, in_upstream, first_seen_chain)` table.
- `node-infra/xaya/{Dockerfile,docker-compose.yml,init.sh,justfile,peers.list,README.md}` - node scaffold (`ubuntu:24.04` toolchain), retained for a future tail top-up.

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (Xaya row).
- Xaya source and the `PowData` format: `xaya/xaya` on GitHub (`src/powdata.{h,cpp}`, `src/primitives/pureheader.h`).
- Block dump: `https://downloads.xaya.io/blocks.zip` (2024-11-15 snapshot).

**Methodological note.**

Xaya is the project's first **node-less full-history recovery driven by a chain's own published block dump**. Where Bitcoin Vault demonstrated node-less recovery via a third-party Blockbook REST explorer, Xaya goes further: the chain operator openly serves the raw `xayad` `blocks/` directory, so the entire history is one unauthenticated download away even though the P2P network is dead. Any wound-down chain whose team still hosts a `blocks.zip`, `bootstrap.dat`, or raw block tarball is a candidate for the same approach. The substantive finding is 40 accepted direct-stale candidates over 2018 to 2024, all already represented by upstream or earlier-born chains under the project's novelty convention.
