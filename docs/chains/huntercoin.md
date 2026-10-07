# Huntercoin

| Field | Value |
|---|---|
| Ticker | HUC |
| AuxPoW activation | 2014-01-31 (genesis; merge-mined from block 0 - see §2 quirks) |
| Network status | Current recovery from the Daniel Kraft native dump; earlier live-node probes were unsuccessful |
| Chronological position | 8 of 27 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin; before unobtanium) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; Huntercoin's February–March 2014 window is inside the paper's period but it was not a sampled data source) |
| AuxPoW chain ID | 6 (SHA-256d branch; the Scrypt branch with chain ID 2 / LTC parent is out of scope) |
| Block time | 120 s per algorithm (dual SHA-256d + Scrypt), ~60 s combined |
| Source tag (in code) | `huntercoin` |
| Loader | `load_huntercoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/huntercoin_validated_stales.csv` |
| Full stale/unknown inventory | Private Kraft generation: 78 stale + 150,853 unknown rows |

Huntercoin (HUC) was a dual-PoW chain (SHA-256d merge-mined with Bitcoin and Scrypt merge-mined with Litecoin in parallel) launched February 2014 by Andrew Colosimo and Mikhail Syndeev (Sindeyev); Daniel Kraft has maintained the core code since 2014 (Xaya legacy page, https://xaya.io/huntercoin-legacy; bitcointalk ANN, https://bitcointalk.org/index.php?topic=435170.0). Earlier live-node and explorer probes were unsuccessful. The native dump
supplied by Daniel Kraft now extends recovery beyond the first ~100k blocks
available through `domob1812/arblockstore`. The current accepted set contains
78 direct-stale candidates; the earlier 13 are all preserved.

## 1. Chain data

### Native dump received in October 2026

The operator received `huntercoin-chain.tar.bz2` from Daniel Kraft. Its
23,830,581,664 bytes have SHA-256
`4f8b7fe2357e69a1b97c300eaf65062925f5408b7ed228293968e3bfd1dcb6b3`.
The source and archive-copy digests match, the complete bzip2 stream passes its
integrity check, and the safe member inventory contains 3,908 files expanding
to 40,167,613,773 bytes. Originals, metadata receipts and earlier recoveries
remain private and immutable. There was no sender checksum or declared tip;
this digest identifies received bytes, while attribution rests on the
operator's report.

A separate working copy contains 163 numbered block files with mainnet magic
`f9beb4fe`. All 3,938,028 unique stored headers link to the retained genesis,
through maximum height 3,937,953 at 2021-07-27 16:18:22 UTC, hash
`3ce9f58cf05956c4b7c9c21e7bba205c168d99c87cdb9bc9640ea2e95311e277`.
All 99,012 retained Arweave height/hash anchors match, including the heights
whose Arweave payloads were unavailable. Stored side branches explain why the
header count exceeds the maximum height plus one. No daemon was started and
neither active-chain membership nor complete native consensus was replayed.

The normal native producer authenticates SHA-256d child targets, parent
transaction Merkle inclusion and child commitments/chain slots before atomically
emitting 1,952,084 raw SHA proofs. It accounts separately for 1,970,861 Scrypt
proofs and 15,083 non-AuxPoW records. Classification yields 161,558 unique
self-target-PoW-passing parents: 10,627 canonical, 78 accepted direct stales and
150,853 unknowns. The other 1,790,526 lower-work observations remain private.
The accepted window spans BTC 285,130 to 488,624 and HUC 43,156 to 1,950,115;
all 78 rows pass the available Bitcoin publication profile with `VALID`.

All 13 preceding accepted events remain. The 65 additional Huntercoin
witnesses include four Bitcoin headers absent from the preceding compact
inputs and pinned upstream dataset, at heights 302,118, 375,604, 377,506 and
488,624. Two authenticated observations of the invalid BIP66 fork and another of the
known BIP34-invalid parent at 331,674 are retained separately in the reviewed
error ledger. The latter is witnessed at native child height 460,428; its full
AuxPoW matches the catalogue header and coinbase bytes.

One authenticated position-zero parent transaction has a non-null prevout.
Its raw transaction and AuxPoW are retained, while Bitcoin coinbase evidence
fields are empty. Its parent and predecessor are absent from the queried
Bitcoin Core node, and it remains unknown. Merkle inclusion alone does not
make that transaction a Bitcoin coinbase or establish its parent network.

### Earlier Arweave generation

The original `domob1812/arblockstore` acquisition covers the first ~100,000
HUC blocks. Its retained raw extraction contains 43,288 SHA-256d proof rows;
the classifier produced 857 canonical, 13 accepted stale and 29 unknown rows.
Its accepted BTC window is 285,130 to 290,178 (February to March 2014).
The historical counts and pool diagnostics below describe that bounded
sample, not the expanded native generation.

**Remaining coverage limits.** Scrypt/Litecoin evidence remains out of scope.
The observed July 2021 endpoint is a dump boundary, not proof of the chain's
final block. Two initially strict-looking observations at BTC 363,732 and
363,733 extend the known BIP66-invalid version-2 root at 363,731. Complete
header paths, full Bitcoin work and the root violation are authenticated by
`data/error-blocks/ancestry_evidence.csv`; their two Huntercoin witnesses are
published as `error_block`, leaving no strict/weak Huntercoin observations.
The source unknown bucket remains unchanged as audit evidence.
The historical 29-row pool audit cannot
be extrapolated to the expanded population. Full Bitcoin block-body validity is generally unproven by AuxPoW.

**Current workflow.** The Kraft dump is the sole foundation input. The retired
Arweave fetcher, per-height binary route, index comparison and failure-manifest
handling are no longer part of the pipeline. Historical inputs and their
acquisition receipts remain private provenance; they are not required to rerun
current recovery. Install the current private classifier family at
`<chain-archive>/huntercoin/classified/`, using the ordinary archive layout;
retain the former family in a dated provenance directory outside discovery.

```bash
just extract-huntercoin \
  --blocks-dir <working-blocks-dir> \
  --workers 6 \
  --output <staged-raw-output.csv>
```

Parent inclusion and child script/branch commitments are shared with Xaya,
Qbit and Lyncoin through `auxpow_commitment`. The native-record adapter keeps
its transaction completeness and index guards, grouped errors and validation
order. Authenticated non-coinbase parents remain control evidence. The shared
rules do not add Huntercoin's historical fork-dependent marker policy or prove
native active-chain membership or full consensus.

The producer scans both algorithms and non-AuxPoW headers to reconstruct stored predecessor
links to the known genesis, rather than assigning heights by file order.
It authenticates the SHA-256d child's encoded target, the parent coinbase
Merkle branch, the child commitment and its chain-ID slot. Missing ancestry,
malformed proofs, unsupported AuxPoW chain IDs or changing inputs prevent atomic replacement of the raw CSV.

Native files may contain zero-filled reserve gaps. The reader accounts for
those gaps without skipping nonzero bytes. Raw native rows retain their
file and record offset, `full_coinbase_hex` and `auxpow_hex`, preserving the
complete parent transaction and proof. These are private
acquisition fields, not additions to the shared Monitor schema. Stored
header ancestry does not establish active-chain membership, replay the
complete child consensus rules, or prove full Bitcoin block validity.

## 2. Extraction → potential stales

**Historical Arweave method.** The superseded workflow used Arweave-archive fetch → AuxPoW parse (SHA-256d branch only, chain_id == 6) → BTC RPC classification on `<archival-host>`. AuxPoW format is Vince Durham / Daniel Kraft serialisation, byte-identical to Namecoin's - the existing binary parser is reused.

**Phases.**

1. **Fetch**: pull the `domob1812/arblockstore` archive from Arweave. The
   source index authenticates 99,012 historical heights; 98,978 payloads are
   available and 34 repeatedly unavailable transactions are recorded in the
   acquisition-failure manifest. The extractor requires that manifest to
   account exactly for every indexed height without a block binary.
2. **Parse**: walk every HUC block in the archive; require the accompanying source index to authenticate each filename height against the computed child-header hash, then extract the parent header + coinbase tx + Merkle branch from the SHA-256d branch (chain ID 6). Drop the Scrypt branch (chain ID 2).
3. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in the parent header. This filter is separate from the raw extractor's `pow_valid` flag, which refers to Huntercoin's child-chain target.
4. **BTC RPC classify** (against the existing Bitcoin Core node on `<archival-host>`): `getblockheader <hash>`. A header with positive confirmations → `canonical`. Otherwise (not found, or known only as a side-chain block) look up `prev_hash`: a predecessor with positive confirmations → `stale`; neither → `unknown`.

A missing source-index entry or hash contradiction terminates extraction. It is
not counted as a recoverable mismatch in the final statistics because no
partial output is publishable after the authentication contract fails.

**Historical Arweave counts.** The raw extractor holds **43,288** SHA-256d-branch AuxPoW rows - every row is `chain_id == 6` and Huntercoin-PoW-valid, and all 43,288 parent-header hashes are distinct. The self-target PoW filter (phase 3) is the dominant cut: **899 rows meet the Bitcoin target encoded in their parent header** (`SHA256d(header) ≤ target(nBits)`, recomputed directly from `btc_header_hex`). Bitcoin RPC then classifies those 899:

| Classification (self-target-PoW-valid rows) | Rows |
|---|---:|
| `canonical` (parent on the BTC mainchain) | 857 |
| `stale` (parent off-chain, prev canonical) | 13 |
| `unknown` (parent + prev both off-chain) | 29 |
| **Total PoW-valid** | **899** |

The earlier loader admitted the 13 publication-gate-accepted rows; the current input contains 78.

An earlier diagnostic instead RPC-classified *every* raw row before the PoW filter, to gauge how many are stale-shaped: 857 parent-canonical, **42,208** with an off-chain parent but a canonical `prev` (stale-shaped), and 211 with both off-chain. The 42,208 stale-shaped rows are overwhelmingly sub-BTC-difficulty AuxPoW noise - only 13 survive the self-target filter - which is the substance of the H2 reading in §3. (Those three provisional categories sum to 43,276; the ~12-row difference from the 43,288 raw total is unresolved RPC-probe remainder in the recovered 2026-05-14 diagnostics, all of it sub-difficulty, so it touches none of the 899 PoW-valid rows or any committed count.)

**Chain-specific quirks.**

- **Dual-PoW chain**: SHA-256d branch (chain ID 6, BTC parent) AND Scrypt branch (chain ID 2, LTC parent), both source-confirmed (`chronokings/huntercoin` `main.cpp`: `chain_id[NUM_ALGOS] = { 0x0006, 0x0002 }`). The extraction filters to chain ID 6 only; the Scrypt branch is out of scope for this project. Target spacing is `nTargetSpacing = 60 * NUM_ALGOS` = 120 s per algorithm (~60 s combined; the dev comment reads "A block every minute for all algos in total"), and the empirical rate across the sampled HUC range is ~57 s/block.
- **Genesis is the AuxPoW activation.** Genesis `nTime` 1391199780 = 2014-01-31 20:23 UTC, merge-mined from block 0: the genesis coinbase names both parents (`Bitcoin block 283440: …` and `Litecoin block 506479: …`) and the source sets `fStrictChainId = true` with no delayed AuxPoW start height. So 2014-01-31 is the real genesis/activation date, not merely a catalogue value.
- **Offline sources**: the retained Arweave archive independently anchors the early native dump. Neither recovery needs a live peer.
- **Standard classifier output schema**: the private full inventory now uses the project-wide schema (`btc_header_hash`, `btc_time`, `classification`) and contains only self-target-PoW-valid non-canonical rows. `pow_valid`, `chain_id`, and `btc_merkle_root` remain in the raw extractor output, not in the standard inventory.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_huntercoin_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

All 78 current entries pass (the compact CSV is VALID-only).

**Post-filter count: 78 accepted direct-stale header candidates.**

Namecoin, I0coin, IXCoin, Devcoin and Groupcoin independently witness members
of Huntercoin's accepted set.

### Novelty

Current upstream overlap and chronological allocation are in the [novelty report](../../results/novelty.md).

### Historical Arweave unknown inventory

The 29 self-target-PoW-passing **unknowns-by-our-standard** (parent not in BTC mainchain, prev_hash also not in BTC mainchain) live in the private unknown-inventory bucket (`huntercoin_unknown_blocks.csv`) under `classification == "unknown"`. These rows are evidence of an isolated chain segment that **no other AuxPoW chain in scope captured**:

| Cross-reference | Hits |
|---|---:|
| Huntercoin unknown `prev_hash` ∈ any chain's validated stales | **0 / 29** |
| Huntercoin unknown `prev_hash` ∈ any chain's unknown inventory | **0 / 29** |
| Huntercoin unknown `parent_hash` ∈ any chain's unknown `prev_hash` | **0 / 29** |
| Huntercoin unknown `parent_hash` ∈ any chain's unknown inventory | **0 / 29** |

Across all integrated chains' validated-stale sets (`namecoin`, `i0coin`, `ixcoin`, `coiledcoin`, `devcoin`, `unobtanium`, `terracoin`, `elastos`, `syscoin`, `rsk`, plus `bitcoin-data/stale-blocks` upstream) AND the archived unknown inventories (`namecoin_stale_blocks.csv` 7,843 unknowns, `devcoin_unknown_blocks.csv` 75,141 unknowns, `ixcoin_unknown_blocks.csv` 253,974 unknowns, `syscoin_unknown_blocks.csv` 18,282 unknowns, `elastos_unknown_blocks.csv` 9,004 unknowns) - **none** of Huntercoin's 29 unknown hashes appear anywhere. The chain segment is fully isolated to Huntercoin's AuxPoW recording.

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

## 4. Outputs & references

**Artifacts.** Loader inputs under `data/`, the
[novelty report](../../results/novelty.md), and the strict/weak and monitor-evidence
exports are committed here. The pool-attribution diagnostics live in the
private archive.

- `data/validated-stales/huntercoin_validated_stales.csv` - 78 validated stales (loader input). Standard schema.
- [Novelty report](../../results/novelty.md).
**Private archive artifacts.**

- `huntercoin_auxpow_raw.csv` - current native raw output (1,952,084 SHA-256d proof rows); the earlier 43,288-row Arweave output is retained separately.
- Split inventories: `huntercoin_stale_blocks.csv` (78 stale) and `huntercoin_unknown_blocks.csv` (150,853 unknown).
- `huntercoin-unknown-pool-attribution.csv` and its summary JSON - historical
  pool-attribution diagnostics.

The classifier requires `huntercoin_auxpow_raw.csv` from the current extractor.
It projects the native acquisition schema for the shared driver; SHA-256d branch
selection and proof authentication belong to the native producer.
The historical normalized inventory is an output, not a fallback acquisition
source, because it cannot reproduce the authenticated child-header bundle.

**External references.**

- `domob1812/arblockstore` on Arweave - independent early-chain acquisition and native-dump anchor.
- `docs/auxpow-recovery.md` - cross-chain summary table (Huntercoin row).

**Remaining work.**

The native dump extends the earlier bounded recovery. Its observed endpoint
and available-evidence limits remain explicit above. The three historical
Arweave follow-ups were closed:

- **Item 1 - pool-tag audit on the 29 unknowns**: resolved. 0/29 recognisable BTC pool tags vs 13/13 in the validated stales. See §3.
- **Item 2 - unknown-inventory schema rewrite**: resolved. Full inventory at standard schema; redundant `huntercoin_orphan_stales.csv` removed. See §1.
- **Item 3 - Arweave archive extension search**: closed with a documented null result on 2026-05-14. The `domob1812/arblockstore` Arweave archive maxes at HUC block 100,000 (Arweave GraphQL `Block-Height` tag confirmed via `sort: HEIGHT_DESC` - newest indexed records carry HUC heights 99,389-100,000, with Arweave indexing timestamps in October 2021 - and the fetched payloads are preserved in the private archive). No longer archive was found at the checked vectors in that review: `chronokings/huntercoin` and `domob1812/huntercore` have empty GitHub-releases listings (no `bootstrap.dat`); `huntercoin/huntercoin` returns 404; `chainz.cryptoid.info/huc/` is delisted (HTTP 307 → root, and HUC is absent from the 109-chain `/api.dws?q=summary` index); archive.org returns 0 hits for "huntercoin blockchain" or "huntercoin bootstrap.dat"; Wayback CDX shows no octet-stream captures of huntercoin.org. No third-party outreach was attempted in that historical search; the operator subsequently obtained the Kraft dump.

## 5. Integration history

- **2026-05-14** - Arweave archive fetched and classified. The original run used a non-standard schema (`btc_parent_hash`/`btc_timestamp`/`pow_valid`) and a three-way `canonical / stale-known / stale-novel` vocabulary; the integration pass normalised it to the shared schema (13 direct stales), computed the cross-chain isolation of the 29 unknowns, closed the Arweave archive-extension search with a documented null result, and defined the unknown-coinbase pool-tag audit in a remaining-work brief.
- **2026-05-31** - Arweave/data-hunt re-verification: the archive maxes at HUC block 100,000, and every alternative source vector was re-checked with nothing found beyond the permaweb archive.
- **2026-06** - Pool-tag H1/H2 audit run: 0/29 recognisable BTC pool tags on the unknowns vs 13/13 on the validated stales (F2Pool 7, Eligius 4, CloudHashing 2), supporting H2. Founder/launch facts were corrected (launch February 2014; founders Colosimo + Syndeev; Kraft maintainer since 2014).
- **2026-06-24** - Canonical refresh / full-evidence build (857 canonical + 13 stale + 29 unknown = 899).
- **2026-07** - Published in merge-mining-research: `orphan`→`unknown` terminology, the redundant `huntercoin_orphan_stales.csv` sidecar removed, and the private diagnostics renamed `huntercoin-unknown-pool-attribution*`.

- **2026-10-05** - Native Kraft dump ingested offline, with all Arweave anchors verified. The accepted set expands from 13 to 78; historical attribution findings remain bounded to their original sample.
