# RSK (Rootstock)

| Field | Value |
|---|---|
| Ticker | RBTC / RSK |
| Recovery chronology | RSK mainnet launched in January 2018. The 2026-09-08 extraction covers the half-open range `[0, 9220905)`, including canonical blocks and every advertised uncle. The former lower bound of 139,999 was an acquisition convention, not a consensus activation or proof-format boundary. The height-zero `0x00` genesis sentinel and structurally recognised RLP fallback signatures are recorded as intentional skips; every other non-80-byte or malformed proof fails the interval. |
| Network status | Active. Data were acquired from an RSKj Vetiver 9.0.1 archive node on `<archival-host>`; 9.0.3 was the current upstream release when audited on 2026-07-22. |
| Chronological position | 16 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven, argentum, terracoin, emercoin) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; RSK is not a Namecoin-family SHA-256d fork and was not sampled. RSK mainnet launched inside the paper's window, but the accepted direct-stale window is almost entirely after the mid-2018 cutoff) |
| Block time | ~30 s (≈ 20 RSK blocks per BTC block) |
| Source tag (in code) | `rsk` |
| Loader | `load_rsk_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/rsk_validated_stales.csv` (353 publication-gate-accepted direct-stale header candidates; historical filename, shared layout plus RSK miner-evidence and historical-label columns) |
| Historical label snapshot | `results/rsk_pool_registry.csv` (miner address to retained pool label) |

RSK is methodologically distinct from the Namecoin-family `CAuxPow` chains. Its merge-mining proof preserves the 80-byte Bitcoin parent header, a trimmed SHA-256 state, an unhashed coinbase tail, and a merkle proof, but not a reconstructable full coinbase transaction. The committed data preserves a historical miner-address label snapshot in `results/rsk_pool_registry.csv`; current classification may carry those labels into validated rows, but neither validation nor the loader depends on them. Sixty accepted rows carry the historical `Foundry USA` label; 43 of those keys are absent from every other chain's accepted direct-stale CSV.

## 1. Chain data

**Source.** Local RSKj v9.0.1 ("Vetiver") archive node on `<archival-host>`, installed via the `ppa:rsksmart/rskj` package and configured for full archive (no pruning). RPC at `http://localhost:4444`. Ethereum-compatible `eth_*` JSON-RPC; all block numbers hex-encoded. Java 17 (OpenJDK). Version 9.0.1 is acquisition provenance, not a claim that the research node runs the latest release.

**Provenance.** Configuration at `/etc/rsk/`. Data directory grows ~100 GB (archive sync). Sync took ~2 days from initial PPA install. Bitcoin Core on `<archival-host>` provided the BTC RPC for stale-block classification.

For a new long extraction, choose an endpoint at least 100 blocks below the
observed RSK tip and record both identities. This operational margin reduces
the chance of pinning a transient tip sibling; it does not replace the final
endpoint check. Set `RSK_RPC_URL` when the research worker reaches RSKj through
a remote endpoint or tunnel. The default remains `http://127.0.0.1:4444`.
Transport and RPC errors retry within the affected batch. Missing or malformed
evidence, identity mismatches and broken continuity stop the interval without
advancing its checkpoint, so the source can be diagnosed before resuming.

Fallback mining stores an RLP list of `v`, `r`, and `s` in the parent-header
field, with empty coinbase and merkle-proof fields. The integer widths vary:
mainnet height 653 has a 68-byte value, while adjacent heights 652 and 654 have
69 and 70 bytes. The extractor checks canonical RLP structure, signed-positive
scalar encoding, recovery-byte range and scalar bounds, following the
representation checks in [RSKj 9.0.1](https://github.com/rsksmart/rskj/blob/VETIVER-9.0.1/rskj-core/src/main/java/co/rsk/validators/ProofOfWorkRule.java#L206).
It does not independently recover the signer or replay RSK activation and
difficulty rules; those remain the trusted node's responsibility. The skip
ledger retains each source identity and actual proof length. Recognizable
representations can range from 4 to 70 bytes, so length alone is insufficient.

**Coverage.** The sealed 2026-09-08 extraction covers RSK heights **0 through 9,220,904**, preserving 18,609,230 parent-header observations and 166,082 intentional skips. All 9,554,407 advertised uncles are accounted for. The private classifier family contains 236,073 canonical Bitcoin-parent observations, 37,410 unknown observations and 354 stale-labelled observations, of which 353 are accepted after the exact-key exclusion gate. Accepted direct-stale candidates span BTC heights **514,235 to 965,652** (March 2018 to 5 September 2026) and reach RSK height 9,214,131. This is a fixed acquisition window, not lifetime coverage.

The completed Monitor projection contains **236,432 observations**: 236,073
canonical parents, 353 accepted direct stales, three accepted descendant
witnesses and three strict unknown observations. All 343 previously published
RSK observations are retained, including their child identity and sidecar
evidence. The canonical observations carry the complete available RSK child
identity and sidecar bundle.

**Holes.**

- **Early acquisition gap resolved**: canonical blocks and advertised uncles below RSK 139,999 are now accounted for. The first canonical child carrying a full 80-byte parent header is at height 43,971. The height-112,829 canary also carries a full header, but fails that header's own Bitcoin proof-of-work target. No parent observation below 139,999 survives the self-target PoW filter, so this interval contributes no canonical, stale or unknown rows to the classifier family. The first surviving canonical-parent observation is at RSK 141,809. Intentional fallback skips are acquisition accounting, not missing data.
- **Full coinbase unavailable**: RSK replaces a variable-length prefix of complete SHA-256 chunks with a 40-byte trimmed state and retains the unhashed tail. Limited output and `RSKBLOCK:` evidence can survive in that tail, but the full transaction and scriptSig cannot be reconstructed. RSK therefore cannot independently apply the scriptSig-length or BIP34-prefix checks, and the standard validated-schema coinbase fields remain empty.
- **`classification` column** (`stale`/`unknown`): emitted by `scripts/classify/classify_rsk_stales.py`. The original 2026-05-15 classification treated any `getblockheader` hit as canonical, so parent headers the Bitcoin node knew only as side-chain blocks (`confirmations=-1`) were silently filed as canonical; the 2026-09-05 reclassification applies the current active-chain test and recovers 39 additional accepted direct stales (§5). Coverage starts after the BCH fork and extends through the BSV-fork era, so altchain contamination is possible in principle. The `nBits` pass rejected zero stale-labelled candidates. Five candidates shared with Namecoin are consensus-invalid: the reclassification routes the four signed-negative versions that fail BIP65's minimum version 4 rule to the error-block sibling output, while the BTC 789,038 BIP34 coinbase-height violation is not derivable from RSK's evidence alone, so that row stays stale-labelled and the exact-key error-block gate excludes it. A sixth shared candidate at Bitcoin height 656,478 extends a trusted stale root, classifies as unknown, and is represented by the stale-descendant parent and witness tables. That leaves 353 accepted direct rows. RSK checks header hash and self-target PoW, active-parent linkage, expected `nBits`, median-time-past, and historical minimum block version. Its midstate-compressed proof does not expose the real coinbase scriptSig, so it cannot independently apply the scriptSig-length or BIP34-prefix checks. Unknown rows pass their encoded self-target and miss canonical-parent linkage; they remain in the private historical classifier inventory rather than the committed loader input. See the [data validity contract](../data-validity.md).
- **Historical audit**: on 20 July 2026, all 298 accepted direct rows were replayed against Bitcoin Core tip 958,882 and passed every check available from RSK's evidence. The scriptSig-length and BIP34-prefix checks remain untested for every accepted row, and this was not a full-block consensus replay. That replay was structurally blind to headers the original classifier had filed as canonical; the 39 rows recovered by the 2026-09-05 reclassification were not part of it (§5).

**Independent incremental audit.** On 8 September 2026, a separate review
checked all 16 newly accepted Bitcoin headers against Bitcoin Core 30.2.0 on
mainnet. All passed header identity and target checks, noncanonical placement,
active-parent linkage, expected Bitcoin difficulty, independently recomputed
median-time-past and the minimum-version rule. The receipt records 595 RPC
calls with the same tip, height 966,121, at the start and end. None matches a
key in the current 39-parent invalid catalogue. This review compared the prior
337 rows byte-for-byte and field-for-field; it did not repeat their contextual
audit. It did not validate a full Bitcoin coinbase or block body, RSK
merge-mining proofs, or child-chain consensus. Its receipt SHA-256 is
`f436cd1793687a88e85b6c574d79938005dfddd237f59a62d96a1d41659e1be6`.

**Reference scripts.**

- `scripts/extract/extract_rsk_auxpow.py:1` - Ethereum-style JSON-RPC extractor (`eth_getBlockByNumber`); reads `bitcoinMergedMiningHeader`, the compressed `bitcoinMergedMiningCoinbaseTransaction`, `bitcoinMergedMiningMerkleProof`, `hashForMergedMining`, and the RSK miner address. It requires explicit half-open bounds, pins both endpoint identities, validates canonical continuity and listed uncle hashes, and keeps RPC batches independent from durable checkpoint intervals. Each interval fsyncs the raw CSV and exact fallback ledger before atomically advancing byte offsets and segment digests. The final end identity is fetched again before full-content digests seal the checkpoint. All three artifacts remain private. Checkpoint version 3 records raw and skip-ledger paths relative to the checkpoint; move the complete bundle while preserving those relative paths.
- `scripts/classify/classify_rsk_stales.py:1` - four-pass classifier that requires the raw CSV's complete matching checkpoint, applies the self-target PoW filter, checks canonical/stale/unknown against Bitcoin Core JSON-RPC, validates `nBits`, median-time-past, and the historical minimum block version for stale candidates, and stages classified and validated outputs. Active-chain observations go to the private `rsk_canonical_blocks.csv` companion discovered by Monitor publication, retaining the archive-node RSK block hash, timestamp, miner, merge-mining hash, mapped merkle proof, and compressed coinbase tail. A hash manifest binding every output to the extractor checkpoint is published last and verified before fresh RSK classifier artifacts enter publication, including rechecking the retained raw extraction and skip-ledger bytes against their sealed sizes and hashes. The classifier reads the committed historical miner-label registry only when carrying labels into validated rows. Its dependency fingerprints also bind the Bitcoin epoch-reference table used by rejection routing. Custom canonical output paths must stay beside the stale inventory and manifest so publication can discover their family.

## 2. Extraction → potential stales

**Method.** RSKj RPC. For each RSK block in the caller-declared half-open range, fetch `eth_getBlockByNumber("0x...", false)` and read five merge-mining-related fields:

1. `bitcoinMergedMiningHeader` - hex-encoded 80-byte BTC parent header.
2. `bitcoinMergedMiningCoinbaseTransaction` - trimmed SHA-256 state plus the unhashed coinbase tail. Limited OP_RETURN and ASCII diagnostics are retained, but the full transaction is not reconstructable.
3. `bitcoinMergedMiningMerkleProof` - merkle branch verified by RSKj consensus; the research classifier does not independently replay this proof.
4. `hashForMergedMining` - the 32-byte RSK commitment hash carried into the classifier and Monitor sidecar as `merge_mining_hash`.
5. `miner` - RSK miner address, retained as evidence for later attribution research.

**Phases.**

1. **Parse**: walk the explicit RSK range via `eth_getBlockByNumber`; require every requested canonical block and every advertised uncle, validate height/hash/timestamp/parent continuity, and extract `bitcoinMergedMiningHeader` when it is exactly 80 bytes. Record structurally recognized RLP fallback proofs and the exact height-zero `0x00` sentinel in a separate private ledger. Missing, malformed, or any other non-80-byte shape fails the durable interval for retry.
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. This does not establish Bitcoin's contemporaneous target.
3. **Observation identity**: the retained historical inventory was deduplicated after classification using the parent-header hash plus classification and uncle context. Fresh classifier runs preserve every distinct canonical or uncle RSK child observation, including repeated observations of the same Bitcoin parent. Monitor ingestion coalesces only an exact repeated RSK child hash for the same source through `UNIQUE (source_id, child_block_hash)`; different RSK children that reference the same Bitcoin parent remain distinct events.
4. **BTC RPC classify**: query Bitcoin Core JSON-RPC for the header and its predecessor, then classify canonical / stale / unknown by active-chain linkage. Canonical observations retain Bitcoin Core's authoritative height in the private companion. With no readable BIP34 prefix, an accepted stale candidate's height is inferred as the active predecessor's height plus one.
5. **Miner evidence preservation**: retain `rsk_miner`. The classifier reads the historical registry snapshot to populate the optional `pool_label` column in validated rows; it does not refresh or independently validate the mapping.

**Classifier counts after the 2026-09-08 acquisition and classification**
(273,841 self-target-PoW-valid observations; the
committed `data/validated-stales/rsk_validated_stales.csv` carries 353
publication-gate-accepted direct-stale header candidates; the one remaining
stale-labelled parent, BTC 789,038, is exact-key-excluded as consensus-invalid,
four consensus-invalid candidates route to the error-block sibling output, and
stale-descendant witnesses remain source-classified as unknown):

| `classification` | From canonical | From uncle | Total |
|---|---:|---:|---:|
| `canonical` | 118,971 | 117,102 | 236,073 |
| `stale`-labelled candidate | 98 | 256 | 354 |
| `unknown` | 21,075 | 16,335 | 37,410 |
| `error_block` | 1 | 3 | 4 |
| **Total** | 140,145 | 133,696 | 273,841 |

RSK uses a **parallel schema**: `rsk_miner`, `merge_mining_hash`, `coinbase_op_return`, and `coinbase_ascii_strings` carry the available RSK-side evidence, while the standard full-coinbase placeholders remain empty. The pre-2026-09-05 retained inventory used the historical value `classification=orphan`; the reclassified inventory emits `unknown` directly, and readers accept both. Its 37,410 such rows are self-target-PoW-valid parent headers without an active-chain Bitcoin predecessor. **Uncle-derived candidates contribute 72.5% of the accepted public direct inventory** (256 of 353) and **43.7% of the private unknown inventory** (16,335 of 37,410).

**Schema consistency.** The committed loader input is `data/validated-stales/rsk_validated_stales.csv`, accepted-candidates-only like the other chain loader inputs: the shared gate columns (`btc_height`, header/coinbase placeholders, `classification`, `validation_status`, `expected_nbits`) followed by RSK miner-evidence and historical-label columns. All 353 public rows pass RSK's available-evidence gate; `VALID` does not mean full Bitcoin block validity. The classifier routes four cross-chain consensus-invalid parents to the error-block sibling output, the exact-key error-block gate excludes the fifth (BTC 789,038), and the parent/witness module represents three RSK-observed stale descendants. The full stale/unknown inventory and the `rsk_canonical_blocks.csv` companion stay together with their manifest in the private run archive. Fresh full-inventory and canonical-companion rows retain the source child identity and complete RSK sidecar bundle. Monitor publication joins compact accepted stale verdicts by exact Bitcoin height and hash onto every matching fresh observation, preserving multiple child witnesses; stale observations absent from the accepted compact input are not published. The compact public CSV emits one verdict per Bitcoin height/hash pair, selecting the earliest RSK child witness deterministically. It retains its established schema and requires the separate child-identity ledger when used without the full inventory. A historical sidecar can replace that bundle only for the exact child height and hash, and the timestamp and populated sidecar cells must agree.

**Chain-specific quirks.**

- **Historical label snapshot.** The committed CSV carries `pool_label` values from an earlier RSK miner-address mapping, but `load_rsk_stales()` ignores them and publication validation does not depend on them.
- **`RSKBLOCK:` commitment**: RSKj searches the retained coinbase bytes for the `RSKBLOCK:` tag; it does not require an OP_RETURN location. Before RSKIP-110 the tag is followed by the older hash format. From the Wasabi activation at RSK 1,591,000, the 32-byte compound value is a 20-byte hash-for-merge-mining prefix, 7-byte CPV, 1-byte uncle count, and 4-byte block number. The extractor records this only when its best-effort output parser recovers an OP_RETURN, so the diagnostic column is not complete proof coverage.
- **Ethereum-compatible JSON-RPC**: hex-encoded block numbers, `eth_*` methods. No Bitcoin-style `getblockcount` / `getrawblock`.
- **RSK uncle blocks**: RSK has Ethereum-style uncle/ommer blocks, and each extracted uncle can carry its own 80-byte parent header. The validated public data contains 256 direct-stale candidates recovered from uncles versus 97 from canonical RSK blocks. The uncle-derived increment is 2.6 times the canonical-derived count, and total accepted yield is 3.6 times the canonical-only count.
- **Historically Foundry-labelled candidates**: 60 of the 353 accepted direct
  rows carry the retained `Foundry USA` label, and 43 of those keys are absent
  from every other chain's accepted direct-stale CSV. The current public
  pipeline does not independently revalidate the attribution.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_rsk_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

The committed CSV contains only the 353 accepted direct-stale rows; the 37,410
unknown rows remain in the private classifier inventory. The public
loader applies both checks above, ignores the historical `pool_label` column,
and then applies the exact-key error-blocks gate (`data/error-blocks/error_blocks.csv`). The accepted rows split into
97 from canonical RSK blocks and 256 from RSK uncle/ommer blocks.

**Post-filter count: 353 accepted direct-stale header candidates.**

**Derived strict/weak relevance: 3 strict, 0 weak observations.** RSK cannot
establish the required BIP34 height evidence from its compressed proof. These
three RSK observations inherit the globally strongest per-header verdict from
matching Namecoin, Elastos, and Syscoin evidence with recoverable coinbases;
they are not RSK-independent strict validations.

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py rsk`. Per-stale row-level breakdown at `results/per-chain-novelty/rsk.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 218 | 61.8 % |
| novel vs upstream | 135 | 38.2 % |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

RSK is 16th chronologically. The earlier-born registry entries include Namecoin, Geistgeld, i0coin, ixcoin, CoiledCoin, Devcoin, Groupcoin, Huntercoin, Unobtanium, Crown, Myriadcoin, SixEleven, Argentum, Terracoin, and Emercoin. The cumulative categories below are exclusive:

| Split | Count |
|---|---:|
| also in upstream | 218 |
| not upstream, but also in an earlier-born chain (`emercoin`) | 14 |
| **novel at this position** | **121** |

The non-exclusive first-seen attribution flags are Namecoin 138, Emercoin 28, and Unobtanium 1; 153 of those 167 rows are also upstream. The historical miner labels suggest overlapping miner populations, but that interpretation must be retested in a future attribution phase.

### Historical pool-label snapshot

These labels were normalised during an earlier attribution pass and remain in
the committed CSV as historical evidence. The current public pipeline neither
depends on `bitcoin-data/mining-pools` nor recomputes this table.

| `pool_label` | Count | Notes |
|---|---:|---|
| F2Pool | 103 | |
| **Foundry USA** | **60** | Historical label; 43 keys are RSK-only among accepted direct-stale CSVs. |
| AntPool | 57 | |
| ViaBTC | 30 | |
| BTC.com | 28 | |
| Poolin | 26 | |
| Braiins Pool | 17 | Post-Slush rebrand. |
| `Unknown` | 21 | 9 distinct miner addresses lack a retained attribution in the accepted set. |
| Luxor | 8 | |
| SecPool | 3 | First surfaced with uncle traversal; the 2026-09-05 reclassification adds one canonical-derived row. |

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/rsk_validated_stales.csv` - the committed loader input (353 publication-gate-accepted direct-stale header candidates). Shared historical validated-stales layout plus RSK-specific columns: `rsk_height`, `rsk_timestamp`, `rsk_miner`, `pool_label`, `merge_mining_hash`, `coinbase_op_return`, `coinbase_ascii_strings`, and the uncle-traversal columns `is_uncle`, `uncle_index`, `uncle_parent_height`. `coinbase_scriptsig_hex` / `coinbase_outputs` are empty placeholders (midstate-compressed, not recoverable). The full 37,764-row stale/unknown inventory stays in the private chain archive.
- `results/rsk_pool_registry.csv` - historical RSK miner-address label snapshot retained for provenance. The classifier reads it when carrying labels into validated rows but does not refresh it; the loader ignores the labels.
- `results/per-chain-novelty/rsk.csv` - per-stale `(height, hash, in_upstream, first_seen_chain)` table.
- Private archive manifest: `chains/rsk/manifest/rsk-schema-exception-2026-05-18.txt` records the historical single-file exception (retired by the `rsk_validated_stales.csv` split) and the SHA-256 of the mirrored classified inventory.

**External references.**

- [RSKIP-92](https://ips.rootstock.io/IPs/RSKIP92.html) and [pinned RSKj activation configuration](https://github.com/rsksmart/rskj/blob/56497ed809dc0eb5db1078659882309b16f45ca9/rskj-core/src/main/resources/config/main.conf#L1-L9) - proof-serialization change activated with Orchid at RSK 729,000, not at the extractor's 139,999 lower bound.
- [RSKIP-110](https://ips.rootstock.io/IPs/RSKIP110.html#specification) - compound merge-mining commitment layout activated with Wasabi at RSK 1,591,000.
- [RSKj proof-of-work validation](https://github.com/rsksmart/rskj/blob/56497ed809dc0eb5db1078659882309b16f45ca9/rskj-core/src/main/java/co/rsk/validators/ProofOfWorkRule.java#L80-L224) - fallback signatures, compressed coinbase verification, and merkle-root validation.
- [RSKj Vetiver 9.0.3 release](https://github.com/rsksmart/rskj/releases/tag/VETIVER-9.0.3) - current release at the publication audit date.
- `docs/auxpow-recovery.md` - cross-chain summary table (RSK row).

**Remaining work.**

- **Historical pool-label cleanup** - **resolved for the retained snapshot**. Earlier work normalised `Foundry USA Pool` to `Foundry USA`, `BTC.COM` to `BTC.com`, `SlushPool` to `Braiins Pool`, and `unknown` to `Unknown`. A future unified attribution phase must revalidate the mapping and the nine unattributed miner addresses represented in the accepted set rather than treating this snapshot as current registry data.
- **Unknown-inventory parallel schema** - **resolved**. The 2026-09-08
  classification produced 37,410 unknown observations (21,075 canonical-child
  and 16,335 uncle-derived), alongside 354 stale-labelled observations. The
  direct-stale loader contains 353 accepted candidates; the remaining
  stale-labelled parent (BTC 789,038) is exact-key-excluded. Stale-descendant
  witnesses remain source-classified as unknown and enter publication through
  the authenticated parent/witness module.
- **Uncle/ommer block traversal** - **resolved**. The sealed extraction
  accounts for all 9,554,407 advertised uncles: 9,553,654 full parent headers
  and 753 intentional fallback skips. Of the 353 accepted direct stales,
  256 are recovered from uncles.
- **RPC-retry duplicate writes** - **resolved in current tooling**. Durable intervals buffer canonical rows, advertised uncles and intentional skips until every RPC and partition check succeeds, then fsync both CSV segments before advancing their content-bound checkpoint. Transient RPC failures retry only the affected batch. Validation failures stop the interval without advancing its checkpoint, and resume validates the committed segments before truncating uncheckpointed tails. The historical run's 15 duplicate unknown rows were deduplicated after classification; its accepted direct-stale rows were unaffected.

## 5. Integration history

- **Historical (predecessor repo)** - original recovery on the RSKj Vetiver
  9.0.1 archive node. Extraction traversed canonical RSK blocks and their
  uncles across about 17.95 million observations, and the retained classifier
  inventory held 37,335 rows (304 stale-labelled candidates plus 37,031
  historical `orphan` rows; original-classification figures, superseded by the
  2026-09-05 reclassification below). Uncle traversal is the decisive design choice:
  222 of the 304 stale-labelled candidates, and 218 of the 298 rows then
  accepted as direct stales, came from uncles (§2). The same run surfaced 15
  duplicate unknown rows from the phase-2 RPC-retry path; they were
  deduplicated post-classification, and the current extractor resolves the buffered-write defect (**Remaining work**).
- **2026-05-18** - the private archive manifest
  `chains/rsk/manifest/rsk-schema-exception-2026-05-18.txt` records the
  historical single-file schema exception, later retired by the
  `rsk_validated_stales.csv` split.
- **2026-07-17** - public release: the committed loader input
  `data/validated-stales/rsk_validated_stales.csv` and
  `results/per-chain-novelty/rsk.csv` land on the shared validated-stales
  layout plus the RSK miner-evidence and historical-label columns.
- **2026-07-20** - current audit: all 298 accepted direct rows replayed
  against Bitcoin Core tip 958,882 and passed every check available from RSK's
  evidence. The scriptSig-length and BIP34-prefix checks remain untested, and
  this was not a full-block consensus replay (§1 Holes).
- **2026-07-22** - publication audit: RSKj Vetiver 9.0.3 recorded as the
  current upstream release against the 9.0.1 archive node the data were
  acquired from.
- **2026-07-31** - the first-class consensus-invalid error-blocks dataset
  lands, and the committed `rsk_validated_stales.csv` is regenerated under the
  uniform child-identity contract.
- **2026-08-31** - canonical error and ancestry modules published: the
  exact-key error-block gate excludes five cross-chain consensus-invalid
  parents and the parent/witness module represents the height-656,478 stale
  descendant, leaving the 298 accepted direct rows.
- **2026-09-04** - upstream refresh (#47): the pinned
  `bitcoin-data/stale-blocks` baseline moves to `102ba00`, where upstream's
  fork.observer automation had independently added the RSK-recovered rows at
  heights 903,259 and 927,647 with byte-identical headers. The regenerated
  novelty CSV read 168 also in upstream, 130 novel versus upstream, and 115
  chronologically novel at the then-committed 298-row set.
- **2026-09-05** - side-chain-aware reclassification: the original 2026-05-15
  classification treated any `getblockheader` hit as canonical, so 39
  side-chain headers (`confirmations=-1`) - real recovered stales, every one
  already in the upstream census - were silently filed as canonical. The
  fleet-wide 2026-06-23/24 remediation missed RSK because its bespoke
  classifier does not use the shared driver. Reclassifying the same archived
  raw extraction with the current active-chain test raises the committed set
  298 -> 337 with zero regressions (all 298 prior rows byte-identical), adds
  RSK's observation of the BTC 941,882 stale descendant (RSK 8,655,953) as
  that parent's fifth chain witness (ledger 32 -> 33), and rebuilds the
  monitor publication (`rsk_monitor_evidence.csv` 303 -> 343 rows). The two
  externally attested body-invalid blocks 783,426 and 784,121 are among the
  39 and are now witnessed by five chains (see `docs/error-blocks.md`
  "Externally attested body-invalid stales").
- **2026-09-07** - upstream refresh: the pinned `bitcoin-data/stale-blocks`
  baseline moves to `d15c8e9`, which adds the Emercoin/RSK-recovered row at
  height 589,477 with a byte-identical header. Recomputed on the 337-row set,
  the novelty CSV reads 208 also in upstream, 129 novel versus upstream, and
  115 chronologically novel; only the isolated split moves, because Emercoin
  already first-claimed 589,477 in the chronological view.
- **2026-09-08** - height-zero acquisition: the sealed range `[0, 9220905)`
  preserves 18,609,230 full parent headers and 166,082 intentional skips,
  with every canonical block and advertised uncle accounted for. Classification
  at clean revision `fa292c5414741125f49da19fea642465ed917ef0`, against
  Bitcoin Core tips 966,094 through 966,095, produces the first complete private
  canonical companion (236,073 observations) and raises the accepted direct
  set from 337 to 353. All 337 prior accepted rows are unchanged field for
  field. The 16 additions are in the later acquisition window, at BTC heights
  950,517 through 965,652; none comes from below RSK 139,999. Ten additions
  already occur in pinned upstream, while six add new chronological claims.
  The raw CSV, fallback ledger, checkpoint and complete classifier family passed
  their content, dependency and provenance checks before archival promotion.
  Complete all-chain ancestry screening against active Bitcoin heights retains
  the same 21 accepted descendant parents and 33 exact witnesses, including
  RSK's three observations, with no new error candidates. Existing immutable
  parent/witness provenance remains published; newer source-file coordinates
  and additional corroborating root-chain labels are retained in the private
  screening receipt.
