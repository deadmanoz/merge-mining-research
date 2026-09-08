# RSK (Rootstock)

| Field | Value |
|---|---|
| Ticker | RBTC / RSK |
| Recovery chronology | RSK mainnet launched in January 2018. The retained extraction starts at RSK 139,999 by historical acquisition convention, not at a consensus activation or proof-format boundary. The current extractor accepts an explicit range from height 0, records the height-zero `0x00` genesis sentinel, and records only 69/70-byte fallback signatures as intentional skips. Every other non-80-byte or malformed proof fails the interval. |
| Network status | Active. Data were acquired from an RSKj Vetiver 9.0.1 archive node on `<archival-host>`; 9.0.3 was the current upstream release when audited on 2026-07-22. |
| Chronological position | 16 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven, argentum, terracoin, emercoin) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; RSK is not a Namecoin-family SHA-256d fork and was not sampled. RSK mainnet launched inside the paper's window, but the accepted direct-stale window is almost entirely after the mid-2018 cutoff) |
| Block time | ~30 s (≈ 20 RSK blocks per BTC block) |
| Source tag (in code) | `rsk` |
| Loader | `load_rsk_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/rsk_validated_stales.csv` (337 publication-gate-accepted direct-stale header candidates; historical filename, shared layout plus RSK miner-evidence and historical-label columns) |
| Historical label snapshot | `results/rsk_pool_registry.csv` (miner address to retained pool label) |

RSK is methodologically distinct from the Namecoin-family `CAuxPow` chains. Its merge-mining proof preserves the 80-byte Bitcoin parent header, a trimmed SHA-256 state, an unhashed coinbase tail, and a merkle proof, but not a reconstructable full coinbase transaction. The committed data preserves a historical miner-address label snapshot in `results/rsk_pool_registry.csv`; current classification may carry those labels into validated rows, but neither validation nor the loader depends on them. Fifty-nine accepted rows carry the historical `Foundry USA` label; 42 of those keys are absent from every other chain's accepted direct-stale CSV.

## 1. Chain data

**Source.** Local RSKj v9.0.1 ("Vetiver") archive node on `<archival-host>`, installed via the `ppa:rsksmart/rskj` package and configured for full archive (no pruning). RPC at `http://localhost:4444`. Ethereum-compatible `eth_*` JSON-RPC; all block numbers hex-encoded. Java 17 (OpenJDK). Version 9.0.1 is acquisition provenance, not a claim that the research node runs the latest release.

**Provenance.** Configuration at `/etc/rsk/`. Data directory grows ~100 GB (archive sync). Sync took ~2 days from initial PPA install. Bitcoin Core on `<archival-host>` provided the BTC RPC for stale-block classification.

**Coverage.** Accepted direct-stale candidates span BTC heights **514,235 to 949,203** (Mar 2018 to 13 May 2026) and reach RSK height 8,832,910. This is a point-in-time accepted-candidate window, not lifetime coverage. The retained private mirror has no consolidated RSK canonical export. The classifier now emits the standard private `rsk_canonical_blocks.csv` companion, but populating it still requires the external archive-node re-run recorded as `needs-infrastructure` in the canonical-coverage metadata.

**Holes.**

- **Early acquisition gap**: the retained corpus starts at RSK 139,999, but public historical RPC responses contain both full 80-byte merge-mining headers and 69/70-byte fallback signatures before that height. At least RSK 112,829 carries a full parent header. The interval below 139,999 has not yet been recovered; 139,999 is not an activation boundary. The current extractor is byte-shape-aware and can acquire the missing interval from an explicit height-zero run.
- **Full coinbase unavailable**: RSK replaces a variable-length prefix of complete SHA-256 chunks with a 40-byte trimmed state and retains the unhashed tail. Limited output and `RSKBLOCK:` evidence can survive in that tail, but the full transaction and scriptSig cannot be reconstructed. RSK therefore cannot independently apply the scriptSig-length or BIP34-prefix checks, and the standard validated-schema coinbase fields remain empty.
- **`classification` column** (`stale`/`unknown`): emitted by `scripts/classify/classify_rsk_stales.py`. The original 2026-05-15 classification treated any `getblockheader` hit as canonical, so parent headers the Bitcoin node knew only as side-chain blocks (`confirmations=-1`) were silently filed as canonical; the 2026-09-05 reclassification applies the current active-chain test and recovers 39 additional accepted direct stales (§5). Coverage is entirely post-BCH/BSV-fork era, so altchain contamination is possible in principle. The `nBits` pass rejected zero stale-labelled candidates. Five candidates shared with Namecoin are consensus-invalid: the reclassification routes the four signed-negative versions that fail BIP65's minimum version 4 rule to the error-block sibling output, while the BTC 789,038 BIP34 coinbase-height violation is not derivable from RSK's evidence alone, so that row stays stale-labelled and the exact-key error-block gate excludes it. A sixth shared candidate at Bitcoin height 656,478 extends a trusted stale root, classifies as unknown, and is represented by the stale-descendant parent and witness tables. That leaves 337 accepted direct rows. RSK checks header hash and self-target PoW, active-parent linkage, expected `nBits`, median-time-past, and historical minimum block version. Its midstate-compressed proof does not expose the real coinbase scriptSig, so it cannot independently apply the scriptSig-length or BIP34-prefix checks. Unknown rows pass their encoded self-target and miss canonical-parent linkage; they remain in the private historical classifier inventory rather than the committed loader input. See the [data validity contract](../data-validity.md).
- **Current audit**: on 20 July 2026, all 298 accepted direct rows were replayed against Bitcoin Core tip 958,882 and passed every check available from RSK's evidence. The scriptSig-length and BIP34-prefix checks remain untested for every accepted row, and this was not a full-block consensus replay. That replay was structurally blind to headers the original classifier had filed as canonical; the 39 rows recovered by the 2026-09-05 reclassification were not part of it (§5).

**Reference scripts.**

- `scripts/extract/extract_rsk_auxpow.py:1` - Ethereum-style JSON-RPC extractor (`eth_getBlockByNumber`); reads `bitcoinMergedMiningHeader`, the compressed `bitcoinMergedMiningCoinbaseTransaction`, `bitcoinMergedMiningMerkleProof`, `hashForMergedMining`, and the RSK miner address. It requires explicit half-open bounds, pins both endpoint identities, validates canonical continuity and listed uncle hashes, and keeps RPC batches independent from durable checkpoint intervals. Each interval fsyncs the raw CSV and exact fallback ledger before atomically advancing byte offsets and segment digests. The final end identity is fetched again before full-content digests seal the checkpoint. All three artifacts remain private.
- `scripts/classify/classify_rsk_stales.py:1` - four-pass classifier that requires the raw CSV's complete matching checkpoint, applies the self-target PoW filter, checks canonical/stale/unknown against Bitcoin Core JSON-RPC, validates `nBits`, median-time-past, and the historical minimum block version for stale candidates, and stages classified and validated outputs. Active-chain observations go to the private `rsk_canonical_blocks.csv` companion discovered by Monitor publication, retaining the archive-node RSK block hash, timestamp, miner, merge-mining hash, mapped merkle proof, and compressed coinbase tail. A hash manifest binding every output to the extractor checkpoint is published last and verified before fresh RSK classifier artifacts enter publication. The classifier reads the committed historical miner-label registry only when carrying labels into validated rows.

## 2. Extraction → potential stales

**Method.** RSKj RPC. For each RSK block in the caller-declared half-open range, fetch `eth_getBlockByNumber("0x...", false)` and read five merge-mining-related fields:

1. `bitcoinMergedMiningHeader` - hex-encoded 80-byte BTC parent header.
2. `bitcoinMergedMiningCoinbaseTransaction` - trimmed SHA-256 state plus the unhashed coinbase tail. Limited OP_RETURN and ASCII diagnostics are retained, but the full transaction is not reconstructable.
3. `bitcoinMergedMiningMerkleProof` - merkle branch verified by RSKj consensus; the research classifier does not independently replay this proof.
4. `hashForMergedMining` - the 32-byte RSK commitment hash carried into the classifier and Monitor sidecar as `merge_mining_hash`.
5. `miner` - RSK miner address, retained as evidence for later attribution research.

**Phases.**

1. **Parse**: walk the explicit RSK range via `eth_getBlockByNumber`; require every requested canonical block and every advertised uncle, validate height/hash/timestamp/parent continuity, and extract `bitcoinMergedMiningHeader` when it is exactly 80 bytes. Record 69/70-byte fallback proofs and the exact height-zero `0x00` sentinel in a separate private ledger. Missing, malformed, or any other non-80-byte shape fails the durable interval for retry.
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. This does not establish Bitcoin's contemporaneous target.
3. **Observation identity**: the retained historical inventory was deduplicated after classification using the parent-header hash plus classification and uncle context. Fresh classifier runs preserve every distinct canonical or uncle RSK child observation, including repeated observations of the same Bitcoin parent. Monitor ingestion coalesces only an exact repeated RSK child hash for the same source through `UNIQUE (source_id, child_block_hash)`; different RSK children that reference the same Bitcoin parent remain distinct events.
4. **BTC RPC classify**: query Bitcoin Core JSON-RPC for the header and its predecessor, then classify canonical / stale / unknown by active-chain linkage. Canonical observations retain Bitcoin Core's authoritative height in the private companion. With no readable BIP34 prefix, an accepted stale candidate's height is inferred as the active predecessor's height plus one.
5. **Miner evidence preservation**: retain `rsk_miner`. The classifier reads the historical registry snapshot to populate the optional `pool_label` column in validated rows; it does not refresh or independently validate the mapping.

**Classifier counts after the 2026-09-05 reclassification** (37,386 rows; the
committed `data/validated-stales/rsk_validated_stales.csv` carries 337
publication-gate-accepted direct-stale header candidates; the one remaining
stale-labelled parent, BTC 789,038, is exact-key-excluded as consensus-invalid,
four consensus-invalid candidates route to the error-block sibling output, and
the stale-descendant parent classifies as unknown):

| `classification` | From canonical | From uncle | Total |
|---|---:|---:|---:|
| `stale`-labelled candidate | 97 | 241 | 338 |
| `unknown` | 20,862 | 16,186 | 37,048 |
| **Total** | 20,959 | 16,427 | 37,386 |

RSK uses a **parallel schema**: `rsk_miner`, `merge_mining_hash`, `coinbase_op_return`, and `coinbase_ascii_strings` carry the available RSK-side evidence, while the standard full-coinbase placeholders remain empty. The pre-2026-09-05 retained inventory used the historical value `classification=orphan`; the reclassified inventory emits `unknown` directly, and readers accept both. Its 37,048 such rows are self-target-PoW-valid parent headers whose `btc_prev_hash` is unknown to the Bitcoin Core node. **Uncle-derived candidates contribute 71.5% of the accepted public direct inventory** (241 of 337) and **44% of the private unknown inventory** (16,186 of 37,048).

**Schema consistency.** The committed loader input is `data/validated-stales/rsk_validated_stales.csv`, accepted-candidates-only like the other chain loader inputs: the shared gate columns (`btc_height`, header/coinbase placeholders, `classification`, `validation_status`, `expected_nbits`) followed by RSK miner-evidence and historical-label columns. All 337 public rows pass RSK's available-evidence gate; `VALID` does not mean full Bitcoin block validity. The classifier routes four cross-chain consensus-invalid parents to the error-block sibling output, the exact-key error-block gate excludes the fifth (BTC 789,038), and the parent/witness module represents one stale descendant. The full historical stale/unknown inventory and the separately emitted `rsk_canonical_blocks.csv` companion stay in the private chain archive under `chains/rsk/classified/`. Fresh full-inventory and canonical-companion rows retain the source child identity and complete RSK sidecar bundle. The compact public CSV retains its established schema and requires the separate child-identity ledger when used without the full inventory. A historical sidecar can replace that bundle only for the exact child height and hash, and the timestamp and populated sidecar cells must agree.

**Chain-specific quirks.**

- **Historical label snapshot.** The committed CSV carries `pool_label` values from an earlier RSK miner-address mapping, but `load_rsk_stales()` ignores them and publication validation does not depend on them.
- **`RSKBLOCK:` commitment**: RSKj searches the retained coinbase bytes for the `RSKBLOCK:` tag; it does not require an OP_RETURN location. Before RSKIP-110 the tag is followed by the older hash format. From the Wasabi activation at RSK 1,591,000, the 32-byte compound value is a 20-byte hash-for-merge-mining prefix, 7-byte CPV, 1-byte uncle count, and 4-byte block number. The extractor records this only when its best-effort output parser recovers an OP_RETURN, so the diagnostic column is not complete proof coverage.
- **Ethereum-compatible JSON-RPC**: hex-encoded block numbers, `eth_*` methods. No Bitcoin-style `getblockcount` / `getrawblock`.
- **RSK uncle blocks**: RSK has Ethereum-style uncle/ommer blocks, and each extracted uncle can carry its own 80-byte parent header. The validated public data contains 241 direct-stale candidates recovered from uncles versus 96 from canonical RSK blocks. The uncle-derived increment is 2.5 times the canonical-derived count, and total accepted yield is 3.5 times the canonical-only count.
- **Historically Foundry-labelled candidates**: 59 of the 337 accepted direct
  rows carry the retained `Foundry USA` label, and 42 of those keys are absent
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

The committed CSV contains only the 337 accepted direct-stale rows; the 37,048
unknown rows remain in the private classifier inventory. The public
loader applies both checks above, ignores the historical `pool_label` column,
and then applies the exact-key error-blocks gate (`data/error-blocks/error_blocks.csv`). The accepted rows split into
96 from canonical RSK blocks and 241 from RSK uncle/ommer blocks.

**Post-filter count: 337 accepted direct-stale header candidates.**

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
| also in upstream | 208 | 61.7 % |
| novel vs upstream | 129 | 38.3 % |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

RSK is 16th chronologically. The earlier-born registry entries include Namecoin, Geistgeld, i0coin, ixcoin, CoiledCoin, Devcoin, Groupcoin, Huntercoin, Unobtanium, Crown, Myriadcoin, SixEleven, Argentum, Terracoin, and Emercoin. The cumulative categories below are exclusive:

| Split | Count |
|---|---:|
| also in upstream | 208 |
| not upstream, but also in an earlier-born chain (`emercoin`) | 14 |
| **novel at this position** | **115** |

The non-exclusive first-seen attribution flags are Namecoin 138, Emercoin 28, and Unobtanium 1; 153 of those 167 rows are also upstream. The historical miner labels suggest overlapping miner populations, but that interpretation must be retested in a future attribution phase.

### Historical pool-label snapshot

These labels were normalised during an earlier attribution pass and remain in
the committed CSV as historical evidence. The current public pipeline neither
depends on `bitcoin-data/mining-pools` nor recomputes this table.

| `pool_label` | Count | Notes |
|---|---:|---|
| F2Pool | 97 | |
| **Foundry USA** | **59** | Historical label; 42 keys are RSK-only among accepted direct-stale CSVs. |
| AntPool | 54 | |
| ViaBTC | 30 | |
| BTC.com | 28 | |
| Poolin | 26 | |
| Braiins Pool | 17 | Post-Slush rebrand. |
| `Unknown` | 16 | 9 distinct miner addresses lack a retained attribution in the accepted set. |
| Luxor | 7 | |
| SecPool | 3 | First surfaced with uncle traversal; the 2026-09-05 reclassification adds one canonical-derived row. |

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/rsk_validated_stales.csv` - the committed loader input (337 publication-gate-accepted direct-stale header candidates). Shared historical validated-stales layout plus RSK-specific columns: `rsk_height`, `rsk_timestamp`, `rsk_miner`, `pool_label`, `merge_mining_hash`, `coinbase_op_return`, `coinbase_ascii_strings`, and the uncle-traversal columns `is_uncle`, `uncle_index`, `uncle_parent_height`. `coinbase_scriptsig_hex` / `coinbase_outputs` are empty placeholders (midstate-compressed, not recoverable). The full 37,386-row stale/unknown inventory stays in the private chain archive.
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
- **Unknown-inventory parallel schema** - **resolved**. The 2026-09-05
  reclassification produced 37,048 unknown rows (20,862 canonical + 16,186
  uncle) alongside 338 stale-labelled candidates. The direct-stale loader
  contains 337 accepted candidates, the remaining stale-labelled parent (BTC
  789,038) is exact-key-excluded, and the stale-descendant parent sits among
  the unknowns and is represented in that module.
- **Uncle/ommer block traversal** - **resolved**. The historical private
  extraction traversed canonical blocks and uncles and processed about 17.95
  million observations. The reclassified inventory contains 241
  uncle-derived stale-labelled candidates, all accepted as direct stales, plus
  the uncle-derived stale-descendant parent among its 16,186 uncle-derived
  unknowns.
  Unsupported rounded canonical/uncle component counts are omitted.
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
