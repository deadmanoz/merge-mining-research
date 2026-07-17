# RSK (Rootstock)

| Field | Value |
|---|---|
| Ticker | RBTC / RSK |
| Recovery chronology | RSK mainnet launched in January 2018. This extraction starts at RSK 139,999 by historical acquisition convention, not at a consensus activation or proof-format boundary. Full 80-byte Bitcoin headers occur in earlier blocks. |
| Network status | Active. Data were acquired from an RSKj Vetiver 9.0.1 archive node on `<archival-host>`; 9.0.3 was the current upstream release when audited on 2026-07-22. |
| Chronological position | 16 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven, argentum, terracoin, emercoin) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; RSK is not a Namecoin-family SHA-256d fork and was not sampled. RSK mainnet launched inside the paper's window, but the accepted direct-stale window is almost entirely after the mid-2018 cutoff) |
| Block time | ~30 s (≈ 20 RSK blocks per BTC block) |
| Source tag (in code) | `rsk` |
| Loader | `load_rsk_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/rsk_validated_stales.csv` (298 publication-gate-accepted direct-stale header candidates; historical filename, shared layout plus RSK miner-evidence and historical-label columns) |
| Historical label snapshot | `results/rsk_pool_registry.csv` (miner address to retained pool label) |

RSK is methodologically distinct from the Namecoin-family `CAuxPow` chains. Its merge-mining proof preserves the 80-byte Bitcoin parent header, a trimmed SHA-256 state, an unhashed coinbase tail, and a merkle proof, but not a reconstructable full coinbase transaction. The committed data preserves a historical miner-address label snapshot in `results/rsk_pool_registry.csv`; current classification may carry those labels into validated rows, but neither validation nor the loader depends on them. Fifty-three accepted rows carry the historical `Foundry USA` label; 37 of those keys are absent from every other chain's accepted direct-stale CSV.

## 1. Chain data

**Source.** Local RSKj v9.0.1 ("Vetiver") archive node on `<archival-host>`, installed via the `ppa:rsksmart/rskj` package and configured for full archive (no pruning). RPC at `http://localhost:4444`. Ethereum-compatible `eth_*` JSON-RPC; all block numbers hex-encoded. Java 17 (OpenJDK). Version 9.0.1 is acquisition provenance, not a claim that the research node runs the latest release.

**Provenance.** Configuration at `/etc/rsk/`. Data directory grows ~100 GB (archive sync). Sync took ~2 days from initial PPA install. Bitcoin Core on `<archival-host>` provided the BTC RPC for stale-block classification.

**Coverage.** Accepted direct-stale candidates span BTC heights **514,235 to 949,203** (Mar 2018 to 13 May 2026) and reach RSK height 8,832,910. This is a point-in-time accepted-candidate window, not lifetime coverage. The private mirror has no consolidated RSK canonical export; producing one requires the external archive-node re-run recorded as `needs-infrastructure` in the canonical-coverage metadata.

**Holes.**

- **Early acquisition gap**: the extractor starts at RSK 139,999, but public historical RPC responses contain both full 80-byte merge-mining headers and 69/70-byte fallback signatures before that height. At least RSK 112,829 carries a full parent header. The interval below 139,999 was not recovered and needs a format-aware backfill; 139,999 is not an activation boundary.
- **Full coinbase unavailable**: RSK replaces a variable-length prefix of complete SHA-256 chunks with a 40-byte trimmed state and retains the unhashed tail. Limited output and `RSKBLOCK:` evidence can survive in that tail, but the full transaction and scriptSig cannot be reconstructed. RSK therefore cannot independently apply the scriptSig-length or BIP34-prefix checks, and the standard validated-schema coinbase fields remain empty.
- **`classification` column** (`stale`/`unknown`): emitted by `scripts/classify/classify_rsk_stales.py`. Coverage is entirely post-BCH/BSV-fork era, so altchain contamination is possible in principle. The `nBits` pass rejected zero stale-labelled candidates. Five candidates shared with Namecoin are consensus-invalid: one fails BIP34 height and four signed-negative versions fail BIP65's minimum version 4 rule. A sixth shared candidate at Bitcoin height 656,478 extends a known stale predecessor rather than an active-chain block and is moved to the stale-descendant sidecar. The exact-key overlay therefore leaves 298 accepted direct rows. RSK checks header hash and self-target PoW, active-parent linkage, expected `nBits`, median-time-past, and historical minimum block version. Its midstate-compressed proof does not expose the real coinbase scriptSig, so it cannot independently apply the scriptSig-length or BIP34-prefix checks. Unknown rows pass their encoded self-target and miss canonical-parent linkage; they remain in the private historical classifier inventory rather than the committed loader input. See the [data validity contract](../data-validity.md).
- **Current audit**: on 20 July 2026, all 298 accepted direct rows were replayed against Bitcoin Core tip 958,882 and passed every check available from RSK's evidence. The scriptSig-length and BIP34-prefix checks remain untested for all 298 rows, and this was not a full-block consensus replay.

**Reference scripts.**

- `scripts/extract/extract_rsk_auxpow.py:1` - Ethereum-style JSON-RPC extractor (`eth_getBlockByNumber`); reads `bitcoinMergedMiningHeader`, the compressed `bitcoinMergedMiningCoinbaseTransaction`, `bitcoinMergedMiningMerkleProof`, and the RSK miner address. The full raw extraction remains private.
- `scripts/classify/classify_rsk_stales.py:1` - four-pass classifier that reads the raw CSV, applies the self-target PoW filter, checks canonical/stale/unknown against Bitcoin Core JSON-RPC, validates `nBits`, median-time-past, and the historical minimum block version for stale candidates, and writes classified and validated outputs. It reads the committed historical miner-label registry only when carrying labels into validated rows.

## 2. Extraction → potential stales

**Method.** RSKj RPC. For each RSK block ≥ 139,999, fetch `eth_getBlockByNumber("0x...", false)` and read four merge-mining-related fields:

1. `bitcoinMergedMiningHeader` - hex-encoded 80-byte BTC parent header.
2. `bitcoinMergedMiningCoinbaseTransaction` - trimmed SHA-256 state plus the unhashed coinbase tail. Limited OP_RETURN and ASCII diagnostics are retained, but the full transaction is not reconstructable.
3. `bitcoinMergedMiningMerkleProof` - merkle branch verified by RSKj consensus; the research classifier does not independently replay this proof.
4. `miner` - RSK miner address, retained as evidence for later attribution research.

**Phases.**

1. **Parse**: walk all RSK blocks ≥ 139,999 via `eth_getBlockByNumber`; extract `bitcoinMergedMiningHeader` (80 bytes) and the RSK miner address.
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. This does not establish Bitcoin's contemporaneous target.
3. **Dedup**: the retained historical inventory was deduplicated after classification using the parent-header hash plus classification and uncle context. Distinct RSK blocks can contribute distinct candidate headers even when they reference the same Bitcoin predecessor.
4. **BTC RPC classify**: query Bitcoin Core JSON-RPC for the header and its predecessor, then classify canonical / stale / unknown by active-chain linkage. With no readable BIP34 prefix, an accepted candidate's height is inferred as the active predecessor's height plus one.
5. **Miner evidence preservation**: retain `rsk_miner`. The classifier reads the historical registry snapshot to populate the optional `pool_label` column in validated rows; it does not refresh or independently validate the mapping.

**Historical classifier counts** (37,335 rows; the committed
`data/validated-stales/rsk_validated_stales.csv` carries 298 publication-gate-accepted direct-stale header candidates after five
stale-labelled candidates are excluded as invalid and one is reclassified as a
stale descendant):

| `classification` | From canonical | From uncle | Total |
|---|---:|---:|---:|
| `stale`-labelled candidate | 82 | 222 | 304 |
| legacy `orphan` (read as `unknown`) | 20,847 | 16,184 | 37,031 |
| **Total** | 20,929 | 16,406 | 37,335 |

RSK uses a **parallel schema**: `rsk_miner`, `merge_mining_hash`, `coinbase_op_return`, and `coinbase_ascii_strings` carry the available RSK-side evidence, while the standard full-coinbase placeholders remain empty. The retained private inventory literally uses the legacy value `classification=orphan`; current readers normalize it to `unknown`. Its 37,031 such rows are self-target-PoW-valid parent headers whose `btc_prev_hash` is unknown to the Bitcoin Core node. **Uncle-derived candidates contribute 73% of the accepted public direct inventory** (218 of 298) and **44% of the private unknown inventory** (16,184 of 37,031).

**Schema consistency.** The committed loader input is `data/validated-stales/rsk_validated_stales.csv`, accepted-candidates-only like the other chain loader inputs: the shared gate columns (`btc_height`, header/coinbase placeholders, `classification`, `validation_status`, `expected_nbits`) followed by RSK miner-evidence and historical-label columns. All 298 public rows pass RSK's available-evidence gate; `VALID` does not mean full Bitcoin block validity. The exact-key overlay removes five cross-chain consensus-invalid candidates and moves one direct-only correction to the stale-descendant sidecar. The full historical stale/unknown inventory stays in the private chain archive under `chains/rsk/classified/`.

**Chain-specific quirks.**

- **Historical label snapshot.** The committed CSV carries `pool_label` values from an earlier RSK miner-address mapping, but `load_rsk_stales()` ignores them and publication validation does not depend on them.
- **`RSKBLOCK:` commitment**: RSKj searches the retained coinbase bytes for the `RSKBLOCK:` tag; it does not require an OP_RETURN location. Before RSKIP-110 the tag is followed by the older hash format. From the Wasabi activation at RSK 1,591,000, the 32-byte compound value is a 20-byte hash-for-merge-mining prefix, 7-byte CPV, 1-byte uncle count, and 4-byte block number. The extractor records this only when its best-effort output parser recovers an OP_RETURN, so the diagnostic column is not complete proof coverage.
- **Ethereum-compatible JSON-RPC**: hex-encoded block numbers, `eth_*` methods. No Bitcoin-style `getblockcount` / `getrawblock`.
- **RSK uncle blocks**: RSK has Ethereum-style uncle/ommer blocks, and each extracted uncle can carry its own 80-byte parent header. The validated public data contains 218 direct-stale candidates recovered from uncles versus 80 from canonical RSK blocks. The uncle-derived increment is 2.7 times the canonical-derived count, and total accepted yield is 3.7 times the canonical-only count.
- **Historically Foundry-labelled candidates**: 53 of the 298 accepted direct
  rows carry the retained `Foundry USA` label, and 37 of those keys are absent
  from every other chain's accepted direct-stale CSV. The current public
  pipeline does not independently revalidate the attribution.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_rsk_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status.startswith("VALID")
```

The committed CSV contains only the 298 accepted direct-stale rows; the 37,031
historical unknown rows remain in the private classifier inventory. The public
loader applies both checks above, ignores the historical `pool_label` column,
and then applies the exact-key exclusion overlay. The accepted rows split into
80 from canonical RSK blocks and 218 from RSK uncle/ommer blocks.

**Post-filter count: 298 accepted direct-stale header candidates.**

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
| also in upstream | 166 | 55.7 % |
| novel vs upstream | 132 | 44.3 % |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

RSK is 16th chronologically. The earlier-born registry entries include Namecoin, Geistgeld, i0coin, ixcoin, CoiledCoin, Devcoin, Groupcoin, Huntercoin, Unobtanium, Crown, Myriadcoin, SixEleven, Argentum, Terracoin, and Emercoin. The cumulative categories below are exclusive:

| Split | Count |
|---|---:|
| also in upstream | 166 |
| not upstream, but also in an earlier-born chain (`emercoin`) | 15 |
| **novel at this position** | **117** |

The non-exclusive first-seen attribution flags are Namecoin 115, Emercoin 25, and Unobtanium 1; 126 of those 141 rows are also upstream. The historical miner labels suggest overlapping miner populations, but that interpretation must be retested in a future attribution phase.

### Historical pool-label snapshot

These labels were normalised during an earlier attribution pass and remain in
the committed CSV as historical evidence. The current public pipeline neither
depends on `bitcoin-data/mining-pools` nor recomputes this table.

| `pool_label` | Count | Notes |
|---|---:|---|
| F2Pool | 86 | |
| **Foundry USA** | **53** | Historical label; 37 keys are RSK-only among accepted direct-stale CSVs. |
| AntPool | 44 | |
| BTC.com | 28 | |
| Poolin | 25 | |
| ViaBTC | 22 | |
| Braiins Pool | 17 | Post-Slush rebrand. |
| `Unknown` | 16 | 9 distinct miner addresses lack a retained attribution in the accepted set. |
| Luxor | 5 | |
| SecPool | 2 | Newly surfaced with uncle traversal - no SecPool-mined stales appeared in canonical-only data. |

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/rsk_validated_stales.csv` - the committed loader input (298 publication-gate-accepted direct-stale header candidates). Shared historical validated-stales layout plus RSK-specific columns: `rsk_height`, `rsk_timestamp`, `rsk_miner`, `pool_label`, `merge_mining_hash`, `coinbase_op_return`, `coinbase_ascii_strings`, and the uncle-traversal columns `is_uncle`, `uncle_index`, `uncle_parent_height`. `coinbase_scriptsig_hex` / `coinbase_outputs` are empty placeholders (midstate-compressed, not recoverable). The full historical 37,335-row stale/unknown inventory stays in the private chain archive.
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
- **Unknown-inventory parallel-schema** - **resolved**. The classifier produced 37,031 unknown rows (20,847 canonical + 16,184 uncle) alongside 304 historical stale-labelled candidates. The loader and overlay expose 298 accepted direct-stale candidates without affecting the unknown inventory; one former direct row is retained separately as a stale descendant.
- **Uncle/ommer block traversal** - **resolved**. The historical private re-extraction traversed canonical blocks and uncles and processed about 17.95 million observations. The retained classifier inventory contains 222 uncle-derived stale-labelled candidates, of which 218 remain accepted as direct stales, plus one reclassified stale descendant and 16,184 uncle-derived unknowns. Unsupported rounded canonical/uncle component counts have been removed.
- **Known minor bug - RPC-retry duplicate writes**: when an `extract_range` call's phase-2 (uncle batch) errors after phase-1 (canonical batch) has already written rows, the retry re-writes the phase-1 rows. 15 such duplicate-unknown rows surfaced in this run (out of 37K unknowns, 0.04%); they were deduplicated post-classification by (classification, btc_header_hash, is_uncle, uncle_parent_height). Fix is to make `extract_range` write through a buffer that is committed only on full success. The 298 accepted direct-stale rows are unaffected.
