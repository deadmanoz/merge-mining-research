# Groupcoin

| Field | Value |
|---|---|
| Ticker | GPC |
| AuxPoW activation | 2012-02-16 (catalogue date, verified from the dump - see §2 quirks) |
| Network status | **Dead** - no live nodes, no public explorer, no Arweave archive |
| Chronological position | 7 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin; before huntercoin) |
| In Stifter et al. 2018 baseline | **Yes** (one of the paper's seven measured Bitcoin-parent chains; Table 1) |
| Block time | ~60 s nominal (per the chain catalogue) |
| Source tag (in code) | `groupcoin` |
| Loader | `load_groupcoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/groupcoin_validated_stales.csv` |
| Full stale/unknown inventory | Private chain archive (32 stale + 2,713 unknown rows) |

Groupcoin (GPC) was a ~2011-launched Namecoin-family merge-mined chain (a Devcoin predecessor/testbed; 2012-02-16 is its merge-mining activation date, not the chain's launch) in the early-2012 merge-mining cohort that followed the original Namecoin / i0coin / ixcoin / Devcoin wave. The network is **dead**: no live nodes, no public explorer, and no community-maintained archive. The only recovery path is Nicholas Stifter's complete `getblock`-JSON dump of every Groupcoin block, which he shared with the project (1.8 GB gzipped, 235,752 records total, 218,494 AuxPoW-bearing - a high 93 % AuxPoW share). The committed set is 30 publication-gate-accepted direct-stale header candidates spanning May 2012 → July 2014, plus a 2,713-row unknown inventory; one stale-classified row fails canonical-at-height `nBits` and one fails BIP66's minimum block version.

## 1. Chain data

**Source.** Nicholas Stifter's archival `getblock` JSON dump (one JSONL record per Groupcoin block; AuxPoW-bearing records carry a fully decoded `auxpow` object with `coinbasetx` + `parent_block`). Nicholas Stifter shared the dump with the project on 2026-05-15 alongside the Geistgeld dump. Without it, no extraction would have been possible - the public `mergedmonitor.json` carries only the BTC-parent-header projection, not the underlying Groupcoin blocks.

**Provenance.** Raw archive at `groupcoin_getblocks_0to235751_auxheight.json.gz` in the private chain archive (1.8 GB gzipped). Streamed and classified by `scripts/classify/classify_groupcoin_stales.py` against the Bitcoin Core RPC on `<archival-host>`. The full classifier output is preserved privately (32 stale-labelled candidates + 2,713 unknown rows under the project-wide standard schema); the public CSV retains 30 candidates accepted by the declared header-context publication gate. See the [data validity contract](../data-validity.md).

**Coverage.** The 30 accepted rows span BTC heights **181,492 → 312,238** (2012-05-25 → 2014-07-24, a ~2.2-year window). GPC heights **31,261 → 131,681**. The dump itself extends from GPC genesis (height 0) to GPC 235,751 with the first AuxPoW-bearing record at GPC 17,187, so the chain's AuxPoW observability window is February 2012 → July 2018, comfortably wider than the accepted direct-stale window.

**Integration status.** Wired into the recovery loader and novelty pipeline. The validated CSV at `data/validated-stales/groupcoin_validated_stales.csv` (30 rows) is consumed by `load_groupcoin_stales()`, and Groupcoin sits at chronological position 7, after Devcoin and before Huntercoin.

**Holes.**

- **Pre-AuxPoW** (GPC < 17,187): no `auxpow` field; nothing to extract. Groupcoin's genesis-to-AuxPoW-activation gap is ~17 k blocks, covered by the dump but inert.
- **Post-2018-07-21**: the dump's last AuxPoW record carries a parent timestamp of 2018-07-21. If Groupcoin produced further blocks after this date they are not in the archive. The Stifter freeze is 2018-07-06, so any later activity is also outside the comparison baseline.
- **Validation scope**: all 30 public rows carry `validation_status=VALID`, meaning they pass the declared header-context publication gate. It is not a full Bitcoin block-validity assertion. BCH/BSV contamination is not a concern because the accepted window ends July 2014, before those forks.

**Reference scripts.**

- `scripts/classify/classify_groupcoin_stales.py:1` - chain-specific classifier; streams the gzipped JSONL, filters to PoW-valid unique BTC parents, classifies against the Bitcoin Core RPC on `<archival-host>`. Closest precedent: `scripts/classify/classify_huntercoin_stales.py:1`; structurally similar `--rpc-url` pattern (forward the remote node's RPC port with `ssh -L`), but reads JSONL instead of an intermediate extraction CSV.

## 2. Extraction → potential stales

**Method.** No extractor is needed. Stifter's `getblock` JSON is already the post-extraction artifact. The classifier streams the gzipped JSONL, reconstructs the 80-byte parent header from `auxpow.parent_block` fields, applies a self-target PoW filter, dedups by parent header hash, and classifies each unique parent against Bitcoin Core RPC on `<archival-host>`.

**Phases.**

1. **Stream-parse** the gzipped JSONL (`gzip.open(..., 'rt')`); ~10–15 GB uncompressed, decoded line-by-line.
2. **Filter** to records with an `auxpow` field (218,494 of 235,752).
3. **Self-target PoW filter**: compute `SHA256d` of the reconstructed parent header bytes and compare it with the target derived from `auxpow.parent_block.bits`. This does not establish Bitcoin's contemporaneous target. A spot-verification pass against 10 sampled records confirmed `auxpow.parent_block.hash` is byte-for-byte reproducible from the JSON fields, so the pre-computed hash is trusted for the dedup step.
4. **Dedup** on `auxpow.parent_block.hash`. Combined with the self-target PoW filter, the 218,494 AuxPoW records reduce to 4,868 unique PoW-valid parents.
5. **BTC RPC classify** against `<archival-host>`:
   - `bitcoin-cli getblockheader <hash>` hit → `canonical` (2,123 rows; not part of the unknown inventory).
   - miss → `bitcoin-cli getblockheader <prev>` hit → `stale`; height = `prev.height + 1` (32 rows before the publication gate, 30 committed).
   - miss + miss → `unknown`; `btc_height` blank (2,713 rows).

**Counts.**

| Stage | Count |
|---|---:|
| Total dump records | 235,752 |
| AuxPoW-bearing | 218,494 |
| Failed self-target PoW or duplicate parent (dropped) | 213,626 |
| Unique PoW-valid parents | 4,868 |
| `canonical` (on BTC mainchain) | 2,123 |
| `stale` (candidate off active chain, predecessor canonical) | **32 raw; 30 committed after the publication gate** |
| `unknown` (parent + prev both off-chain) | 2,713 |

**Chain-specific quirks.**

- **`scriptPubKey.addresses` are Groupcoin-base58-encoded.** The dump pre-decodes parent-coinbase outputs but the decoder runs Groupcoin's address format (e.g. `2hihMi7xggbZxKgJsF8FcA86qSSHVBQzY6R` - `2h…` prefix), not BTC mainnet's. The classifier deliberately emits raw `scriptPubKey.hex` semicolon-joined into `coinbase_outputs` (matches the i0coin / ixcoin / Unobtanium / Huntercoin pattern), preserving the pkscripts for BTC-mainnet decoding in a later attribution phase. Do not use the `addresses` field.
- **A handful of `vout` entries are non-standard parser artifacts.** Some leading outputs decode as `20d7ad…` (a 32-byte push that is the merge-mining commit rather than a real output) or the ASCII string `736372697074` ("script"). They are preserved as source evidence; a future attribution pass must ignore them and use scriptSig markers or valid outputs instead.
- **Very high AuxPoW density (93 %).** Almost every Groupcoin block carries an AuxPoW parent header. About 2.2 % of them survive as unique PoW-valid parents (4,868 of 218,494) and proceed to Bitcoin RPC classification.
- **Activation date matches the catalogue.** First AuxPoW-bearing block at GPC 17,187 has `parent_block.time` 2012-02-16 10:56:16 UTC; the catalogue's `2012-02-16` is correct and `CHAINS_BY_AUXPOW_ACTIVATION` did not need updating. Groupcoin sits between Devcoin (2012-01-07) and Huntercoin (2014-01-31) at chronological position 7.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_groupcoin_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status.startswith("VALID")
```

The exact-key publication overlay is applied after this persisted gate. Thirty
entries pass. One stale-classified row is rejected because its encoded
`btc_bits` (`1a1bf2d4`) does not match Bitcoin's canonical bits
(`181287ba`) at height 376,388. One version 2 header after BIP66 height
363,725 (BTC 367,047, a shared consensus-invalid exclusion applied via the
exact-key overlay) fails the minimum version 3 rule.

**Post-filter count: 30 accepted direct-stale header candidates.**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py groupcoin`. Per-stale row-level breakdown at `results/per-chain-novelty/groupcoin.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 15 | 50.0 % |
| novel vs upstream | 15 | 50.0 % |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Groupcoin is 7th chronologically. The earlier-born integrated chains are namecoin, geistgeld, i0coin, ixcoin, coiledcoin, and devcoin. Geistgeld contributes zero validated stales. Breakdown:

| Split | Count |
|---|---:|
| also in upstream | 15 |
| also in earlier-born chain (`i0coin`: 15, `namecoin`: 13, `ixcoin`: 1) | 29 |
| **novel at this position** | **1** |

i0coin and namecoin between them already claim almost every Groupcoin stale - both chains were at high merge-mining hashrate during Groupcoin's May 2012 → July 2014 accepted window and dominate the chronological-precedence attribution. Only **1 stale is novel** at Groupcoin's position:

- **BTC 269,699** (`0000000000000000297d4b57222904867a480b967aea07677aac23a5f124df6d`, Nov 2013) - not in upstream `bitcoin-data/stale-blocks`, and not in any chronologically-earlier integrated chain's validated set.

Groupcoin's marginal yield at chronological position 7 is therefore small (1 of 30 = 3.3 %) - most of the window overlaps with five chronologically-earlier integrated chains that were heavier merge-miners during 2012–2014.

### Unknown inventory

The 2,713 self-target-PoW-passing **unknowns-by-our-standard** (parent not on BTC mainchain, prev_hash also not on BTC mainchain) live in the private unknown-inventory bucket (`groupcoin_unknown_blocks.csv`) under `classification == "unknown"`. It is a comparatively small unknown inventory - the raw-hex parses of ixcoin, i0coin, and devcoin each carry tens to hundreds of thousands more.

The unknown population is not yet characterised. It **may** encode a non-BTC SHA-256d substrate (for example testnet or private-chain BTC parents that Groupcoin miners attached as AuxPoW commits) or chain segments lost to deep BTC reorgs that no other AuxPoW chain in scope captured, but this reading is explicitly speculative pending the queued pool-attribution audit (§4). Until then the unknown rows are preserved verbatim for diagnostic use.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/groupcoin_validated_stales.csv` - 30 publication-gate-accepted direct-stale header candidates (loader input; committed). Standard schema.
- `results/per-chain-novelty/groupcoin.csv` - per-stale `(btc_height, btc_hash, in_upstream, first_seen_chain)` table.
- `scripts/classify/classify_groupcoin_stales.py` - reproducer (streams the gzipped dump and writes the two CSVs above).

**Private archive artifacts.**

- `groupcoin_getblocks_0to235751_auxheight.json.gz` - raw archival dump shared by Nicholas Stifter (1.8 GB gzipped).
- Split inventories: `groupcoin_stale_blocks.csv` (32 stale) and `groupcoin_unknown_blocks.csv` (2,713 unknown). 2.1 MB combined.

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (Groupcoin row at chronological position 7).

**Remaining work.**

- **Pool-attribution audit of the 2,713 unknowns** (queued; analogue of the Huntercoin audit). The Huntercoin precedent settled the H1/H2 question by inspecting recognisable BTC pool tags on unknown coinbases vs validated stales. Groupcoin's unknown population is roughly two orders of magnitude larger than Huntercoin's 29, so the same audit is worth running here.
- **i0coin dependency**: Groupcoin's chronological-novelty attribution to i0coin (currently 15 stales) rests on i0coin's January 2018 partial snapshot. If i0coin is ever re-extracted from a fuller history, this count should be re-run and may shift.

## 5. Integration history

- **2026-05-15** - Archival `getblock`-JSON dump shared by Nicholas Stifter alongside the Geistgeld dump.
- **2026-06** - Streaming classifier (`classify_groupcoin_stales.py`) shipped; `load_groupcoin_stales()` wired into the recovery and novelty pipeline; the `docs/auxpow-recovery.md` cross-chain table gained the Groupcoin row at chronological position 7. Classification produced 32 stale candidates; the canonical-at-height `nBits` gate rejected the row at BTC 376,388, leaving 31.
- **2026-07** - Repo-wide exact-key exclusion overlay applied. The shared version 2 header at BTC 367,047 (also observed by Namecoin, Devcoin, i0coin, and Unobtanium) was excluded under BIP66, dropping the accepted set from 31 to 30. The doc's accepted window was corrected from an earlier upper bound of BTC 376,388 / September 2015 (which counted the excluded `nBits` row) to the true BTC 181,492 → 312,238 (May 2012 → July 2014).
