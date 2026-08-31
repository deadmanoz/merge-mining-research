# Geistgeld

| Field | Value |
|---|---|
| Ticker | GG (contemporary sources; the launch ANN notes the name "neatly abbreviates to GG or GEG", bitcointalk.org/index.php?topic=42417.0. "XGG" is this project's internal tag and now belongs to an unrelated coin, 10x.gg) |
| AuxPoW activation | 2011-10-08 (catalogue date, a project convention for Geistgeld; Namecoin's own merged-mining activation was NMC height 19200, 2011-10-11, on BTC block 148553 per Stifter et al. 2018). The dump shows AuxPoW commitments from GG height 14,092 / 2011-09-16, but those early blocks ran Geistgeld's own merged-mining code (the repo ships the standard Durham AuxPoW implementation verbatim) and don't reflect real BTC merge-mining; see §2 quirks. |
| Network status | **Dead** - no live nodes, no public explorer, no Arweave archive |
| Chronological position | 2 of 26 (tied with Namecoin at 2011-10-08, alphabetical tie-break to second; Namecoin at 1) |
| In Stifter et al. 2018 baseline | **Yes** (one of the paper's seven measured Bitcoin-parent chains; Table 1 lists `XGG` with a negligible BTC-parent contribution - 2 parent blocks against 2,493,631 child blocks). The paper mentions GeistGeld only incidentally in the text - as a very-short-block-interval example and as the chain whose block 144590 parented canonical Namecoin block 19236 - not as a quantified Bitcoin stale-block contributor. Consistent with this repo's 0-accepted-stale result. |
| Source tag (in code) | `geistgeld` |
| Loader | `load_geistgeld_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/geistgeld_validated_stales.csv` (header-only - **0 validated stales**) |
| Full stale/unknown inventory | Private chain archive (0 stale + 2,290 unknown rows) |

Geistgeld was an early experimental merge-mined chain launched in 2011 by bitcointalk user Lolcust as a fork of sacarlson's MultiCoin-exp (not by Vince Durham, who authored Namecoin and the AuxPoW spec; github.com/Lolcust/GeistGeld). The network has been dead for years and has no recoverable online presence. **Nicholas Stifter shared a complete `getblock`-JSON dump with the project on 2026-05-15** (1.6 GB gzipped, 7,309,972 total blocks, 2,493,631 AuxPoW-bearing). After classification, **the chain contributes zero accepted direct-stale candidates**, and the validated CSV is header-only. The reason is a chain-design quirk: Geistgeld accepted AuxPoW commitments whose embedded "BTC parent headers" satisfied only Geistgeld's lower difficulty, not Bitcoin's full target. The vast majority of parent headers in the dump are therefore unresolved, relaxed-target BTC-like proofs rather than accepted Bitcoin evidence.

## 1. Chain data

**Source.** Nicholas Stifter's archival per-block JSON dump, shared from his own records. Without this data, no extraction would be possible - there are no peers, no public archives, and no Arweave mirrors.

**Provenance.**

- Data shared by Nicholas Stifter on 2026-05-15.
- Staged in the private chain archive as `geistgeld_getblock_0to7309971_nbits_fixedlabels_auxheight.json.gz` (1.6 GB gzipped; ~10–20 GB uncompressed).
- Streamed end-to-end without read errors (gzip integrity verified). Filename's `0to7309971` matches the observed record count of 7,309,972 (inclusive of genesis).

**Coverage.** Across the dump:

| Metric | Count |
|---|---:|
| Total Geistgeld blocks (heights 0–7,309,971) | 7,309,972 |
| AuxPoW-bearing blocks | 2,493,631 (~34.1 %) |
| Pre-AuxPoW blocks (out of scope; no parent header to recover) | ~4.8 M |
| Unique parent header hashes that satisfy their own encoded `nBits` target | 2,291 |

The first AuxPoW-bearing block is **GG height 14,092**, parent-block timestamp **2011-09-16 00:27:52 UTC**. The one Bitcoin-canonical hit has `parent_block.time` 2013-11-21. AuxPoW commitments continue throughout the dump, but no later Bitcoin-linked parent header was identified.

**Holes.**

- **Pre-AuxPoW blocks (heights 0 → 14,091)**: no `auxpow` field in the dump; nothing to extract.
- **Post-dump**: the file covers 0–7,309,971; whatever the chain did after that is not in scope.
- **No live node / no Arweave / no public explorer**: 100 % of the recoverable data is what Stifter shipped.

**Reference scripts.**

- `scripts/classify/classify_geistgeld_stales.py:1` - chain-specific classifier; streams the gzipped JSONL directly (the dump *is* the extraction output, so there's no separate `extract_*` script for Geistgeld).

## 2. Extraction → potential stales

**Method.** Streaming gzipped JSONL → self-target PoW filter → dedup on parent hash → BTC RPC classification against the `<archival-host>` archive node. AuxPoW format is Durham serialisation, but the dump is already JSON-decoded so no binary parser is needed.

**Phases.**

1. **Stream-parse** the gzipped JSONL with `gzip.open(..., 'rt')` + per-line `json.loads`. Don't load into memory; uncompressed size is ~10–20 GB. Skip records without an `auxpow` field.
2. **Header reconstruction**. Build the 80-byte BTC header bytes from `auxpow.parent_block.{version, previousblockhash, merkleroot, time, bits, nonce}` (each field little-endian; the hex strings in the JSON are big-endian display form, byte-reversed before concatenation). Sample-verified against `auxpow.parent_block.hash` for 10 random records: **10/10 pass** - Stifter's pre-computed hash is trustworthy, so per-record header reconstruction is only needed for the `btc_header_hex` column in the output.
3. **PoW filter**. Compute `SHA256d(header)` and compare to the target derived from the header's own `nBits`. Discard headers that fail. This is the same filter every other classifier in the project uses.
4. **Dedup** on `auxpow.parent_block.hash`. Many Geistgeld blocks can embed the same BTC parent header during a BTC interval; the first GG height to witness a parent wins.
5. **BTC RPC classify** against `<archival-host>` (`ssh <archival-host>` + local `bitcoind` cookie auth - same path as the Huntercoin / CoiledCoin classifiers). `getblockheader <btc_header_hash>` hit → `canonical`. Miss → lookup `btc_prev_hash`. Prev canonical → `stale`. Both miss → `unknown`. The shared writer persists all three split inventories.

**Counts after Phase 1 + Phase 2.**

| Category | Count |
|---|---:|
| Total records streamed | 7,309,972 |
| AuxPoW-bearing | 2,493,631 |
| Headers reconstructed and PoW-filtered | 2,493,631 |
| Self-target PoW passes (header's own `nBits`) | 2,291 (~0.092 % of AuxPoW; dedup is a no-op because Stifter's parent hashes are already unique here) |
| **Canonical** | **1** |
| **Stale** | **0** |
| **Unknown** | **2,290** |
| BTC height of the 1 canonical | 270,741 (parent_block.time 2013-11-21; nBits `19070bfb`) |

**Chain-specific quirks.** Three are worth calling out, in increasing order of how much each explains the outcome:

- **`coinbase_outputs` always empty.** `auxpow.coinbasetx` in the dump has *no* `vout` field at all (only `vin[0].coinbase` and `txid` / `version` / `locktime`). The validated CSV's `coinbase_outputs` column is therefore empty for every Geistgeld row. Any future attribution is limited to scriptSig markers. This is moot for the current dataset because no validated stale rows exist.
- **Pre-Oct-2011 dump activity ran Geistgeld's own merged-mining code, not real BTC merge-mining.** The dump's first AuxPoW block (GG height 14,092) has `parent_block.time` 2011-09-16 00:27:52 UTC - 22 days before the 2011-10-08 catalogue date Geistgeld shares with Namecoin, and 25 days before Namecoin's own height-19200 merged-mining block (2011-10-11, on BTC block 148553 per Stifter et al. 2018). A literalist reading of the data would flip Geistgeld's chronological position to 1 (ahead of Namecoin). The project intentionally does **not** do this: the early "parent" headers don't connect to BTC mainchain (zero become publication-gate-accepted direct-stale candidates), and their `nBits` values are too easy for the BTC difficulty of late Sept 2011 (the chain id GeistGeld encodes in its own aux block version is operator-configurable via `-OurChainID`, defaulting to 0, so Geistgeld's AuxPoW identity is not fixed from the public record). The early Geistgeld AuxPoW commitments came from Geistgeld's own copy of the standard Durham AuxPoW implementation (the repo ships `src/auxpow.cpp/.h` and `contrib/merged-mine-proxy` verbatim), not from a separate Durham testbed. The convention is that `CHAINS_BY_AUXPOW_ACTIVATION` records production activation, not test-spec-development activity. Catalogue date stands; Namecoin keeps position 1.
- **Geistgeld accepted relaxed-target parent headers.** Of the 2,291 self-target-PoW-passing parent headers, **2,290 reference a `prev_hash` that `<archival-host>` does not recognise**, so they do not connect to BTC mainnet. Their `nBits` values cluster in the `1b…` / `1c…` range, easier than Bitcoin's actual `1a…` target in the corresponding period. The 1 canonical hit, from 2013-11-21, is the lone Bitcoin-mainchain exception. The evidence supports Geistgeld's own experimental, relaxed-difficulty use of its copy of the Durham AuxPoW implementation, but does not establish that every unknown was synthetic or identify a single parent chain.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_geistgeld_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

Zero entries pass; the validated CSV is header-only.

**Post-filter count: 0 accepted direct-stale header candidates.**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py geistgeld`. Per-stale row-level CSV at `results/per-chain-novelty/geistgeld.csv` (header-only, mirroring the validated CSV).

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count |
|---|---:|
| also in upstream | 0 |
| novel vs upstream | 0 |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain (with integrated loaders)**

Geistgeld sits at position 2, so `compute_chain_novelty.py` consults exactly one chronologically-earlier chain with an integrated loader: Namecoin (both share the 2011-10-08 catalogue date; the alphabetical tie-break orders Namecoin first, Geistgeld second). This is the script's `earlier_chains_consulted` list.

| Split | Count |
|---|---:|
| also in upstream | 0 |
| also in earlier chain (Namecoin) | 0 |
| **novel at this position** | **0** |

Every split is zero because Geistgeld's validated set is empty - there is nothing to attribute to upstream or to Namecoin in the first place. The count would stay zero even under a literalist reordering that placed Geistgeld ahead of Namecoin, because Geistgeld witnessed *no* BTC parent header that is also on the BTC chain as a stale.

> **Summary.** Geistgeld contributes **0 chronologically novel accepted direct-stale candidates**. The chain's merge-mining design accepted relaxed-difficulty parent headers, so its AuxPoW commitments mostly point to unresolved BTC-like headers whose `nBits` values do not match Bitcoin's target history. The recovery effort is documented for completeness - including the reverted position-1 experiment and the activation-date reasoning (§2, §5) - but does not contribute accepted candidates to the project.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/geistgeld_validated_stales.csv` - header-only (0 stale rows). Committed.
- `results/per-chain-novelty/geistgeld.csv` - header-only.
- `scripts/classify/classify_geistgeld_stales.py` - streaming gzipped-JSONL classifier; runs against `<archival-host>` over `--rpc-url` (forward the remote node's RPC port with `ssh -L`; same pattern as `classify_huntercoin_stales.py`).

**Private archive artifacts.**

- `geistgeld_unknown_blocks.csv` holds the 2,290 unknown rows in the standard schema; the `geistgeld_stale_blocks.csv` split bucket is header-only (0 stale).
- `geistgeld_getblock_0to7309971_nbits_fixedlabels_auxheight.json.gz` - staged source dump.

**External references.**

- Stifter et al. 2018, "Echoes of the Past: Recovering Blockchain Metrics From Merged Mining."
- `docs/auxpow-recovery.md` - cross-chain summary table (Geistgeld now at row 2; was in the "Pending / unwired" section before this integration).

## 5. Integration history

- **2026-05-15** - Archival dump shared by Nicholas Stifter alongside the Groupcoin dump.
- **2026-05-15** - Stub doc filed (`docs/chains/geistgeld.md`) marking the dump received and integration pending.
- **2026-05-15** - Integration completed: streaming classifier shipped, loader wired into the recovery pipeline, cross-chain table moved out of "Pending / unwired".
- **2026-05-15** - Initial chronological-precedence experiment placed Geistgeld at position 1 (on the basis of the 2011-09-16 first-AuxPoW-block timestamp), reverted later the same day. The pre-Oct-2011 dump activity ran Geistgeld's own merged-mining code, not real BTC merge-mining (see §2 last bullet). Catalogue activation date 2011-10-08 stands for both chains; alphabetical tie-break puts Geistgeld at position 2, Namecoin at 1. `CHAINS_BY_AUXPOW_ACTIVATION` and `docs/auxpow-recovery.md` updated accordingly.

The 0-stale result was unexpected - the integration brief's going-in guess was "tens of stales", extrapolating from GeistGeld's dump size relative to Namecoin/ixcoin/Devcoin. In hindsight the paper's own XGG row (just 2 BTC parent blocks in Table 1) already pointed to a near-zero outcome. It's the correct result under the project's classification methodology and explains itself once the relaxed-difficulty parent-header quirk is understood (§2 last bullet). The doc is kept as a record of negative results for future reference: any new XGG data source should produce the same outcome unless the underlying chain-design quirk has been mischaracterised here.
