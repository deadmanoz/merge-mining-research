# Fractal Bitcoin

Fractal Bitcoin recovery is now integrated into the public loader pipeline.
`fractald` v0.3.0 completed IBD on `<archival-host>`, extraction ran through
FB height 1,807,154, and
`data/validated-stales/fractal_validated_stales.csv` contains the 40 accepted
BTC direct-stale rows.

| Field | Value |
|---|---|
| Ticker | FB |
| AuxPoW activation | Fractal's post-genesis chain launched 2024-09-09; AuxPoW is permitted from height 1 and first observed at height 2. Height 0 reuses Bitcoin's 2009 genesis. |
| Network status | Active. The research node and latest official binary release are v0.3.0 as audited on 2026-07-22. |
| Chronological position | 26 of 26 (latest, after Lyncoin) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; chain post-dates the paper by 6+ years) |
| AuxPoW chain ID | `0x2024` (decimal 8228) |
| Block time | 30 s aggregate target; Cadence Mining targets roughly one-third AuxPoW, and v0.3.0 adds a third Indexer class after height 1,500,000 |
| Source tag (in code) | `fractal` |
| Loader | `load_fractal_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/fractal_validated_stales.csv` (40 rows) |
| Novelty CSV | `results/per-chain-novelty/fractal.csv` |

Fractal Bitcoin is the newest merge-mined chain in the integrated set. Its
parent coinbases contain markers historically attributed to Foundry, AntPool,
ViaBTC, MARA, F2Pool, and other contemporary pools. These unauthenticated
miner-selected strings are attribution evidence, not independent proof of
operator identity. The final marginal yield is small because most recovered
Fractal accepted candidates overlap RSK or Namecoin, but Fractal still
contributes one chronologically novel accepted candidate and one new upstream
sidecar row.

## 1. Chain Data

**Source.** Pre-built `fractald` v0.3.0 running on `<archival-host>` inside
Docker with a private archival datadir (build and run recipe in
`node-infra/fractal/`). The node uses P2P port 18333 and RPC port 18332 to
avoid colliding with Bitcoin Core's production ports. Bitcoin Core on the
same host provided BTC RPC for classification.

**Sync state.** On 2026-05-29, `getblockchaininfo` reported
`initialblockdownload=false`. The extraction tip was FB height 1,807,154.
These are dated acquisition-run observations; the synchronized local archive
does not retain the original raw extraction or run log.

**Coverage.** The committed stale rows span BTC heights 865,079 to 949,204 and
FB heights 93,061 to 1,761,665. The extraction scanned FB heights 1 through
1,807,154. A 2026-07-18 reclassification against Bitcoin Core independently
materialized 58,980 canonical rows and reproduced the 31 accepted stales and
493 unknowns. The canonical file is retained in the private consolidated
archive, where the coverage ledger records 53,396,150 bytes.
The 30 August current-Core reclassification of the same 59,504 self-target-valid
parents yields 58,970 canonical, 40 accepted direct stale, and 494 unknown
rows. The final Monitor projects those 58,970 canonical rows, all 40 direct
stales, and one authenticated 941,882 witness as `stale_descendant`.

**Holes and filters.**

- Genesis height 0 is outside the extraction window. Height 1 is non-AuxPoW;
  height 2 is the first observed `0x20240100` AuxPoW block.
- Cadence Mining non-merge-mined blocks do not carry CAuxPow and are skipped.
- Fractal is entirely post-BCH and post-BSV, so the classifier uses the shared
  publication gate before committing rows. It corroborates header identity and
  self-target PoW, active-parent placement, expected `nBits`, median-time-past,
  historical minimum version, coinbase scriptSig length, and the BIP34 height
  prefix. `VALID` means this available-evidence profile passed, not that a
  complete Bitcoin block was replayed for full consensus validity.
- Stifter comparison is not applicable because Fractal launched after the
  2018-07-06 Stifter freeze.

## 2. Extraction and Classification

`scripts/extract/extract_fractal_auxpow.py` walks FB heights and requests:

```text
getblockheader <hash> false true
```

That RPC path returns the compact serialized Fractal block header with the
CAuxPow tail, avoiding full Fractal transaction payloads. The extractor then
parses the embedded BTC parent header, parent coinbase scriptsig, and parent
coinbase outputs.

Fractal-specific version filtering matters. Official v0.3.0 semantics require
the `0x100` AuxPoW flag together with chain ID `0x2024`; the observed mainnet
encoding in this extraction is `0x20240100`. Testing the generic flag alone is
unsafe because the `0x20260100` Indexer class also sets it but serializes a
different proof. The current extractor applies the flag-plus-chain-ID
predicate; the historical run's exact-encoding gate produces the same counts
over this point-in-time range.

Historical extraction counts from the 2026-05-29 run, followed by the
2026-07-18 classifier reproduction:

| Stage | Rows |
|---|---:|
| FB blocks scanned | 1,807,154 |
| Non-merge-mined blocks skipped | 1,205,394 |
| AuxPoW rows extracted | 601,760 |
| Parse errors | 0 |
| Self-target-PoW-valid unique parent headers | 59,504 |
| Canonical BTC parents | 58,980 |
| Stale-labelled candidates | 31 |
| BTC unknowns | 493 |
| Publication-gate-accepted direct-stale rows | 31 |
| Publication-gate rejected stale rows | 0 |

Private operational outputs are bucket-split by classification. The
synchronized local mirror retains the classified and validated files plus the
July canonical-refresh note; the bulky raw extraction and intermediate remain
on the archival tier:

- `fractal_stale_blocks.csv` (31 stale rows)
- `fractal_unknown_blocks.csv` (493 unknown rows)
- `fractal_canonical_blocks.csv` (58,980 canonical parents)
- `fractal_validated_stales.csv`

Only the compact validated loader input is committed publicly.

## 3. Filtering and Novelty

`load_fractal_stales()` accepts only rows with:

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

The committed input yields 40 accepted direct-stale header candidates whose
predecessors are canonical Bitcoin blocks.

Generated by `python scripts/compute_chain_novelty.py fractal`:

| View | Count |
|---|---:|
| Total validated | 40 |
| Also in upstream `bitcoin-data/stale-blocks` | 25 |
| Novel vs upstream | 15 |
| Already first-seen by RSK | 19 |
| Already first-seen by Namecoin | 16 |
| Already first-seen by Elastos | 1 |
| Chronologically novel at Fractal's position | 1 |
| Stifter baseline overlap | 0 |

The upstream and `first_seen_chain` columns are independent flags. The 19 RSK,
16 Namecoin, and 1 Elastos first-seen rows overlap the upstream set; they are
not an exclusive partition of the 40 rows. Four rows have no earlier-chain
flag. Bitcoin heights 865,079, 901,092, and 949,204 are already upstream, while
928,455 is the sole chronologically novel row.

The chronologically novel stale is BTC height 928,455:

```text
00000000000000000000398ead6702380e49e5e872d194a35cbd64c066a3d47f
```

Three Fractal rows at Bitcoin heights 865,079, 901,092, and 949,204 are already
upstream but not in an earlier integrated AuxPoW chain, so they are not counted
as chronologically novel.

## 4. Historical Pool-Label Snapshot

An earlier attribution pass used the BTC parent coinbase extracted from CAuxPow,
not the Fractal-layer block coinbase. The table records normalized coinbase
marker strings, including the historical `/slush/` to Braiins normalization.
Markers are unauthenticated miner-selected claims. The table is retained as a
historical research result, is not generated by the current public recovery
pipeline, and has not been refreshed against a current pool registry.

| Pool | Stales |
|---|---:|
| Foundry USA | 16 |
| AntPool | 5 |
| ViaBTC | 4 |
| MARA Pool | 2 |
| SecPool | 1 |
| Braiins Pool | 1 |
| SpiderPool | 1 |
| F2Pool | 1 |

## 5. Outputs and Caveats

In-repo artifacts:

- `data/validated-stales/fractal_validated_stales.csv`
- `results/per-chain-novelty/fractal.csv`
- `data/new_stale_blocks_for_upstream.csv` includes the one net-new Fractal
  upstream candidate at BTC height 928,455.

The dated 58,980-row consolidated canonical export remains in the private
archive and is not an in-repo artifact.

Primary protocol references:

- [Fractal v0.3.0 chain parameters](https://github.com/fractal-bitcoin/fractal/blob/1f5213d3dc779ed11e1128f1a4600709baab34b2/src/kernel/chainparams.cpp#L125-L160)
  define strict chain-ID validation and reuse Bitcoin's height-0 genesis.
- Official explorer headers for [height 1](https://mempool.fractalbitcoin.io/api/block/00000000000000005a5c13fe33f6717c7ad81fc8837ae75e4693c16acbdd0f66/header)
  and [height 2](https://mempool.fractalbitcoin.io/api/block/ab92f4fc0ebf37fe128e63c42bd12c8f277afa3674340c7ed6bb0fb4db1e25ea/header)
  establish the first observed post-launch AuxPoW boundary.
- [Fractal v0.3.0 header predicates](https://github.com/fractal-bitcoin/fractal/blob/1f5213d3dc779ed11e1128f1a4600709baab34b2/src/primitives/pureheader.h#L24-L34)
  define the AuxPoW flag and `0x2024` / `0x2026` chain IDs.
- [Fractal block serialization](https://github.com/fractal-bitcoin/fractal/blob/1f5213d3dc779ed11e1128f1a4600709baab34b2/src/primitives/block.h#L24-L63)
  separates CAuxPow, Indexer, and ordinary headers.
- [Fractal v0.3.0 release](https://github.com/fractal-bitcoin/fractald-release/releases/tag/v0.3.0)
  documents the Indexer-class activation at height 1,500,000.
- [Fractal `getblockheader` RPC](https://github.com/fractal-bitcoin/fractal/blob/1f5213d3dc779ed11e1128f1a4600709baab34b2/src/rpc/blockchain.cpp#L603-L680)
  documents the third `auxpow` argument used by the extractor.

The full Fractal classifier output is private archive material. The local
unknown-stale reconciliation script should not be regenerated unless the private
full inventories are mounted, because a checkout with only compact public inputs
cannot reproduce the full unknown graph.
