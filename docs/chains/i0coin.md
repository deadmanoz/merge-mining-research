# i0coin

> **Provisional and incomplete.** The committed i0coin set comes from a January 2018 third-party blockchain snapshot. It ends in January 2018 and captures no later activity, so the 166 validated stales are a lower bound on i0coin's true stale signal. If a fuller i0coin history is ever obtained, the chain can be re-extracted and this doc refreshed.

| Field | Value |
|---|---|
| Ticker | I0C |
| AuxPoW activation | 2011-12-20 (I0C height 160,000, BTC height ~158,300) |
| Network status | Effectively dead (of 7 fixed seeds only `51.254.131.226:7333` answers on the P2P port, and it does not complete an i0coin handshake; DNS seeds dead; project sites static since early 2018) |
| Chronological position | 3 of 26 (after namecoin, geistgeld) |
| In Stifter et al. 2018 baseline | **Yes** (one of the paper's seven measured Bitcoin-parent chains; Table 1) |
| AuxPoW chain ID | 2 (Namecoin's is 1; ixcoin's is 3) |
| Block time | 90 seconds (≈ 6.67 i0coin blocks per BTC block) |
| Source tag (in code) | `i0coin` |
| Loader | `load_i0coin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/i0coin_validated_stales.csv` |

i0coin was the third SHA-256d AuxPoW chain by merged-mining activation order (after Namecoin and Geistgeld), launched in August 2011 (genesis nTime 1313457620 = 2011-08-15) and merge-mining-enabled at I0C block 160,000 on 20 December 2011 with the original Namecoin AuxPoW code (Vince Durham's design). Daniel Kraft (`domob1812`) later became i0coin's maintainer and rebased it onto Bitcoin Core 0.12.x in 2016, but that port postdates the chain's launch by several years. Its 90-second block time is the unusual feature: it captures roughly six to seven independent AuxPoW proofs per BTC block interval, so any BTC stale broadly propagated to i0coin miners has many opportunities to be embedded as a parent header. In principle this gives i0coin substantially higher sampling density for short-lived BTC stales than the 10-minute chains (Namecoin, ixcoin, Devcoin).

In practice the committed data is a January 2018 partial snapshot, and the validated set is small (166). Because the snapshot ends in early 2018 and the extraction only reaches the parent headers i0coin actually embedded, the true i0coin stale signal is very likely larger than what is captured here; treat these counts as a lower bound.

## 1. Chain data

**Source.** Offline `blk*.dat` binary parse of a January 2018 third-party blockchain snapshot of i0coin (`I0coin_full_blockchain_20-Jan-2018.zip`, 2.4 GB compressed; the parse expanded to ~7.9 GB across 59 `blk*.dat` files, spanning roughly 2.3M I0C blocks), originally hosted on MediaFire and Mega and downloaded to `<archival-host>` during the recovery effort. No live i0coin node was practical at sync time: DNS seeds were dead and, of seven fixed seeds, only `51.254.131.226:7333` answered on the P2P port (and it did not complete an i0coin handshake). The same generic Namecoin-family extractor (`extract_auxpow_from_blkdat.py`) handles i0coin because its AuxPoW format is byte-identical to Namecoin's (Vince Durham's original specification).

**Provenance.** Snapshot downloaded to `<archival-host>` in early 2026, extracted into `~/.i0coin/`, parsed offline against the project's generic Namecoin-family AuxPoW extractor. No live RPC node ran for this chain. Bitcoin Core on `<archival-host>` provided the RPC for the subsequent classification step.

**Coverage.** Validated stales span BTC heights **160,948 → 504,952** (parent timestamps **2012-01-06 → 2018-01-19**, i.e. Jan 2012 → Jan 2018), bounded above by the January 2018 snapshot date. The snapshot does not provide authenticated I0C consensus heights.

**Holes.**

- **Pre-AuxPoW** (I0C 0 → 159,999): solo SHA-256 mining, no embedded BTC parent headers.
- **Before the BIP34 transition** (BTC < 224,413): height is inferred from the active-chain parent, with `nBits` epoch and `nTime` as supporting evidence. From 224,413 through 227,930, the coinbase-height prefix is enforced for version 2 or newer candidates; from 227,931 it is universal.
- **Post-snapshot gap (the big one)**: the committed data ends with the January 2018 snapshot (last parent `btc_time` 2018-01-19). If the chain continued past that, whatever activity existed between early 2018 and its true death is invisible to this extraction. Closing that gap would require a fuller i0coin history than the 2018 snapshot; none has been obtained.
- **Post-BCH/BSV contamination**: 12 validated rows are tagged `VALID (post-BCH, difficulty matches BTC)` - these are Aug 2017 → Jan 2018 records where the `nBits` check confirms the parent header is BTC rather than BCH/BSV. None are `REJECTED` in the committed set, but the full classifier additionally rejected 9 stale-labelled candidates on the `nBits` gate (parent difficulty inconsistent with Bitcoin at that height); those rejected rows are gitignored and not included here.

**Reference scripts.**

- `scripts/extract/extract_auxpow_from_blkdat.py:1` - generic Namecoin-family `blk*.dat` extractor (shared with Namecoin; invoke with `--chain i0coin`).
- `scripts/classify/classify_auxpow_candidates.py:1` - generic AuxPoW classifier (canonical / stale / unknown; includes `nBits` BCH/BSV cross-check for post-2017 blocks).

## 2. Extraction → potential stales

**Method.** Offline binary parse of every block in the snapshot's `blk*.dat`. Same extractor used for Namecoin. For each I0C block ≥ 160,000 carrying a `CAuxPow` payload, extract the embedded Bitcoin parent header, coinbase tx, and Merkle branch.

The snapshot exposes the serialized child header and hash but no authenticated
consensus height. Because `blk*.dat` order is not chain order, the extractor
leaves the uniform `child_height` slot blank and does not persist a scan
counter. The full child header, authenticated child hash, timestamp, and
`nBits` remain the available child identity evidence.

**Phases.**

1. **Parse**: walk all I0C blocks in `blk*.dat`; for each AuxPoW-bearing block, extract parent header + coinbase tx + Merkle branch.
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. Bitcoin's contemporaneous target is checked later for stale-labelled candidates.
3. **Dedup** on `btc_header_hash` (with 6.67× block density, many consecutive I0C blocks can reference the same BTC parent - especially from the same miner running the same hashing job across multiple I0C blocks).
4. **BTC RPC classify** (`classify_auxpow_candidates.py`): batch `bitcoin-cli getblockheader <hash>`. Hit → `canonical`. Miss → look up `prev_hash`. Prev canonical → `stale`. Neither → `unknown`.
5. **Validation**: like Namecoin, candidates are checked against BTC's actual
   difficulty, historical minimum block version, and applicable BIP34 height
   rule. Rows are tagged `VALID`, `VALID (post-BCH, difficulty matches BTC)`,
   `REJECTED`, or `UNKNOWN`.

The classifier's primary accepted, rejected, canonical, stale, and unknown
publication files use the normalized parent columns `btc_height`,
`btc_header_hash`, and `btc_bits`. Source-specific fields such as
`btc_stale_height`, `btc_hash`, `btc_bits_hex`, `nbits_match`, and
`post_bch_fork` remain in the private full classifier inventory, where they
serve as diagnostics rather than loader fields.

**Counts in the private full classifier output** (103,383 rows total):

| `classification` | Count |
|---|---:|
| `canonical` | 16,958 |
| `unknown` | 86,249 |
| `stale`-labelled candidate | 176 |
| **Total** | **103,383** |

The 103,383 total is the deduped, self-target-PoW-passing unique parent-header
set; the full historical CSV remains external because of its size. The
normalized full-evidence export contains 103,382 rows because it applies the
same exact-key exclusion that removes the invalid BTC-height-367,047 candidate.
The normal Monitor publication includes all 16,958 canonical parents, the 166
accepted stales, and the 2 unknown rows with final strict relevance verdicts.
The other unknown and rejected rows remain in the full external evidence. Of
the 176 stale-labelled candidates, 9 fail the `nBits` gate (parent difficulty
inconsistent with Bitcoin at that height) and are rejected, leaving 167
`VALID`; the error-blocks dataset (`data/error-blocks/error_blocks.csv`) then
removes one shared post-BIP66 version 2 candidate (BTC 367,047), leaving
**166** committed loader rows.

**Counts in the committed validated CSV** (`data/validated-stales/i0coin_validated_stales.csv`, 166 rows, all `classification == "stale"`):

| `validation_status` | Count |
|---|---:|
| `VALID` (pre-BCH-fork) | 154 |
| `VALID (post-BCH, difficulty matches BTC)` | 12 |
| **Total** | **166** |

**Chain-specific quirks.**

- **High block density (6.67×)**: many BTC parents are referenced by multiple I0C blocks. Dedup is essential to avoid double-counting.
- **No `auxpow` JSON in RPC**: the Bitcoin Core 0.12.x lineage of i0coin Core (release `i0coin-0.12.0.1`, 2016) doesn't expose decoded AuxPoW via `getblock`. Extraction is binary-only - but since the snapshot is parsed offline from `blk*.dat`, the RPC path doesn't matter for this chain.
- **Snapshot integrity**: the 2018 snapshot was a third-party upload (izerocoin.org via MediaFire/Mega). The extraction relied on the snapshot being uncorrupted; no independent cryptographic verification of the snapshot was possible.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_i0coin_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status.startswith("VALID")
```

The `VALID`-prefix gate passes both `VALID` (pre-BCH) and `VALID (post-BCH, ...)` rows. All 166 committed entries are `classification == "stale"` with a `VALID` prefix; the loader also applies the exact-key error-blocks exclusion gate, which removes the one shared post-BIP66 version 2 candidate (BTC 367,047).

**Post-filter count: 166 accepted direct-stale header candidates.**

**Derived strict/weak relevance: 2 strict, 0 weak observations.** These are
unknown rows admitted to the separate relevance axis, not direct-stale
promotions. They remain `classification=unknown` in the monitor evidence.

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py i0coin`. Per-stale row-level breakdown at `results/per-chain-novelty/i0coin.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 129 | 77.7 % |
| novel vs upstream | 37 | 22.3 % |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

i0coin is 3rd chronologically. The chronologically-earlier integrated chains are `namecoin` and `geistgeld`; Geistgeld contributes zero validated stales, so Namecoin is the only earlier-chain first-claim source here. Breakdown:

| Split | Count |
|---|---:|
| also in upstream | 129 |
| also in earlier-born chain (`namecoin`: 102) | 102 |
| **novel at this position (current snapshot)** | **37** |

The current-snapshot 37 i0coin-novel hashes are stales that Namecoin's extraction didn't catch but i0coin's did - likely a combination of (a) blocks where Namecoin's lower sampling density missed a short-lived stale that i0coin's 6.67× density caught, and (b) blocks where i0coin's miner population overlapped with stale-block-producing pools that Namecoin's didn't. Treat this as provisional: the January 2018 snapshot bounds i0coin's coverage, so this novelty contribution is a lower bound.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/i0coin_validated_stales.csv` - 166 validated stales (committed; the loader's input).
- `results/monitor-evidence/i0coin_monitor_evidence.csv` - 16,958 canonical,
  166 accepted stale, and 2 strict unknown-row observations.
- `results/per-chain-novelty/i0coin.csv` - per-stale `(height, hash, in_upstream, first_seen_chain)` table.

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (i0coin row).

**Remaining work.**

- **Fuller re-extraction (if data becomes available)**: the committed set is bounded by the January 2018 snapshot. A complete i0coin history, if one is ever obtained, would likely increase the validated-stale count and shift i0coin's cumulative-novelty contribution. No such fuller history is currently in hand.
- **Unknown-chain origin (H1 vs H2)**: Namecoin's [private research
  boundary](namecoin.md#private-research-boundary) rejects promoting its broad
  unknown population while retaining a small strict/weak subset. i0coin's
  86,249-row unknown population likewise yields only the 2 strict observations
  above and remains a substantial sample for substrate research.
