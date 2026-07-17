# Bitcoin Vault

| Field | Value |
|---|---|
| Ticker | BTCV |
| AuxPoW activation | 2020-11-17 (BTCV mainnet block h=58,420, `consensus.nAuxpowStartHeight=58420`) |
| Network status | **Dormant** (chain tip stalled at h=228,360 since 2024-03-10 03:54:40 UTC; repo last commit 2024-02-19 v2.6.0) |
| Chronological position | 23 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven, argentum, terracoin, emercoin, rsk, doichain, bitmark, xaya, elastos, syscoin, hathor; before Electric Cash) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; 2020-11-17 launch post-dates the paper's mid-2018 data cutoff) |
| AuxPoW chain ID | `1638` (`0x0666`), strict (`fStrictChainId=true`). **Do not confuse with Emercoin's `666` decimal (`0x029A` hex)** - different by an order of magnitude despite visual similarity when written as just "666". |
| Block time | 600 s (Bitcoin-identical 10-minute target) |
| Source tag (in code) | `bitcoin-vault` |
| Loader | `load_bitcoin_vault_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/bitcoin-vault_validated_stales.csv` |

Bitcoin Vault is the **first chain in the integrated pipeline recovered without ever running a node**. The chain has been dormant since March 2024, but Trezor's Blockbook explorer at `btcvexplorer.com` exposes a `/api/rawblock/<hash>` endpoint that returns the full serialised block hex including the AuxPoW tail. The 4-host REST extraction (<archival-host> + three worker hosts, ~24h wall-clock at 1 req/s/host) pulled all 169,939 in-scope AuxPoW commitments, of which the classifier surfaced **9 stale BTC blocks (6 novel vs upstream, 3 enrich upstream; 6 chronologically novel within the project - zero overlap with earlier AuxPoW chain CSVs; the ninth, BTC h=665,005, surfaced in the June 2026 refresh classification)**.

The other novelty BTCV brings to the catalogue: it's the second visual-similarity chain-ID-collision-class member alongside Emercoin (`0x0666` / 1638 dec vs `0x029A` / 666 dec). The cataloguing-hygiene rule - record chain IDs in both decimal and hex with explicit labels (e.g. `1638 (0x0666)`) - was prompted by BTCV's entry.

## 1. Chain data

**Source.** No live node. Trezor Blockbook backend at `https://btcvexplorer.com/api/rawblock/<hash>` returns the raw serialised block hex including the Namecoin-byte-identical AuxPoW tail. Blockbook's default `/api/v2/tx-specific` and `/api/v2/block` endpoints decode the BTCV-side block but discard the AuxPoW serialised data (Blockbook is a Bitcoin-pattern indexer that doesn't know about the post-header tail), so the working endpoint took some digging - `/api/rawblock` was the necessary path.

**Provenance.** Phase 2 extraction across 4 hosts with distinct egress IPs (four worker hosts) for IP diversity vs Cloudflare rate limiting. At 1 req/s/host × 2 calls per block (one `v2/block/{h}` for hash + one `rawblock/{hash}` for hex) the run completed in ~24h. Bitcoin Core on `<archival-host>` provided the BTC RPC for classification.

**Coverage.** AuxPoW commitments span BTCV heights **58,420 → 228,360** (mainnet launch 2020-11-17 → chain stall 2024-03-10) and BTC parent timestamps from late 2020 to early 2024. **169,939 unique BTCV heights extracted (99.99% of the 169,941 in-scope range)**, the only gap being h=123,472 and h=123,473 which legitimately solo-mined without an AuxPoW header (the chain permits this - those two blocks just satisfy BTCV's own PoW without a merge-mined parent).

**Holes.**

- **Pre-activation (h=1 → 58,419)**: out of scope. Mainnet launched 2020-11-17 with AuxPoW active from the genesis block; pre-58420 blocks are a BitcoinRoyale-lineage development era and don't carry AuxPoW. `src/policy/auxpow.h::FAKE_AUXPOW_PREFORK_BLOCKS` special-cases 4 specific pre-fork hashes that have the auxpow version flag set but no AuxPoW header attached - `IsFakeAuxpowPreforkBlock(hash)` excludes them from validation.
- **Post-tip (h=228,361+)**: chain hasn't produced blocks since 2024-03-10. The 2024-03 "mining decentralisation" press push (news.bitcoin.com) coincided with the v2.6.0 release on 2024-02-19 and the chain's own `StopDDMSHeight = 226566` consensus constant (DDMS mining disabled ~1,800 blocks before the final block at h=228,360) - strong evidence the chain died ~19 days after the v2.6.0 release rather than the explorer's backend silently stalling. The seed `seed.bitcoinvault.global:8333` accepts TCP but returns no p2p handshake within 5s, consistent with a sleepy/dormant node.
- **Two legitimate AuxPoW-less blocks** at h=123,472 and h=123,473 (solo-mined, no `auxpow` bit set in `nVersion`). The disk-full incident on worker-a mid-run also dropped 9 rows at h=128,488–128,496 - backfilled in a separate one-off run after the main extraction completed.
- **Historical schema**: the original classifier did not emit a
  `validation_status` column. The June 2026 refresh rewrote the committed input
  on the shared schema; all 9 rows carry `validation_status=VALID` and matching
  `expected_nbits`.

**Reference scripts.**

- `scripts/extract/extract_bitcoin_vault_auxpow.py:1` - stdlib-only urllib-based extractor (no third-party dependencies; the 3 NixOS VPSes don't have `requests` and root partitions are tight). BTC coinbase-output addresses are decoded via the shared `stale_blocks_analysis.bitcoin_binary.format_outputs_addr` helper (bech32 + base58check), not inlined in the extractor.
- `scripts/classify/classify_bitcoin_vault_stales.py:1` - BTC RPC batch classifier on <archival-host> (`requests`-based, same shape as `classify_syscoin_stales.py`).
- `scripts/extract/_btcv_extract_status.sh:1` - 4-host partition-map-aware status helper (the partition map was revised mid-run when worker-a hit 100% disk at h=128,495 and the remaining ~14k blocks were reassigned to worker-c as a second concurrent process).

## 2. Extraction → potential stales

**Method.** REST against Blockbook. For each BTCV block ≥ 58,420, `GET /api/v2/block/{h}` returns the block hash; `GET /api/rawblock/{hash}` returns the full serialised block hex. The hex is parsed with a Namecoin/BTCV AuxPoW-aware reader (`parse_btcv_block()` in the extractor - verified end-to-end in Phase 1 across 8 sampled blocks): pure-header (80 bytes), AuxPoW tail (`coinbaseTx | hashBlock=zero | vMerkleBranch | nIndex=0 | vChainMerkleBranch | nChainIndex | parentBlockHeader`), then the BTCV-side transaction vector.

**Phases.**

1. **Parse**: walk all BTCV blocks ≥ 58,420 via REST. Extract the parent BTC header (80 bytes), parent coinbase tx (scriptsig + decoded outputs), and BIP-34 height from the parent scriptsig.
2. **Self-target PoW filter**: keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. **Primary volume reduction: 167,364 of 169,939 (98.5%) of BTCV parent headers fail their encoded target.** This is not yet the Bitcoin contemporaneous-target check.
3. **Dedup**: 2,575 unique self-target-PoW-valid header hashes survive (0 duplicate hashes). Two accepted candidates are competing hashes at the same BTC height 661,031, committed ~15 s apart by BTCV h=62,019 and h=62,026. They are distinct events under the `(height, hash)` key, not a duplicated parent.
4. **BTC RPC classify** (`classify_bitcoin_vault_stales.py`): batch
   `bitcoin-cli getblockheader`. The original run classified 2,567 canonical,
   8 stale-labelled candidates, and 0 unknown rows from its 2,575 self-target-PoW-valid headers. The
   June 2026 refresh added the already-upstream stale at BTC height 665,005 to
   the committed accepted set, which now contains 9 rows.

**Counts in the private full classifier output**
(`bitcoin-vault_stale_blocks.csv`; the June 2026 refresh lifted the stale
bucket to 9, from 8 in the original run):

| `classification` | Count |
|---|---:|
| `unknown` | 0 |
| `stale` | 9 |
| **Total** | **9** |

Zero unknowns is unusual. Most pipeline chains have orders-of-magnitude more unknowns than accepted direct-stale candidates. A historical private attribution pass associated the surviving 2020-11 to 2021-09 rows with KnoxPool, BTCPool, and TogetherPool, and later low-target submissions with Binance Pool. The public recovery pipeline does not reproduce those pool labels. It establishes only that no self-target-PoW-valid unknown rows were observed in this extraction.

**Chain-specific quirks.**

- **REST extraction (no node)**. First chain in the project recovered without running a synced full node. Made possible by Blockbook's `/api/rawblock` endpoint surfacing the post-header AuxPoW tail in raw hex form. The Phase 1 brief originally tried `/api/v2/tx-specific` and concluded a node sync would be required; the workable path turned out to be the explicit raw-block endpoint. Approach is portable to any AuxPoW chain whose only available data source is a Blockbook-style indexer.
- **Refactored AuxPoW class layout (Namecoin-byte-identical wire format)**. BTCV separates the `CAuxPow` validator (in `src/auxpow.{h,cpp}`) from the `CAuxBlockHeader` data carrier (in `src/primitives/block.h`). The Namecoin reference inlines both in `CAuxPow`. The wire format is byte-identical (`CAuxBlockHeader::SerializationOp` emits the same fields in the same order as `CAuxPow::SerializationOp`), so the extractor's parser handles BTCV blocks with no chain-specific branching beyond field naming.
- **`fStrictChainId=true`, hard activation at h=58420**. No version-bit-driven implicit activation gate (unlike Jincoin) and no `nLegacyBlocksBefore` constant. Every block ≥ 58,420 has chain ID `0x0666` in the high 16 bits of `nVersion`; blocks below 58,420 don't carry AuxPoW (except 4 known pre-fork blocks special-cased via `IsFakeAuxpowPreforkBlock`).
- **Visual-similarity chain-ID-collision-class with Emercoin**. BTCV chain ID `0x0666` (1638 dec); Emercoin chain ID `666` dec (`0x029A` hex). Different by an order of magnitude. Anywhere either chain ID is recorded - catalogue rows, cross-reference tables, pipeline constants - the convention is to write both forms with explicit `dec`/`hex` labels.
- **Historical pool-label shift**. A private attribution pass associated the early surviving rows with KnoxPool, BTCPool, and TogetherPool and later low-target submissions with Binance Pool. The public pipeline does not recompute this attribution. After the accepted candidate at BTC height 699,616 / BTCV height 100,670, the extraction covers roughly 128,000 more AuxPoW blocks without another accepted direct-stale candidate.
- **`coinbase_outputs` semicolon-joined addresses**: the loader transforms the `addr:value|addr:value|OP_RETURN:value` format emitted by the extractor's shared `bitcoin_binary` bech32+base58 decoders into the Syscoin-pattern `addr;addr` format. `nonstandard:<hex>` entries (very rare) are dropped alongside `OP_RETURN`.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_bitcoin_vault_stales()` in `stale_blocks.py`):

```python
classification == "stale"
```

The June 2026 refresh re-emitted this CSV on the shared 12-column layout with a persisted `validation_status`; all 9 entries are `VALID`. (The original 10-column file without the verdict columns is preserved in the archive backup.)

**Post-filter count: 9 accepted direct-stale header candidates.**

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py bitcoin-vault`. Per-stale row-level breakdown at `results/per-chain-novelty/bitcoin-vault.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 3 | 33.3 % |
| novel vs upstream | 6 | 66.7 % |

The 3 already-in-upstream candidates are at BTC heights 665,005, 671,759, and 693,118; height 665,005 is the row integrated from the June 2026 refresh. BTCV provides independent AuxPoW-side evidence for candidates already present in the upstream observation record.

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

| Split | Count |
|---|---:|
| also in upstream | 3 |
| also in earlier-born chain | 0 |
| **novel at this position** | **6** |

BTCV is 23rd chronologically. The earlier-born integrated chains with validated stale inventories contribute zero overlap with BTCV's accepted set. The 6 chronologically novel candidates are hashes that neither the upstream catalogue nor an earlier-born integrated chain had surfaced. Later-born Electric Cash independently re-observes three of the nine (BTC 688,349 / 693,118 / 699,616) with byte-identical parent headers via its own AuxPoW path; under earlier-born precedence BTCV keeps the first claim (see `docs/chains/elcash.md`). The public data does not support a cross-chain miner-population comparison.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

### Accepted-candidate summary

The pool tags below are retained historical labels derived from coinbase
evidence. The current public recovery pipeline does not recompute them.

| BTC h | BTCV h | Date (UTC) | Pool tag (scriptsig) | Notes |
|---:|---:|:---|:---|:---|
| 657,561 | 58,585 | 2020-11-18 18:41 | KnoxPool | Activation-era pool, first month of BTCV mainnet |
| 661,031 | 62,019 | 2020-12-12 12:31 | BTCPool | Two competing BTCPool stale hashes at BTC h=661,031 (this row + h=62,026), ~15 s apart - distinct stale events, not one block |
| 661,031 | 62,026 | 2020-12-12 12:32 | BTCPool | Second competing stale hash at BTC h=661,031 (see h=62,019) |
| 665,005 | 65,742 | 2021-01-07 18:41 | BTCPool | Integrated from the June 2026 refresh; already catalogued upstream |
| 666,931 | 67,614 | 2021-01-20 18:41 | BTCPool | |
| 671,759 | 72,383 | 2021-02-23 00:07 | TogetherPool | |
| 688,349 | 89,307 | 2021-06-21 04:31 | (unidentified) | Pool tag not extractable from scriptsig |
| 693,118 | 94,702 | 2021-07-28 19:37 | (unidentified) | Pool tag not extractable from scriptsig |
| 699,616 | 100,670 | 2021-09-08 10:50 | binance/fr714r | Final accepted direct-stale candidate in the extraction |

Historical label distribution across the 9 accepted candidates: KnoxPool 1, BTCPool 4, TogetherPool 1, Binance Pool 1, and 2 unidentified. No accepted candidate appears after BTC height 699,616 in the extraction.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/bitcoin-vault_validated_stales.csv` - 9 accepted direct-stale
  candidates (committed; the loader's refreshed input).
- `scripts/extract/extract_bitcoin_vault_auxpow.py` - REST-driven extractor.
- `scripts/classify/classify_bitcoin_vault_stales.py` - RPC-driven classifier.
- `scripts/extract/_btcv_extract_status.sh` - 4-host partition status helper (kept for reproducibility; see header notes for the mid-run worker-a disk-full reassignment).

**Private archive artifacts.**

- `bitcoin-vault_stale_blocks.csv` is the refreshed stale bucket of the split
  classifier output (9 stale; 0 unknown; the original run had 8, before the
  June 2026 refresh added BTC height 665,005).
- `bitcoin-vault_auxpow_raw.csv` - full Phase 2.1 extract (169,939 rows × 93.7 MB; useful for pool-attribution and weak-share-pattern research).
- `bitcoin-vault_btc_valid.csv` - 2,575 self-target-PoW-valid headers (private intermediate classifier output; useful for canonical-versus-stale audit).

**External references.**

- `https://btcvexplorer.com/` (Trezor Blockbook) - the only practical data source; `/api/rawblock/<hash>` is the workable endpoint, not `/api/v2/tx-specific`.
- `https://github.com/bitcoinvault/bitcoinvault` v2.6.0 - source. `src/primitives/block.h::CAuxBlockHeader` is the AuxPoW data structure; `src/auxpow.{h,cpp}::CAuxPow` is the validator; `src/policy/auxpow.h::FAKE_AUXPOW_PREFORK_BLOCKS` is the 4-hash pre-fork exemption set.
- BTCV merge-mining explainer (Medium): https://medium.com/bitcoin-vault-btcv/btcv-merged-mining-explained-5b61479eba85
- March 2024 BTC.com-distributed press: https://news.bitcoin.com/bitcoin-vault-btcv-proudly-announces-mining-decentralization-with-bitcoin-btc-merge-mining-opportunity/ - the "decentralisation" push that coincided with the chain's death.

**Remaining work.**

- **Weak-share pattern research**. The 167,364 weak-share parents are the largest source of "pool aggregation policy" data the project has. Worth investigating in detail which Binance-aggregated chains share BTCV's merkle root slots (`vChainMerkleBranch_len` of 1–4) and how that population evolves through 2021–2024. Could feed back into RSK / Hathor analyses where similar Binance aggregation is in play.
- **Future attribution for the 2 historically unidentified stales** (h=688,349 and h=693,118). The scriptSig did not yield a printable pool tag. Revisit them through coinbase-output address matching when the pool-attribution phase is designed. Electric Cash's validated set carries the same two parent headers with identical scriptSigs (shared merge-mining nonce `7296cd10`), so its observation confirms multi-child aggregation but adds no new coinbase evidence.
- **Tip-stall confirmation**. The chain has not produced a new block since 2024-03-10 per Blockbook. Worth a one-off probe in 6 months to confirm the chain is genuinely dead (not just explorer-backend-stalled). If new blocks appear, extend the extract range and re-run; otherwise leave the BTCV row as Dormant in the catalogue and close out the chain.
