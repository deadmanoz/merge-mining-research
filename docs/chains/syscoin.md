# Syscoin

| Field | Value |
|---|---|
| Ticker | SYS |
| AuxPoW activation | 2019-06-03 (SYS chain-2 genesis, BTC height ~579,000). AuxPoW permitted from SYS 1 (`nAuxpowStartHeight = 1`); first AuxPoW block SYS 1,973 |
| Network status | Active (modern Bitcoin Core fork, v5.0.5, July 2025) |
| Chronological position | 21 of 26 (after namecoin, geistgeld, i0coin, ixcoin, coiledcoin, devcoin, groupcoin, huntercoin, unobtanium, crown, myriadcoin, SixEleven, argentum, terracoin, emercoin, rsk, doichain, bitmark, xaya, elastos) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; chain 2 is a 2019 launch, after the paper's mid-2018 data cutoff) |
| AuxPoW chain ID | 16 (with legacy 4096), strict (`fStrictChainId=true`) |
| Block time | 60 s pre-NEVM (Jun 2019 → Dec 2021), 150 s post-NEVM (Dec 2021 → present). 10× then 4× per BTC interval. |
| Source tag (in code) | `syscoin` |
| Loader | `load_syscoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/syscoin_validated_stales.csv` |

This doc covers the **current Syscoin chain (chain 2)** - the fresh-genesis 2019-06-03 launch, not the retired Syscoin 2.x/3.x chain that ran May 2016 → Jun 2019 (SHA-256d Bitcoin-merge-mined from launch under the legacy chain ID 4096, separate genesis). The Scrypt era belongs to a third, still-earlier chain: the original Syscoin 1.0 launched Aug 2014 on a Litecoin lineage and was retired at the 2.0 swap. The old 2016-2019 chain is in scope for the merge-mining catalogue but is **not extracted by this project**; its `chainz.cryptoid.info/sys-old/` archive is dead ("hosting expired", already so when the 2026-05 feasibility probe checked), and no other public source of chain-1 block data has been located (see **Remaining work** below).

Syscoin chain 2 is one of the most direct extractions in scope: a modern Bitcoin Core fork that returns a fully decoded `auxpow` JSON object from `getblock <hash> 1`. No raw-hex parsing, no binary CAuxPow deserialisation. The 98 committed validated stales are produced from straightforward JSON field access after stale-classified rows are filtered by canonical-at-height `nBits` validation.

## 1. Chain data

**Source.** Local `syscoind` v5.0.5 node on `<archival-host>`, the official Linux x86_64 release binary. Modern Bitcoin Core lineage - builds and runs cleanly with no patches.

**Provenance.** Chain data under `<chain-data-dir>` on `<archival-host>` (config in `~/.syscoin/`). Standard `txindex=1` + RPC config. Default P2P 8369 / RPC 8370. Bitcoin Core on `<archival-host>` provided the BTC RPC for classification.

**Coverage.** Validated stales span BTC heights **585,083 → 944,852** (Jul 2019 → Apr 2026) and SYS heights **62,165 → 2,220,906**. The window starts ~6,000 BTC blocks after Syscoin chain 2's genesis (Jun 2019, BTC ~579,000) and continues through to recent blocks.

**Holes.**

- **Solo-mined prefix (SYS 0 → 1,972)**: AuxPoW is permitted from SYS 1 (`nAuxpowStartHeight = 1`; genesis itself is a plain non-AuxPoW block), but the first AuxPoW block on the chain is SYS 1,973. Extraction starts there.
- **Old chain (chain 1)**: May 2016 → Jun 2019, BTC heights ~410,000 → ~579,000. Not extracted by this project. The blocker is data, not software - legacy 3.x binaries survive as Docker images, but no public source of chain-1 block data could be located (see **Remaining work** below).
- **Validation status is explicit**: the classifier now emits `validation_status` and `expected_nbits` for Syscoin. Coverage starts post-BCH (Aug 2017) and post-BSV (Nov 2018) - both fork chains use different DAAs from BTC at this height, so contamination is visible as `nBits` mismatch. Only rows marked `VALID` are committed.
- **Outside Stifter cutoff**: Syscoin chain 2 didn't exist at the paper's mid-2018 data cutoff, so it post-dates the prior-art baseline entirely. Neither Syscoin chain was among the seven Bitcoin-parent chains the paper sampled; the retired chain 1 is in the merge-mining catalogue but is not extracted here.

**Reference scripts.**

- `scripts/extract/extract_syscoin_auxpow.py:1` - JSON-driven extractor (`getblock <hash> 1` → `auxpow.tx`, `auxpow.parentblock`).
- `scripts/classify/classify_syscoin_stales.py:1` - BTC RPC batch classifier.

## 2. Extraction → potential stales

**Method.** RPC against the local syscoind. For each SYS block ≥ 1,973 (the first AuxPoW block), fetch `getblock <hash> 1` and read the decoded `auxpow` object - parent block header hex (`auxpow.parentblock`, 80 bytes), decoded coinbase transaction (`auxpow.tx.vin[0].coinbase` scriptsig + `auxpow.tx.vout` outputs), and Merkle branches. No binary parsing required.

**Phases.**

1. **Parse**: walk all SYS blocks ≥ 1,973, read `auxpow.parentblock` (80 bytes) + `auxpow.tx` (decoded coinbase).
2. **Self-target PoW filter** (shared `run_classifier` Phase 1 in `btc_classify.py`, not the extractor): keep only headers where `SHA256d(header) ≤ target(nBits)` using the target encoded in that header. Bitcoin's contemporaneous target is checked later for stale-labelled candidates.
3. **Dedup**: do *not* dedup at extraction time - with 10× (pre-NEVM) or 4× (post-NEVM) sampling density, consecutive SYS blocks reference different parent headers within the same BTC interval. Downstream cross-source publication views deduplicate only exact `(height, hash)` identities.
4. **BTC RPC classify** (`classify_syscoin_stales.py`): batch `bitcoin-cli getblockheader`. Hit → `canonical`. Miss → look up `prev_hash`. Prev canonical → `stale`. Neither → `unknown`.

**Counts.** The 2026-04-17 extraction walked 2,220,963 AuxPoW blocks (SYS 1,973 → tip) and yielded **116,994 unique self-target-PoW-valid parent headers**. The source-driven 2026-08-03 reclassification materialized the complete current split across `syscoin_canonical_blocks.csv`, `syscoin_stale_blocks.csv`, and `syscoin_unknown_blocks.csv`:

| `classification` | Count |
|---|---:|
| `canonical` | 98,613 |
| `unknown` | 18,282 |
| `stale` | 99 raw; 98 committed after `nBits` validation |
| **Total** | **116,994** |

The one rejected stale candidate is BTC 717,696 (SYS 1,336,057, Jan 2022) - the first block of difficulty epoch 356, whose header carries the previous epoch's target (`nBits` `170b98ab` vs expected `170b8c8b`). Emercoin's set rejects a BTC 717,696 candidate with the same `nBits` mismatch (emercoin.md §3). The 18,282-row unknown tail is mid-sized for the integrated set - larger than Namecoin's 7,843, well below Devcoin's 75,141 or Argentum's 634,277. Syscoin's recovery window (2019-06 onward) post-dates the Namecoin-family era discussed in Namecoin's [private research boundary](namecoin.md#private-research-boundary).

**Chain-specific quirks.**

- **JSON `auxpow` decoded by RPC**: this is Syscoin's distinguishing technical advantage. Bitcoin Core lineage + Daniel Kraft's AuxPoW + a maintained codebase means `AuxpowToJSON()` works as designed. Same shape as Terracoin (Dash-derived); Emercoin's structured-JSON path is a field-decoded variant. Elastos, by contrast, returns the whole AuxPoW struct as a single hex blob for the client to deserialise, and Devcoin's Bitcoin Core 22.0 fork never exposed decoded AuxPoW at all - the JSON path exists only where a fork kept namecoin-core's `AuxpowToJSON` (present since namecoin's Bitcoin Core 0.13-era rebase) wired up.
- **Two block-time eras**: pre-NEVM (60s) and post-NEVM (150s) at SYS 1,317,500 (Dec 2021). Extraction is unaffected - both eras carry AuxPoW with the same payload structure. Worth noting for any downstream temporal analysis that wants to normalise per-BTC-interval observation density.
- **Syscoin 5.0 "Nexus" AuxPoW tag (SYS 2,010,345+)**: post-Nexus consensus requires the *Bitcoin parent* coinbase to carry an `OP_RETURN` output tagging the Syscoin ancestor blockhash + height (`'sys'` magic, for BitVM2 bridge coordination; enforced in `validation.cpp`, reject codes `missing-syscoin-tag`/`bad-auxpow-tag`). The CAuxPow structure itself is unchanged - extraction logic is unaffected - but recovered post-Nexus parent coinbases carry the extra `OP_RETURN` output, which the loader's `coinbase_outputs` transform drops (below). The committed set includes post-Nexus rows (SYS max 2,197,798).
- **`coinbase_outputs` semicolon-joined addresses**: the loader transforms `addr:value|addr:value|OP_RETURN:value` to `addr;addr` (drops `OP_RETURN` entries), preserving the established loader schema for later attribution research. Same pattern as Devcoin and Terracoin.

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_syscoin_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

The exact status gate is unconditional and fails closed: only `VALID` and
`VALID (post-BCH, difficulty matches BTC)` load. The shared loader also
applies the exact-key error-blocks exclusion gate. No accepted Syscoin loader
row overlaps the gate. 98 entries pass.

**Post-filter count: 98 accepted direct-stale header candidates.**

**Derived strict/weak relevance: 1 strict, 0 weak observation.** This is an
unknown row admitted to the separate relevance axis, not a direct-stale
promotion. It remains `classification=unknown` in the monitor evidence.

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py syscoin`. Per-stale row-level breakdown at `results/per-chain-novelty/syscoin.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count | % |
|---|---:|---:|
| also in upstream | 83 | 84.7 % |
| novel vs upstream | 15 | 15.3 % |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

Syscoin is 21st chronologically. Earlier-born integrated chains now include Namecoin-family chains, Crown, Myriadcoin, SixEleven, Argentum, Terracoin, Emercoin, RSK, Bitmark, Xaya, and Elastos. Breakdown:

| Split | Count |
|---|---:|
| also in upstream | 83 |
| also in earlier-born chain (`namecoin`: 67, `emercoin`: 14, `rsk`: 12, `elastos`: 1, `xaya`: 1 - first-claim distribution) | 95 |
| **novel at this position** | **1** |

Two rows are upstream-only (in upstream but first-claimed by no earlier-born chain), completing the 98. Namecoin, Emercoin, RSK, Elastos, and Xaya contribute to the earlier-chain attribution. The Dec-2011 / Jan-2012 Namecoin-family cohort after Namecoin (i0coin, ixcoin, coiledcoin, devcoin, groupcoin) and the mid-2010s singletons (unobtanium, myriadcoin, argentum, terracoin) have zero first-claim overlap with Syscoin's stale set. Only **1 stale is novel** at Syscoin's position:

- **BTC 751,763** (`0000000000000000000993e1c4ab09844605bbec0b810e70beb0c364312bce86`, Aug 2022) - not in upstream `bitcoin-data/stale-blocks`, and not in any chronologically-earlier integrated chain's validated set.

> **Differs from the "16 novel" figure in earlier project notes.** The 16-novel count was a multi-chain cross-reference at extraction time, when elastos and rsk weren't yet integrated. Under chronological precedence, the expanded earlier-born set now claims nearly all of the original candidate novel set, leaving 1 chronologically-novel stale for Syscoin. The recovery-era "15 F2Pool, 1 ViaBTC" pool split of the original 16-novel set still describes a real signal but is now distributed differently across attribution columns.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a simplifying convention for reproducible attribution, **not** a claim about which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/syscoin_validated_stales.csv` - 98 validated stales (committed; the loader's input).
- `results/per-chain-novelty/syscoin.csv` - per-stale `(btc_height, btc_hash, in_upstream, first_seen_chain)` table.

**Private archive artifacts.**

- Split inventories: `syscoin_canonical_blocks.csv` (98,613 canonical), `syscoin_stale_blocks.csv` (99 stale-classified), and `syscoin_unknown_blocks.csv` (18,282 unknown) - 116,994 rows total (§2).

**External references.**

- `docs/auxpow-recovery.md` - cross-chain summary table (Syscoin row at chronological position 21).
- `chainz.cryptoid.info/sys-old/` - defunct archive of Syscoin chain 1 (May 2016 → Jun 2019); dead as of 2026-07 ("hosting expired"). The current-chain page `chainz.cryptoid.info/sys/` remains live.

**Remaining work.**

- **Old chain (Syscoin 2.x/3.x) recovery decision** - closed. Phase A feasibility + value investigation concluded "not worth it" on the value side (estimated novel yield in BTC 410k–580k window is < 5%; upstream + namecoin + unobtanium alone cover 96.2% of the 391-event hash-keyed union), and found chain-1 block data unrecoverable through any public source in any case (legacy 3.x binaries survive as Docker images, so software was never the blocker).
- **Unknown-chain origin (H1 vs H2)**. Syscoin's 18,282 unknowns are a moderate-sized sample. Because Syscoin chain 2 starts in 2019, most of the 31 cross-chain-confirmed Namecoin unknown roots are too early to appear in Syscoin's unknown set. A future public analysis could test whether that substrate is era-bound; no public reproducer exists yet.
- **nBits validation against BTC mainchain difficulty schedule** - closed. The classifier now emits `validation_status` and `expected_nbits`; only rows marked `VALID` are committed.
- **Future F2Pool concentration check**: earlier notes recorded "15 F2Pool, 1 ViaBTC" for the original 16-novel extraction-time set. Under chronological precedence the novel count is now 1. In the later attribution phase, recompute labels against `results/per-chain-novelty/syscoin.csv` and check the remaining chronologically novel hash (BTC 751,763).

## 5. Integration history

- **2026-04-16/17** - original recovery (predecessor repo): syscoind v5.0.5 release binary installed on the archival host; extraction walked 2,220,963 AuxPoW blocks in ~20 minutes (~1,830 blocks/s); classification yielded 116,994 unique PoW-valid parents → 79 stale + 18,281 unknown (canonical rows not persisted). Cross-reference at the time: 16 novel across all prior recoveries (15 F2Pool, 1 ViaBTC by coinbase attribution).
- **2026-05-14** - chain doc written; Syscoin chain-1 (old chain) Phase A feasibility opened and closed the same day (the **Remaining work** decision records novel yield bounded < 5%, 96.2% of the 391-event window union already covered, and chain-1 data publicly unrecoverable).
- **2026-05-20** - nBits-validation schema regeneration: 79 → 78 (BTC 717,696 rejected - §2); `validation_status`/`expected_nbits` columns added; novelty CSV regenerated.
- **2026-06-24** - full-evidence export (18,360 non-canonical rows, split unchanged).
- **2026-07-17** - public release: novelty recomputed at the bumped upstream pin (isolated view 63 in upstream / 15 novel).
- **2026-07-18** - canonical backfill: the preserved raw extraction re-classified against a live Bitcoin Core node, producing the 98,634-row canonical split (Syscoin was still on the canonical needs-infrastructure list until this run); stale/unknown counts unchanged.
- **2026-08-03** - source-driven reclassification against Bitcoin Core corrected 20 side-chain headers from canonical to valid direct stale and one from canonical to an accepted stale descendant. The complete split is now 98,613 canonical, 99 stale candidates (98 accepted), and 18,282 unknown.
