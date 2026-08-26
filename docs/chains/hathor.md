# Hathor

| Field | Value |
|---|---|
| Ticker | HTR |
| Earliest confirmed merge-mining evidence | Hathor height 60,275 on 2020-01-24 is `version == 3`; BTC-linked work is independently confirmed by height 100,000 on 2020-02-07. The exact first merge-mined height is not established. Mainnet launched 2020-01-03. |
| Network status | Active. Joining the mainnet P2P network requires allowlisting; this recovery used the documented public REST API. |
| Chronological position | 22 of 26 (after Syscoin, before Bitcoin Vault) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; Hathor mainnet and merge mining post-date the paper's mid-2018 data cutoff) |
| Block time | 30 s (about 20 Hathor blocks per Bitcoin target interval) |
| Multi-parent-chain | **Yes**: the proof can bind to a compatible Bitcoin-derived SHA-256d parent. The production classifier does not identify the parent chains of its unresolved rows. |
| Source tag (in code) | `hathor` |
| Loader | `load_hathor_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/hathor_validated_stales.csv` (6 accepted direct-stale rows) |
| Accepted direct-stale candidate count | **6** (BTC heights 710,969 / 751,763 / 776,941 / 843,741 / 883,674 / 938,873) |

Hathor's merge-mining proof differs from the Namecoin-family `CAuxPow` format. Three properties require a dedicated extraction path:

1. **Split-header proof format** ([Hathor RFC 0006](https://github.com/HathorNetwork/rfcs/blob/492c4fd6b9f1c4ff4e8058c9f70d94184d7cd40d/text/0006-merged-mining-with-bitcoin.md)): the first 36 and last 12 bytes of the 80-byte parent header are stored directly; the 32-byte merkle root has to be **reconstructed** from the coinbase transaction and merkle path. The RFC and API call this field `aux_pow`, but it is not Namecoin-family `CAuxPow`.
2. **Coinbase commitment `"Hath" || aux_block_hash`**: RFC 0006 does not fix the commitment to the scriptSig. In the retained 3,612-row predecessor-linked inventory, 3,601 commitments are in `OP_RETURN` outputs and 11 are in scriptSig; all six accepted candidates use an output.
3. **Compatible parent formats**: the proof can carry a Bitcoin-style 80-byte SHA-256d parent header. The production classifier establishes Bitcoin linkage only when the predecessor resolves on Bitcoin's active chain; it does not identify the alternative parents behind RPC misses.

## 1. Chain data

**Source.** Public REST API at `https://node1.mainnet.hathor.network/v1a` (and `https://node2.mainnet.hathor.network/v1a` as fallback). Hathor's [mainnet configuration](https://github.com/HathorNetwork/hathor-core/blob/7c9c68ae00bd4b7e9876fe6da8b09a8761710180/hathor/conf/mainnet.py#L11-L17) enables a peer allowlist. The software can be run locally, but joining the public mainnet peer graph requires authorization, so this recovery used the public API.

**Provenance.** No local node. Extraction and classification ran on a private archival host; only the compact validated output is committed:

- `data/validated-stales/hathor_validated_stales.csv` - committed; 6 stale rows, standard schema.
- `data/hathor_stale_blocks.csv` - full Phase B classifier output (3,612 BTC-parent rows: 3,606 canonical + 6 stale). Gitignored as a large private report (matches the `data/*_stale_blocks.csv` convention).
- `data/hathor_error_blocks.csv` - Phase C's error-block peer of the Phase B input (the shared `_stale_blocks` → `_error_blocks` derivation), carrying the standard schema plus `rules_violated`. For the recovered range it will be header-only: all 6 accepted candidates are `VALID`, so no rejected row's bytes prove a consensus rule broken.
- `data/hathor_unknown_blocks.csv` - Phase C's unknown peer of the same input, for rejected rows that are not direct stales at all (an unplaceable predecessor, or a difficulty that is not Bitcoin's at that height). Also header-only for the recovered range.
- The 5.57M-row post-million raw `aux_pow` CSV, its consolidated funds+graph
  supplement (~2 GB), and the private pre-million ledger and payload estate are
  too large for the repo and remain on the archival host.

Hathor-specific repo artifacts:

- `scripts/extract/extract_hathor_auxpow.py` - REST-API extractor; saves the raw `aux_pow` blob untouched. Resumable.
- `scripts/extract/hathor_metadata_ledger.py` - historical pre-million
  migration worker. A frozen manifest partitions the range and repeats its
  declared global bounds in every shard row, so losing a terminal shard cannot
  silently shorten the run contract. Legacy manifests require explicit
  `--start` and `--end` assertions and are never rewritten in place. Each worker
  records one terminal metadata outcome for every assigned height before any
  payload acquisition. Completion audits reject unresolved outcomes; selected
  failures can be re-driven into a new no-clobber, ordered ledger without
  mutating the source. A version-3 outcome resolves only with a canonical
  lowercase 64-character hex transaction ID, while truncated response bodies
  remain retryable. Completion also requires every ready transaction ID to map
  to exactly one height. New manifest, ledger, and repair directory entries are
  synced after their files become durable.
- `scripts/extract/extract_hathor_payloads_from_ledger.py` - historical
  ledger-driven migration worker. Each transaction request writes one sealed
  source row containing `aux_pow`, `raw`, and locally derived funds+graph
  bytes. New sealed-v2 rows also retain the serving endpoint, HTTP status, and
  total attempt count, and successful gap recovery leaves the primary CSV in
  deterministic height order. Payload processing rejects resolved metadata
  rows whose recorded status is not 2xx, whitespace-bearing payload hex, and
  any artifact paths that alias one another. A successful response must echo
  the requested transaction ID, use exact integer version 3, and carry an exact
  non-negative integer timestamp. A blank fallback URL disables fallback, and
  newly created evidence directory entries are synced after their headers. The
  completed seven-column sealed-v1 estate remains readable and byte-immutable;
  it cannot be mixed with new rows because its missing request provenance cannot
  be reconstructed honestly. These two workers preserve acquisition provenance;
  they are not the future supported acquisition interface.
- `scripts/prep/probe_hathor_btc_signal.py` - historical stratified-sample feasibility probe. Its parent mix is sample-specific and is not used for production classification.
- `scripts/prep/verify_hathor_extraction.py` - early reconstruction sanity-check (note: validates `prev_hash` only - see §2).
- The historical pool-population pre-flight audit is retained privately; it is
  not reproduced by a public script in this release.
- `scripts/prep/supplement_hathor_funds_graph.py` (with a NixOS-compatible urllib variant archived at `scripts/_archive/supplement_hathor_funds_graph_urllib.py`) - supplement fetchers for the funds+graph bytes needed by RFC 0006 header reconstruction.
- `scripts/prep/backfill_hathor_gaps.py` - one-shot gap-fill for raw + supplement extraction holes.
- `scripts/classify/classify_hathor_stales.py` - Phase A: header reconstruction + self-target PoW filter + BTC-prevhash RPC lookup.
- `scripts/classify/classify_hathor_phase_b.py` - Phase B: canonical/stale classification + nBits validation gate.
- `scripts/classify/classify_hathor_phase_c.py` - Phase C: coinbase parse + BIP34 cross-check + standard-schema output + the error-block and unknown peers.

**Coverage.** The presently committed classification starts at Hathor height
1,000,000 on 2020-12-18 and runs to roughly 6,569,000, yielding 5,569,557
`version == 3` rows. A later private migration surveyed heights 0 through
999,999 with one terminal ledger row per height and retained 938,732
`version == 3` payload rows. The pre-million classification is not reflected
in the committed counts below. The retained 3,606 canonical rows span Hathor
heights 1,047,018 to 6,567,450 and Bitcoin heights 664,341 to 949,982. The six
accepted candidates span Bitcoin heights 710,969 to 938,873.

**Holes.**

- **Early merge-mining classification not yet integrated**: merge-mined
  `version == 3` blocks are observed from at least height 60,275. The private
  migration acquired heights through 999,999, but the committed classifier
  outputs and counts in this document still cover the post-million scope.
- **Unknown parent-linkage rows**: 143,604 self-target-PoW-valid headers have a `prev_hash` that does not resolve on Bitcoin's active chain and are excluded from the direct-stale path. This is 97.55% of the 147,216 self-target-valid rows. An RPC miss does not identify BCH, BSV, DigiByte, or any other parent.
- **Extraction gaps**: roughly 822 raw-extraction holes and 12,631 supplement holes were recovered by `backfill_hathor_gaps.py`. The historical private audit records 259 residual missing-supplement rows and one reconstruction failure. The original audit reported no self-target passes among the 259 rows, but the required source rows are not in the local publication mirror; the single reconstruction failure remains unresolved.

## 2. Extraction → potential stales

**Method.** REST API against `node1.mainnet.hathor.network/v1a`, two requests per Hathor block (`block_at_height` then `transaction`). For each `version == 3` block the `aux_pow` field carries the RFC 0006 custom proof layout:

| Bytes | Field | Contents |
|---|---|---|
| 36 | `bitcoin_header_head` | BTC header offsets 0–35 (version + prevhash) |
| varint | `coinbase_tx_head` length | |
| ≥ 47 | `coinbase_tx_head` | BTC coinbase up to just before the embedded AuxPoW hash |
| varint | `coinbase_tx_tail` length | |
| ≥ 18 | `coinbase_tx_tail` | BTC coinbase from after the embedded AuxPoW hash to end |
| varint | `merkle_path` count | |
| 32 × N | `merkle_path` | sibling hashes (coinbase → merkle root) |
| 12 | `bitcoin_header_tail` | BTC header offsets 68–79 (nTime + nBits + nNonce) |

**Header reconstruction (the critical step):**

```python
aux_digest     = SHA256d(SHA256(block_funds) || SHA256(block_graph))
aux_block_hash = reverse(aux_digest)                # display order in coinbase
full_coinbase  = coinbase_tx_head || aux_block_hash || coinbase_tx_tail
coinbase_txid  = SHA256d(full_coinbase)             # internal byte order
merkle_root    = fold(coinbase_txid, reverse_each(merkle_path))
btc_header     = bitcoin_header_head || merkle_root || bitcoin_header_tail
hathor_hash    = reverse(SHA256d(btc_header))       # display order
```

**Three byte-order corrections were required** vs. the first-draft
algorithm and `verify_hathor_extraction.py` - all confirmed against RFC 0006's
worked example and live data:

1. The value embedded between `cb_head` and `cb_tail` is `aux_block_hash`
   (hash of the *un-nonced* portion), **not** the full Hathor block hash.
2. `aux_block_hash` is embedded in display (byte-reversed) order.
3. Merkle path links are byte-reversed before each fold step.

The fix is verified by the identity `SHA256d(reconstructed_header)[::-1] ==
hathor_block_hash`. The historical private check recorded 50 of 50 sampled blocks with the fix and 0 of 50 without it.
`verify_hathor_extraction.py` never caught the bug because it validates only
the `prev_hash` (the first 36 bytes, which need no computation) and never the
merkle-derived middle 32 bytes.

**Funds+graph supplement.** Computing `aux_block_hash` needs the
`block_funds`+`block_graph` bytes, which the original extractor did not save.
`supplement_hathor_funds_graph.py` re-fetched them for every height (~5.57M
API calls, parallelised across 4 IPs).
The pre-million migration instead retains both `raw` and the derived
funds+graph bytes in one sealed source row, then builds the same supplement CSV
locally. A row is accepted only when its integrity digest and locally
re-derived funds+graph bytes match, so an interrupted or modified write is not
treated as acquired evidence.

**Phases (all complete).**

1. **Extract** - `extract_hathor_auxpow.py`: raw `aux_pow` blobs per `version == 3` block.
2. **Supplement** - `supplement_hathor_funds_graph.py`: funds+graph bytes for `aux_block_hash`.
3. **Phase A** - `classify_hathor_stales.py`: RFC 0006 reconstruction + self-target PoW filter (`SHA256d(header) ≤ target(nBits)`) + Bitcoin predecessor RPC lookup. Of 5,569,557 input rows, 5,422,081 fail their encoded target, 143,604 pass but lack canonical Bitcoin predecessor linkage, **3,612 pass and have canonical-predecessor linkage**, 259 lack the required supplement, and 1 fails reconstruction. These five categories reconcile to the input total.
4. **Phase B** - `classify_hathor_phase_b.py`: `getblockheader` on the reconstructed header → canonical / stale-labelled candidate. Adds an `nBits` validation gate (the reconstructed header's `nBits` must equal the canonical `nBits` at `parent_height + 1`). Result: 3,606 canonical, **6 stale-labelled candidates**, all 6 `validation_status = VALID` under the available-evidence profile. Phase B writes the shared verdict vocabulary (`VALID`, `REJECTED: <reason>`, `UNKNOWN: <reason>`); Phase C also accepts the pre-rename tokens archived Phase B intermediates still carry.
5. **Phase C** - `classify_hathor_phase_c.py`: parse the coinbase for scriptsig/outputs, BIP34 height cross-check (`BIP34 == parent_height + 1`), emit `data/validated-stales/hathor_validated_stales.csv` in the standard schema. All 6 pass the BIP34 cross-check. Rejected rows are not dropped silently: those whose bytes prove a consensus rule broken go to `data/hathor_error_blocks.csv` with the derived `rules_violated` (the committed retarget-epoch table is loaded, so an epoch-start candidate still carrying the previous epoch's bits becomes `nbits_retarget_not_applied` here rather than vanishing), those the rejection says are not direct stales at all go to `data/hathor_unknown_blocks.csv` as `classification=unknown`, and only the remainder (rejections resting on unusable or missing evidence) are dropped, counted in the run summary.

**Chain-specific quirks.**

- **DAG, not a pure chain**: Hathor blocks have 3 parents (1 block + 2 transactions). Only the block-parent matters for height-linked iteration.
- **Block version filter is essential**: `version == 0` blocks carry no `aux_pow`.
- **Python REST node, not Bitcoin Core**: higher API latency; extraction is wall-clock-bound, not CPU-bound.

## 3. Filtering → accepted direct-stale candidates

`load_hathor_stales()` in `stale_blocks.py` applies the shared fail-closed
loader contract:

```python
classification == "stale" and validation_status.startswith("VALID")
```

The loader uses source tag `hathor`. `CHAIN_SPECS` and
`CHAINS_BY_AUXPOW_ACTIVATION` register it in the shared public pipeline.

**Final yield: 6 accepted direct-stale header candidates** - BTC heights 710,969 · 751,763 · 776,941 ·
843,741 · 883,674 · 938,873. The accepted-candidate rate among the 3,612
self-target-valid, canonical-predecessor-linkage rows is 6 / 3,612 = 0.17%.
The unresolved 143,604-row population has not been classified into the
strict/weak relevance buckets, so no zero strict/weak result is claimed.

### Two novelty views

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**: 4 of 6 also in
upstream; 2 novel vs upstream (the bumped upstream pin includes this
project's merged contribution).

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier
chain**: **0 novel at this position**. All 6 are covered by earlier-born AuxPoW
chains: RSK 3, Namecoin 2, and Syscoin 1 under the first-claim convention.
A historical private attribution sample was F2Pool-dominated (84%) and near
RSK's labelled population, but the public pipeline does not reproduce that
result. The public finding is 6 cross-chain corroborations and no
chronologically novel accepted candidate.

> Novelty precedence rule: earlier-born chain has novelty precedence. This is a
> simplifying convention for reproducible attribution, **not** a claim about
> which chain literally observed each stale first in real-world block time.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/hathor_validated_stales.csv` - 6 validated stale rows, standard schema (`btc_height, btc_header_hash, btc_prev_hash, btc_time, btc_bits, coinbase_scriptsig_hex, coinbase_outputs, btc_header_hex, hathor_height, classification, validation_status, expected_nbits`).
- `results/per-chain-novelty/hathor.csv` - generated by `compute_chain_novelty.py hathor`.
- `scripts/classify/classify_hathor_stales.py`,
  `scripts/classify/classify_hathor_phase_b.py`, and
  `scripts/classify/classify_hathor_phase_c.py` - the three classifier phases.
- `scripts/prep/supplement_hathor_funds_graph.py` and
  `scripts/prep/backfill_hathor_gaps.py` - supporting tooling. The historical
  pool-population audit remains private.

**External references.**

- [Hathor RFC 0006, pinned revision](https://github.com/HathorNetwork/rfcs/blob/492c4fd6b9f1c4ff4e8058c9f70d94184d7cd40d/text/0006-merged-mining-with-bitcoin.md) - authoritative source for the split-header proof format. **Note:** the RFC's `base_hash` comment on line 297 is a typo; the worked example downstream produces the correct `coinbase_hash` only with the algorithm-derived value.
- [Hathor system specifications](https://docs.hathor.network/references/system-specs/) - mainnet launch, SHA-256d mining, and 30-second target interval.
- [Hathor public network endpoints](https://docs.hathor.network/references/networks/public/) - documented REST sources used by the extractor.
- Hathor API evidence at heights [60,274](https://node1.mainnet.hathor.network/v1a/block_at_height?height=60274), [60,275](https://node1.mainnet.hathor.network/v1a/block_at_height?height=60275), and [100,000](https://node1.mainnet.hathor.network/v1a/block_at_height?height=100000) - bounds the first observed `version == 3` transition and confirms merge-mined production before this survey's lower bound.
- `docs/auxpow-recovery.md` - cross-chain summary table.

## 5. Integration history

Hathor was integrated end to end following a four-item brief.

- **Item 1 - historical private pool audit.** Sampled 50 parent blocks and found
  an F2Pool-dominant (84%) label set near RSK's. This is not reproduced by the
  public recovery pipeline.
- **Item 2 - extraction.** ~5.57M `version == 3` blocks scraped from the public
  REST API.
- **Item 3 - classifier.** Three phases (A/B/C). The substantive work was the
  RFC 0006 reconstruction bug fix (§2) and the funds+graph supplement that the
  fix required.
- **Item 4 - integration.** `HATHOR_CSV` and its entries in `CHAIN_SPECS` and
  `CHAINS_BY_AUXPOW_ACTIVATION` (`config.py`); `load_hathor_stales()`
  (`stale_blocks.py`); per-source reporting (colour `#76B7B2`); and the
  `compute_chain_novelty.py` `LOADERS` map.

**Outcome.** 6 accepted direct-stale candidates, 0 net-novel. The integration's value is cross-chain
corroboration plus validation of the corrected RFC 0006 reconstruction
methodology. Without the fix, the classifier would have found none of these
candidates. A historical private attribution pass found an F2Pool-dominated,
RSK-overlapping miner population; the public pipeline does not reproduce that
attribution. Hathor contributes no chronologically novel accepted candidates.
