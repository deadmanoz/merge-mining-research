# Doichain

Doichain is a Namecoin-style SHA-256d AuxPoW chain. A pinned-source node and
its numbered block files were surveyed through the active-chain tip observed at
child height 430,684 on 2026-06-24. The survey found no accepted Bitcoin
direct-stale candidates and no strict or weak BTC orphans. This is a negative
result for the recovered window, not a claim about later Doichain history.

| Field | Value |
|---|---|
| Ticker | DOI |
| AuxPoW activation | Child height 1 |
| AuxPoW chain ID | Nominally 2; `fStrictChainId=false` |
| Source | `Doichain/doichain-core` at `7eb68ae902f8329c80dc38e464f80d8bda2ed514` |
| Observed child tip | 430,684, hash `f0d15b6a4b5c713e246061d188bd77a461d767f59c5f168700cfba2c8ddb5e42` |
| Observed node state | 16 connections and `initialblockdownload=false` on 2026-06-24 |
| Chronological position | 17 of 26 (after RSK; before Bitmark) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; Doichain launched in 2018 and was not sampled) |
| Source tag (in code) | `doichain` |
| Loader | `load_doichain_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/doichain_validated_stales.csv` (header only) |

## Provenance and consensus

The recovery used the source revision pinned by
[`node-infra/doichain/`](../../node-infra/doichain/). The same revision remained
the upstream repository's `master` head when checked on 2026-07-22, after the
repository was archived on 2026-07-07. The source checkout and recovered
datadir are retained privately. The public workspace retains 12 peer hints from
the run; these are a subset of the 16 connections observed at the survey tip
and may decay.

The pinned source establishes these mainnet constants:

- network magic `f8 b2 b2 ff`;
- P2P port 8338 and RPC port 8339;
- nominal AuxPoW chain ID 2;
- AuxPoW accepted from child height 1;
- `fStrictChainId=false`.

The non-strict rule is important. Doichain does not require an AuxPoW child
version to carry chain ID 2, and it does not use the nominal ID to establish
the parent chain's identity. The recovery must validate the extracted parent
header independently and classify it against Bitcoin Core. Doichain consensus
checks the parent hash against the child block's target; it does not establish
that the embedded parent `nBits` equals Bitcoin's expected target.

Primary source references:

- [`chainparams.cpp` at the pinned revision](https://github.com/Doichain/doichain-core/blob/7eb68ae902f8329c80dc38e464f80d8bda2ed514/src/chainparams.cpp#L97-L127)
  for the AuxPoW parameters, network magic, and P2P port;
- [`chainparamsbase.cpp` at the pinned revision](https://github.com/Doichain/doichain-core/blob/7eb68ae902f8329c80dc38e464f80d8bda2ed514/src/chainparamsbase.cpp#L39-L45)
  for the mainnet RPC port;
- [`validation.cpp` at the pinned revision](https://github.com/Doichain/doichain-core/blob/7eb68ae902f8329c80dc38e464f80d8bda2ed514/src/validation.cpp#L1157-L1200)
  for parent proof-of-work and AuxPoW validation;
- [`auxpow.cpp` at the pinned revision](https://github.com/Doichain/doichain-core/blob/7eb68ae902f8329c80dc38e464f80d8bda2ed514/src/auxpow.cpp#L39-L86)
  for the non-strict chain-ID and coinbase-commitment checks.

## Extraction and exact child identity

The completed pass scanned the recovered numbered block files with the generic
extractor's `--all-headers` mode:

```bash
python scripts/extract/extract_auxpow_from_blkdat.py \
  --chain doichain \
  --blocks-dir <chain-data-dir>/blocks \
  --all-headers \
  --output doichain_auxpow_full.csv
```

That scan read 430,685 block records, exactly the observed tip plus genesis, and
found 429,401 parseable AuxPoW commitments. The archived extractor recorded its
file-order sequence in the historical `child_height` field. Those values are
offset by one from Doichain consensus height: sequence 1 is genesis and
sequence 2 is child height 1. This does not affect any published row because
the accepted output is empty, but it must not be treated as exact child
provenance. The current extractor instead keeps `child_height` blank. A new run
must resolve each child hash through Doichain RPC before classification:

```bash
python scripts/prep/normalize_auxpow_child_heights.py \
  --chain doichain \
  --input doichain_auxpow_full.csv \
  --output doichain_auxpow_full.heights.csv \
  --rpc-conf <chain-data-dir>/doichain.conf
```

The normalizer checks the extracted hash byte order, AuxPoW flag, version,
timestamp, canonical confirmations, height, and `getblockhash(height)` result.
It deliberately does not require child chain ID 2 because the pinned mainnet
sets `fStrictChainId=false`.

`scripts/classify/classify_doichain_stales.py` normalizes the Doichain columns
and delegates to the shared Bitcoin classifier and publication gate. The
header-only
[`data/validated-stales/doichain_validated_stales.csv`](../../data/validated-stales/doichain_validated_stales.csv)
records the resulting zero accepted direct-stale candidates.

The header-only input still follows the shared fail-closed loader contract:

```python
classification == "stale" and validation_status.startswith("VALID")
```

No rows pass because the surveyed window produced no stale-labelled candidate
to validate.

## Parent-header characterization

The retained 2026-06-24 characterization reported the following populations:

| Measured population | Count |
|---|---:|
| AuxPoW commitments in the block-file scan | 429,401 |
| Parent rows whose compact-target exponent is `0x17` | 300,646 |
| Exponent-`0x17` rows building on canonical Bitcoin tips | 300,625 |
| Canonical-tip rows matching exact expected Bitcoin `nBits` and BIP34 height | 300,625 |
| Unique self-target-PoW-valid headers with another exponent | 50,621 |
| Exponent-`0x17` self-target-PoW-valid headers | 0 |
| Accepted direct-stale candidates | 0 |

The exponent label is intentional because `0x17` alone does not prove that the
full parent `nBits` value equals Bitcoin's expected target at that height. A
separate 2026-07-22 audit closed that gap for the 300,625 canonical-tip rows.
Against an unpruned Bitcoin Core 30.2 node at tip 959,096, every one matched the
exact expected full `nBits` and the BIP34 height implied by its previous block.
At 62 retarget-boundary observations, the audit used the canonical next block's
`nBits` rather than carrying forward the previous epoch's target. There were 0
`nBits` mismatches and 0 BIP34-height mismatches.

This supports Bitcoin-derived work-template merge mining in the surveyed
extract. It does not identify a particular pool, establish continuous mining,
measure a share of Bitcoin hashrate, or prove a causal explanation for the
zero-stale result.

The complete exponent histogram is internally consistent with the 429,401-row
total:

| `nBits` exponent | Rows |
|---|---:|
| `0x14` | 1 |
| `0x17` | 300,646 |
| `0x18` | 63,645 |
| `0x19` | 61,282 |
| `0x1a` | 3,805 |
| `0x1b` | 19 |
| `0x1c` | 2 |
| `0x1d` | 1 |

Among the exponent-`0x17` rows, 134,089 of 134,101 unique previous tips were
canonical and 134,093 were known to the Bitcoin node used for the run. The
other 128,755 commitments have a different exponent. They include the 50,621
unique headers that passed their own encoded target and entered the private
full classifier inventory. The archived classifier found 0 canonical and 0
direct-stale observations among them; its legacy `orphan` label corresponds to
the current primary classification `unknown`.

The 21 remaining exponent-`0x17` rows do not extend the active Bitcoin chain:
9 build on 4 node-known noncanonical tips and 12 build on 8 unknown tips.

`scripts/reports/characterize_doichain_auxpow.py` reproduces the population and
canonical-tip partitions when the private raw extract and the required node RPC
are supplied. Its historical JSON keys retain the older `real_difficulty`
shorthand for compatibility, but the implementation groups on the exponent.

## Strict and weak review

The 2026-06-24 bespoke classifier wrote these 50,621 rows with the legacy
`orphan` token. Current readers accept that token as `unknown`, and the later
strict/weak relevance pass assessed all 50,621 against the committed Bitcoin
epoch reference. It found 0 strict and 0 weak BTC orphans. A new run uses the
shared classifier and writes `unknown` directly. The public output is the
header-only
[`results/strict-weak-orphans/doichain_strict_weak_orphans.csv`](../../results/strict-weak-orphans/doichain_strict_weak_orphans.csv),
and the aggregate zero is recorded in
[`strict-weak-orphans-counts.csv`](../../results/strict-weak-orphans/strict-weak-orphans-counts.csv).
The full unknown inventory remains private because it is a bulky intermediate.

The header-only
[`results/monitor-evidence/doichain_monitor_evidence.csv`](../../results/monitor-evidence/doichain_monitor_evidence.csv)
keeps Doichain non-selectable in the Merge Mining Monitor while preserving the
survey outcome in its manifest.

## Coverage limits

The completeness claim stops at the active-chain tip observed by the node on
2026-06-24. The pinned source also contains a
minimum-chain-work comment referring to height 500,000, which is not reconciled
with the observed height-430,684 network state. For that reason, this document
does not call the result a lifetime or full-chain survey.

A future chain extension, different active chain, or refreshed source archive
requires a new sync, exact-height normalization, classification, and relevance
pass. The zero-row novelty CSV is expected because Doichain contributed no
accepted direct-stale candidates.
