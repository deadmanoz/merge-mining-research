# SixEleven

| Field | Value |
|---|---|
| Ticker | 611 |
| AuxPoW activation | 2015-11-03; child height 19,200 |
| Network status | Active at recovery time; six peers served the observed height-999,406 tip on 2026-07-10 |
| Chronological position | 12 of 26 (after Myriadcoin; before Argentum) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured Bitcoin-parent chains) |
| AuxPoW chain ID | `1`, verified from the official chain and recovered blocks |
| Source tag (in code) | `sixeleven` |
| Loader | `load_sixeleven_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/sixeleven_validated_stales.csv` (header-only) |

SixEleven is an integrated zero-stale recovery from a complete observed-tip
legacy chain. The project synced the pinned official node image, scanned its
numbered block files, and resolved exact child identity before Bitcoin
classification. The broader catalogued-source campaign and its operational
history remain in
[`catalogued-recovery.md`](catalogued-recovery.md#sixeleven).

## 1. Provenance and scope

The recovery pins the official `611project/611coin` linux/amd64 image manifest
`sha256:64a174792a4a2112d06c895a72bfcb70c8d25b2ab19bfe624d235cc75a156283`.
The node synced through the observed height-999,406 tip with six connected
peers. The retained datadir is about 2.4 GB and remains private; the reproducible
runtime and peer configuration live under `node-infra/sixeleven/`.

The complete legacy pass scanned 999,407 blocks, explicitly excluding
`blkindex.dat`: 969,317 carried AuxPoW and 30,090 did not. There were no parse
errors or chain-ID mismatches. Because the legacy RPC does not expose the full
proof, extraction reads `blkNNNN.dat`, then
`scripts/prep/normalize_auxpow_child_heights.py` verifies each child hash,
version, timestamp, confirmations, exact height, and
`getblockhash(height)` identity before Bitcoin classification.

## 2. Bitcoin classification and publication result

| Stage | Count |
|---|---:|
| Self-target-PoW-valid parent candidates | 80,364 |
| Canonical Bitcoin parents | 7 |
| Stale-labelled candidates | 0 |
| Unknown parents | 80,357 |
| Accepted direct-stale candidates | **0** |
| Strict / weak BTC-orphan observations | **0 / 0** |

Every unknown candidate failed the Bitcoin epoch-`nBits` consistency gates.
The result is a complete negative stale and strict/weak result for the chain
through the observed tip, not a claim about blocks produced after 2026-07-10.

The header-only loader input follows the common fail-closed contract:

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

No row passes. The header-only
`results/per-chain-novelty/sixeleven.csv` consequently records zero upstream or
chronologically novel direct-stale candidates.

## 3. Limitations and outputs

- The surveyed range ends at the active-chain tip observed on 2026-07-10.
- The full 80,364-row candidate inventory and synced datadir remain private.
  The repository commits the compact 7-row canonical Monitor export and the
  zero-row publication inputs and summaries.
- A rerun must scan only numbered `blkNNNN.dat` files and must normalize exact
  child heights through the legacy RPC before Bitcoin classification.

Public artifacts:

- `data/validated-stales/sixeleven_validated_stales.csv`
- `results/per-chain-novelty/sixeleven.csv`
- `results/monitor-evidence/sixeleven_monitor_evidence.csv`
- `results/strict-weak-orphans/sixeleven_strict_weak_orphans.csv`
- `node-infra/sixeleven/`
