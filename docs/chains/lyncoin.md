# Lyncoin

| Field | Value |
|---|---|
| Ticker | LYN |
| AuxPoW activation | 2022-12-30 launch; AuxPoW permitted from child height 1 and recovered through the pre-Flex boundary at 260,499 |
| Network status | Active at recovery time; a live peer advertised Lyncoin Core v4.0.0 at roughly height 1.36 million on 2026-07-10 |
| Chronological position | 25 of 26 (after Electric Cash; before Fractal Bitcoin) |
| In Stifter et al. 2018 baseline | **No** (Lyncoin launched after the paper's measurement window) |
| AuxPoW chain ID | `2829` (`0x0B0D`), strict in the recovered pre-Flex consensus rules |
| Source tag (in code) | `lyncoin` |
| Loader | `load_lyncoin_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/lyncoin_validated_stales.csv` (header-only) |

Lyncoin is an integrated zero-stale recovery. Its pre-Flex extended headers
preserve complete Namecoin-family AuxPoW proofs, so the project recovered the
full scoped history from a peer's P2P `headers` stream without waiting for
child block bodies. The broader catalogued-source campaign and its operational
history remain in [`catalogued-recovery.md`](catalogued-recovery.md#lyncoin).

## 1. Provenance and scope

The recovery pins Lyncoin Core v4.0.0 source commit
`c289540da7ea3bb78f6e9eb661ad72b90476cc40`. The capture covers the continuous
pre-Flex sequence from child height 0 through 260,499 and validates the first
Flex boundary header at 260,500. The committed
[`p2p-capture-manifest.json`](../../node-infra/lyncoin/p2p-capture-manifest.json)
records 132 atomic batches and `complete=true`. The `node-infra/lyncoin/`
workspace is a reproducible full-node fallback, not the provenance of the
committed evidence.

The 260,500 pre-Flex headers comprise 249,640 AuxPoW headers and 10,860 solo
headers. `scripts/extract/download_lyncoin_auxpow_headers.py` validates the
source-pinned genesis, checkpoints, header continuity, child proof of work,
AuxPoW chain commitment, parent proof against the child target, and the 260,500
Flex boundary before emitting parent candidates.

## 2. Bitcoin classification and publication result

| Stage | Count |
|---|---:|
| Self-target-PoW-valid parent candidates | 56,653 |
| Canonical Bitcoin parents | 11 |
| Stale-labelled candidates | 0 |
| Unknown parents | 56,642 |
| Accepted direct-stale candidates | **0** |
| Strict / weak BTC-orphan observations | **0 / 0** |

Every unknown candidate failed the Bitcoin epoch-`nBits` consistency gates.
The result therefore says that the recovered pre-Flex window contains no
accepted direct-stale, strict, or weak evidence. It does not claim the same for
post-Flex history.

The header-only loader input follows the common fail-closed contract:

```python
classification == "stale" and validation_status in {
    "VALID",
    "VALID (post-BCH, difficulty matches BTC)",
}
```

No row passes. The header-only
`results/per-chain-novelty/lyncoin.csv` consequently records zero upstream or
chronologically novel direct-stale candidates.

## 3. Limitations and outputs

- The public recovery stops at the Flex transition. Lyncoin's later proof and
  hash formats are outside this pure-stdlib pre-Flex recovery.
- The 56,653-row classifier inventory is private. The repository commits only
  the compact 11-row canonical Monitor export and the zero-row publication
  inputs and summaries.
- Peer availability is time-sensitive. The capture manifest, pinned source,
  checkpoints, and batch hashes make the completed historical result
  reproducible without assuming that the same peer remains online.

Public artifacts:

- `data/validated-stales/lyncoin_validated_stales.csv`
- `results/per-chain-novelty/lyncoin.csv`
- `results/monitor-evidence/lyncoin_monitor_evidence.csv`
- `results/strict-weak-orphans/lyncoin_strict_weak_orphans.csv`
- `node-infra/lyncoin/p2p-capture-manifest.json`
- `node-infra/lyncoin/`
