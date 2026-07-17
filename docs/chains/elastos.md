# Elastos

| Field | Value |
|---|---|
| Ticker | ELA |
| AuxPoW activation | No coded activation constant. The first observed non-dummy proof is ELA height 177,153 on 2018-08-26, carrying Bitcoin parent height 538,457. |
| Network status | Active; merge-mined BPoS since ELA 1,405,000, after DPoS v1 consensus began at 402,680. Current blocks continue to carry AuxPoW. |
| Chronological position | 20 of 26 (after Xaya, before Syscoin) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; real Bitcoin-parent evidence begins after its 2018-07-06 data freeze) |
| AuxPoW chain ID | 1224, used in the merged-mining tree index calculation rather than encoded as a child-header version predicate |
| Block time | 120 s target |
| Source tag (in code) | `elastos` |
| Loader | `load_elastos_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/elastos_validated_stales.csv` (153 rows) |
| Novelty CSV | `results/per-chain-novelty/elastos.csv` |

Elastos uses an independent Go codebase rather than a Bitcoin Core fork. Its
JSON-RPC exposes a hex-encoded, Namecoin-compatible CAuxPow structure. The
research parser recovers the real Bitcoin parent header, parent coinbase
scriptSig, and outputs from that blob.

The post-2017 parent-header window makes Bitcoin-family contamination a
material risk, but the evidence must be stated narrowly. One direct-stale
candidate extending Bitcoin height 717,695 failed the expected-`nBits` check
at height 717,696 (`170b98ab` instead of `170b8c8b`). That establishes a
Bitcoin-linked, consensus-invalid candidate whose difficulty context is not
Bitcoin's. It does not identify the header as BCH or BSV. The 153 committed
rows passed the full available-evidence publication profile.

## 1. Chain Data

**Source.** Historical hybrid extraction used a local `ela` node through ELA
1,817,250 and the official-domain public RPC at `api.elastos.io/ela` from
1,817,251 through the extraction tip. The raw archive contains 2,018,508
retained AuxPoW rows from ELA 177,153 through 2,195,844. Its parent timestamps
run from 2018-08-26 through 2026-04-21 UTC.

**Operational boundary.** In the later local-node follow-up, official v0.9.9.4
and v0.9.9.5 both stalled at ELA 1,817,250 while rejecting block 1,817,251 in
DPoS claim-reward validation. A bounded local research workaround later
allowed the archival node to synchronize, but it was not published upstream
or included in this repository. It did not affect the recovered data, because
the public-RPC tail had already completed the historical extraction. The
hybrid acquisition path remains the reproducible provenance for this dataset.

**Accepted coverage.** The committed direct-stale rows span ELA heights
360,062 through 2,138,062 and Bitcoin heights 572,333 through 934,425. Their
parent timestamps run from 2019-04-19 through 2026-01-31 UTC.

**Holes and filters.**

- The archived scan from ELA 177,000 through 177,152 contains locally generated
  dummy parent proofs. `scripts/extract/extract_elastos_auxpow.py` discards
  parents with `bits` equal to 0 or `0x7fffffff`, or with no coinbase outputs.
  The first retained row therefore establishes the observed transition without
  treating the scan floor as a hard-fork constant.
- The raw window is entirely post-BCH and mostly post-BSV. Every parent header
  must satisfy its own encoded target before classification. Direct-stale
  candidates then pass the shared publication profile: header identity,
  active-parent placement, expected `nBits`, median-time-past, historical
  minimum version, coinbase scriptSig length, and BIP34 height prefix.
- `VALID` records that this available-evidence profile passed. It is not a
  claim that a complete historical Bitcoin block was replayed for every
  consensus rule.
- The governance-era transition does not remove the AuxPoW evidence. ELA
  343,400 begins the CRC-only DPoS-era transition, while explorer consensus
  mode remains PoW through 402,679 and changes to DPoS at 402,680. It changes
  from DPoS to BPoS at 1,405,000, and current blocks still carry parent proofs.

Reference scripts:

- `scripts/extract/extract_elastos_auxpow.py` fetches `getblockbyheight`, parses
  the `auxpow` hex blob, and writes the Bitcoin parent evidence.
- `scripts/classify/classify_elastos_stales.py` applies self-target PoW,
  deduplicates by parent-header hash, classifies against Bitcoin Core, and
  applies the shared direct-stale context gate.

## 2. Extraction and Classification

For each ELA block in the requested range, the extractor decodes the serialized
CAuxPow fields in this order: parent coinbase transaction, parent hash, parent
coinbase Merkle branch and index, auxiliary Merkle branch and index, then the
80-byte parent header. The decoded coinbase evidence is retained for later
attribution research.

The pipeline then:

1. Filters dummy proofs and empty parent coinbases.
2. Corroborates the published hash, previous hash, timestamp, and `nBits`
   against the serialized 80-byte parent header.
3. Retains only headers satisfying their own encoded target and deduplicates
   them by `btc_header_hash`.
4. Uses Bitcoin Core `getblockheader`. A header with positive confirmations is
   `canonical`; otherwise a header whose predecessor has positive confirmations
   is a direct-`stale` candidate; the remaining rows are `unknown`.
5. Applies the shared available-evidence publication gate to direct-stale
   candidates and writes bucket-split canonical, stale, unknown, validated, and
   rejected outputs.

The archived 2026-07-18 refresh reproduced this accounting:

| Stage | Rows |
|---|---:|
| Retained raw AuxPoW rows | 2,018,508 |
| Unique self-target-valid parent headers | 184,235 |
| Canonical Bitcoin parents | 175,078 |
| Direct-stale candidates before the publication gate | 154 |
| Unknown parents | 9,003 |
| `validation_status=VALID` direct stales | 153 |
| Publication-gate rejected direct stales | 1 |

The 9,003 unknowns satisfy their encoded targets but do not resolve as active
Bitcoin headers or direct children of active Bitcoin headers. Their parent-chain
origin remains unresolved. The current public relevance pass identifies three
of them as `strict_btc_orphan` from BIP34 height plus expected-`nBits` evidence,
and none as `weak_btc_orphan`; that is not a general origin result for the
remaining 9,000 rows.

## 3. Filtering and Novelty

`load_elastos_stales()` uses the shared loader contract:

```python
classification == "stale" and validation_status.startswith("VALID")
```

All 153 committed rows pass. The one rejected candidate and all unknown rows
remain outside the direct-stale loader input.

Generated by `python scripts/compute_chain_novelty.py elastos`:

| View | Count |
|---|---:|
| Total validated | 153 |
| Also in upstream `bitcoin-data/stale-blocks` | 118 |
| Novel vs upstream alone | 35 |
| First-seen flag: Namecoin | 102 |
| First-seen flag: RSK | 10 |
| First-seen flag: Emercoin | 9 |
| First-seen flag: Devcoin | 3 |
| Chronologically novel at Elastos's position | 25 |

The upstream and first-seen columns are independent flags, so the table is not
a disjoint partition. Chronological novelty removes any row already present
upstream or claimed by an earlier-born integrated chain. SixEleven is earlier
in the 26-chain chronology but contributes no accepted direct-stale rows, so it
does not change Elastos's novelty count.

The precedence rule is a reproducible attribution convention, not a claim
about which child chain literally observed a Bitcoin stale first.

## 4. Outputs and References

In-repo artifacts:

- `data/validated-stales/elastos_validated_stales.csv`
- `results/per-chain-novelty/elastos.csv`
- `results/monitor-evidence/elastos_monitor_evidence.csv`
- `results/strict-weak-orphans/elastos_strict_weak_orphans.csv`

Private archive artifacts:

- `elastos_canonical_blocks.csv` (175,078 canonical rows; 142,842,409 bytes)
- `elastos_stale_blocks.csv` (153 accepted stale rows)
- `elastos_unknown_blocks.csv` (9,003 unknown rows)
- `elastos_rejected.csv` (one rejected direct-stale candidate)
- `elastos_btc_valid.csv` and the raw extraction CSV

Primary protocol references:

- [Elastos dummy parent-proof generator](https://github.com/elastos/Elastos.ELA/blob/c61c9e614b640e3f664925401edccda20a29eb84/auxpow/btcfaker.go)
  explains why a fixed height is not a consensus activation boundary.
- Official explorer records for [ELA 177,152](https://blockchain.elastos.io/api/v1/block/177152)
  and [ELA 177,153](https://blockchain.elastos.io/api/v1/block/177153)
  establish the observed dummy-to-real parent transition.
- [Elastos CAuxPow serialization and chain ID](https://github.com/elastos/Elastos.ELA/blob/c61c9e614b640e3f664925401edccda20a29eb84/auxpow/auxpow.go#L18-L161)
  define chain ID 1224 and the serialized proof fields.
- [Elastos block validation](https://github.com/elastos/Elastos.ELA/blob/c61c9e614b640e3f664925401edccda20a29eb84/blockchain/blockvalidator.go#L31-L43)
  passes chain ID 1224 to the AuxPoW tree check.
- [Mainnet consensus parameters](https://github.com/elastos/Elastos.ELA/blob/c61c9e614b640e3f664925401edccda20a29eb84/common/config/config.go#L263-L310)
  define the H1 CRC-only transition, H2 public DPoS height, and two-minute
  target. Official explorer records at [343,400](https://blockchain.elastos.io/api/v1/block/343400)
  and [402,680](https://blockchain.elastos.io/api/v1/block/402680) distinguish
  the era transition from the observed consensus-mode change. Records at
  [1,404,999](https://blockchain.elastos.io/api/v1/block/1404999) and
  [1,405,000](https://blockchain.elastos.io/api/v1/block/1405000) establish the
  later BPoS boundary.
- [Elastos JSON-RPC block encoder](https://github.com/elastos/Elastos.ELA/blob/c61c9e614b640e3f664925401edccda20a29eb84/servers/interfaces.go#L1082-L1104)
  returns the serialized proof in the `auxpow` field.
- [Elastos.ELA v0.9.9.6](https://github.com/elastos/Elastos.ELA/releases/tag/v0.9.9.6)
  was the latest official node release at the 2026-07-22 publication audit.

The full unknown-origin analysis remains private archive work. A future public
reproduction should publish its exact input inventory and epoch-reference
boundary before making broader claims about BCH, BSV, or another parent chain.
