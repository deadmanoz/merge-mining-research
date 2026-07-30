# Electric Cash

| Field | Value |
|---|---|
| Ticker | ELCASH |
| AuxPoW activation | 2020-12-20 (fresh genesis, nTime 1608451200; AuxPoW permitted from height 1 - see §2 quirks) |
| Network status | Zombie: still producing merge-mined blocks on schedule, but real Bitcoin-difficulty block wins ceased November 2024 |
| Chronological position | 24 of 26 (after Bitcoin Vault, before Lyncoin) |
| In Stifter et al. 2018 baseline | **No** (not among the paper's seven measured chains; 2020 launch, after the paper's mid-2018 data cutoff) |
| AuxPoW chain ID | `8503` (`0x2137`), strict (`consensus.fStrictChainId = true`) |
| Block time | 600 s (Bitcoin-identical 10-minute target, `nPowTargetSpacing = 10 * 60`) |
| Source tag (in code) | `elcash` |
| Loader | `load_elcash_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/elcash_validated_stales.csv` |
| Full classified inventory | External refresh (2,426 canonical + 3 stale + 2,711 unknown) |

Electric Cash is a Bitcoin Core 0.20.2 fork that merge-mines Bitcoin from a
fresh December 2020 genesis, launched within the MineBest ecosystem as a
sibling project of Bitcoin Vault. Real Bitcoin-difficulty pool hashrate
merge-mined it continuously from January 2021 to November 2024 (2,426
canonical Bitcoin-parent wins, peaking in September-October 2021). The three
committed stales fall in June-September 2021, near that peak, and all three
re-observe parent headers first-claimed by Bitcoin Vault. Since November 2024
no further real-difficulty wins appear; the chain keeps producing merge-mined
blocks at negligible hashrate.

## 1. Chain data

**Source.** Raw AuxPoW evidence was extracted from a self-synced `elcashd`
node (build and run recipe in `node-infra/elcash/`) over JSON-RPC with cookie
auth. The chain uses standard Namecoin-style AuxPoW under the Bitcoin Core
0.20.2 codebase - the namecoin-core lineage (the `getauxblock`/`AuxpowMiner`
RPC machinery carries Daniel Kraft's copyright upstream) - so the shared
`CAuxPow` parser applies unchanged.

**Provenance.** The node was built and synced on the acquisition host on
2026-06-26 (chain tip ≈ 285,143 blocks); 248,640 AuxPoW-bearing blocks were
parsed and their unique Bitcoin-parent candidates classified against Bitcoin
Core. The full classified inventory is bucket-split in the private chain
archive (`elcash_canonical_blocks.csv` with 2,426 canonical rows,
`elcash_stale_blocks.csv` with the 3 stale rows, and a header-only
`elcash_unknown_blocks.csv` with 2,711 rows). The 2026-07-30
source-authenticated rerun exercised the normal RPC extractor and classifier
again, producing complete child-header bundles and parent-coinbase outputs.
The committed
`data/validated-stales/elcash_validated_stales.csv` carries the 3 VALID stale
rows.

**Coverage.** The 3 accepted rows span BTC heights **688,349 → 699,616**
(2021-06-21 → 2021-09-08). ELCASH heights 26,353 → 37,634. The canonical
attestation evidence is much wider: 2,426 canonical Bitcoin parents from
2021-01-21 to 2024-11-17.

**Integration status.** Wired into the recovery loader and novelty pipeline;
`results/monitor-evidence/elcash_monitor_evidence.csv` exports all 2,426
canonical rows and 3 accepted stale rows.

**Holes.**

- **Post-extraction tail**: blocks after the 2026-06-26 extraction tip are
  unscanned. The chain keeps producing merge-mined blocks; given that real
  Bitcoin-difficulty wins ceased in November 2024, no further stale evidence
  is expected there, but this is unverified.
- **Launch era**: no AuxPoW was observed before ELCASH ≈ 4,741 (late January
  2021, a recovery-session observation); the earliest blocks were
  direct-mined even though AuxPoW is permitted from height 1. The first
  canonical Bitcoin-parent win (2021-01-21) is consistent with that start.
- **BCH/BSV contamination**: 2,711 BCH/BSV-like parent headers classify as
  `unknown` and remain in the full evidence. None receives a final
  strict/weak relevance verdict, so they do not enter the Monitor projection.
  The pools merge-mining ELCASH pointed the same child commitments at BCH/BSV
  work as well.

**Reference scripts.**

- `scripts/extract/extract_elcash_auxpow.py` - RPC extractor, doubling as a
  version-bit census (AuxPoW flag plus a chain ID histogram filtered to
  `0x2137`); rewritten 2026-07-17 on the shared `CAuxPow` parser (the
  original pipeline ran as scratch scripts beside the node).
- `scripts/classify/classify_elcash_stales.py` - thin `run_classifier`
  wrapper that reproduces the committed schema (the committed values predate
  the wrapper - see §5).

## 2. Extraction → classification

**Method.** `extract_elcash_auxpow.py` walks the chain over JSON-RPC,
censuses every block version for the AuxPoW flag and chain ID `0x2137`,
parses the embedded Bitcoin parent header and coinbase from each merge-mined
block with the shared `CAuxPow` parser, and writes the standard
raw-candidates CSV. Classification runs through the shared `run_classifier`
driver: header corroboration and self-target PoW, dedup on parent hash, the
Bitcoin Core RPC canonical/stale/unknown split, and the declared
header-context validation gates.

**Counts** (chain state as of the 2026-06-26 extraction):

| Stage | Count |
|---|---:|
| Chain tip at extraction | ≈ 285,143 |
| AuxPoW-bearing blocks parsed | 248,640 |
| Classified unique parent candidates | 5,140 |
| `canonical` (on BTC mainchain) | 2,426 |
| `stale` (candidate off active chain, predecessor canonical) | **3** |
| `unknown` (parent + prev both off-chain) | 2,711 |

The stage-by-stage funnel between 248,640 AuxPoW blocks and the classified
unique parents (duplicate parents across child blocks, plus sub-difficulty
parents from the chain's low-hashrate eras) was not preserved - the raw
extract was scratch-only (§5) - so only the endpoint counts are recorded
here.

**Chain-specific quirks.**

- **AuxPoW permitted from height 1.** `src/chainparams.cpp` sets
  `consensus.nAuxpowStartHeight = 1` with genesis nTime 1608451200
  (2020-12-20 08:00 UTC), so every post-genesis block may carry AuxPoW. The
  first observed merge-mined block is nonetheless ELCASH ≈ 4,741 (§1 Holes).
- **Strict chain ID.** `consensus.nAuxpowChainId = 0x2137` (8503) with
  `fStrictChainId = true`.
- **MineBest / Bitcoin Vault sibling.** ELCASH was launched by the operator
  ecosystem behind Bitcoin Vault, and the same parent mining work frequently
  committed to multiple child chains (the September 2021 stale's merkle size
  is 4). That aggregation is why every ELCASH stale also appears in Bitcoin
  Vault's validated set (§3).

## 3. Filtering → accepted direct-stale candidates

**Loader filter** (`load_elcash_stales()` in `stale_blocks.py`):

```python
classification == "stale" and validation_status.startswith("VALID")
```

The exact-key exclusion overlay is applied after this persisted gate (no
ELCASH rows are excluded). Three entries pass; `expected_nbits` matches the
encoded `btc_bits` on every row.

**Post-filter count: 3 accepted direct-stale header candidates.**

| BTC h | ELCASH h | Date (UTC) | Pool tag (scriptsig) | Notes |
|---:|---:|:---|:---|:---|
| 688,349 | 26,353 | 2021-06-21 04:31 | (none printable) | mm nonce `7296cd10`, merkle size 2 |
| 693,118 | 31,669 | 2021-07-28 19:37 | (none printable) | mm nonce `7296cd10`, merkle size 2; in upstream `bitcoin-data/stale-blocks` (0xB10C's node; the full block is archived upstream) |
| 699,616 | 37,634 | 2021-09-08 10:50 | `binance/fr714r` | Binance Pool; merkle size 4 |

All three header timestamps sit within 2-26 seconds of their canonical
same-height competitors, and each `btc_prev_hash` is the canonical block at
the previous height (re-verified against a public Bitcoin API during the
2026-07 audit). The two untagged rows share an identical merge-mining-nonce
fingerprint (`7296cd10`) and merkle size, so they plausibly come from a
single pool configuration distinct from the Binance row's; they remain
unattributed.

### Two novelty views

Generated by `python scripts/compute_chain_novelty.py elcash`. Per-stale
row-level breakdown at `results/per-chain-novelty/elcash.csv`.

**(a) Isolated - vs upstream `bitcoin-data/stale-blocks` only**

| Split | Count |
|---|---:|
| also in upstream | 1 |
| novel vs upstream | 2 |

**(b) Chronological cumulative - layered on upstream + every chronologically-earlier chain**

| Split | Count |
|---|---:|
| also in upstream | 1 |
| also in earlier-born chain (`bitcoin-vault`: 3) | 3 |
| **novel at this position** | **0** |

Electric Cash is 24th chronologically, and every accepted row is a
re-observation: all three parent headers are first-claimed by Bitcoin Vault
(BTCV heights 89,307 / 94,702 / 100,670) with byte-identical headers and
coinbase scriptSigs - the same parent mining work carried both children's
commitments, observed independently through each chain's AuxPoW path. The
marginal yield is 0 novel stales, but the re-observation corroborates the
Bitcoin Vault evidence from a second ledger. Upstream already carries
693,118 (added 2022-05-18 from 0xB10C's node observations).

> Novelty precedence rule: earlier-born chain has novelty precedence. This is
> a simplifying convention for reproducible attribution, **not** a claim
> about which chain literally observed each stale first in real-world block
> time.

The 2,711 unknown rows receive no strict or weak verdict, so the committed
strict/weak projection is header-only while the rows remain in the complete
external evidence.

## 4. Outputs & references

**In-repo artifacts.**

- `data/validated-stales/elcash_validated_stales.csv` - 3 VALID direct-stale
  rows (loader input; committed) in the 16-column historical child-header
  schema. The normal source rerun populated `coinbase_outputs` with the parent
  transaction's output scripts and values.
- `results/per-chain-novelty/elcash.csv` - per-stale
  `(btc_height, btc_hash, in_upstream, first_seen_chain)` table.
- `results/monitor-evidence/elcash_monitor_evidence.csv` - 2,426 canonical and
  3 accepted stale rows.
- `scripts/extract/extract_elcash_auxpow.py`,
  `scripts/classify/classify_elcash_stales.py` - reproducers.

**Private archive artifacts.**

- Classified split: `elcash_canonical_blocks.csv` (2,426 rows),
  `elcash_stale_blocks.csv` (3 rows), `elcash_unknown_blocks.csv`
  (2,711 rows).

**External references.**

- `https://github.com/electric-cash/electric-cash` - source. Bitcoin Core
  0.20.2 base; `src/chainparams.cpp` carries `nAuxpowChainId = 0x2137`,
  `fStrictChainId = true`, `nAuxpowStartHeight = 1`, and genesis nTime
  1608451200.
- `https://explorer.electriccash.global/` - project explorer (unreachable at
  the 2026-07 audit; search-engine-indexed pages show on-schedule block
  production through at least 2026-06-17, block 283,811).
- `docs/chains/bitcoin-vault.md` - the sibling chain that first-claims all
  three stales; its remaining-work attribution item for BTC 688,349 /
  693,118 is shared with this chain.

**Remaining work.**

- **Attribution of the two untagged stales** (shared with Bitcoin Vault's
  remaining-work item): coinbase-output address matching may resolve the
  `7296cd10` pool. ELCASH adds no extra coinbase evidence (the scriptSigs
  are identical to Bitcoin Vault's) but its independent observation confirms
  the multi-child aggregation.

## 5. Integration history

- **2026-06-26** - Recovery ran alongside the merge-mining-monitor work:
  `elcashd` built and synced on the acquisition host, 248,640 AuxPoW blocks
  parsed, and the unique parents classified to 2,426 canonical + 3 stale
  (2,711 BCH/BSV-contaminated parents excluded). The three stales were first
  committed to the predecessor repo as `classification=orphan` (Core-absent)
  and relabelled `stale` the same night: each builds on a canonical Bitcoin
  block and has a canonical competitor at its own height, so they are
  inferred stales, not Core-absent orphans.
- **2026-07-17** - Public-repo port: the extractor was rewritten on the
  shared `CAuxPow` parser (the original pipeline was scratch scripts beside
  the node), the `node-infra/elcash/` recipe was ported, and the committed
  CSV was normalized from the legacy 10-column layout to the shared
  12-column validated-stales layout (adding the empty `coinbase_outputs`
  column and the persisted `expected_nbits` verdict). The 2026-07-30 source
  regeneration then expanded it to the shared 16-column layout with the four
  authenticated child-header fields.
- **2026-07-22** - Audit: all three stale events re-verified against
  canonical Bitcoin (same-height competitor, canonical parent, matching
  nBits); the activation date tightened to the source genesis (2020-12-20);
  the earlier "brief mid-2021 window" framing corrected - real-difficulty
  merge-mining ran January 2021 → November 2024 with its peak in
  September-October 2021, and the stale sample (June-September 2021) sits
  inside it; the Bitcoin Vault cross-confirmation recorded.
- **2026-07-30** - The normal extractor/classifier path was rerun from the
  authoritative node source. It retained the 2,711 non-Bitcoin parent rows as
  `unknown`, authenticated child headers for all 5,140 rows, populated parent
  outputs, and published all 2,426 canonical rows through the uniform Monitor
  projection.
