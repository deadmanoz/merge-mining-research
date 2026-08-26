# Hathor

| Field | Value |
|---|---|
| Ticker | HTR |
| Earliest confirmed merge-mining evidence | Hathor height 60,275 on 2020-01-24 is `version == 3`; BTC-linked work is independently confirmed by height 100,000 on 2020-02-07. The exact first merge-mined height is not established. Mainnet launched 2020-01-03. |
| Network status | Active. Joining the mainnet P2P network requires allowlisting, so this recovery uses the documented public REST API. |
| Chronological position | 22 of 26 (after Syscoin, before Bitcoin Vault) |
| In Stifter et al. 2018 baseline | **No**. Hathor mainnet and merge mining post-date the paper's data cutoff. |
| Block time | 30 s |
| Multi-parent-chain | **Yes**. The proof can bind to a compatible Bitcoin-derived SHA-256d parent. An unresolved parent is not assumed to be Bitcoin, BCH, BSV, or any other particular chain. |
| Source tag | `hathor` |
| Loader | `load_hathor_stales()` in `src/stale_blocks_analysis/stale_blocks.py` |
| Validated CSV | `data/validated-stales/hathor_validated_stales.csv` |
| Accepted direct-stale candidates | **6** at BTC heights 710,969 / 751,763 / 776,941 / 843,741 / 883,674 / 938,873 |

Hathor's proof is not Namecoin-family `CAuxPow`. It uses the RFC 0006
split-header format: the first 36 and final 12 bytes of the Bitcoin-style
parent header are stored directly, while the 32-byte merkle root is rebuilt
from the parent coinbase and its merkle path. The coinbase commits to
`"Hath" || aux_block_hash`, and RFC 0006 permits that commitment in either the
scriptSig or an output.

## 1. Acquisition and provenance

The source is Hathor's public REST API at
`https://node1.mainnet.hathor.network/v1a`, with node 2 as fallback. No local
Hathor node was used.

Hathor remains an active live child chain. It is absent from the separate
`data/child-identity/` hydration target set only because the API acquisition
already authenticates and retains each published child identity and timestamp.

The supported acquisition path has one logical dataset:

1. `scripts/extract/hathor_metadata_ledger.py` partitions a caller-declared
   height range and records one terminal metadata outcome for every height.
   Resume requires a contiguous prefix. A separate retry output can re-drive
   unresolved rows without mutating the source ledger.
2. `scripts/extract/extract_hathor_payloads_from_ledger.py` fetches every
   `version_3_ready` transaction into a sealed acquisition row. Each row keeps
   the Hathor identity and timestamp, `aux_pow`, full raw transaction,
   funds-and-graph bytes, successful request provenance, and its record digest.
   The audit checks exact coverage against the ledger and produces an evidence
   root.
3. `scripts/classify/classify_hathor.py` reads the acquisition dataset
   directly and writes the complete category family in one atomic output
   directory.

Repeat `--input` for physical shards, supplied in ascending height-range order;
the classifier treats them as one globally ordered stream.

Physical shards are only an operational way to collect the logical dataset.
They do not define different kinds of Hathor data, and the classifier has no
persisted acquisition-era or classifier-stage concepts.

The initial recovery saved `aux_pow` separately from the funds-and-graph bytes
needed for reconstruction. That omission forced a second fetch and created two
files that then had to be joined. The current acquisition row keeps the complete
evidence together, so the raw/supplement path and its gap-fill tooling are no
longer supported. Private artifacts in an earlier shape must be transformed by
a disposable operator script, not by compatibility code in the pipeline.

The full acquisition dataset and category inventories are private archival
artifacts because of their size. The committed publication keeps the compact
six-row direct-stale loader input, the Monitor-facing canonical and stale
projection, the one consensus-invalid parent observation, and the zero-result
strict/weak artifact.

## 2. RFC 0006 reconstruction

For every version-3 observation, the classifier parses this proof layout:

| Bytes | Field | Contents |
|---|---|---|
| 36 | `bitcoin_header_head` | Parent header offsets 0 to 35 |
| CompactSize + bytes | `coinbase_tx_head` | Coinbase bytes before the embedded Hathor hash |
| CompactSize + bytes | `coinbase_tx_tail` | Coinbase bytes after the embedded Hathor hash |
| CompactSize + 32-byte items | `merkle_path` | Coinbase-to-root sibling hashes |
| 12 | `bitcoin_header_tail` | Parent header time, `nBits`, and nonce |

The reconstruction is:

```python
aux_digest     = SHA256d(SHA256(block_funds) || SHA256(block_graph))
aux_block_hash = reverse(aux_digest)
full_coinbase  = coinbase_tx_head || aux_block_hash || coinbase_tx_tail
coinbase_txid  = SHA256d(full_coinbase)
merkle_root    = fold(coinbase_txid, reverse_each(merkle_path))
btc_header     = bitcoin_header_head || merkle_root || bitcoin_header_tail
hathor_hash    = reverse(SHA256d(btc_header))
```

The acquisition row stores `block_funds || block_graph` as one concatenated
value. The classifier tries candidate split positions and accepts only the one
whose reconstructed header authenticates against the Hathor block identity.

Three corrections were needed after the first implementation:

1. Embed `aux_block_hash`, not the final Hathor block hash.
2. Embed `aux_block_hash` in display, byte-reversed order.
3. Reverse each merkle sibling before folding it into the root.

The decisive invariant is
`SHA256d(reconstructed_header)[::-1] == hathor_block_hash`. It passed for all
50 sampled blocks after the correction and for none under the original
algorithm. The earlier sanity check examined only `prev_hash`, which occupies
the directly stored header prefix and could not expose a bad reconstructed
merkle root.

## 3. Classification

The classifier processes each sealed observation once:

1. Verify the acquisition seal, parse RFC 0006, rebuild the parent coinbase and
   header, and authenticate the result against the Hathor block identity.
2. Apply the header's encoded proof-of-work target. A header that misses its own
   target is `near`.
3. Ask Bitcoin Core about the candidate and predecessor. An active candidate is
   `canonical`. A self-target-valid header without an active Bitcoin parent is
   `unknown`.
4. For a candidate extending an active Bitcoin parent, derive its Bitcoin
   height, compare `nBits` with the canonical block at that height, and apply
   the available median-time-past, historical minimum-version, coinbase
   scriptSig-length, and BIP34 checks. A valid candidate is `stale`; a rejection
   is routed to `unknown`, `error_block`, or retained as a rejected stale using
   the shared rejection semantics.

A malformed seal, proof, target, or incomplete validation context aborts the
staged run without publication. Otherwise, every authenticated input
observation reaches one primary category. The output directory contains:

- `hathor_near_blocks.csv`
- `hathor_canonical_blocks.csv`
- `hathor_stale_blocks.csv`
- `hathor_unknown_blocks.csv`
- `hathor_error_blocks.csv`
- `hathor_validated_stales.csv`

The validated file is the `VALID`-only projection consumed by
`load_hathor_stales()`. The error-block file alone adds `rules_violated`; the
remaining files use the standard evidence schema.

## 4. Published recovery result

The retained corpus covers every Hathor height from 0 through 6,593,796:
6,593,797 terminal height records. It contains 6,532,372 version-3
observations, partitioned exactly into 6,279,947 `near`, 3,658 `canonical`, 6
`stale`, 248,760 `unknown`, and 1 `error_block` record. The remaining 61,425
terminal rows are non-version-3 blocks.

The Monitor-facing Hathor file contains the 3,658 canonical rows and all 6
`VALID` direct stales. The strict/weak rerun processed all 248,760 unknown rows,
decoded a BIP34 candidate height for 1,304 of them, and found no strict or weak
observations. The error block is published
through the separate error-observation aggregate: Hathor height 756,587
witnessed Bitcoin height 649,674 with
`rejection_reason=bip34_coinbase_height_missing`.

The publication is an offline projection of the authenticated August 2026 run,
not a new acquisition or Bitcoin RPC classification. Classification manifest
`3698483c1ef4d2bfb33e03df01639eeefb2dad42df0ae0cb9fe0b074c775dce8`
binds the retained category files; frozen classifier contract
`f73f5955a1473246ba291b0d9232466868267a3c0e773773089193d46cd418c6`
identifies the executed source snapshot. The projection removes a retired
diagnostic field while preserving row order, identities, evidence, verdicts,
and source provenance.

The six accepted direct-stale candidates are already covered by upstream or
chronologically earlier sibling chains, so Hathor contributes no
chronologically novel accepted candidate under the project's first-claim
convention. The convention is a reproducible attribution rule, not a claim
that the earlier chain observed the event first in real time.

## 5. References

- [Hathor RFC 0006, pinned revision](https://github.com/HathorNetwork/rfcs/blob/492c4fd6b9f1c4ff4e8058c9f70d94184d7cd40d/text/0006-merged-mining-with-bitcoin.md)
- [Hathor system specifications](https://docs.hathor.network/references/system-specs/)
- [Hathor public network endpoints](https://docs.hathor.network/references/networks/public/)
- Hathor API evidence at heights [60,274](https://node1.mainnet.hathor.network/v1a/block_at_height?height=60274), [60,275](https://node1.mainnet.hathor.network/v1a/block_at_height?height=60275), and [100,000](https://node1.mainnet.hathor.network/v1a/block_at_height?height=100000)
- `docs/auxpow-recovery.md`
