# Research directions

Merge mining lets a sibling chain reuse hashing work performed for Bitcoin, and
in doing so can preserve evidence about Bitcoin mining outside Bitcoin's own
canonical chain. Namecoin-style auxiliary proof of work (AuxPoW) stores the
Bitcoin parent header, coinbase transaction, and inclusion proofs on the sibling
chain. Other systems use chain-specific commitment formats. Dozens of chains
have used one of these approaches since Namecoin activated AuxPoW in 2011,
leaving a large, independently hosted, and often long-lived corpus of Bitcoin
mining artifacts to study.

This repository treats that corpus as a research substrate for questions about
Bitcoin mining generally: mining pools, block propagation, the canonical-versus-
stale record, and the structure of merge mining itself. The scope is
intentionally broad and not limited to stale blocks. Each strand is developed as
a coherent body of tooling, datasets, and methodology documentation, sharing
the parent-header parsing and Bitcoin-classification modules where applicable.

## What the evidence records

Each Namecoin-style AuxPoW proof carries a full 80-byte Bitcoin parent header
and the parent coinbase transaction. Other merge-mining schemes preserve a
different subset of the relationship between the Bitcoin work and the sibling
chain. Where a parent header is available, it usually belongs to a
**canonical** Bitcoin block and occasionally to a valid **stale** block that did
not remain in the canonical chain. Both are useful evidence:

- The canonical parents are a merge-mining-observed view of ordinary Bitcoin
  mining: which blocks were built on, by which pool, when, across the slice of
  Bitcoin history a given chain merge-mined.
- The stale parents are the rarer case: Bitcoin blocks with little surviving
  public evidence, preserved because a miner committed the non-canonical header
  into a sibling chain.

## Current foundations

### Stale-block recovery

The most developed strand. It recovers stale Bitcoin blocks from the AuxPoW
commitments of merge-mined chains and preserves the recovered coinbase and
miner evidence needed for later attribution. The recovered evidence provides a
basis for later work on mining-pool behaviour and block propagation. See
[`auxpow-recovery.md`](auxpow-recovery.md) and the per-chain provenance under
[`chains/`](chains/).

### Bitcoin coinbase commitment census

The canonical-side counterpart scans Bitcoin coinbase transactions for known
commitment patterns, including the AuxPoW `0xFABE6D6D` magic, chain-specific
`OP_RETURN` tags, pool tags, and the SegWit commitment. The public release
contains the marker registry in
`src/stale_blocks_analysis/coinbase_markers.py` and its focused tests. The large
generated census database is not committed, and broader analysis of the scan is
future work.

## Planned research directions

These questions frame the next uses of the evidence base. They are research
directions, not findings reported by the initial public release.

- **Pool share and stale-block incidence.** Are smaller mining pools
  overrepresented among recovered stale blocks relative to their share of
  canonical Bitcoin blocks at corresponding heights? The planned
  observed-versus-expected comparison will define pool size from canonical
  block share over matched height ranges, then make its sensitivity to the
  chosen ranges, pool attribution, incomplete recovery coverage, changing pool
  identities, and small samples explicit. Time-period or propagation-era splits
  will be introduced only where the boundary is technically justified and the
  sample supports it.
- **Mining-proxy and aggregator analysis.** AuxPoW pairs a Bitcoin coinbase with
  a sibling-chain coinbase for the same work. Comparing the two sides can reveal
  evidence consistent with a merge-mining proxy or aggregator between the
  Bitcoin pool and the sibling chain, and how that relationship changes over
  time.
- **Selfish-mining and reorg analysis.** Recovered stale and unknown headers,
  together with their timing, are raw material for studying withholding and
  reorg behaviour that the canonical chain alone does not preserve. Neither
  classification is, by itself, evidence of selfish mining.
- **Mining-pool operations analysis.** The marker census over the canonical
  chain can show how pools adopt, change, and retire merge-mining arrangements.

## Relationship to the merge-mining-monitor

A separate project, the merge-mining-monitor, turns the same class of evidence
into a live monitoring service backed by a database and a dashboard. It tracks
both canonical and stale Bitcoin blocks across the merge-mined chains it
follows. This repository is the research and data side: methodology, reproducible
tooling, and published datasets. The monitor consumes datasets produced here as
historical inputs, and the two projects deliberately share a classification
taxonomy: the monitor's BTC-orphan classifier is a port of this repository's
relevance classifier, and the committed monitor-facing exports under
`results/monitor-evidence/` use the shared canonical, validated-stale,
stale-descendant, and strict/weak BTC-orphan vocabularies. See the
[dataset reference](data-reference.md) for their exact definitions.
