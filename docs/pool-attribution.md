# Pool attribution

This repository holds the merge-mining evidence base and the pool-attribution
layer built directly on top of it: the code that turns a Bitcoin coinbase into
a mining-pool label, the stale-source merge that layer runs over, and a
per-stale-block attribution export. It does not hold the stale-rate analysis
that consumes those labels; see [Scope boundary](#scope-boundary). Attribution
is a separate pass over loaded records, never part of acquisition or recovery:
the loaders in `stale_blocks.py` do not import the pool dataset, so recovery
stays reproducible without it.

## Registry-pinned coinbase attribution

`src/stale_blocks_analysis/pool_identification.py` is the single entry point
for coinbase-based identification. It reads a clone of
`bitcoin-data/mining-pools` (one JSON per pool, carrying that pool's coinbase
tags and payout addresses) fetched by `scripts/fetch-data.sh` and pinned at an
exact commit in `data-sources.tsv`, the same reproducibility contract the
upstream stale-block census uses, so a label is always traceable to the
registry state that produced it.

Identification runs in a fixed order:

1. **scriptSig tags**, matched longest-first so a longer, more specific tag
   wins over a substring of it.
2. **Coinbase `OP_RETURN` outputs**, scanned for the same registry tags, which
   is where some pools place their marker instead of the scriptSig.
3. **Payout addresses**, matched by hash160 (P2PKH, P2SH, P2WPKH), a last
   resort for tagless miners.

A coinbase that matches nothing is retained as unknown rather than silently
dropped. Registry coverage is thinner for earlier years, so an unknown label
is partly evidence about the registry.

## Stale-source merging and tagging

`src/stale_blocks_analysis/stale_merge.py` prepares the record set.
`merge_stale_sources` combines the upstream `bitcoin-data/stale-blocks` census
with the AuxPoW-recovered direct stales in the committed loader inputs and the
stale descendants in `data/stale_descendants.csv`, deduplicating by
`(height, hash)`. The upstream row wins on an exact duplicate, but the AuxPoW
coinbase evidence is carried onto it so the merged record stays attributable
where no full block is on hand. Competing same-height stale hashes are distinct
events and both are kept.

`tag_stale_blocks` then labels each record, preferring a locally available raw
block as the coinbase source and otherwise using the carried AuxPoW coinbase
fields. RSK rows enter tagging untagged like every other record (their loader
returns header identity only); the historical registry label is joined
afterwards, onto rsk-sourced rows whose coinbase evidence produced no
attribution, so grafted coinbase evidence always wins over the historical
registry. The `has_bin` column records which coinbase path a row took.

## RSK: historical labels only

RSK's merge-mining proof does not expose the Bitcoin parent coinbase, so RSK
rows usually cannot be attributed by the process above (the exception is an
RSK-witnessed header whose coinbase another chain carried, grafted in the
merge; coinbase evidence then wins). After tagging, the remaining rsk-sourced
rows are labelled from the historical `pool_label` column of the committed
RSK loader input, itself derived from `results/rsk_pool_registry.csv` by
`rsk_miner` address. That registry is a
historical snapshot (see [`chains/rsk.md`](chains/rsk.md)), and labels derived
from it surface only with `attribution_basis=rsk_historical`: they are
preserved as historical evidence, never reported as a current attribution
result.

## Dual attribution: tag owner and template producer

Attribution is dual. Every attributable block carries a *tag-owner* label from
the coinbase and, where the evidence supports it, a *template-producer* label
folded in by `src/stale_blocks_analysis/template_producers.py`. The fold
applies only to labels derived from an actual coinbase-tag observation
(scriptSig or OP_RETURN): a payout-address-only identification observes no
tag, and an `rsk_historical` label is a
miner-address attribution with no coinbase behind it, so both are carried
into the `template_producer` column unfolded rather than upgraded to a
template-producer claim. Fold windows also end at their evidence horizon: a
proxy relationship is a positive claim, so a tag dated after the last
measurement the table cites passes through unfolded until newer evidence
raises the cap. Non-custodial-template pools (Ocean.xyz's DATUM model,
P2Pool) are not table rows at all: their tags pass through unchanged, since
the table carries only measurement-backed cross-entity proxy relationships,
and the non-custodial characterization is recorded here as prose. The two have
diverged materially since roughly 2021 to 2023, because proxy pooling and
template sharing decouple the coinbase tag from the entity that built the
block: 0xB10C's stratum-job measurements show near-identical templates across
nominally distinct pools and document stratum endpoints serving jobs that carry
another pool's coinbase tag, with the resulting cluster at a large share of
network hashrate. Under proxy pooling the coinbase tag is systematically wrong
as a measure of who built a block, and therefore of who won or lost a
propagation race, so both labels are carried and neither is discarded in favour
of the other. The full treatment, including how the two are reported against
each other and the threats to validity attaching to both, belongs to the
methodology in the companion `stale_rate_analysis` repo (a separate analysis
repo, not yet published).

## Export contract

`python -m stale_blocks_analysis.attribution` (or `just attribute`) writes the
per-stale-block attribution export to
`results/analysis/pool-attribution/stale-block-attributions.csv`:

```
height,hash,source,pool,template_producer,attribution_basis,has_bin
```

`attribution_basis` is one of `coinbase`, `rsk_historical`, or `unattributed`,
so a consumer can always tell which evidence path produced a label. A
`stale-block-attributions.meta.json` sidecar records the provenance the labels
came from: the pinned and actual commits (plus dirty state) of both fetched
clones, this repository's own commit and dirty state (the committed loader
inputs and the attribution code are inputs too), the requested height floor,
the pool dataset's content fingerprint, and per-basis row counts. The
registry is read from its working tree on every run, since a local fork is a
supported workflow, so a run whose registry is not the clean committed pin is
flagged on stderr and identified in the sidecar. The export
is a gitignored, regenerable run product under `results/analysis/`, and
deliberately not a committed dataset for now: the registry pin and the loader
inputs it derives from are committed, and the export is reproducible from them
together with the recorded registry state.

## Scope boundary

The observed-versus-expected stale-rate analysis is not part of this
repository. The propagation-era scheme, the pool size tiers, the main-chain
denominators, and the study methodology and its threats to validity are
maintained in the companion `stale_rate_analysis` repo, which consumes this
repository as a same-trust-domain library. The boundary is enforced in the
code as well as by convention: this repository intentionally carries no era
constants and no era vocabulary, and the attribution API takes `min_height` as
a caller-supplied parameter rather than deriving a height window from an era
definition of its own.

## References

- 0xB10C. "Block Template Similarities between Mining Pools," September 2024,
  <https://b10c.me/observations/12-template-similarity/>. The
  template-producer evidence base.
- 0xB10C. "Bitcoin Mining Centralization in 2025," April 2025,
  <https://b10c.me/blog/015-bitcoin-mining-centralization/>. Proxy-pooling
  hashrate estimates.
- `bitcoin-data/mining-pools`,
  <https://github.com/bitcoin-data/mining-pools>. The tag and payout-address
  registry.
