# Pool attribution

This repository holds the merge-mining evidence base and the pool-attribution
layer built directly on top of it: the code that turns a Bitcoin coinbase into
a mining-pool label, and an export that labels this repo's own recovered
evidence (the AuxPoW-recovered direct stales, the stale descendants, and the
RSK observations). It does not label the upstream stale-block census, and it
does not hold the stale-rate analysis that consumes labels; see
[Scope boundary](#scope-boundary). Attribution
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
`merge_stale_sources` combines the AuxPoW-recovered direct stales in the
committed loader inputs with the stale descendants in
`data/stale_descendants.csv`, deduplicating by
`(height, hash)`. When two chains observed the same header, the first record
wins and the other's coinbase fields are carried onto it, so the merged
record stays attributable whichever chain supplied the coinbase. Competing
same-height stale hashes are distinct events and both are kept. (The same
function also handles the upstream census when the companion analysis repo
builds its combined census-plus-recovered set; this repo's own export does
not include census rows.)

`tag_stale_blocks` then labels each record, preferring a raw block from the
fetched census clone's `blocks/` directory where one archives a header we
witnessed, and otherwise using the carried AuxPoW coinbase
fields. RSK rows enter tagging untagged like every other record (their loader
returns header identity only); the historical registry label is joined
afterwards: any merged row whose `(height, hash)` matches an accepted RSK
stale observation and whose coinbase evidence produced no attribution
receives the label, regardless of which source's row survived the merge, so
coinbase evidence always wins over the historical registry. The `has_bin` column records which coinbase path a row took.

## RSK: historical labels only

RSK's merge-mining proof does not expose the Bitcoin parent coinbase, so RSK
rows usually cannot be attributed by the process above (the exception is an
RSK-witnessed header whose coinbase another chain carried, grafted in the
merge; coinbase evidence then wins). After tagging, rows matching an accepted
RSK stale observation by `(height, hash)` and still unattributed
are labelled from the historical `pool_label` column of the committed
RSK loader input, itself derived from `results/rsk_pool_registry.csv` by
`rsk_miner` address. That registry is a
historical snapshot (see [`chains/rsk.md`](chains/rsk.md)), and labels derived
from it surface only with `attribution_basis=rsk_historical`: they are
preserved as historical evidence, never reported as a current attribution
result.

## Dual attribution: tag owner and template producer

Since roughly 2021, proxy pooling and template sharing have decoupled the
coinbase tag from the entity that built the block. 0xB10C's stratum-job
measurements show near-identical templates across nominally distinct pools,
and stratum endpoints serving jobs that carry another pool's coinbase tag,
with the resulting cluster at a large share of network hashrate. Under proxy
pooling the coinbase tag misidentifies who built a block, and therefore who
won or lost a propagation race.

Every attributable block therefore carries two labels: the tag-owner `pool`
from the coinbase, and, where the evidence supports it, a `template_producer`
folded in by `src/stale_blocks_analysis/template_producers.py`. Both are
kept; neither replaces the other.

The fold applies only to labels that came from an actual tag observation
(scriptSig or OP_RETURN). A payout-address match observes no tag, and an
`rsk_historical` label has no coinbase behind it, so both go into the
`template_producer` column unchanged.

Each fold row also has an end height. The folds rest on measurements from
specific periods, and nothing here knows whether a proxy arrangement
continued after the cited data ends, so a tag from a later block is left
as-is until newer published measurements extend a row.

Non-custodial-template pools (Ocean.xyz's DATUM model, P2Pool) are not table
rows at all: their tags are left as-is. Every row in the table is a measured
proxy relationship between two named pools; the non-custodial
characterization is recorded here as prose.

How the two labels are reported against each other, and the threats to
validity attaching to both, belong to the methodology in the companion
`stale_rate_analysis` repo (not yet published).

## Export contract

`python -m stale_blocks_analysis.attribution` (or `just attribute`) labels
the merge-mining-recovered stale corpus and writes the export to
`results/analysis/pool-attribution/stale-block-attributions.csv`.

It first checks that the fetched block archive is complete, comparing what
is on disk against what the clone tracks at its current commit, because a
missing binary downgrades that row to AuxPoW-only evidence with nothing
visible in the output. Pass `--allow-partial` to attribute from an
incomplete archive anyway; the sidecar records that choice and the counts.

The export columns are:

```
height,hash,source,pool,template_producer,attribution_basis,has_bin
```

`attribution_basis` is one of `coinbase`, `rsk_historical`, or `unattributed`,
so a consumer can always tell what kind of evidence produced a label.

A `stale-block-attributions.meta.json` sidecar records what produced the
labels: the pinned and actual commits (plus dirty state) of both fetched
clones and of this repository, the requested height floor, per-basis row
counts, and content fingerprints of everything the run reads. Those
fingerprints cover the pool dataset, the block binaries, and this
repository's own consumed files (the committed loader CSVs, the descendant
and error-block inputs, and the attribution modules), so two runs from the
same commit with different local edits are still distinguishable.

The registry is read from its working tree on every run, since a local fork
is a supported workflow. A run whose registry is not the clean committed pin
is flagged on stderr and identified in the sidecar.

The export is a gitignored, regenerable run product under
`results/analysis/`, and deliberately not a committed dataset for now: the
registry pin and the loader inputs it derives from are committed, and the
export is reproducible from them together with the recorded registry state.

## Scope boundary

The observed-versus-expected stale-rate analysis is not part of this
repository, and neither is labelling the upstream census. This repo needs the
census for deduplication, novelty accounting, and upstreaming, but has no use
of its own for census labels.

The combined census-plus-recovered stale set the analysis works over is
assembled and labelled in the companion `stale_rate_analysis` repo, using
this repository's functions. That repo also maintains the propagation-era
scheme, the pool size tiers, the main-chain denominators, and the study
methodology and its threats to validity, and consumes this repository as a
same-trust-domain library. The boundary is enforced in the
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
