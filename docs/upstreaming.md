# Upstreaming to bitcoin-data/stale-blocks

This repository contributes newly recovered Bitcoin stale-block headers to
[`bitcoin-data/stale-blocks`](https://github.com/bitcoin-data/stale-blocks).
The exact upstream baseline used by this project is pinned in
`data-sources.tsv` so novelty and deduplication results remain reproducible.

Mining-pool attribution is planned as a later research phase. It is not part of
the current analysis pipeline or upstreaming workflow.

## What gets contributed

A direct stale block qualifies for upstream contribution only when all of the
following hold:

- The serialized 80-byte header hashes to the recorded Bitcoin block hash and
  satisfies the proof-of-work target encoded in its `nBits` field.
- Its `nBits` equals Bitcoin's canonical expected `nBits` at that height. This
  is the contamination gate that excludes easier BCH/BSV-family headers.
- Bitcoin Core does not report the header itself as canonical, but does report
  its previous block hash as canonical. This establishes a direct stale rather
  than merely a full-difficulty non-canonical header.
- The committed row carries an accepted `VALID` validation status.

A stale descendant may also qualify when the same header, hash, proof-of-work,
and expected-`nBits` checks pass and its validated ancestry reaches a known
stale root. These rows carry `classification=stale_descendant` and
`validation_status=VALID_STALE_DESCENDANT`.

In both cases, the hash must be absent from the pinned upstream
`data/stale-blocks/stale-blocks.csv` and from the other pending contribution
rows. `scripts/reports/build_upstream_stale_sidecar.py` derives this set from
the committed validated inputs rather than relying on manual row removal.

## CSV schema

```csv
height,hash,header
```

`height` and `hash` identify the stale Bitcoin header. `header` is its
80-byte serialization as 160 hexadecimal characters. It lets reviewers verify
the header hash and encoded proof-of-work target without rerunning extraction;
checking the expected target at that height still requires the canonical
Bitcoin `nBits` reference.

## Keeping the upstream pin current

The project keeps an exact commit pin instead of following a moving branch.
This gives each project commit a precise upstream baseline while making
freshness easy to check:

```bash
just upstream-check
```

The command fetches remote metadata and exits non-zero when a pin differs from
the upstream default-branch head. It does not edit `data-sources.tsv` or change
the checked-out dataset.

To move a source to the latest upstream commit deliberately:

```bash
just upstream-update stale-blocks
```

This updates the manifest to the exact current commit and checks out that
commit under `data/stale-blocks/`. Review and commit the resulting
`data-sources.tsv` diff alongside any regenerated data or documentation. The
commit hash in that diff is the upstream version referenced by the project
commit.

## Merge-mining-monitor vocabulary lockstep

The `error_block` primary `classification` value (catalogued in
`data/error-blocks/error_blocks.csv`) and the extended `rejection_reason` /
`rules_violated` vocabulary this branch introduces are a BREAKING change for
the merge-mining-monitor importer and its ported BTC-orphan relevance
classifier, which read these strings verbatim. The new rejection-reason
tokens are:

- `time_below_mtp` and `nbits_retarget_not_applied` — each has a committed
  dataset row (heights 946,213 and 717,696 respectively);
- `time_beyond_future_limit` — vocabulary-only (no committed row; the rule is
  not offline-recheckable, so the offline validator rejects any row carrying
  the token);
- `bip34_block_version_below_2` and `coinbase_scriptsig_length_below_2` —
  vocabulary-only correctness hardening (no committed row uses them yet).

Landing this PR means the monitor will need a corresponding update to handle
`error_block` and the new tokens; until that update lands, the monitor may
reject or misclassify these rows. The monitor-side change is a deliberate,
accepted follow-up in that repository: merging this PR constitutes accepting
that the monitor must be updated to match (break-then-fix).

## Contribution and post-merge workflow

1. Run `just upstream-check`. If upstream has moved, run
   `just upstream-update stale-blocks` and regenerate the sidecar before
   preparing the contribution, so the PR contains only rows still absent from
   the latest baseline.
2. Fork `bitcoin-data/stale-blocks`, create a feature branch, merge the rows
   from `data/new_stale_blocks_for_upstream.csv` into `stale-blocks.csv`, and
   sort the complete file by descending height as upstream CI requires.
3. Submit a PR linking to the relevant chain methodology and recovery evidence.
4. After the PR merges, run `just upstream-update stale-blocks` again. This
   records the merge commit or a later upstream commit as the new baseline.
5. Run `just upstream-sidecar`. Do not delete contributed rows manually: the
   generator removes them because they now exist in the pinned upstream CSV.
6. Regenerate every result whose membership or ownership depends on the
   upstream baseline. At minimum this means the per-chain novelty CSVs and
   their cited documentation. If the known-stale set changed and the private
   classifier inventories are available, rerun unknown-stale ancestry and its
   dependent relevance and monitor-evidence exports as well.
