# Analysis diagnostics

This directory documents the namespace used for research diagnostics. The
row-level files currently live in the private archive rather than this public
repository. They are grouped by the question they answer, not by the recovery
campaign that produced them:

- `btc-stale-relevance/` refines unknown rows into strict, weak, excluded, or
  pending BTC-stale relevance buckets.
- `stale-ancestry/` reconciles unknown headers against known stale roots and
  validates stale-fork descendants.
- `unknown-origin/` contains H1/H2 substrate tests, dangling-root review, and
  cross-chain unknown-root comparisons.
- `fork-reconstruction/` contains candidate multi-block Bitcoin header-chain
  reconstructions rooted in stale or unknown evidence.
- historical pool-identification audits over unknown rows are private and are
  not a current public pipeline stage.

Most row-level diagnostics depend on private full classifier inventories and
can be large, so they are regenerated or retained in the private chain archive
rather than committed. Compact public inputs and final outputs remain under
`data/`, `results/per-chain-novelty/`, `results/strict-weak-orphans/`, and
`results/monitor-evidence/`.

These diagnostics do not upgrade `validation_status=VALID` into a full Bitcoin
block-validity claim. Accepted direct-stale rows pass the declared
available-evidence header-context gate, including active-parent linkage,
expected `nBits`, median-time-past, historical minimum block version, and the
coinbase scriptSig length and BIP34 prefix when available. Most rows do not
include a complete Bitcoin block or historical chain state, and RSK lacks the
coinbase evidence needed for the two coinbase-dependent checks. See
[`docs/data-validity.md`](../../docs/data-validity.md).
