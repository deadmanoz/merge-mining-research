# Error blocks: consensus-invalid full-PoW Bitcoin blocks witnessed via merge mining

An **error block** is a full-proof-of-work Bitcoin block, witnessed via
merge-mining evidence, that *would have been* a stale/orphan contender except
that the block itself violates a consensus rule. It lost no race; it was never
eligible to race. The proof of work is real (the header hash meets the Bitcoin
target in force at the claimed position), the AuxPoW commitments are real, but
the block is consensus-invalid for a specific, mechanically re-checkable
reason.

The category is defined by three necessary conditions, all re-derived from
committed bytes:

1. **Full proof of work.** The 80-byte header's sha256d digest meets the
   Bitcoin target in force at the claimed position. A header that merely fails
   the PoW *target* is not an error block; it is a share / `near` row, a
   different category that is permanently out of scope. This distinction is
   re-verified per row via `hash_meets_btc_difficulty`, never inherited from
   an old rejection label.
2. **AuxPoW-witnessed.** The header is recovered from a merge-mining proof
   embedded in a sibling chain's block (or, for one row, from merge-mining
   monitor live capture of the same commitment).
3. **At least one named, mechanically re-checkable consensus violation.** The
   block fails a rule that can be re-derived offline from the committed header
   and coinbase bytes plus committed canonical-chain context. Rules that
   require live network state are not sufficient on their own (see the
   future-limit note below).

Error blocks are catalogued in `data/error-blocks/error_blocks.csv` and carry
the primary `classification` value `error_block` (see
[`data-reference.md`](data-reference.md) "Value vocabularies"). The dataset is
simultaneously the rich evidence record and the exact-key exclusion gate: it
supersedes the former `data/stale_block_exclusions.csv` overlay, and public
loaders, upstream novelty calculations, the upstream sidecar builder,
full-evidence and relevance exports, and unknown-ancestry reconciliation all
derive the exclusion key set from its `classification == "error_block"` rows
via `src/stale_blocks_analysis/error_blocks.py`.

## The rule set

Every rule below is a necessary Bitcoin consensus condition, so a single
failure is conclusive evidence that the block is invalid. Enforcement heights
are the constants in `stale_blocks_analysis.config`; the gates are reused from
`stale_blocks_analysis.btc_stale_validation`, never reimplemented.

| Rule token | Rule | Enforcement |
|---|---|---|
| `bip34_v2_coinbase_height_mismatch` | BIP34 coinbase-height prefix, first stage: version 2 or newer blocks must begin the coinbase scriptSig with the exact serialized height | from height 224,413 |
| `bip34_coinbase_height_mismatch` | BIP34 coinbase-height prefix, second stage: the prefix is mandatory for every valid block and version 1 is rejected | from height 227,931 |
| `bip34_block_version_below_2` | BIP34 minimum block version 2 (vocabulary-only; no committed row uses it yet) | from height 227,931 |
| `bip66_block_version_below_3` | BIP66 minimum block version 3 | from height 363,725 |
| `bip65_block_version_below_4` | BIP65 minimum block version 4 | from height 388,381 |
| `coinbase_scriptsig_length_above_100` | Coinbase scriptSig serialized length must be 2 to 100 bytes (the historical token name; the gate enforces the full 2–100 bound) | height-independent |
| `coinbase_scriptsig_length_below_2` | Coinbase scriptSig serialized length below the 2-byte minimum (the same 2–100 gate; vocabulary-only, no committed row uses it yet) | height-independent |
| `median_time_past_violation` | Block time must be greater than the median-time-past of its parent | height-independent |
| `time_below_mtp` | Block `nTime` at or below the canonical parent's median-time-past (the 946,213 class) | height-independent |
| `nbits_retarget_not_applied` | At a retarget-boundary height (`height % 2016 == 0`) the block carries the previous epoch's `nBits` instead of the newly retargeted value, while still meeting full proof of work | epoch boundaries |
| `time_beyond_future_limit` | Block `nTime` more than 2 hours beyond network-adjusted time | **not mechanically re-checkable offline** |

BIP34's two-stage rule is applied explicitly because modern Bitcoin Core buries
the deployment at 227,931 and does not replay the earlier rolling-threshold
transition for alternative historical branches.

The minimum-version gates (`bip34_block_version_below_2`,
`bip66_block_version_below_3`, `bip65_block_version_below_4`) use a hard height
cutover at the observed canonical activation heights (227,931 / 363,725 /
388,381). This is an approximation of Bitcoin Core's actual IsSuperMajority
enforcement, which required a rolling threshold of 750-of-1000 blocks to
*lock in* and then 950-of-1000 to *enforce* the new minimum version. The
approximation is exact for a direct stale, which covers every row currently in
the dataset, and exactly at the boundary as much as far past it. Core counts
the vote over the block's OWN ancestors, and a direct stale's parent is
canonical, so its 1000-block window is the same window the canonical block at
that height has and the two verdicts cannot differ. Distance from activation is
not what decides it. What decides it is whether the block's ancestry within
that window IS the canonical chain, and for a direct stale it is, by the same
node lookup that made it a direct stale in the first place.

The cutover can therefore diverge from Core in one case, not two: a stale-fork
block whose branch left the canonical chain *before* activation. Core judges it
against the rolling threshold state on its own fork, where a different version
mix can give a different verdict. That is the descendant path, and it is why
`descendant_consensus_rules` refuses to promote a descendant on a version rule
alone. The negative-version headers produced by
version-rolling/overt ASICBoost are a genuinely subtle instance of the same
problem: their `nVersion` reads as below the minimum under a naive comparison,
but the rolling-threshold and version-bit semantics make the cutover verdict
unreliable for them. A future exact IsSuperMajority implementation is tracked
as GitHub issue #21; until it lands, treat the minimum-version tokens as
canonical-context verdicts, not universal ones.

The `time_beyond_future_limit` row is deliberately empty. Bitcoin's real
future bound is network-adjusted time plus two hours, and network-adjusted
time is not reconstructable from committed offline evidence. The canonical
parent's block time is only a neighbor-evidence approximation, so a modest
excess over parent time + 2h is normal (a block 2–7 hours after its parent is
ordinary under the real rule), not proof of a violation. The one exception —
child-chain commit-time evidence showing the `nTime` more than two hours
beyond the commit time itself — did not occur in the swept corpus. By
contrast, `time_below_mtp` and `median_time_past_violation` *are*
mechanically re-checkable, because the canonical parent's median-time-past is
committed canonical-chain context. This is why the dataset contains a
`time_below_mtp` row (946,213) and a `median_time_past_violation` row
(380,992) but no `time_beyond_future_limit` rows. See the time-rule sweep
report for the full resolution.

`nbits_retarget_not_applied` is distinct from a plain `nBits mismatch`
rejection at a non-boundary height. The latter is the contamination gate's
target class (a share/`near` row whose difficulty context is not Bitcoin's),
not an error block. The error-block case is specifically the
retarget-not-applied at an epoch boundary where the header still meets full
proof of work at the real Bitcoin difficulty with a wrong `nBits` field.

## The dataset

`data/error-blocks/error_blocks.csv` is the single source of truth: one
committed consolidated file, because error blocks are chain-independent (one
invalid Bitcoin block is witnessed by many sibling chains, and the exclusion
gate is global). Columns, ordered for the loader:

```
height, hash, btc_prev_hash, btc_header_version, btc_time, btc_bits,
expected_nbits, btc_header_hex, coinbase_height, coinbase_scriptsig_hex,
source_chains, source_child_observations, classification, rejection_reason,
rules_violated, first_observed_child_time, provenance
```

`hash` is in display order; byte order is handled via
`stale_blocks_analysis.auxpow_chainid` helpers. `classification` is
`error_block` for every data row, and the gate keys off that value directly —
there is no `exclusion_scope` column, because membership in the dataset already
means consensus-invalid. `rejection_reason` is the primary (first) failure in
the ordered gate composition; `rules_violated` is the pipe-joined full set.
The `btc_header_version`, `btc_time`, `btc_bits`, and `coinbase_height`
columns are convenience/audit values derived from `btc_header_hex` and
`coinbase_scriptsig_hex` by the builder at build time; they are kept so the
CSV is human-auditable without re-parsing, and the byte-identical rebuild
guarantees they match the header bytes.
`provenance` records the artifact each row's facts came from.

A committed sidecar, `data/error-blocks/mtp_context.csv`, carries the
canonical parent's median-time-past for the `time_below_mtp` and
`median_time_past_violation` rows, keyed by `(height, hash)`, so those rules
re-derive offline.

### Composition and per-rule counts

The dataset holds **33 rows** (33 distinct `(height, hash)` blocks), spanning
Bitcoin heights 225,013 through 946,213. Thirty-one are carried over from the
former exclusion overlay; height 946,213 (`time_below_mtp`, from
merge-mining-monitor live evidence) and height 717,696
(`nbits_retarget_not_applied`, found by the rejected-row sweep) were added by
this work. Per-rule counts by primary `rejection_reason`:

| Rule | Rows |
|---|---:|
| `bip34_v2_coinbase_height_mismatch` | 12 |
| `bip34_coinbase_height_mismatch` | 9 |
| `bip65_block_version_below_4` | 5 |
| `bip66_block_version_below_3` | 3 |
| `coinbase_scriptsig_length_above_100` | 1 |
| `median_time_past_violation` | 1 |
| `time_below_mtp` | 1 |
| `nbits_retarget_not_applied` | 1 |
| **Total** | **33** |

Because one invalid block is witnessed by several sibling chains, the 33
blocks produce 73 per-chain observations: namecoin 32, devcoin 16, ixcoin 13,
rsk 5, syscoin 2, elastos 1, emercoin 1, groupcoin 1, i0coin 1, unobtanium 1.
Per-chain observation views are generated as diagnostics (see "Per-chain
views" below).

The former overlay's 32nd row — height 656,478,
`exclusion_scope=direct_stale_only` — is not an error block and is not carried
into this dataset. It is a valid `stale_descendant` that was double-catalogued;
it now lives in exactly one place (`data/stale_descendants.csv`) with no
exclusion guard.

## Evidence standard

No row enters on an old label. Every violation is re-derived from committed
bytes by the offline validator, `scripts/analysis/validate_error_blocks.py`,
which is wired into `tests/` so it runs in CI. For every row it re-checks,
with no live RPC:

1. full proof of work via `hash_meets_btc_difficulty` (separating error
   blocks from shares);
2. each rule token in `rules_violated`, by re-running the matching gate in
   `btc_stale_validation` against the committed header/coinbase bytes;
3. `expected_nbits` against the committed `data/bitcoin-epoch-reference/`
   retarget table; and
4. `time_below_mtp` and `median_time_past_violation` against the committed
   `mtp_context.csv` sidecar.

A row that fails re-derivation fails the test suite. The builder
(`scripts/prep/build_error_blocks.py`) and the sweeps fail closed when a
required private input is absent, requiring `--allow-partial` plus a
disposable output directory for any diagnostic run — the same contract as the
ancestry reconciliation and `just monitor-evidence`.

The offline validator deliberately does NOT verify active-parent placement:
it does not check that a row's claimed parent (`btc_prev_hash`) is a
canonical/active Bitcoin block. That check requires canonical chain context
(a live RPC view of the active chain) and is enforced by the online
classification pipeline at classification time, not by the offline
re-derivation. The offline validator's job is to prove the named consensus
violation from the committed bytes; active-parent/canonical placement is a
separate, online gate.

## Classification-time labelling

Error blocks are now an outcome of the normal classification pass, not a
separate discovery step. `route_rejected_stale_rows`
(`src/stale_blocks_analysis/btc_classify.py`) sorts every gate-rejected stale
candidate by what the rejection actually means, re-deriving the broken rules
from the row's own bytes via `consensus_violations` rather than parsing the
verdict string:

The three meanings are ranked, not tested in whatever order is convenient,
because one row can satisfy several of them and the weakest claim has to win
(`rejection_route` owns the order):

1. a placement rejection (the predecessor is not on the active chain) makes the
   row `unknown` first. Without an active-chain parent the row's height was
   never established, so every height-dependent rule re-derived from its bytes
   is unreliable;
2. a contamination rejection (the difficulty is not Bitcoin's at that height)
   also makes the row `unknown`, and it outranks a broken rule: a foreign
   SHA-256 chain's header is not an invalid Bitcoin block, even when its bytes
   would break a Bitcoin rule. Contamination is read off the persisted
   `expected_nbits` rather than the verdict string, because the later
   header-context gate can overwrite an `nBits` REJECTED and erase the only
   trace of it. The one exception is `nbits_retarget_not_applied`, whose bits
   are the previous epoch's by definition, the sanctioned `nBits` mismatch that
   really is a Bitcoin consensus violation;
3. only then does a proven consensus violation make the row
   `classification=error_block`, written to the `data/<chain>_error_blocks.csv`
   sibling of the stale inventory (gitignored, like its four bucket peers). That
   file carries its peers' columns plus the pipe-joined `rules_violated`, the
   full derived rule set: the rules are the evidence for the claim, and
   `validation_status` names only the gate that fired first, which for
   `nbits_retarget_not_applied` is a generic `nBits` mismatch. The four peers,
   including the `*_validated_stales.csv` loader input, keep their schema;
4. a rejection whose evidence proves nothing stays a rejected stale, as does
   one where the canonical `nBits` was never recorded, since nothing then shows
   the header is Bitcoin's at that height.

The same routing runs in the shared driver (16 chains), the four classifiers
that call the gate directly (elastos, coiledcoin, geistgeld, groupcoin), the
namecoin/i0coin classifier, the RSK classifier (which can only ever produce
the version, median-time-past, and retarget rules, since its proof exposes no
parent coinbase), and Hathor Phase C, whose re-routed unknowns go to the
`_unknown_blocks` peer of its Phase B input. The stale-descendant
reconciliation applies the identical derivation to its rejected candidates
(`descendant_consensus_rules` in
`scripts/analysis/reconcile_unknown_stale_ancestry.py`), judging only rows
whose supplied header authenticates against the claimed hash and whose path,
proof of work, and canonical bits all verified; the ones it does judge leave
`data/stale_descendants.csv` entirely for its `_error_blocks` peer, so the
descendant sidecar only ever carries `stale_descendant` rows. Hathor Phase A is
deliberately outside this machinery (import-free, runs on the archive host),
and Phase B feeds Phase C using the shared verdict vocabulary.

Every gate rejection is still counted, whichever bucket the routing moved the
row into: `write_classifier_outputs` returns the total as `rejected` plus the
`rejected_stale` / `rejected_error_block` / `rejected_unknown` breakdown.

The committed dataset below remains the publication surface and exclusion
gate; consolidating classifier-emitted rows into it across chains is the
builder's job, not the classifier's.

## The sweeps

Four sweeps under `scripts/analysis/`, sharing `scripts/analysis/_sweep_common.py`,
hunted for error blocks beyond the carried-over set, and they predate
classification-time labelling: they remain the retroactive path for archived
inventories produced before the routing existed. Each re-verifies full
proof of work per row and writes a dated report to
`results/analysis/error-blocks/`, including negative results.

- **Rejected-row sweep** (`sweep_error_blocks_rejected_rows.py`;
  [report](../results/analysis/error-blocks/rejected-rows-report.md)):
  re-examined all 45 `REJECTED:` rows across 8 reachable classified
  inventories. Found the 717,696 block — rejected for an `nBits` mismatch, yet
  meeting the canonical expected target at a retarget boundary — which was
  promoted into the dataset as `nbits_retarget_not_applied`. No other new
  error blocks.
- **Time-rule sweep** (`sweep_error_blocks_time_rule.py`;
  [report](../results/analysis/error-blocks/time-rule-report.md)): applied the
  time rules to stale-classified and BIP34-height unknown rows across 19
  inventories. Found **0** `time_below_mtp` violations among
  trustworthy-height candidates (the 946,213 class does not recur in the
  historical inventories) and resolved all 15 `time_beyond_future_limit` flags
  as late-mined, not future-dated (**0** violations) — establishing that the
  future-limit rule is not mechanically re-checkable offline.
- **Version/BIP sweep** (`sweep_error_blocks_version_bip.py`;
  [report](../results/analysis/error-blocks/version-bip-report.md)):
  proactively applied the minimum-version and BIP34 rules to every catalogued
  stale candidate across 45 inventories, including rows currently accepted as
  VALID stales. Found **0** new error blocks: every full-PoW violation is
  already catalogued, and no accepted VALID stale is an error block.
- **Coinbase-form sweep** (`sweep_error_blocks_coinbase_form.py`;
  [report](../results/analysis/error-blocks/coinbase-form-report.md)): applied
  the coinbase scriptSig 2–100 length and BIP34 height-serialization rules
  across 45 inventories. Confirmed the single
  `coinbase_scriptsig_length_above_100` member (277,975) is real: across
  32,661 full-PoW candidates it is the only distinct above-100 block (two
  observations of the same block, via devcoin and ixcoin), and no
  below-2 case exists anywhere in the corpus.

## Per-chain views

`scripts/reports/report_error_blocks_by_chain.py` reads the consolidated
dataset and writes per-chain observation views under
`results/analysis/error-blocks/by-chain/` — one CSV per chain, keyed off
`source_chains` / `source_child_observations`, so a row appears in each chain
that witnessed it. These are generated diagnostics for readability, not
committed loader inputs; regenerate them with `just error-blocks-report`.

## Relationship to other categories

An error block is not a stale block and not an orphan: it was never eligible
to race, so it is never a stale/orphan contender. It is also not a `near` row:
a `near` row fails the PoW target and was never a Bitcoin block at all, while
an error block meets full proof of work and fails a consensus rule. The
primary `classification` axis keeps these distinct: `canonical`, `stale`,
`unknown`, `stale_descendant`, `near`, and `error_block`. Adding `error_block`
is a breaking vocabulary change for the merge-mining-monitor importer and its
ported relevance classifier; renames and additions must land in lockstep with
the monitor (see [`upstreaming.md`](upstreaming.md)).
