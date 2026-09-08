# Recover early RSK coverage in production and research

Bead: `merge-mining-research-15q`

Related bead: `merge-mining-research-9ec`

Execution status refreshed: 2026-09-08.

## High-Level Summary

Recover RSK child heights 0 through 139998 independently into the production
monitor and the research corpus. Production uses the monitor's packaged
`backfill-rsk` command through a fixed-range, resumable deploy wrapper. Research
uses one height-zero archive extraction shared with `merge-mining-research-9ec`,
then classifies every retained 80-byte Bitcoin parent header and publishes the
result through the existing uniform Monitor-evidence path.

Height 139999 is a polling acquisition floor, not a consensus or proof-format
activation. Early blocks contain three intentional shapes: the height-zero
`0x00` sentinel, 69/70-byte fallback signatures, and full 80-byte Bitcoin
parent headers. The first two are accounted as skips. The last is captured and
classified. Missing data and every other proof shape fail closed.

On 2026-09-08 the operator authorised code commits, local review and fixes,
pull requests, Codex GitHub review through merge, and then data recovery.
Claude is the selected local reviewer. The execution gates below still apply;
this authorisation does not waive validation, backups, or provenance checks.

## Objective

Close the early-RSK evidence gap in both destinations without copying the
production database into research:

1. Production contains the live `auxpow:rsk` events discoverable from RSK
   canonical blocks and advertised uncles associated with the fixed parent
   range 0 through 139998.
2. Research contains one complete, resumable, independently acquired RSK
   corpus from height 0 to a pinned tip, including canonical blocks and
   advertised uncles.
3. Research publication contains every resulting valid stale observation and
   every Bitcoin Core-confirmed canonical observation available from that
   corpus.
4. Operator evidence makes skips, retries, enrichments, and pre-existing rows
   distinguishable without pretending successful upserts are new inserts.

## Recovered Context

- The production poller never acquires below child height 139999.
  The floor must remain there for live polling, but `backfill-rsk` already
  accepts lower explicit ranges.
- RSKIP-92 activated at RSK height 729000. It does not explain the 139999
  acquisition floor.
- The dormant eight-commit monitor branch contains the real height-112829
  fixture and pre-floor regression coverage. It has been rebased without
  semantic patch drift onto current monitor `origin/main` in a dedicated
  worktree.
- The height-112829 Bitcoin parent hash is
  `00000000000002fe6f674f927a92fcd4757d30b50dee32e36b479b0c725142cd`.
  It fails its own encoded target, so the expected monitor kind is `near`.
- Production is not literally empty below the floor. One uncle-derived event
  already exists at child height 139997 because it was discovered from the
  canonical height-139999 response. Recovery must preserve and, where
  compatible, enrich such rows.
- Current monitor identity is `UNIQUE (source_id, child_block_hash)`. Exact
  compatible upserts can enrich event, RSK sidecar, and attribution state;
  contradictory evidence fails. This is not a first-writer-wins model.
- Explicit backfill traversal does not write the production poll cursor. The
  live RSK poller can still advance it normally while the repair runs, so the
  acceptance rule is monotonic continuity: the cursor must remain present and
  never regress.
- The August preflight found the research archive node and Bitcoin Core
  synchronized and usable, with sufficient private archive storage. It did not
  start extraction. Historical artefacts have since moved to a dedicated VM;
  that transfer does not establish current RPC readiness or extraction state.
  Repeat the research preflight before the run using the current private
  infrastructure notes.
- The August production preflight found `known_stale_block` populated. Verify
  membership again before backfill. Do not run a separate known-stale import
  during the repair window; an unexpected membership gap requires diagnosis
  against the current monitor publication workflow first.

## Planning Risks / Unknowns

- The number of 80-byte parents, fallbacks, uncles, new inserts, and compatible
  enrichments is unknown until the two runs complete. Counts are outputs, not
  prerequisites.
- A production restore can preserve event identities while losing enriched
  event, RSK-sidecar, or pool-attribution fields. Resume decisions therefore
  require semantic snapshots of all direct capture state, not identity counts
  alone.
- An uncle is requested by its canonical parent height but is stored at the
  uncle's own child height. Chunk snapshots must select rows by acquisition
  height while serializing the actual stored event, RSK sidecar, and
  attribution state so boundary uncles cannot evade replay validation.
- Production release, backup freshness, RPC reachability, database capacity,
  Core synchronization, and exact network identity can change after this
  read-only audit. Recheck every gate immediately before the write.
- The scheduled backup and prune jobs normally retain only the newest archive
  across their managed roots. The repair must stop those timers or otherwise
  protect the exact bound rollback archive for the complete repair window.
- Bitcoin Core can change its active-chain view during a long research
  classification. Capture the classification run's Core context in its private
  summary and repeat classification if an observed reorg invalidates the run.
- The full research extraction is shared with `merge-mining-research-9ec`.
  Starting a second competing full-tip RSK extraction would create ambiguous
  provenance and is prohibited.

## Approach

Use two independent acquisition tracks with one common publication outcome.

### Production track

Keep the poller floor unchanged. Ship the rebased monitor fixture, comments,
and tests, then run the existing packaged `backfill-rsk` command through a
deploy-owned fixed-range wrapper. The wrapper divides parent heights 0 through
139998 into deterministic chunks, validates the RSK network and pinned boundary
blocks, requires a current hash-verified backup, and holds the shared database
mutation lock for its complete mutating lifetime.

Each attempt records the installed release, raw command summary, redacted log
digest, and a semantic database snapshot covering the direct event, RSK
evidence, and pool-attribution rows affected by that chunk. A receipt is
skippable only when its internal range and attempt match its path and its
current semantic database snapshot still matches. A restore or other state
change supersedes the receipt and triggers an idempotent replay. Successful
upsert counts describe capture outcomes, not inserted-row counts.

The live poller may stay active because its canonical polling range begins at
139999, but every explicit database mutation workflow, including manual
restore, migration, equivalence migration, historical publication, and this
backfill, uses the same filesystem mutation lock. Final acceptance verifies
that the live RSK poll cursor remained present and moved only forward.

### Research track

Run one explicit half-open extraction `[0, pinned_tip + 1)` against the private
RSKj archive. The extractor writes two append-only CSVs as one durable unit:
the 80-byte parent-header inventory and an exact skip ledger for the known
fallback shapes. Each durable interval is assembled fully in memory, including
all advertised uncles, before either CSV is appended. Both append segments are
fsynced, hashed, and recorded before the checkpoint advances atomically.

The checkpoint binds the explicit range, source-chain endpoint identities,
schemas, byte offsets, segment digests, canonical continuity, partition counts,
and final whole-file digests. Resume verifies every committed segment and
truncates only an uncheckpointed tail. Null blocks, missing advertised uncles,
identity mismatches, continuity breaks, and unknown proof shapes retry and then
fail. Completion is sealed only after re-reading the pinned end identity.

Classification accepts only the matching completed checkpoint. It preserves
the RSK node-order child hash, child timestamp, miner, merge-mining hash, uncle
placement, merkle proof, and compressed coinbase tail. It stages the canonical,
stale/unknown, error-block, validated-stale, and summary outputs, then publishes
their content manifest last. Fresh RSK publication verifies the complete
manifest before reading canonical or full-inventory rows. A historical
child-identity sidecar may replace a fresh source bundle only when height, hash,
time, and every populated source cell agree exactly, preventing hybrid rows.

Raw extraction data, the skip ledger, checkpoint, complete classifier family,
and summary remain in the private archive. Git receives only the established
validated-stale input, Monitor-evidence LFS payload, counts, manifest, novelty,
and documentation outputs required by the existing publication contract.

## Implementation Steps

1. Preserve and verify the monitor branch.

   - Work only in the dedicated `fix/rsk-pre-floor-backfill` worktree.
   - Retain a backup ref for the pre-rebase tip.
   - Confirm the eight commits remain patch-equivalent with `git range-diff`.
   - Keep `PreRskip92Skipped` as the compatibility name while correcting its
     acquisition-floor comments.
   - Pin the real height-112829 block fixture and exact database identity.
   - Test that production traversal is not clamped to the polling floor and
     that a full pre-floor header writes successfully.
   - Run the focused RSK tests, DB integration tests, `just lint`, and the
     monitor workspace test gate.

2. Verify and land the implemented research acquisition contract.

   - Keep `scripts/extract/extract_rsk_auxpow.py` as the operator entry point.
   - Put durable state and validation in
     `src/stale_blocks_analysis/rsk_extraction.py`.
   - Require explicit `--start`, `--end`, and `--output`; derive checkpoint and
     skip-ledger paths only when they are omitted.
   - Keep RSKj RPC batches at or below 50 while allowing a separately
     configurable durable interval.
   - Validate strict integer response IDs, canonical identity and continuity,
     exact advertised uncle hashes, and the known proof shapes.
   - Test retry atomicity, crash-tail truncation, content tampering, endpoint
     drift, partition accounting, cross-batch continuity, and explicit CLI
     bounds.

3. Verify and land the implemented research classifier and publication boundary.

   - Gate `scripts/classify/classify_rsk_stales.py` on a completed extraction
     checkpoint before constructing Bitcoin RPC.
   - Require a clean Git worktree, record its exact HEAD, and preserve the
     original dependency fingerprints for a final publisher-side recheck.
   - Preserve every Monitor-required RSK sidecar field and reject malformed
     source bundles.
   - Emit the private `rsk_canonical_blocks.csv` companion with the RSK child
     hash in forward node order and the Bitcoin height confirmed by Core.
   - Stage the five-output family through
     `src/stale_blocks_analysis/rsk_classifier_artifacts.py` and publish the
     digest manifest last.
   - Verify fresh full and canonical artifacts in
     `evidence_normalization.py` before publication, then apply exact whole-
     bundle hydration in `evidence_hydration.py`.
   - Test asymmetric hash byte order, incomplete checkpoints, output aliasing,
     manifest and artifact tampering, empty sealed input, and a non-empty
     end-to-end Monitor publication row.
   - Run `just format-check`, `just lint`, `just test-unit`,
     `just test-dataset`, `just test`, and `just check-leaks` in the activated
     project virtual environment.

4. Verify and land the implemented deploy-owned fixed-range wrapper.

   - Add `scripts/rsk-early-backfill.sh`, its local fake harness, Nix package
     wiring, systemd preflight and mutation services, just recipes, and operator
     documentation in the deploy repository.
   - Pin RSK mainnet chain ID `0x1e`, exact height-112829 and height-139999 child
     identities, proof shape, tip coverage, synchronized Bitcoin Core, source
     identity, populated known-stale state, and stable poll cursor.
   - Require an explicit current PostgreSQL custom archive and matching SHA-256
     before initializing the run manifest, and keep backup/prune scheduling
     drained until the completed run no longer depends on that archive.
   - Verify the shared filesystem mutation lock on manual archive restore,
     ordinary migration, equivalence migration, historical publication import,
     the early backfill, and its unknown-parent reconciliation. This coarse
     operator lock surrounds the existing PostgreSQL advisory locks; it does
     not replace their in-database serialization.
   - Record one atomic receipt per attempt. Bind its range and attempt to its
     canonical or history path and its full semantic database snapshot.
   - Recover safely from interruption during receipt supersession and replay a
     chunk whenever its current database state differs.
   - Parse the unredacted command summary before producing the redacted human
     log. Reject missing or malformed canonical and uncle outcomes.
   - Test wrong-network, wrong-canary, unsynchronized-Core, bad backup,
     backup tampering, shared-lock exclusion, partial failure, resume,
     semantic restore drift, boundary uncles, receipt path swapping,
     supersession crash recovery, log tampering, release mismatch, and final
     canary/boundary/cursor gates.
   - Run `just test-rsk-early-backfill`, maintenance-drain tests, Bash syntax,
     Nix formatting/evaluation, `just check`, and `git diff --check` locally.

5. Re-review the three repositories before external action.

   - Read every changed file and compare every claimed behavior with the diff.
   - Confirm no stale RSKIP-92 explanation, first-writer claim, inserted-row
     claim, private infrastructure identifier, dead import, or untracked raw
     artifact remains.
   - Confirm the attached monitor main checkout and original deploy main
     checkout remain clean; changes belong only to their dedicated branches.
   - Update `merge-mining-research-15q` and `merge-mining-research-9ec`
     sequentially through the shared Beads server with the verified state.

6. Confirm execution remains within the recorded operator authorisation.

   - The 2026-09-08 close-out instruction authorises the ordered code review,
     merge, and recovery workflow above. Do not request the same approval again.
   - Escalate a new destructive operation or a material change in scope.

7. Release and preflight production after approval.

   - Merge or otherwise select the reviewed monitor and deploy commits.
   - Update the deploy app pin, evaluate the closure, run a deployment dry run,
     then deploy the exact reviewed release.
   - Run `just rsk-early-backfill-dry-run <host>`.
   - Open the protected scheduler window with
     `just rsk-early-backfill-drain-window <host>`, then create and durably pin
     the required current custom archive with
     `just rsk-early-backfill-create-backup <host>`. Use
     `just rsk-early-backfill-record-backup <archive> <sha256> <host>` only to
     bind an already-created archive after the same drain gate passes.
   - Run `just rsk-early-backfill-preflight <host>` and stop on any release,
     RPC, network, Core, backup, database, source, cursor, or canary mismatch.

8. Execute and validate the production repair after approval.

   - Start only with
     `just rsk-early-backfill-start RUN-RSK-EARLY-0-139998 <host>`.
   - Monitor systemd status and wrapper receipts. A failed or interrupted run
     resumes through the same command after diagnosis.
   - Require `just rsk-early-backfill-validate-complete <host>`.
   - Run `just rsk-early-backfill-reclassify-unknown <host>` if unknown parents
     remain, rerun the confirmed backfill start so semantic receipt drift is
     replayed, and require complete validation again.
   - Stop the pollers for `just rebuild-source-health <host>`, verify source
     health, then restart the pollers and check runtime status.
   - Verify the public height-112829 parent canary is `auxpow:rsk`, child height
     112829, kind `near`; the height-139999 semantic snapshot is unchanged; and
     the live RSK poll cursor remained present and never regressed.
   - Release the rollback pin only after those checks pass, then resume the
     stopped schedulers through their separate literal-confirmation target.

9. Execute the shared research run after approval.

   - Read current private migration notes and verify the actual RSK RPC source,
     historical canonical and advertised-uncle reads, synchronized Bitcoin Core,
     and writable storage on the new research VM. Archive transfer and live-node
     cutover are separate operations; do not assume they completed together.
   - Inventory matching raw CSVs, skip ledgers, checkpoints, and active jobs on
     both the retained source host and destination VM. Resolve any existing run
     before starting; never create a competing extraction or edit a checkpoint
     to conceal a path or identity mismatch.
   - Coordinate with `merge-mining-research-9ec` and pin one explicit current
     archive tip.
   - Run the extractor from height 0 to that pinned tip's exclusive successor,
     resuming only with the exact matching checkpoint.
   - Classify the sealed raw inventory against the synchronized Bitcoin Core
     node into the staged private output family.
   - Validate the extraction checkpoint, skip ledger, classifier manifest,
     output counts, and full canonical/stale/unknown/error partition before
     publication.

10. Publish and reconcile research outputs.

    - Copy only reviewed publication inputs from private staging into the
      research worktree. Do not copy production database rows or raw extracts.
    - Regenerate `data/validated-stales/rsk_validated_stales.csv`, descendant
      corrections if any, `results/monitor-evidence/rsk_monitor_evidence.csv`,
      publication counts and manifest, novelty, and every document whose RSK
      counts or coverage statement changes.
    - Run the complete research quality and dataset gates again against the
      materialized LFS inputs.
    - Confirm no publication allowlist or private archive artifact entered Git.

11. Close or hand off the beads only after evidence exists.

    - Close `merge-mining-research-15q` only when production and research both
      contain the early interval.
    - If `merge-mining-research-9ec` deliberately owns a remaining full-chain
      publication step, record the exact completed early-RSK evidence and
      dependency before closing `15q`.
    - After acceptance evidence is retained and the rollback window is closed,
      track retirement or consolidation of the one-time deploy machinery as a
      separate cleanup. Do not remove its safety gates before acceptance.

## Acceptance Criteria

- The monitor code documents height 139999 only as a polling acquisition floor
  and has regression coverage for real pre-floor capture, database identity,
  and unclamped traversal.
- The deploy wrapper is fixed to parent heights 0 through 139998, resumable,
  backup-gated, network-pinned, release-pinned, and protected by the shared
  production mutation lock.
- Every completed production chunk has a path-bound receipt whose semantic
  snapshot covers all direct event, RSK evidence, and attribution state it can
  write, including boundary uncles.
- Production height 112829 is publicly queryable as an `auxpow:rsk` `near`
  event with the expected child identity.
- The pre-existing height-139997 uncle and the complete height-139999 boundary
  semantic state are preserved or compatibly enriched, never contradicted.
- The RSK poll cursor remains present and is no lower than its preflight value;
  source health is rebuilt successfully.
- The research extraction checkpoint records a validated continuous explicit
  height-zero run through its pinned endpoint, with every canonical height and
  advertised uncle represented exactly once as either an 80-byte row or an
  intentional skip-ledger outcome.
- The classifier accepts only the sealed extraction, produces a verified
  complete output family, and retains all Monitor-required RSK child identity
  and sidecar fields without byte-order reversal or hybrid hydration.
- The private classified inventory covers the early interval and the shared
  `9ec` full-chain range. Every new valid direct stale and every available
  canonical observation appears in regenerated publication outputs.
- RSK documentation no longer treats 139999 as an activation boundary and,
  after the actual data run, no longer describes heights 0 through 139998 as
  unrecovered.
- Raw extracts, skip ledgers, checkpoints, full classifier inventories,
  manifests, summaries, credentials, hostnames, IP addresses, and database
  archives remain outside Git.
- All monitor, deploy, and research quality gates pass on the final reviewed
  changes and regenerated data.
- No commit, push, archive write, deployment, production mutation, or bead
  closure occurs without the corresponding explicit approval and evidence.
