# Changelog

## Unreleased

Store every per-chain monitor-evidence publication payload in Git LFS while
keeping its counts CSV and JSON manifest in ordinary Git, and emit evidence CSV
line endings as LF directly so regenerated LFS objects remain byte-reproducible.

Teach every historical Namecoin-family extraction path to emit authenticated
child-chain evidence directly from its original block source. Raw RPC blocks,
decoded JSON dumps, offline `blk*.dat` scans, Huntercoin block binaries,
Blockbook responses, and Xaya's `PowData` wrapper now produce
`child_block_hash`, `child_header_hex`, `child_block_time`, and `child_nbits`;
the classifier and evidence exporters preserve and validate the same bundle.
`just child-header-coverage` reports per-chain hydration coverage and fails on
header/hash, header/time, or header/`nBits` contradictions. The completed
source-authenticated regeneration covers 2,933,154 of 2,933,154 historical
rows with zero unrecoverable rows, plus all 6 accepted stale-descendant source
observations. The generic snapshot classifier's primary accepted and rejected
publication outputs now use the established normalized `btc_height` /
`btc_header_hash` / `btc_bits` schema. Its full `--classified-output` inventory
retains the source-specific `btc_stale_height` / `btc_hash` / `btc_bits_hex`
fields and validation annotations. The normalized rejected rows no longer carry
standalone `nbits_match` or `post_bch_fork` columns; those diagnostics remain
represented by `validation_status` and `expected_nbits` and are preserved as
standalone fields in the full classifier inventory.

Recover node-verified child block identity for the six live-lifecycle chains
(Namecoin, RSK, Syscoin, Hathor, Elastos, Fractal) and publish it through the
monitor-evidence exports, so merge-mining-monitor's dataset importer can key
imported rows exactly like live capture and deduplicate against it.

- New `scripts/extract/recover_child_identity.py` recovers each row's child
  block hash and timestamp by height -> hash -> block RPC against the live
  child nodes (public API for Hathor), verifying the Bitcoin parent linkage
  re-derives from every fetched child block. All 2,219 chain/header
  observations across the six chains verified (1,870 distinct Bitcoin
  parent headers; 214 parents were observed by more than one chain);
  results are committed under `data/child-identity/`.
- The evidence schema gains `child_block_time` (after `child_block_hash`),
  and both the monitor and full-evidence exports hydrate the child identity
  columns from `data/child-identity/` at build time, refusing identities
  recorded at a different child height. A publication monitor build
  (without `--allow-partial`) now fails closed when a live-chain row lacks a
  verified identity, because the monitor importer deliberately skips such
  rows; `recover_child_identity.py --limit` requires a disposable
  `--output-dir` so a smoke run can never truncate the committed identity
  files.
  Hydrated child hashes use the pipeline's internal (wire) byte order
  (forward for RSK), matching monitor storage. Coverage lands in the counts
  `notes` as `child_identity_hydration=hydrated:N`, and the six live chains
  are targeted unconditionally: a missing, empty, or verification-less
  identity file surfaces as `missing_identity` (fatal to a publication
  build) instead of silently narrowing the target set.
- The RSK monitor export appends the seven columns the monitor's
  `rsk_merge_mining_evidence` sidecar requires (`rsk_miner`,
  `merge_mining_hash`, `is_uncle`, `uncle_index`, `uncle_parent_height`,
  `rsk_merkle_proof`, `rsk_coinbase_tail`), sourced from the live RSK node
  and cross-checked against the classified recovery metadata.
- The stale-descendants export is deliberately outside the exact
  child-identity contract: its rows aggregate observations from several
  chains into chain-less rows and merge-mining-monitor's import surface has
  no stale-descendants entry, so its child identity columns stay empty. The
  counts row records `child_identity=represented_by_source_chain_observations`;
  all 6 corresponding historical source-chain observations carry complete
  authenticated child headers.
- Because the strict/weak orphan projections mirror the monitor export's
  schema, the regenerated RSK projection also carries the seven sidecar
  columns; the other chains' projections gain only `child_block_time`.
- Regenerate all 30 monitor publication artifacts from the same complete
  inputs. Normal publication now includes every available canonical row for
  every chain, with no per-chain allowlist, together with accepted direct
  stales, accepted descendants, and strict/weak unknown-row observations.
  `--skip-canonical` remains available only for explicit disposable
  diagnostics. The strict/weak projection contains 24 strict and 10 weak
  observations across 7 chains.
- Retain complete dated external refreshes for all 17 canonical classifier
  inventories and the 30-artifact normalized full-evidence set. Regenerate
  all 17 historical committed validated inputs and
  `results/child-header-coverage.csv` from the normal source paths. The
  Electric Cash rerun now carries parent output scripts; Terracoin carries
  source-native parent output addresses; Bitcoin Vault classifies 2,566
  canonical and 9 accepted stale rows from 169,939 ordered acquisitions.
- Make publication preflight source-aware without weakening coverage floors:
  accept canonical rows already present in an authoritative full inventory,
  merge split unknown companions for relevance coverage, and avoid inspecting
  unrelated sources when a chain has no strict/weak baseline rows. Resolve
  repository-relative CLI paths before provenance redaction so regenerated
  rows keep reproducible in-repo source paths. Doichain's authoritative
  50,621-row inventory remains an explicit archive-layout declaration rather
  than a smaller substitute.
- Harden the final provenance and validation contract: redact supplemental
  staging roots, union disjoint canonical companions by exact header identity,
  preserve original input row numbers in evidence diagnostics, and fail closed
  on malformed Terracoin RPC child-header fields.

The scheduled Bitcoin epoch-reference refresh now merges its own pull request
once CI passes, instead of leaving it for a manual merge. Opening the pull
request with an `AUTOMATION_PAT` repository secret is what makes this possible:
a pull request opened with the default `GITHUB_TOKEN` never triggers a workflow
run, so there was no CI result to gate on. Without the secret the refresh
degrades to the previous open-and-wait behaviour.

## 0.1.0 - 2026-07-22

Initial public release of the merge-mining research pipeline, documentation,
reproducible node infrastructure, and compact datasets.
