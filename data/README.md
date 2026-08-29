# Input data

The analysis consumes the [`bitcoin-data/stale-blocks`](https://github.com/bitcoin-data/stale-blocks)
repository, which contains:

- `stale-blocks.csv` - canonical list of known stale blocks with heights and hashes
- `blocks/` - raw block binaries retained as full evidence for known stale blocks

Derived recovery sidecars also live here when they are consumed by the main
analysis package:

- `bitcoin-epoch-reference/` - compact public-source Bitcoin reference used by
  strict and weak BTC-orphan relevance gates. It contains one row per retarget
  boundary plus a six-confirmation horizon block, fetched from mempool.space's
  public Esplora-compatible API with `just refresh-bitcoin-epoch-reference`.
  The source URL and finalized block identity are recorded in its manifest. This is
  reproducible input data, not a private runtime cache.

- `stale_descendants.csv` - publication-gate-accepted BTC stale-fork
  continuation header candidates
  recovered by walking the full unknown inventories back to known stale
  roots, plus one historical direct-stale row corrected after its predecessor
  was shown to be stale rather than active. Raw classifier rows stay `unknown`;
  this file carries the separate `stale_descendant` classification, and loaders
  admit only `VALID_STALE_DESCENDANT` rows.
- `error-blocks/error_blocks.csv` - the error-blocks dataset and publication
  gate: 39 full-proof-of-work Bitcoin headers that each fail a contextual
  consensus rule, keyed off `classification == "error_block"` (there is no
  `exclusion_scope` column). It supersedes the deleted
  `stale_block_exclusions.csv` overlay: its rows are removed from all public
  stale sets by exact `(height, hash)` key. The former `direct_stale_only`
  row (656478) is not here - it is a `stale_descendant` single-home in
  `stale_descendants.csv`; raw source projection requires its separate
  exact-key correction overlay.
- `stale_descendant_corrections.csv` - the compact typed exact-key correction
  overlay for raw source rows formerly labelled direct stale or canonical. A
  projection requires the correction reason to match the source bucket and
  agreement with the accepted stale-descendant sidecar observation.
- `error-blocks/error_block_observations.csv` - the recovered child-observation
  ledger for every catalogued parent.
- `error-blocks/reconciled_child_identities.csv` - the committed identity and
  source-authentication manifest for the eight observations imported from the
  reconciled descendant-error peer. The manifest pins source coordinates and
  SHA-256 values and carries node-verified 80-byte child headers.
- `error-blocks/mtp_context.csv` - the median-time-past sidecar: the
  canonical parent's median-time-past for each time-rule error block, keyed
  by `(height, hash)`, so the offline validator can re-derive time-rule
  violations without live RPC.

Per-chain recovery intermediates do not live in the public repo. The committed
inputs are the stale-only `data/validated-stales/*_validated_stales.csv` files named after each
chain's source tag (for example `data/validated-stales/bitcoin-vault_validated_stales.csv`)
plus the sidecars above - this includes RSK, whose
`data/validated-stales/rsk_validated_stales.csv` carries RSK miner-address evidence and
historical label columns in place of decoded coinbase outputs but is stale-only
like every other loader input. Raw extractor output, PoW-passing intermediates, rejection files, full
stale/unknown inventories, and source dumps are kept in the private chain
archive and can be copied back into `data/` only for ad hoc reclassification
or unknown-row analysis.

Four header-only files record completed zero-stale outcomes:

- `data/validated-stales/geistgeld_validated_stales.csv` records 0 stales from
  the complete 7,309,972-block `getblock` JSON dump. Of the 2,291
  self-target-PoW-valid parent headers, only one was canonical Bitcoin evidence;
  the other 2,290 failed the Bitcoin epoch-`nBits` relevance gates. The
  committed monitor and strict/weak files are therefore also header-only.

- `data/validated-stales/doichain_validated_stales.csv` accompanies a negative
  survey through the active-chain tip observed at height 430,684 on 2026-06-24.
  It is a normal, header-only loader input, while the
  Monitor keeps Doichain non-selectable because the survey admitted no rows.
  Supporting counts and exact-target audit results live in
  `docs/chains/doichain.md`.
- `data/validated-stales/lyncoin_validated_stales.csv` records 0 stales from the complete
  pre-Flex Lyncoin recovery. The source was a live peer's raw P2P extended
  `headers` stream, which carries the complete AuxPoW proof, rather than a
  full block-body sync. Lyncoin is nevertheless historical and import-ready
  because `results/monitor-evidence/lyncoin_monitor_evidence.csv` retains 11
  admissible canonical Bitcoin-parent rows.
- `data/validated-stales/sixeleven_validated_stales.csv` records 0 stales from the complete
  SixEleven recovery through height 999,406. The pinned official node image
  synced from six live peers; extraction scanned the recovered datadir's
  legacy `blkNNNN.dat` files, excluded `blkindex.dat`, and validated child
  identity through legacy RPC. SixEleven is nevertheless historical and
  import-ready because
  `results/monitor-evidence/sixeleven_monitor_evidence.csv` retains 7
  admissible canonical Bitcoin-parent rows.

The complete candidate inventories were subsequently assessed for strict/weak
BTC-orphan relevance. Both chains produced 0 strict and 0 weak rows: all
56,642 Lyncoin unknowns and all 80,357 SixEleven unknowns failed the Bitcoin
epoch-`nBits` consistency gates. The committed zero rows live under
`results/strict-weak-orphans/`.

Canonical rows are not loader inputs. The compact rows selected for publication
live with all other final monitor-facing evidence under
`results/monitor-evidence/`; their source provenance points to the private
classifier or explorer archive from which they were derived. In particular,
`results/monitor-evidence/vcash_monitor_evidence.csv` contains 68 hydrated
canonical mappings from a 767-row explorer archive, but no VCash blockchain
was recovered and 699 mappings remain unresolved. It is canonical-only partial
evidence, not a stale-only loader input or a basis for stale and strict/weak
totals. `scripts/prep/hydrate_vcash_canonical.py` writes the standard
gitignored `data/vcash_canonical_blocks.csv` source by default; the publication
builder discovers and normalizes it like every other canonical companion.

For downstream consumers that need canonical, stale, unknown, near, rejected,
or stale-descendant evidence rather than only stale census inputs, build the
generated full-evidence layer with:

```bash
just full-evidence
```

The output under `results/full-evidence/` is separate from `data/` and is
gitignored by default. Its manifest records whether each chain used a full
classifier inventory, a stale-only publication file, or no discovered source.
Private runs can pass one or more `--chain-archive-dir` roots to
`scripts/reports/build_auxpow_full_evidence.py`; archive files are read in
place and are not copied into this repository.

Each historically named `*_validated_stales.csv` carries the canonical
16-column direct-stale-candidate layout: the chain height, four authenticated
child-header columns (`child_block_hash`, `child_header_hex`,
`child_block_time`, `child_nbits`), the eight shared header/coinbase columns
(`btc_height`, `btc_header_hash`,
`btc_prev_hash`, `btc_time`, `btc_bits`, `coinbase_scriptsig_hex`,
`coinbase_outputs`, `btc_header_hex`),
`classification`, and the persisted publication-gate verdict (`validation_status`,
`expected_nbits`). The committed file is publication-gate accepted only
(`stale` rows with `validation_status=VALID`); the gate runs once at
classification time and the loader never recomputes it. `VALID` is a legacy
compatibility token for the declared available-evidence header-context checks,
not proof that a complete Bitcoin block was consensus-valid. Those checks
include header hash and self-PoW, active-parent linkage, expected `nBits`,
median-time-past, historical minimum block version, and, when the real
coinbase scriptSig is available, its length and BIP34 height prefix. RSK lacks
the evidence for the coinbase-dependent checks. See
[`docs/data-validity.md`](../docs/data-validity.md). Chains with extra research
columns trail them after the gate columns (for example coiledcoin's
`eligius_attack_window`). `btc_bits` is canonical lowercase 8-char hex.

The 20 July 2026 audit replayed all 3,652 accepted direct observations against
Bitcoin Core tip 958,882. All passed their available checks; this was not a
full-block consensus replay. RSK's 298 rows still lack evidence for the two
coinbase-dependent checks.

Many extractor/classifier scripts keep their defaults under `data/` so an
operator can run them from the repo root without a long path. Those outputs are
ignored scratch files. After a run is validated, move the full raw/intermediate
artifacts to the private chain archive
(`<private-chain-archive>/chains/<chain>/`) and commit only the canonical
compact loader input or public sidecar.

## Fetching

Run the helper script from the repo root:

```bash
./scripts/fetch-data.sh
```

This clones the upstream repository into `data/stale-blocks/` on first run. On
subsequent runs it fetches remote refs and keeps the clone at the commit pinned
in `data-sources.tsv`, unless a branch or local edits make checkout unsafe. The
directory is gitignored - nothing from `data/stale-blocks/` is tracked by this
repository.

## Overriding the location

If you already have a clone of the data repository somewhere else, point the
analysis at it via the `STALE_BLOCKS_DIR` environment variable. For example,
this prints Namecoin novelty without rewriting its committed result:

```bash
STALE_BLOCKS_DIR=/path/to/stale-blocks \
  python scripts/compute_chain_novelty.py namecoin --no-csv
```

The same variable is respected by `scripts/fetch-data.sh`.
