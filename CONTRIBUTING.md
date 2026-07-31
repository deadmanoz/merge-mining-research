# Contributing

Thanks for your interest in this project. It is a research pipeline rather than a
conventional application: the important outputs are claims, datasets, figures, and
methodology docs. Contributions that add a new merge-mined chain recovery, correct
an attribution, tighten the methodology, or improve reproducibility are all welcome.
New chain data and AI-assisted contributions are both explicitly welcome; the
sections below spell out where the coverage gaps are and how verification works.

## Especially welcome: new data

New data is the most valuable thing you can bring to this project, and a small,
verifiable addition is as welcome as a large one. Two kinds of gap in the
README's [child-chain coverage](README.md#child-chain-coverage) tables are worth
calling out because closing either one is exactly the sort of contribution we
want.

**Chains with no recovered data.** Five surveyed candidates reached the
infrastructure stage but yielded no block data at all: BLAST, Bitcoin Stash,
Fusioncoin, Jax.Network, and Jincoin. For any of these, a reachable peer, a
block archive, an explorer dump, or a working sync path would be a genuine
first. See [`docs/chains/surveyed-infra.md`](docs/chains/surveyed-infra.md) for
what was tried and where each one is currently blocked.

**Chains with partial or bounded coverage.** Several integrated chains have known
holes where more history would extend or firm up the result:

- **VCash** is canonical-only: 68 of 767 archived mappings are hydrated, 699
  remain unresolved, and no VCash blockchain has been recovered.
- **i0coin** is bounded by a January 2018 third-party snapshot, so its committed
  counts are provisional.
- **Huntercoin** is recovered from an Arweave archive that ends early, so it is
  not full-lifetime coverage.
- **Xaya** is bounded by a 2024-11-15 snapshot whose tail to the roughly 7.3M
  deprecation height is missing.
- **Syscoin** covers only the fresh-genesis 2019 chain; the retired 2016 to 2019
  Syscoin chain was not extracted.
- **Bitcoin Vault** was recovered from a third-party Blockbook API with no node
  available; its post-2021 weak-share era yields no further accepted candidates.

The per-chain notes under [`docs/chains/`](docs/chains/) record the exact hole in
each case. Raw block data, node datadirs, snapshots, peer addresses, or archive
locations are all useful even when you cannot run the recovery pipeline
yourself. Open an issue describing what you have, and we can work out how to
extract and validate it.

## Setup

Use Python 3.10 or newer. Install the
[`just`](https://github.com/casey/just) command runner before using the task
recipes below.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
./scripts/fetch-data.sh
```

`scripts/fetch-data.sh` clones or updates `bitcoin-data/stale-blocks` under
`data/stale-blocks/` and checks it out at the exact commit pinned in
`data-sources.tsv`. Use `just upstream-check` to detect a stale pin and
`just upstream-update stale-blocks` to record and check out the latest upstream
commit as a reviewable manifest change. Override the clone location with
`STALE_BLOCKS_DIR`.
The recovery pipeline is intentionally mostly standard library plus the
runtime dependencies in `pyproject.toml`. The `dev` extra adds pytest and Ruff
for the documented checks; use `pip install -e .` for a runtime-only install.

## Running checks

Run the narrowest meaningful checks for what you touched, then broaden:

```bash
just format-check
just lint
just test
```

Lint is enforced through a focused ruleset (syntax errors plus the likely-bug
pyflakes rules, including `F821` undefined-name). Style-only rules are not enforced
repo-wide. Formatting is canonicalized by `ruff format .`. CI runs the format
check, lint, and test suite for pull requests and pushes to `main`.

## Data boundaries

Be strict about what belongs in git:

- Commit only the canonical, compact loader inputs (for example
  `data/validated-stales/*_validated_stales.csv`, including RSK, plus
  `data/stale_descendants.csv` and the error-blocks dataset
  `data/error-blocks/error_blocks.csv` with its
  `data/error-blocks/mtp_context.csv` sidecar).
- Do not commit fetched upstream data under `data/stale-blocks/`, raw extracts,
  PoW-passing intermediates, full classifier outputs, marker SQLite/Parquet
  outputs, or node datadirs.
- Private or bulky per-chain artifacts belong in a private archive, not in this
  repo.

## Adding a chain or changing a claim

When code changes affect a published claim, update the corresponding data and docs
in the same change, or call out what still needs regeneration. For an integrated
chain that typically means keeping these in sync: `src/stale_blocks_analysis/config.py`,
`src/stale_blocks_analysis/stale_blocks.py`, `docs/chains/<chain>.md`,
`docs/auxpow-recovery.md`, `docs/process-data-outcomes.md`, the per-chain novelty
CSV, the upstream sidecar, `README.md`, and the tests under `tests/`.

See `AGENTS.md` for the full set of repository conventions (research semantics,
code conventions, validation expectations) and `docs/upstreaming.md` for the rules
on contributing recovered headers back to `bitcoin-data/stale-blocks`.

## Use of AI and LLM tools

AI- and LLM-assisted contributions are welcome. This project was itself built
with heavy LLM assistance under human direction (see the README's
[Use of AI and LLMs](README.md#use-of-ai-and-llms) note), so a pull request
written with those tools is not treated any differently from one written by
hand.

What matters is verification, not the tooling. Every technical claim and every
piece of generated code is checked against primary sources, node behaviour,
chain data, and reproducible pipeline outputs before it is accepted, and LLM
output is treated as working material rather than evidence on its own. So before
you open a contribution produced with AI assistance, ground its claims the same
way: confirm counts against the committed CSVs or JSON summaries they cite, run
the relevant checks, and be ready to point to the source or node behaviour a
change relies on. The main failure mode to guard against is confident but
unverifiable output: plausible-looking numbers that do not match the data, or
citations to code or behaviour that does not exist.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/) (`type(scope):
  description`) and keep each commit a single logical change.
- Explain the why, not just the what, especially for methodology or data changes;
  their counts and caveats are audit evidence.
- State which checks you ran and which you skipped.
