# Contributing

Contributions that add a merge-mined chain recovery, correct an attribution,
tighten the methodology, or improve reproducibility are welcome, including new
chain data and AI-assisted work.

## Especially welcome: new data

The coverage holes are the README
[child-chain coverage](README.md#child-chain-coverage) tables: five surveyed
candidates with no block data (BLAST, Bitcoin Stash, Fusioncoin, Jax.Network,
and Jincoin), and the partial or bounded rows (VCash, i0coin, Huntercoin,
Xaya, Syscoin, and Bitcoin Vault). What was tried for the blocked candidates
is in [`docs/chains/surveyed-infra.md`](docs/chains/surveyed-infra.md). Raw
block data, node datadirs, snapshots, peer addresses, or archive locations are
useful even without running the pipeline. The per-chain notes under
[`docs/chains/`](docs/chains/) record each hole. Open an issue describing what
you have.

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

Committed surfaces and the private-archive boundary are in
[research contracts](docs/research-contracts.md#data-boundaries).

## Adding a chain or changing a claim

When code changes affect a published claim, update the corresponding data and docs
in the same change, or call out what still needs regeneration. For an integrated
chain that typically means keeping these in sync: `src/stale_blocks_analysis/config.py`,
`src/stale_blocks_analysis/stale_blocks.py`, `docs/chains/<chain>.md`,
`docs/auxpow-recovery.md`, `docs/process-data-outcomes.md`, the shared
[novelty report](results/novelty.md) (`just novelty`), the upstream sidecar,
`README.md`, and the tests under `tests/`.

See [research contracts](docs/research-contracts.md) for evidence semantics,
[the pipeline reference](docs/pipeline-reference.md#code-conventions) for
implementation conventions, and [upstreaming](docs/upstreaming.md) for contributing
recovered headers to `bitcoin-data/stale-blocks`. `AGENTS.md` is the agent entry point.

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
