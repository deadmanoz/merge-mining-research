# merge-mining-research — common tasks
#
# `just` (https://github.com/casey/just) targets. Activate the venv first:
#   source .venv/bin/activate

# Activated venv assumed. Override on the command line if needed:
#   just python=python3.11 test
python := "python"

default:
    @just --list

# ── Pinned upstream data ────────────────────────────────────────────────

# Fetch remote metadata and fail if a data-sources.tsv pin is not current.
# Does not change the manifest or checked-out data.
upstream-check:
    bash scripts/manage-data-source-pins.sh check

# Move one manifest entry to its upstream default branch head, then check out
# that exact commit. The data-sources.tsv diff is intentionally reviewable.
upstream-update source="stale-blocks":
    bash scripts/manage-data-source-pins.sh update {{source}}

# Refresh the committed Bitcoin epoch nBits/time reference from mempool.space's
# public Esplora-compatible API. Scheduled CI uses the same command.
refresh-bitcoin-epoch-reference *ARGS:
    {{python}} scripts/prep/refresh_bitcoin_epoch_reference.py {{ARGS}}

# Rebuild the pending stale-block contribution sidecar against the pinned
# bitcoin-data/stale-blocks baseline.
upstream-sidecar:
    {{python}} scripts/reports/build_upstream_stale_sidecar.py

# ── AuxPoW evidence exports ─────────────────────────────────────────────

# Build normalized full-evidence artifacts and manifest (all evidence states;
# bulky, gitignored).
full-evidence:
    {{python}} scripts/reports/build_auxpow_full_evidence.py

# Build the per-chain strict/weak BTC-orphan CSVs under
# results/strict-weak-orphans/ by filtering the committed monitor-evidence
# exports to their classification=unknown rows.
strict-weak-orphans *ARGS:
    {{python}} scripts/reports/build_strict_weak_orphans.py {{ARGS}}

# Build the publication monitor-evidence exports (curated canonical rows,
# gate-accepted stales, valid descendants, and strict/weak BTC orphans).
# This fails closed unless a private archive and relevance inventory are
# available. A disposable diagnostic build must opt in explicitly with
# `--allow-partial` (and may add `--skip-canonical`).
#   just monitor-evidence --chain-archive-dir <private-chain-archive>/chains \
#     --relevance-inventory <private-relevance-inventory.csv> \
#     --supplemental-evidence <private-vcash-canonical-hydration.csv>
monitor-evidence *ARGS:
    {{python}} scripts/reports/build_monitor_evidence.py {{ARGS}}

# ── Tests ───────────────────────────────────────────────────────────────

test:
    {{python}} -m pytest tests/

test-markers:
    {{python}} -m pytest tests/test_coinbase_markers.py -v

# ── Release hygiene ─────────────────────────────────────────────────────

# Format all Python sources with ruff.
format:
    ruff format .

# Fail when Python sources differ from ruff's canonical formatting.
format-check:
    ruff format --check .

# Lint with ruff (the focused gate CI enforces; see [tool.ruff] in pyproject).
lint:
    ruff check .

# Fail if any private-infra token (host alias, personal handle, LAN IP) leaks
# into a tracked file. Such values are redacted to placeholders like
# <archival-host>; this guards against regressions. A built-in baseline always
# covers private LAN IP ranges. Operator-specific tokens (internal host
# aliases, personal handles) are read from a gitignored .leak-tokens file, one
# extended-regex per line, so real host names never live in this public tree;
# see .leak-tokens.example. Excludes this justfile and the example, which
# necessarily name the tokens they describe.
check-leaks:
    #!/usr/bin/env bash
    set -uo pipefail
    baseline='192\.168\.|10\.0\.0\.|/mnt/|archival notes|project memory'
    pattern="$baseline"
    if [ -f .leak-tokens ]; then
        extra=$(grep -vE '^[[:space:]]*(#|$)' .leak-tokens | paste -sd '|' -)
        [ -n "$extra" ] && pattern="$pattern|$extra"
    fi
    if git grep -nIE "$pattern" -- . ':!justfile' ':!.leak-tokens.example'; then
        echo "FAIL: private-infra token found in tracked files (see above)"
        exit 1
    fi
    echo "check-leaks: clean"
