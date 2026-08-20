#!/usr/bin/env bash
#
# Fetch the upstream public data dependencies declared in data-sources.tsv and
# check each one out at its pinned commit, so stale-block analysis is
# reproducible. These are living datasets this project consumes and
# contributes back to, so they are fetched into gitignored data/ subdirectories
# (not committed, not git submodules). Use `just upstream-check` to compare the
# pins with current upstream and `just upstream-update <key>` to update one.
#
# Override the stale-blocks destination with STALE_BLOCKS_DIR. This script is
# non-destructive: it never discards local changes and leaves a clone alone if
# it is on a branch or has uncommitted edits.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${DATA_SOURCES_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
MANIFEST="${DATA_SOURCES_MANIFEST:-${PROJECT_ROOT}/data-sources.tsv}"

# Resolve the destination for a source key, honoring its override env var.
resolve_dest() {
    local key="$1" subdir="$2"
    case "${key}" in
        stale-blocks) printf '%s' "${STALE_BLOCKS_DIR:-${PROJECT_ROOT}/${subdir}}" ;;
        mining-pools) printf '%s' "${LOCAL_MINING_POOLS_DIR:-${PROJECT_ROOT}/${subdir}}" ;;
        *)            printf '%s' "${PROJECT_ROOT}/${subdir}" ;;
    esac
}

pin_checkout() {
    local key="$1" dest="$2" ref="$3"
    if [ "${ref}" = "HEAD" ]; then
        git -C "${dest}" pull --ff-only \
            || echo "  (${key}: not on a fast-forwardable branch; left as-is)"
        return
    fi
    # status --porcelain, not diff: untracked files (an operator's
    # in-progress pool registry edits) must also keep the clone untouched.
    if [ -n "$(git -C "${dest}" status --porcelain 2>/dev/null)" ]; then
        echo "  (${key} has local changes; left as-is. Pinned ref: ${ref})"
        return
    fi
    local on_branch
    on_branch="$(git -C "${dest}" symbolic-ref -q --short HEAD || true)"
    if [ -n "${on_branch}" ]; then
        echo "  (${key} is on branch '${on_branch}'; left as-is. Pinned ref: ${ref})"
        return
    fi
    if [ "$(git -C "${dest}" rev-parse HEAD)" = "${ref}" ]; then
        echo "  (${key} already at pinned ${ref})"
    else
        git -C "${dest}" checkout -q "${ref}"
        echo "  (${key} checked out at pinned ${ref})"
    fi
}

fetch_one() {
    local key="$1" url="$2" ref="$3" subdir="$4"
    local dest
    dest="$(resolve_dest "${key}" "${subdir}")"

    if [ ! -d "${dest}/.git" ]; then
        echo "Cloning ${key} (${url}) into ${dest}"
        mkdir -p "$(dirname "${dest}")"
        git clone "${url}" "${dest}"
        if [ "${ref}" != "HEAD" ]; then
            git -C "${dest}" checkout -q "${ref}"
            echo "  (${key} pinned at ${ref})"
        fi
    else
        echo "Updating ${key} at ${dest}"
        git -C "${dest}" fetch origin
        pin_checkout "${key}" "${dest}" "${ref}"
    fi
}

[ -f "${MANIFEST}" ] || { echo "Manifest not found: ${MANIFEST}" >&2; exit 1; }

echo "Reading pinned data sources from ${MANIFEST}"
while IFS=$'\t' read -r key url ref subdir; do
    [ -z "${key}" ] && continue
    case "${key}" in \#*) continue ;; esac
    fetch_one "${key}" "${url}" "${ref}" "${subdir}"
done < "${MANIFEST}"

echo
echo "Done. Pinned data sources are ready."
