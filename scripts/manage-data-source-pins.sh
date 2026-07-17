#!/usr/bin/env bash
# Check or update the exact upstream commits recorded in data-sources.tsv.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${DATA_SOURCES_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
MANIFEST="${DATA_SOURCES_MANIFEST:-${PROJECT_ROOT}/data-sources.tsv}"

usage() {
    echo "Usage: $0 check | update <source-key>" >&2
    exit 2
}

resolve_dest() {
    local key="$1" subdir="$2"
    case "${key}" in
        stale-blocks) printf '%s' "${STALE_BLOCKS_DIR:-${PROJECT_ROOT}/${subdir}}" ;;
        *)            printf '%s' "${PROJECT_ROOT}/${subdir}" ;;
    esac
}

latest_commit() {
    local key="$1" dest="$2"
    if [ ! -d "${dest}/.git" ]; then
        echo "${key}: clone missing at ${dest}; run scripts/fetch-data.sh first" >&2
        return 2
    fi

    if ! git -C "${dest}" fetch origin; then
        echo "${key}: failed to refresh origin; freshness is unknown" >&2
        return 2
    fi

    local latest_ref
    latest_ref="$(git -C "${dest}" symbolic-ref --quiet --short refs/remotes/origin/HEAD || true)"
    if [ -z "${latest_ref}" ]; then
        git -C "${dest}" remote set-head origin --auto >/dev/null
        latest_ref="$(git -C "${dest}" symbolic-ref --quiet --short refs/remotes/origin/HEAD || true)"
    fi
    if [ -z "${latest_ref}" ]; then
        echo "${key}: cannot determine origin's default branch" >&2
        return 2
    fi
    git -C "${dest}" rev-parse "${latest_ref}"
}

check_pins() {
    local stale=0 key url pin subdir dest latest
    while IFS=$'\t' read -r key url pin subdir; do
        [ -z "${key}" ] && continue
        case "${key}" in \#*) continue ;; esac
        dest="$(resolve_dest "${key}" "${subdir}")"
        latest="$(latest_commit "${key}" "${dest}")"
        if [ "${pin}" = "${latest}" ]; then
            echo "${key}: up to date at ${pin}"
        else
            echo "${key}: pinned ${pin}"
            echo "${key}: latest ${latest}"
            stale=1
        fi
    done < "${MANIFEST}"
    return "${stale}"
}

update_pin() {
    local wanted="$1" key url pin subdir dest latest found=0
    while IFS=$'\t' read -r key url pin subdir; do
        [ -z "${key}" ] && continue
        case "${key}" in \#*) continue ;; esac
        if [ "${key}" != "${wanted}" ]; then
            continue
        fi
        found=1
        dest="$(resolve_dest "${key}" "${subdir}")"
        latest="$(latest_commit "${key}" "${dest}")"
        if [ "${pin}" = "${latest}" ]; then
            echo "${key}: already pinned at latest ${pin}"
            return
        fi
        if [ -n "$(git -C "${dest}" status --porcelain)" ]; then
            echo "${key}: clone has local changes; refusing to update the pin" >&2
            return 2
        fi
        if git -C "${dest}" symbolic-ref --quiet --short HEAD >/dev/null; then
            echo "${key}: clone is on a branch; detach it before updating the pin" >&2
            return 2
        fi

        local manifest_tmp
        manifest_tmp="$(mktemp "${MANIFEST}.tmp.XXXXXX")"
        trap 'rm -f "${manifest_tmp}"' EXIT
        awk -F '\t' -v OFS='\t' -v wanted="${wanted}" -v latest="${latest}" \
            '$1 == wanted { $3 = latest } { print }' \
            "${MANIFEST}" > "${manifest_tmp}"
        mv -f "${manifest_tmp}" "${MANIFEST}"
        trap - EXIT

        DATA_SOURCES_ROOT="${PROJECT_ROOT}" DATA_SOURCES_MANIFEST="${MANIFEST}" \
            bash "${SCRIPT_DIR}/fetch-data.sh"
        echo "${key}: updated pin ${pin} -> ${latest}"
        echo "Review and commit the data-sources.tsv diff with regenerated outputs."
        return
    done < "${MANIFEST}"

    if [ "${found}" -eq 0 ]; then
        echo "Unknown data source: ${wanted}" >&2
        return 2
    fi
}

[ -f "${MANIFEST}" ] || { echo "Manifest not found: ${MANIFEST}" >&2; exit 2; }

case "${1:-}" in
    check)
        [ "$#" -eq 1 ] || usage
        check_pins
        ;;
    update)
        [ "$#" -eq 2 ] || usage
        update_pin "$2"
        ;;
    *)
        usage
        ;;
esac
