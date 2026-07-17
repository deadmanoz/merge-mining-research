#!/usr/bin/env bash
# Render data/jincoin.conf. JIN's six DNS seeds and single hardcoded mainnet
# peer (192.52.166.125:23099) are all dead as of 2026-05-16, so the daemon
# will not find any peers via the standard discovery channels. If a private
# addnode= is ever recovered (e.g. via Bitcointalk thread outreach or an
# archived peers.dat), drop it into peers.list one-per-line before running
# this script.
#
# Idempotent.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${HERE}/data"
PEERS_FILE="${HERE}/peers.list"
ADDNODE_COUNT="${ADDNODE_COUNT:-8}"

mkdir -p "${DATA_DIR}"

CONF="${DATA_DIR}/jincoin.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering jincoin.conf"

    addnodes=""
    if [[ -s "${PEERS_FILE}" ]]; then
        # awk filter avoids the pipefail-vs-grep-no-matches trap when
        # peers.list contains only comments (the realistic case today).
        addnodes=$(awk '!/^[[:space:]]*(#|$)/' "${PEERS_FILE}" \
            | head -n "${ADDNODE_COUNT}" | sed 's/^/addnode=/')
    fi

    rpcuser="${RPCUSER:-jincoin}"
    rpcpassword="${RPCPASSWORD:-$(openssl rand -hex 24)}"

    cat > "${CONF}" <<EOF
server=1
txindex=1
disablewallet=1
listen=1

# RPC — bound to 0.0.0.0 inside the container; docker-compose only publishes
# 127.0.0.1:23098 on the host, so the public P2P port (23099) stays the only
# exposed one.
rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcuser=${rpcuser}
rpcpassword=${rpcpassword}
rpcport=23098

port=23099

${addnodes}
EOF
    chmod 600 "${CONF}"
    echo "    wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "==> jincoin.conf already present, skipping"
fi

if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 1000:1000 "${DATA_DIR}"
fi

echo "==> Ready. Next:"
echo "    docker compose build && docker compose up -d"
