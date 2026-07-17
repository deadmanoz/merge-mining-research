#!/usr/bin/env bash
# Render data/unobtanium.conf with addnode= entries from peers.list.
#
# No bootstrap.dat is available for Unobtanium; IBD proceeds directly from
# the pinned peers. Idempotent.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${HERE}/data"
PEERS_FILE="${HERE}/peers.list"
ADDNODE_COUNT="${ADDNODE_COUNT:-8}"

mkdir -p "${DATA_DIR}"

CONF="${DATA_DIR}/unobtanium.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering unobtanium.conf"
    if [[ ! -s "${PEERS_FILE}" ]]; then
        echo "peers.list is missing or empty" >&2
        exit 1
    fi
    addnodes=$(head -n "${ADDNODE_COUNT}" "${PEERS_FILE}" | sed 's/^/addnode=/')

    rpcuser="${RPCUSER:-uno}"
    rpcpassword="${RPCPASSWORD:-$(openssl rand -hex 24)}"

    cat > "${CONF}" <<EOF
server=1
txindex=1
disablewallet=1
listen=1

# RPC — bound to 0.0.0.0 inside the container; docker-compose only publishes
# 127.0.0.1:65535 on the host, so the public P2P port stays the only exposed one.
rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcuser=${rpcuser}
rpcpassword=${rpcpassword}
rpcport=65535

port=65534

${addnodes}
EOF
    chmod 600 "${CONF}"
    echo "    wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "==> unobtanium.conf already present, skipping"
fi

if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 1000:1000 "${DATA_DIR}"
fi

echo "==> Ready. Next:"
echo "    docker compose build && docker compose up -d"
