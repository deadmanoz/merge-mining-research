#!/usr/bin/env bash
# Render data/bitmark.conf. 12 DNS seeds are listed in chainparams.cpp
# (status as of 2021-03-08); if any have churned, peers.list supplies the
# 6 hardcoded IPs from pnSeed[] as fallback. Idempotent.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${HERE}/data"
PEERS_FILE="${HERE}/peers.list"
ADDNODE_COUNT="${ADDNODE_COUNT:-12}"

mkdir -p "${DATA_DIR}"

CONF="${DATA_DIR}/bitmark.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering bitmark.conf"

    addnodes=""
    if [[ -s "${PEERS_FILE}" ]]; then
        addnodes=$(head -n "${ADDNODE_COUNT}" "${PEERS_FILE}" | sed 's/^/addnode=/')
    fi

    rpcuser="${RPCUSER:-bitmark}"
    rpcpassword="${RPCPASSWORD:-$(openssl rand -hex 24)}"

    cat > "${CONF}" <<EOF
server=1
txindex=1
listen=1

# RPC -- bound to 0.0.0.0 inside the container; docker-compose only publishes
# 127.0.0.1:9266 on the host, so the public P2P port (9265) stays the only
# exposed one.
rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcuser=${rpcuser}
rpcpassword=${rpcpassword}
rpcport=9266

port=9265

${addnodes}
EOF
    chmod 600 "${CONF}"
    echo "    wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "==> bitmark.conf already present, skipping"
fi

if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 1000:1000 "${DATA_DIR}"
fi

echo "==> Ready. Next:"
echo "    docker compose build && docker compose up -d"
