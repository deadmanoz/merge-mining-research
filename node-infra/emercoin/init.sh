#!/usr/bin/env bash
# Render data/emercoin.conf. DNS seed `seed.emercoin.com` was healthy
# at scaffold time (5 IPs, 3/3 TCP probes on 6661); peers.list is the
# fallback if DNS seed drops. Idempotent.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${HERE}/data"
PEERS_FILE="${HERE}/peers.list"
ADDNODE_COUNT="${ADDNODE_COUNT:-8}"

mkdir -p "${DATA_DIR}"

CONF="${DATA_DIR}/emercoin.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering emercoin.conf"

    addnodes=""
    if [[ -s "${PEERS_FILE}" ]]; then
        addnodes=$(head -n "${ADDNODE_COUNT}" "${PEERS_FILE}" | sed 's/^/addnode=/')
    fi

    rpcuser="${RPCUSER:-emercoin}"
    rpcpassword="${RPCPASSWORD:-$(openssl rand -hex 24)}"

    cat > "${CONF}" <<EOF
server=1
txindex=1
disablewallet=1
listen=1

# RPC — bound to 0.0.0.0 inside the container; docker-compose only publishes
# 127.0.0.1:6662 on the host, so the public P2P port (6661) stays the only
# exposed one.
rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcuser=${rpcuser}
rpcpassword=${rpcpassword}
rpcport=6662

port=6661

${addnodes}
EOF
    chmod 600 "${CONF}"
    echo "    wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "==> emercoin.conf already present, skipping"
fi

if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 1000:1000 "${DATA_DIR}"
fi

echo "==> Ready. Next:"
echo "    docker compose build && docker compose up -d"
