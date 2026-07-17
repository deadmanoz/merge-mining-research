#!/usr/bin/env bash
# Render lyncoin.conf with the currently reachable seed peer as an explicit
# addnode. Lyncoin also retains seed.lyncoin.net in its native DNS seed list.
# Idempotent.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${LYNCOIN_DATA_DIR:-${HERE}/data}"
PEERS_FILE="${HERE}/peers.list"
ADDNODE_COUNT="${ADDNODE_COUNT:-8}"

mkdir -p "${DATA_DIR}"

CONF="${DATA_DIR}/lyncoin.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering lyncoin.conf"

    addnodes=""
    if [[ -s "${PEERS_FILE}" ]]; then
        addnodes=$(awk '!/^[[:space:]]*(#|$)/' "${PEERS_FILE}" \
            | head -n "${ADDNODE_COUNT}" | sed 's/^/addnode=/')
    fi

    rpcuser="${RPCUSER:-lyncoin}"
    rpcpassword="${RPCPASSWORD:-$(openssl rand -hex 24)}"

    cat > "${CONF}" <<EOF
server=1
txindex=1
disablewallet=1
listen=1

# RPC listens inside the Docker network. Compose publishes it only on the
# host loopback interface.
rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcuser=${rpcuser}
rpcpassword=${rpcpassword}
rpcport=5053

port=5054

${addnodes}
EOF
    chmod 600 "${CONF}"
    echo "    wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "==> lyncoin.conf already present, skipping"
fi

if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 1000:1000 "${DATA_DIR}"
fi

echo "==> Ready. Next:"
echo "    docker compose build && docker compose up -d"
