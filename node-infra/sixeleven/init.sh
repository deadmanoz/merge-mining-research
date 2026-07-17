#!/usr/bin/env bash
# Render the 611.conf expected by the official 611project/611coin image.
# peers.list contains nodes observed at the public explorer height on
# 2026-07-10. Idempotent.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SIXELEVEN_DATA_DIR:-${HERE}/data}"
PEERS_FILE="${HERE}/peers.list"
ADDNODE_COUNT="${ADDNODE_COUNT:-8}"

mkdir -p "${DATA_DIR}"

CONF="${DATA_DIR}/611.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering 611.conf"

    addnodes=""
    if [[ -s "${PEERS_FILE}" ]]; then
        addnodes=$(awk '!/^[[:space:]]*(#|$)/' "${PEERS_FILE}" \
            | head -n "${ADDNODE_COUNT}" | sed 's/^/addnode=/')
    fi

    rpcuser="${RPCUSER:-sixeleven}"
    rpcpassword="${RPCPASSWORD:-$(openssl rand -hex 24)}"

    cat > "${CONF}" <<EOF
server=1
txindex=1
listen=1
dns=1
noirc=1

# Compose publishes RPC only on the host loopback interface. This legacy
# daemon accepts clients from the Docker bridge through rpcallowip.
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcuser=${rpcuser}
rpcpassword=${rpcpassword}
rpcport=8663

port=8661

${addnodes}
EOF
    chmod 600 "${CONF}"
    echo "    wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "==> 611.conf already present, skipping"
fi

echo "==> Ready. Next:"
echo "    docker compose pull && docker compose up -d"
