#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${DOICHAIN_DATA_DIR:-${HERE}/data}"
PEERS_FILE="${HERE}/peers.list"
ADDNODE_COUNT="${ADDNODE_COUNT:-12}"

mkdir -p "${DATA_DIR}"
CONF="${DATA_DIR}/doichain.conf"
if [[ ! -f "${CONF}" ]]; then
    addnodes=""
    if [[ -s "${PEERS_FILE}" ]]; then
        addnodes=$(awk '!/^[[:space:]]*(#|$)/' "${PEERS_FILE}" \
            | head -n "${ADDNODE_COUNT}" | sed 's/^/addnode=/')
    fi
    rpcuser="${RPCUSER:-doichain}"
    rpcpassword="${RPCPASSWORD:-$(openssl rand -hex 24)}"
    cat > "${CONF}" <<EOF
server=1
txindex=1
disablewallet=1
listen=1
rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcuser=${rpcuser}
rpcpassword=${rpcpassword}
rpcport=8339
port=8338
${addnodes}
EOF
    chmod 600 "${CONF}"
    echo "wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "${CONF} already exists"
fi
