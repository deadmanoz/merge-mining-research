#!/usr/bin/env bash
# Prepare ./data/ for the crownd container:
#   1. Render data/crown.conf with addnode= entries from peers.list (if any)
#
# Crown does not publish an official bootstrap.dat at a known stable URL, so
# initial sync relies on DNS seeds (crowncoin.org / crowncoin.net) plus any
# addnode entries we pin via peers.list. If a community bootstrap surfaces,
# add a download/verify step here matching the terracoin/ pattern.
#
# Idempotent: re-running skips steps whose outputs already exist.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${HERE}/data"
PEERS_FILE="${HERE}/peers.list"
# Pick the first N peers from peers.list as addnodes.
ADDNODE_COUNT="${ADDNODE_COUNT:-10}"

mkdir -p "${DATA_DIR}"

# --- crown.conf ------------------------------------------------------------
CONF="${DATA_DIR}/crown.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering crown.conf"

    addnodes=""
    if [[ -s "${PEERS_FILE}" ]]; then
        addnodes=$(head -n "${ADDNODE_COUNT}" "${PEERS_FILE}" | sed 's/^/addnode=/')
    else
        echo "    (peers.list empty — relying on DNS seeds only)"
    fi

    # Random RPC credentials unless the user pre-set them via env.
    rpcuser="${RPCUSER:-crw}"
    rpcpassword="${RPCPASSWORD:-$(openssl rand -hex 24)}"

    cat > "${CONF}" <<EOF
server=1
txindex=1
disablewallet=1
listen=1

# RPC — bound to 0.0.0.0 inside the container; docker-compose only publishes
# to 127.0.0.1 on the host, so the public P2P port stays the only exposed one.
rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcuser=${rpcuser}
rpcpassword=${rpcpassword}
rpcport=9341

port=9340

${addnodes}
EOF
    chmod 600 "${CONF}"
    echo "    wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "==> crown.conf already present, skipping"
fi

# --- Perms --------------------------------------------------------------
# Container runs as UID/GID 1000. If this script ran as root or a different UID,
# nudge the data dir into a state the container can read.
if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 1000:1000 "${DATA_DIR}"
fi

echo "==> Ready. Next:"
echo "    docker compose build && docker compose up -d"
