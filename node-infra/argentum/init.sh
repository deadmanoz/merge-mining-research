#!/usr/bin/env bash
# Render data/argentum.conf. DNS seeds in source code (seed.argentum.cc,
# dnsseed.argentum.cc, dnsseed.argentumcoin.cc) all NXDOMAIN as of
# 2026-05-16, so peers.list addnode entries are REQUIRED — not a
# fallback. peers.list ships with the 41 hard-coded fixed seeds from
# src/contrib/seeds/nodes_main.txt (~2017 snapshot). Re-harvest via
# `just refresh-peers` once chainetics.com/nodes/arg.php starts serving
# IPs again (currently broken across all chains, not ARG-specific).
# Idempotent.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${HERE}/data"
PEERS_FILE="${HERE}/peers.list"
ADDNODE_COUNT="${ADDNODE_COUNT:-16}"

mkdir -p "${DATA_DIR}"

CONF="${DATA_DIR}/argentum.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering argentum.conf"

    addnodes=""
    if [[ -s "${PEERS_FILE}" ]]; then
        addnodes=$(head -n "${ADDNODE_COUNT}" "${PEERS_FILE}" | sed 's/^/addnode=/')
    else
        echo "==> WARNING: peers.list is empty; node will rely on DNS seeds (dead) + chainparamsseeds.h"
    fi

    rpcuser="${RPCUSER:-argentum}"
    rpcpassword="${RPCPASSWORD:-$(openssl rand -hex 24)}"

    cat > "${CONF}" <<EOF
server=1
txindex=1
disablewallet=1
listen=1

# RPC — bound to 0.0.0.0 inside the container; docker-compose only publishes
# 127.0.0.1:13581 on the host, so the public P2P port (13580) stays the only
# exposed one. (Argentum's canonical RPC port in chainparams isn't fixed by
# code; 13581 chosen here to mirror the P2P+1 convention used across this
# project's node-infra deployments.)
rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcuser=${rpcuser}
rpcpassword=${rpcpassword}
rpcport=13581

port=13580

${addnodes}
EOF
    chmod 600 "${CONF}"
    echo "    wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "==> argentum.conf already present, skipping"
fi

if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 1000:1000 "${DATA_DIR}"
fi

echo "==> Ready. Next:"
echo "    docker compose build && docker compose up -d"
