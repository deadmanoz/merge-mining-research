#!/usr/bin/env bash
# Render data/blast.conf. BLAST's three DNS seeds and their www/bare-domain
# siblings all wildcard-resolve to a single dead GCP IP (35.220.144.141)
# with TCP 64640 closed as of 2026-05-16, so the daemon will not find peers
# via the standard discovery channels. If a private addnode= is ever
# recovered (a former pool operator's peers.dat, a BitcoinTalk-thread lead,
# an archived blk*.dat with peer hints, etc.), drop it into peers.list one
# per line before running this script.
#
# Idempotent.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${HERE}/data"
PEERS_FILE="${HERE}/peers.list"
ADDNODE_COUNT="${ADDNODE_COUNT:-8}"

mkdir -p "${DATA_DIR}"

CONF="${DATA_DIR}/blast.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering blast.conf"

    addnodes=""
    if [[ -s "${PEERS_FILE}" ]]; then
        # awk filter avoids the pipefail-vs-grep-no-matches trap when
        # peers.list contains only comments (the realistic case today).
        addnodes=$(awk '!/^[[:space:]]*(#|$)/' "${PEERS_FILE}" \
            | head -n "${ADDNODE_COUNT}" | sed 's/^/addnode=/')
    fi

    rpcuser="${RPCUSER:-blast}"
    rpcpassword="${RPCPASSWORD:-$(openssl rand -hex 24)}"

    cat > "${CONF}" <<EOF
server=1
txindex=1
disablewallet=1
listen=1

# RPC — bound to 0.0.0.0 inside the container; docker-compose only publishes
# 127.0.0.1:64639 on the host, so the public P2P port (64640) stays the only
# exposed one.
rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcuser=${rpcuser}
rpcpassword=${rpcpassword}
rpcport=64639

port=64640

${addnodes}
EOF
    chmod 600 "${CONF}"
    echo "    wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "==> blast.conf already present, skipping"
fi

if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 1000:1000 "${DATA_DIR}"
fi

echo "==> Ready. Next:"
echo "    docker compose build && docker compose up -d"
