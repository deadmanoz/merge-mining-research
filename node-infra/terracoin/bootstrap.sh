#!/usr/bin/env bash
# Prepare ./data/ for the terracoind container:
#   1. Download & verify bootstrap.dat.gz from the official mirror
#   2. Decompress into data/bootstrap.dat
#   3. Render data/terracoin.conf with addnode= entries from peers.list
#
# Idempotent: re-running skips steps whose outputs already exist.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${HERE}/data"
BOOTSTRAP_URL="https://terracoin.io/bin/bootstrap/bootstrap.dat.gz"
SIGFILE_URL="https://terracoin.io/bin/bootstrap/bootstrap-SHA256SUM.asc"
EXPECTED_SHA256="3c8ffca131301365673463a16df6d2dc800403f2966d2a589b88b686135725a3"
PEERS_FILE="${HERE}/peers.list"
# Pick the first N peers from peers.list as addnodes.
ADDNODE_COUNT="${ADDNODE_COUNT:-10}"

mkdir -p "${DATA_DIR}"

# --- 1. bootstrap.dat.gz ----------------------------------------------------
GZ="${DATA_DIR}/bootstrap.dat.gz"
if [[ ! -f "${DATA_DIR}/bootstrap.dat" ]]; then
    if [[ ! -f "${GZ}" ]]; then
        echo "==> Downloading bootstrap.dat.gz (~1.3 GB)"
        curl -L --fail --retry 3 -o "${GZ}" "${BOOTSTRAP_URL}"
    else
        echo "==> bootstrap.dat.gz already present, skipping download"
    fi

    echo "==> Verifying SHA256"
    actual=$(shasum -a 256 "${GZ}" | awk '{print $1}')
    if [[ "${actual}" != "${EXPECTED_SHA256}" ]]; then
        echo "SHA256 mismatch!"
        echo "  expected: ${EXPECTED_SHA256}"
        echo "  actual:   ${actual}"
        exit 1
    fi
    echo "    ok"

    echo "==> Decompressing to bootstrap.dat"
    gunzip -k "${GZ}"
    mv "${DATA_DIR}/bootstrap.dat" "${DATA_DIR}/bootstrap.dat.tmp"
    mv "${DATA_DIR}/bootstrap.dat.tmp" "${DATA_DIR}/bootstrap.dat"
    rm -f "${GZ}"
else
    echo "==> bootstrap.dat already present, skipping"
fi

# --- 2. terracoin.conf ------------------------------------------------------
CONF="${DATA_DIR}/terracoin.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering terracoin.conf"

    if [[ ! -s "${PEERS_FILE}" ]]; then
        echo "peers.list is missing or empty" >&2
        exit 1
    fi
    addnodes=$(head -n "${ADDNODE_COUNT}" "${PEERS_FILE}" | sed 's/^/addnode=/')

    # Random RPC credentials unless the user pre-set them via env.
    rpcuser="${RPCUSER:-trc}"
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
rpcport=13332

port=13333

${addnodes}
EOF
    chmod 600 "${CONF}"
    echo "    wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "==> terracoin.conf already present, skipping"
fi

# --- 3. Perms --------------------------------------------------------------
# Container runs as UID/GID 1000. If this script ran as root or a different UID,
# nudge the data dir into a state the container can read.
if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 1000:1000 "${DATA_DIR}"
fi

echo "==> Ready. Next:"
echo "    docker compose build && docker compose up -d"
