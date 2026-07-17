#!/usr/bin/env bash
# Render bitcoin.conf in the Fractal datadir for archival-mode sync.
# Idempotent: re-running skips if the config already exists.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${FRACTAL_DATA_DIR:-${HERE}/data}"

mkdir -p "${DATA_DIR}"

CONF="${DATA_DIR}/bitcoin.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering bitcoin.conf at ${CONF}"

    rpcuser="${RPCUSER:-fractal}"
    rpcpassword="${RPCPASSWORD:-$(openssl rand -hex 24)}"

    cat > "${CONF}" <<CONFEOF
# Fractal Bitcoin (fractald v0.3.0) — archival mode for AuxPoW recovery.

server=1
txindex=1
listen=1

# Ports remapped to 18332/18333 so the node can share a host with a
# Bitcoin Core instance on the default 8332/8333.
port=18333
rpcport=18332

# RPC — bound to 0.0.0.0 inside the container; docker-compose publishes
# only 127.0.0.1:18332 on the host. allowip is widened because Docker's
# userland proxy can present source IPs from the compose network gateway
# that plain 127.0.0.1 + 172.16/12 rules don't always match. Safe because
# the published port is loopback-only on the host.
rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcallowip=0.0.0.0/0
rpcuser=${rpcuser}
rpcpassword=${rpcpassword}
CONFEOF
    chmod 600 "${CONF}"
    echo "    wrote ${CONF} (rpcuser=${rpcuser})"
else
    echo "==> bitcoin.conf already present at ${CONF}, skipping"
fi

# The container runs as UID/GID 1000. If init runs as root, normalise ownership.
if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 1000:1000 "${DATA_DIR}"
fi

echo "==> Ready. Next:"
echo "    docker compose build && docker compose up -d"
