#!/usr/bin/env bash
# Render elcash.conf in the ELCASH datadir. Idempotent.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${ELCASH_DATA_DIR:-${HERE}/data}"

mkdir -p "${DATA_DIR}"

CONF="${DATA_DIR}/elcash.conf"
if [[ ! -f "${CONF}" ]]; then
    echo "==> Rendering elcash.conf at ${CONF}"
    cat > "${CONF}" <<'CONFEOF'
# Electric Cash (ELCASH) — headless node for AuxPoW extraction.
# Extraction reads blocks over RPC with cookie auth (.cookie in the datadir).

server=1
listen=1

# Ports remapped off Bitcoin Core's 8332/8333 defaults so the node can
# share a host with a Core instance.
port=8433
rpcport=18432

rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcallowip=0.0.0.0/0
CONFEOF
    chmod 600 "${CONF}"
else
    echo "==> elcash.conf already present at ${CONF}, skipping"
fi

# The container runs as UID/GID 1000. If init runs as root, normalise ownership.
if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 1000:1000 "${DATA_DIR}"
fi

echo "==> Ready. Next:"
echo "    docker compose build && docker compose up -d"
