#!/bin/sh
# Render solidar.conf into the datadir with generated RPC credentials.
# Idempotent: an existing solidar.conf is left untouched.
set -eu

DATA_DIR="${SOLIDAR_DATA_DIR:-./data}"
CONF="$DATA_DIR/solidar.conf"

if [ -f "$CONF" ]; then
    echo "init: $CONF already exists, leaving it untouched"
    exit 0
fi

mkdir -p "$DATA_DIR"
RPC_USER="solidar-$(openssl rand -hex 8)"
RPC_PASS="$(openssl rand -hex 24)"

cat > "$CONF" <<EOF
server=1
rpcuser=$RPC_USER
rpcpassword=$RPC_PASS
# This 0.8-era daemon ignores -rpcbind and listens on all interfaces as
# soon as any rpcallowip is set (see README "Legacy RPC listener
# behaviour"). Exposure is bounded by the container network namespace
# plus the loopback-only host publish; RPC auth is always required.
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
EOF
chmod 600 "$CONF"

# The container runs as UID/GID 1000.
if [ "$(id -u)" = "0" ]; then
    chown -R 1000:1000 "$DATA_DIR"
fi
echo "init: rendered $CONF"
