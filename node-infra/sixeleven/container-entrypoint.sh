#!/bin/bash
# Require the host-generated config and suppress an upstream entrypoint bug
# that otherwise prints 611.conf, including its RPC password, to container logs.

set -euo pipefail

if [[ ! -s /sixeleven/611.conf ]]; then
    echo "ERROR: /sixeleven/611.conf is missing; run 'just init' first" >&2
    exit 1
fi

# The upstream script treats this variable as a filesystem path in its logging
# guard. Pointing it at the existing config prevents the unsafe `cat`; the RPC
# password itself remains the random value already stored inside 611.conf.
export SIXELEVEN_RPC_PASSWORD=/sixeleven/611.conf

exec /entrypoint.sh "$@"
