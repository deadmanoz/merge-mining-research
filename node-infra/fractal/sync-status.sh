#!/usr/bin/env bash
# One-line Fractal IBD status with deltas since the last check.
# State is kept at /tmp/fractal-last.json.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${FRACTAL_DATA_DIR:-${HERE}/data}"
CONF="${DATA_DIR}/bitcoin.conf"
RPCUSER=$(grep '^rpcuser=' "$CONF" | cut -d= -f2)
RPCPASS=$(grep '^rpcpassword=' "$CONF" | cut -d= -f2)
RPC_URL=http://127.0.0.1:18332/
LAST=/tmp/fractal-last.json

if ! docker ps --filter name=fractald --format '{{.Names}}' | grep -qx fractald; then
  echo 'fractald container not running'
  exit 1
fi

D=$(curl -s --max-time 15 --user "$RPCUSER:$RPCPASS" -H 'content-type: application/json' \
    --data '{"jsonrpc":"1.0","id":0,"method":"getblockchaininfo","params":[]}' "$RPC_URL")
P=$(curl -s --max-time 10 --user "$RPCUSER:$RPCPASS" -H 'content-type: application/json' \
    --data '{"jsonrpc":"1.0","id":0,"method":"getconnectioncount","params":[]}' "$RPC_URL")
export D P LAST

python3 <<'PY'
import json, os, sys
try:
    info = json.loads(os.environ['D'])['result']
    peers = json.loads(os.environ['P'])['result']
except Exception as e:
    print(f'RPC error: {e}'); sys.exit(0)
b = info['blocks']; h = info['headers']
v = info.get('verificationprogress', 0) * 100
disk = info.get('size_on_disk', 0) / 1e9
last = os.environ['LAST']
prev = json.load(open(last)) if os.path.exists(last) else {'blocks': 0, 'disk': 0}
db = b - prev['blocks']
dd = disk - prev['disk']
flags = []
if prev['blocks'] and prev['blocks'] < 1500000 <= b:
    flags.append('crossed 1,500,000 (v0.3.0 hard-fork height)')
if peers < 3:
    flags.append(f'peers low={peers}')
print(f'blocks={b:,} headers={h:,} verif={v:.4f}% peers={peers} disk={disk:.2f}GB Dblocks=+{db:,} Ddisk=+{dd:.2f}GB')
if flags:
    print(' | '.join(flags))
json.dump({'blocks': b, 'disk': disk}, open(last, 'w'))
PY
