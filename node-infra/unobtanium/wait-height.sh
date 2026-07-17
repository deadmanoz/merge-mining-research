#!/usr/bin/env bash
# Wait until unobtaniumd reports blocks >= TARGET. Emit periodic events; exit on reach.
set -u
UNO_DATA_DIR=${UNO_DATA_DIR:-./data}
RPCUSER=$(grep '^rpcuser=' "$UNO_DATA_DIR/unobtanium.conf" | cut -d= -f2)
RPCPASS=$(grep '^rpcpassword=' "$UNO_DATA_DIR/unobtanium.conf" | cut -d= -f2)
TARGET=${1:-600000}
while true; do
  H=$(curl -s --max-time 10 --user "$RPCUSER:$RPCPASS" -H 'content-type: application/json' \
    --data '{"jsonrpc":"1.0","id":0,"method":"getblockcount","params":[]}' \
    http://127.0.0.1:65535/ | python3 -c 'import sys,json; r=json.load(sys.stdin); print(r.get("result",-1))' 2>/dev/null)
  if [[ -z "$H" || "$H" == 'None' || "$H" == '-1' ]]; then
    echo "RPC unreachable"
    sleep 30; continue
  fi
  if [[ "$H" -ge "$TARGET" ]]; then
    echo "REACHED blocks=$H target=$TARGET"
    exit 0
  fi
  sleep 60
done
