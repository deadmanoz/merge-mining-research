#!/usr/bin/env bash
set -u
UNO_DATA_DIR=${UNO_DATA_DIR:-./data}
RPCUSER=$(grep '^rpcuser=' "$UNO_DATA_DIR/unobtanium.conf" | cut -d= -f2)
RPCPASS=$(grep '^rpcpassword=' "$UNO_DATA_DIR/unobtanium.conf" | cut -d= -f2)
while true; do
  D=$(curl -s --max-time 10 --user "$RPCUSER:$RPCPASS" -H 'content-type: application/json' \
    --data '{"jsonrpc":"1.0","id":0,"method":"getblockchaininfo","params":[]}' \
    http://127.0.0.1:65535/ 2>/dev/null)
  H=$(echo "$D" | python3 -c 'import sys,json; d=json.load(sys.stdin)["result"]; print(d.get("blocks",-1))' 2>/dev/null)
  V=$(echo "$D" | python3 -c 'import sys,json; d=json.load(sys.stdin)["result"]; print(d.get("verificationprogress",0))' 2>/dev/null)
  # treat verif >= 0.9999 as tip-reached
  if python3 -c "import sys; sys.exit(0 if float('$V') >= 0.9999 else 1)" 2>/dev/null; then
    echo "REACHED blocks=$H verif=$V"
    exit 0
  fi
  sleep 120
done
