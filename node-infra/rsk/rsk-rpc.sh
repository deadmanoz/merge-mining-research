#!/bin/sh
set -eu

method=${1:?usage: rsk-rpc METHOD [JSON_PARAM ...]}
shift

# Parse each argument separately, rejecting empty, malformed or multiple values.
params=$(jq -cn --args '$ARGS.positional | map(fromjson)' -- "$@")

request=$(jq -cn --arg method "$method" --argjson params "$params" \
    '{jsonrpc:"2.0",id:1,method:$method,params:$params}')
response=$(curl --fail-with-body --silent --show-error \
    --max-time "${RSK_RPC_TIMEOUT:-15}" \
    -H 'content-type: application/json' \
    --data "$request" \
    "http://${RSK_RPC_BIND:-127.0.0.1}:${RSK_RPC_PORT:-4444}")

if printf '%s\n' "$response" | jq -e 'has("error") and (.error != null)' >/dev/null; then
    printf '%s\n' "$response" | jq -c '.error' >&2
    exit 1
fi

if ! printf '%s\n' "$response" | jq -e 'has("result")' >/dev/null; then
    printf '%s\n' 'RPC response has no result or error' >&2
    exit 1
fi

printf '%s\n' "$response" | jq -c '.result'
