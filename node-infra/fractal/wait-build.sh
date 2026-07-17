#!/usr/bin/env bash
set -u
LOG="$(cd "$(dirname "$0")" && pwd)/build.log"
IMG='merge-mining-research/fractald:0.3.0'
while true; do
  if docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -qx "$IMG"; then
    echo '=== BUILD SUCCESS ==='
    docker images | grep -E 'fractald|REPOSITORY' | head -5
    exit 0
  fi
  if grep -qE '^ERROR|Error response from daemon|cannot find|No such file|404 Not Found|failed to solve' "$LOG" 2>/dev/null; then
    echo '=== BUILD FAILED ==='
    tail -25 "$LOG"
    exit 1
  fi
  if ! pgrep -af 'docker buildx|buildkit|just build|docker compose build' > /dev/null 2>&1; then
    sleep 5
    if docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -qx "$IMG"; then continue; fi
    echo '=== BUILD PROCESS EXITED — tail ==='
    tail -25 "$LOG"
    exit 2
  fi
  sleep 15
done
