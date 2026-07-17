#!/usr/bin/env bash
set -u
LOG=$HOME/uno-docker/build.log
IMG='merge-mining-research/unobtaniumd:master-54d68b08'
while true; do
  if docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -qx "$IMG"; then
    echo '=== BUILD SUCCESS ==='
    docker images | grep -E 'unobtaniumd|REPOSITORY' | head -5
    exit 0
  fi
  if grep -qE '^ERROR|make\[[0-9]+\]: \*\*\*|Error response from daemon|cannot find|No such file' "$LOG" 2>/dev/null; then
    echo '=== BUILD FAILED ==='
    tail -40 "$LOG"
    exit 1
  fi
  if ! pgrep -af 'docker buildx|buildkit|docker compose build|just build' > /dev/null 2>&1; then
    sleep 5
    if docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -qx "$IMG"; then
      continue
    fi
    echo '=== BUILD PROCESS EXITED — tail ==='
    tail -40 "$LOG"
    exit 2
  fi
  sleep 30
done
