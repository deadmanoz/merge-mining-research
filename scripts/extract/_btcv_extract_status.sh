#!/usr/bin/env bash
# Status + rsync-pull helper for the 4-host BTCV AuxPoW extraction.
# Run with no args to print per-host status. Pass --pull to rsync all four
# CSVs into ./data/ for inspection while jobs are still running.

set -eu

# Partition map (revised 2026-05-17 after worker-a disk-full incident at h=128495):
# worker-a finished early at h=128525; leftover 128526-142500 reassigned to
# worker-c as a second concurrent process (see *-dev01leftover.csv).
# Operator-local SSH host aliases (not public hostnames); set your own in ~/.ssh/config.
HOSTS=(primary-worker worker-a worker-b worker-c worker-c)
RANGES=("58420-100000" "100001-128525" "142501-185000" "185001-228360" "128526-142500")
EXPECTED=(41581 28525 42500 43360 13975)
CSVS=("bitcoin-vault_auxpow_raw.primary-worker.csv"
      "bitcoin-vault_auxpow_raw.worker-a.csv"
      "bitcoin-vault_auxpow_raw.worker-b.csv"
      "bitcoin-vault_auxpow_raw.worker-c.csv"
      "bitcoin-vault_auxpow_raw.worker-c-dev01leftover.csv")
LABELS=("primary-worker" "worker-a" "worker-b" "worker-c" "worker-c-2")

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="$PROJECT_ROOT/data"

mode="${1:-status}"

if [ "$mode" = "--pull" ]; then
  echo "=== Pulling partial CSVs from all hosts → $DATA_DIR ==="
  for i in "${!HOSTS[@]}"; do
    H="${HOSTS[$i]}"
    C="${CSVS[$i]}"
    rsync -avz --partial -e "ssh -o ConnectTimeout=5" \
      "$H:~/btcv-extract/$C" \
      "$DATA_DIR/$C" 2>&1 | tail -3
  done
  echo "=== Local sizes ==="
  ls -la "$DATA_DIR"/bitcoin-vault_auxpow_raw.*.csv 2>/dev/null
  exit 0
fi

printf "%-18s %-16s %8s %8s %5s\n" "LABEL" "RANGE" "DONE" "TOTAL" "%"
total_done=0
total_expected=0
for i in "${!HOSTS[@]}"; do
  H="${HOSTS[$i]}"
  R="${RANGES[$i]}"
  T="${EXPECTED[$i]}"
  C="${CSVS[$i]}"
  L="${LABELS[$i]}"
  rows=$(ssh -n -o ConnectTimeout=4 "$H" "
    cd ~/btcv-extract 2>/dev/null || exit 0
    [ -f '$C' ] && r=\$(wc -l < '$C') || r=1
    [ \"\$r\" -lt 1 ] && r=1
    echo \$((\$r - 1))
  " 2>/dev/null)
  rows=${rows:-0}
  pct=$(( rows * 100 / T ))
  printf "%-18s %-16s %8d %8d %4d%%\n" "$L" "$R" "$rows" "$T" "$pct"
  total_done=$((total_done + rows))
  total_expected=$((total_expected + T))
done
echo "---------------------------------------------------------"
overall_pct=$(( total_done * 100 / total_expected ))
printf "%-18s %-16s %8d %8d %4d%%\n" "TOTAL" "58420-228360" "$total_done" "$total_expected" "$overall_pct"
