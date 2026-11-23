#!/usr/bin/env bash
# Serial sweep driver for E4: run a worklist of topology IDs one at a time (CONTRACT: one
# topology up at a time per worker). laravel ids use the healthcheck-override runner.
# Usage (from binding/harness): sweep.sh <worklist-file> <progress-log>
set -uo pipefail
WL=$1
PROG=${2:-../experiments/e4/sweep_progress.log}
: > "$PROG"
n=0; tot=$(grep -cvE '^\s*(#|$)' "$WL")
while read -r id; do
  [ -z "$id" ] && continue
  case "$id" in \#*) continue;; esac
  n=$((n+1))
  echo "[$(date -u +%H:%M:%S)] ($n/$tot) START $id" >> "$PROG"
  if [[ "$id" == *laravel* ]]; then
    bash ../experiments/e4/scripts/run_one_hcfix.sh "$id" >/dev/null 2>&1
  else
    bash ../experiments/e4/scripts/run_one.sh "$id" >/dev/null 2>&1
  fi
  st=$(cat ../experiments/e4/runs/$id/status.txt 2>/dev/null | tr '\n' ' ')
  echo "[$(date -u +%H:%M:%S)] ($n/$tot) DONE  $st" >> "$PROG"
done < "$WL"
echo "[$(date -u +%H:%M:%S)] SWEEP COMPLETE ($n topologies)" >> "$PROG"
