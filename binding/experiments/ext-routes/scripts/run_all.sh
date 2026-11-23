#!/usr/bin/env bash
# Run every ext-routes topology, ONE at a time (CONTRACT: one topology up at a time).
# Run from binding/harness:  bash ../experiments/ext-routes/scripts/run_all.sh [outdir-root]
set -uo pipefail
K=$(cd ../experiments/ext-routes && pwd)
ROOT=${1:-$K/runs}
mkdir -p "$ROOT"
: > "$ROOT/summary.csv"
echo "started $(date -u +%FT%TZ)" > "$ROOT/run_all.log"
n=0
while read -r id; do
  [ -z "$id" ] && continue
  n=$((n+1))
  echo "[$n] $id ..." | tee -a "$ROOT/run_all.log"
  bash "$K/scripts/run_one.sh" "$id" "$ROOT" >> "$ROOT/run_all.log" 2>&1 || echo "  run_one nonzero for $id" | tee -a "$ROOT/run_all.log"
  tail -1 "$ROOT/$id/status.txt" 2>/dev/null | tee -a "$ROOT/run_all.log"
done < "$K/topologies.txt"
echo "done $(date -u +%FT%TZ): $n topologies" | tee -a "$ROOT/run_all.log"
