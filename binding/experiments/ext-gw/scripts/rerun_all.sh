#!/usr/bin/env bash
# Determinism reruns: each default-profile hit topology, 3x on fresh topology.
# default==recommended proven identical (analysis/hits_per_topology.csv), so recommended is omitted.
# Run from binding/harness.  ONE topology up at a time (rerun.py), w13-bh- prefix.
set -uo pipefail
K=../experiments/ext-gw
PY=orchestrator/.venv/bin/python
prog=$K/reruns/progress.log
n=0; tot=$(wc -l < $K/reruns/rerun_list.txt | tr -d ' ')
while read -r id; do
  [ -z "$id" ] && continue
  n=$((n+1))
  if [ -f "$K/reruns/$id/rerun_outcome.jsonl" ]; then
    echo "[$n/$tot] SKIP(done) $id" | tee -a "$prog"; continue
  fi
  echo "[$n/$tot] $(date +%H:%M:%S) START $id" | tee -a "$prog"
  $PY $K/scripts/rerun.py "$id" --reps 3 >> "$prog" 2>&1 \
    && echo "[$n/$tot] $(date +%H:%M:%S) DONE $id" | tee -a "$prog" \
    || echo "[$n/$tot] $(date +%H:%M:%S) FAIL $id" | tee -a "$prog"
done < "$K/reruns/rerun_list.txt"
echo "ALL RERUNS DONE $(date +%H:%M:%S)" | tee -a "$prog"
