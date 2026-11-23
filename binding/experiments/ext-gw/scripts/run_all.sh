#!/usr/bin/env bash
# Run all 96 ext-gw topologies SERIALLY (ONE topology up at a time, per CONTRACT §12 / brief).
# Run from binding/harness:  bash ../experiments/ext-gw/scripts/run_all.sh
set -uo pipefail
K=../experiments/ext-gw
prog=$K/runs/progress.log
: > "$prog"
n=0; tot=$(wc -l < $K/topologies.txt | tr -d ' ')
while read -r id; do
  [ -z "$id" ] && continue
  n=$((n+1))
  # skip if already completed (status.txt present with runner_rc=0) to allow resume
  if grep -q 'runner_rc=0' "$K/runs/$id/status.txt" 2>/dev/null; then
    echo "[$n/$tot] SKIP (done) $id" | tee -a "$prog"; continue
  fi
  echo "[$n/$tot] $(date +%H:%M:%S) START $id" | tee -a "$prog"
  bash $K/scripts/run_one.sh "$id" >/dev/null 2>&1
  h=$(wc -l < "$K/runs/$id/hits.jsonl" 2>/dev/null | tr -d ' ' || echo NA)
  echo "[$n/$tot] $(date +%H:%M:%S) DONE  $id hits=$h $(cat $K/runs/$id/status.txt 2>/dev/null | grep -oE 'runner_rc=[0-9]+ secs=[0-9]+')" | tee -a "$prog"
done < "$K/topologies.txt"
echo "ALL DONE" | tee -a "$prog"
